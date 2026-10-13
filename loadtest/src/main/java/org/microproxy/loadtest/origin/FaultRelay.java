package org.microproxy.loadtest.origin;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.microproxy.loadtest.Json;

/**
 * A Toxiproxy-style TCP relay between the proxy under test and the origin, applying one fault
 * ("toxic") to every connection:
 *
 * <ul>
 *   <li>{@code latency:ms=<n>}: each chunk the proxy sends towards the origin waits {@code n} ms;
 *   <li>{@code bandwidth:bps=<n>}: the origin's bytes reach the proxy at {@code n} bytes a second;
 *   <li>{@code reset:after=<n>}: after {@code n} bytes towards the proxy (0: as soon as the request
 *       arrives), both sides are reset;
 *   <li>{@code stall:after=<n>}: after {@code n} bytes towards the proxy, nothing more is relayed,
 *       but the connections stay open until the proxy closes its side;
 *   <li>{@code blackhole}: the request is read and never answered; the origin is not contacted.
 * </ul>
 *
 * <p>Each relay counts the connections it holds, so the fault scenario can check that the proxy
 * closed every one (no leak).
 */
public final class FaultRelay {

    private final String name;
    private final String kind;
    private final Map<String, Long> params;
    private final InetSocketAddress origin;
    private final AtomicLong open = new AtomicLong();
    private final AtomicLong accepted = new AtomicLong();
    private ServerSocket listener;

    private FaultRelay(String name, String kind, Map<String, Long> params, InetSocketAddress origin) {
        this.name = name;
        this.kind = kind;
        this.params = params;
        this.origin = origin;
    }

    /** Parses {@code name:kind[:param=value...]}. */
    public static FaultRelay parse(String spec, InetSocketAddress origin) {
        String[] f = spec.split(":");
        if (f.length < 2) throw new IllegalArgumentException("relay spec name:kind[:k=v]: " + spec);
        Map<String, Long> params = new LinkedHashMap<>();
        for (int i = 2; i < f.length; i++) {
            String[] kv = f[i].split("=");
            params.put(kv[0], Long.parseLong(kv[1]));
        }
        if (!java.util.List.of("latency", "bandwidth", "reset", "stall", "blackhole").contains(f[1])) {
            throw new IllegalArgumentException("unknown relay kind " + f[1]);
        }
        return new FaultRelay(f[0], f[1], params, origin);
    }

    /** The relay's name. */
    public String name() {
        return name;
    }

    /** Starts listening on an ephemeral port of the origin's address; returns the port. */
    public int start() throws IOException {
        listener = new ServerSocket();
        listener.bind(new InetSocketAddress(InetAddress.getByName(origin.getHostString()), 0), 1024);
        Thread.ofPlatform().daemon().name("relay-" + name).start(() -> {
            while (!listener.isClosed()) {
                try {
                    Socket client = listener.accept();
                    accepted.incrementAndGet();
                    open.incrementAndGet();
                    Thread.ofVirtual().start(() -> relay(client));
                } catch (IOException e) {
                    if (listener.isClosed()) return;
                }
            }
        });
        return listener.getLocalPort();
    }

    /** The relay's counters. */
    public Map<String, Object> stats() {
        return Json.obj("kind", kind, "open", open.get(), "accepted", accepted.get());
    }

    private void relay(Socket client) {
        Socket server = null;
        try {
            client.setTcpNoDelay(true);
            if (kind.equals("blackhole")) {
                InputStream in = client.getInputStream();
                byte[] buf = new byte[8192];
                while (in.read(buf) >= 0) {
                    // Swallow the request; never answer.
                }
                return;
            }
            server = new Socket();
            server.connect(origin, 5000);
            server.setTcpNoDelay(true);
            Socket s = server;
            long after = params.getOrDefault("after", 0L);
            if (kind.equals("reset") && after == 0) {
                // Reset as soon as the request arrives, before any response byte.
                if (client.getInputStream().read() >= 0) {
                    client.setSoLinger(true, 0);
                    s.setSoLinger(true, 0);
                }
                return;
            }
            Thread up = Thread.ofVirtual().start(() -> pumpUp(client, s));
            pumpDown(s, client);
            up.join();
        } catch (IOException e) {
            // A side closed or reset.
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            closeQuietly(client);
            closeQuietly(server);
            open.decrementAndGet();
        }
    }

    /** Proxy to origin: the request, delayed by the latency toxic. */
    private void pumpUp(Socket client, Socket server) {
        long latency = kind.equals("latency") ? params.getOrDefault("ms", 0L) : 0;
        byte[] buf = new byte[16 * 1024];
        try {
            InputStream in = client.getInputStream();
            OutputStream out = server.getOutputStream();
            int n;
            while ((n = in.read(buf)) >= 0) {
                if (latency > 0) Thread.sleep(latency);
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (IOException e) {
            // Closed.
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            // The proxy closed its side: end both connections (this also ends a stall).
            closeQuietly(client);
            closeQuietly(server);
        }
    }

    /** Origin to proxy: the response, throttled, reset or stalled. */
    private void pumpDown(Socket server, Socket client) throws IOException {
        long bps = kind.equals("bandwidth") ? params.getOrDefault("bps", 0L) : 0;
        long after = params.getOrDefault("after", Long.MAX_VALUE);
        boolean limited = kind.equals("reset") || kind.equals("stall");
        byte[] buf = new byte[bps > 0 ? (int) Math.max(512, Math.min(16 * 1024, bps / 20)) : 16 * 1024];
        InputStream in = server.getInputStream();
        OutputStream out = client.getOutputStream();
        long sent = 0;
        long start = System.nanoTime();
        while (true) {
            int max = buf.length;
            if (limited) max = (int) Math.min(max, after - sent);
            if (limited && max <= 0) {
                if (kind.equals("reset")) {
                    client.setSoLinger(true, 0);
                    server.setSoLinger(true, 0);
                    closeQuietly(client);
                    closeQuietly(server);
                    return;
                }
                // Stall: relay nothing more; wait until the proxy closes its side (pumpUp ends it).
                while (!client.isClosed()) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
                return;
            }
            int n = in.read(buf, 0, max);
            if (n < 0) {
                client.shutdownOutput();
                return;
            }
            out.write(buf, 0, n);
            out.flush();
            sent += n;
            if (bps > 0) {
                long due = start + sent * 1_000_000_000L / bps;
                long wait = due - System.nanoTime();
                if (wait > 0) {
                    try {
                        Thread.sleep(wait / 1_000_000, (int) (wait % 1_000_000));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
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
