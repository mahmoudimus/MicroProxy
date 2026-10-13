package org.microproxy.loadtest.client;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import org.HdrHistogram.Histogram;

/**
 * Holds idle keep-alive connections for the connection ramp. Each connection is opened from one of
 * several loopback source addresses (127.0.0.2, 127.0.0.3, ...; each has its own ephemeral ports),
 * optionally carries one request (so the proxy holds an upstream connection too), then idles. A
 * virtual thread per connection blocks reading it, so a connection the proxy closes is noticed at
 * once.
 */
public final class Holder {

    private final InetSocketAddress proxy;
    private final List<InetAddress> sources;
    private final int perSource;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final ReentrantLock lock = new ReentrantLock();
    private final List<HttpConn> held = new ArrayList<>();
    private final AtomicLong closedByPeer = new AtomicLong();
    private final AtomicLong opened = new AtomicLong();

    /**
     * A holder of connections to {@code proxy}; each source address takes at most
     * {@code perSource} connections.
     */
    public Holder(InetSocketAddress proxy, List<InetAddress> sources, int perSource, int connectTimeoutMs, int readTimeoutMs) {
        this.proxy = proxy;
        this.sources = sources;
        this.perSource = perSource;
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
    }

    /** Connections held now (opened and not closed by the proxy). */
    public long alive() {
        return opened.get() - closedByPeer.get();
    }

    /**
     * Opens {@code count} more connections, {@code parallel} at a time, each sending
     * {@code warm} (null: none) first. Stops early when the load generator hits its own limits
     * (descriptors, ports) or when more than {@code maxFailures} attempts fail.
     */
    public Map<String, Object> open(int count, int parallel, List<HttpConn.Target> warm, long maxFailures)
            throws InterruptedException {
        AtomicInteger next = new AtomicInteger();
        AtomicLong failed = new AtomicLong();
        AtomicReference<String> clientLimit = new AtomicReference<>();
        AtomicReference<String> firstError = new AtomicReference<>();
        EnumMap<Outcome, Long> outcomes = new EnumMap<>(Outcome.class);
        Map<String, Long> statuses = new LinkedHashMap<>();
        ReentrantLock tallyLock = new ReentrantLock();
        Histogram warmLatency = Histograms.create();
        long start = System.nanoTime();
        List<Thread> workers = new ArrayList<>();
        int base = (int) opened.get();
        for (int w = 0; w < parallel; w++) {
            workers.add(Thread.ofVirtual().start(() -> {
                while (clientLimit.get() == null && failed.get() <= maxFailures) {
                    int i = next.getAndIncrement();
                    if (i >= count) return;
                    // Stop before the load generator's own heap runs out, so it reports a client
                    // limit instead of dying with an OutOfMemoryError mid-step.
                    if ((i & 0xFF) == 0 && heapNearlyFull()) {
                        clientLimit.compareAndSet(null, "the load generator is near its heap limit ("
                                + usedHeapMb() + " MB of " + maxHeapMb() + " MB -Xmx): raise its --client-heap");
                        return;
                    }
                    int index = base + i;
                    InetAddress source = sources.isEmpty() ? null : sources.get(Math.min(index / perSource, sources.size() - 1));
                    if (!sources.isEmpty() && index / perSource >= sources.size()) {
                        clientLimit.compareAndSet(null, "every source address has " + perSource + " connections ("
                                + sources.size() + " addresses): add source addresses");
                        return;
                    }
                    long t0 = System.nanoTime();
                    Outcome outcome;
                    HttpConn conn = null;
                    String detail = null;
                    int status = -1;
                    try {
                        conn = HttpConn.open(proxy, source, connectTimeoutMs, readTimeoutMs, 0);
                        if (warm != null && !warm.isEmpty()) {
                            HttpConn.Result r = conn.exchange(warm.get(index % warm.size()));
                            outcome = r.outcome();
                            status = r.status();
                            detail = r.detail();
                        } else {
                            outcome = Outcome.OK;
                        }
                    } catch (IOException e) {
                        outcome = Outcome.of(e, true, false);
                        detail = e.getMessage();
                    }
                    long t1 = System.nanoTime();
                    tallyLock.lock();
                    try {
                        outcomes.merge(outcome, 1L, Long::sum);
                        if (status > 0) statuses.merge(Integer.toString(status), 1L, Long::sum);
                        if (outcome == Outcome.OK) Histograms.recordNanos(warmLatency, t1 - t0);
                    } finally {
                        tallyLock.unlock();
                    }
                    if (outcome == Outcome.OK && conn != null && conn.usable()) {
                        hold(conn);
                    } else {
                        if (conn != null) conn.close();
                        if (outcome == Outcome.OK) outcome = Outcome.CLOSED;
                        failed.incrementAndGet();
                        firstError.compareAndSet(null, outcome + (status > 0 ? " " + status : "") + (detail != null ? ": " + detail : ""));
                        if (outcome.clientLimit()) {
                            clientLimit.compareAndSet(null, outcome == Outcome.CLIENT_FDS
                                    ? "the load generator ran out of file descriptors (" + detail + "): raise its ulimit -n"
                                    : "the load generator ran out of ephemeral ports (" + detail + "): add source addresses or widen ip_local_port_range");
                        }
                    }
                }
            }));
        }
        for (Thread t : workers) t.join();
        long elapsed = System.nanoTime() - start;
        long ok = outcomes.getOrDefault(Outcome.OK, 0L);
        Map<String, Object> errors = new LinkedHashMap<>();
        outcomes.forEach((k, v) -> {
            if (k != Outcome.OK) errors.put(k.name(), v);
        });
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("requested", count);
        m.put("attempted", Math.min(count, next.get()));
        m.put("opened", ok);
        m.put("failed", failed.get());
        m.put("errors", errors);
        m.put("statuses", statuses);
        m.put("setupS", elapsed / 1e9);
        m.put("setupRate", Math.round(ok * 1e10 / Math.max(1, elapsed)) / 10.0);
        m.put("warmLatencyMs", Histograms.summary(warmLatency));
        m.put("held", alive());
        m.put("closedByPeer", closedByPeer.get());
        if (clientLimit.get() != null) m.put("clientLimit", clientLimit.get());
        if (firstError.get() != null) m.put("firstError", firstError.get());
        return m;
    }

    private static boolean heapNearlyFull() {
        Runtime rt = Runtime.getRuntime();
        long used = rt.totalMemory() - rt.freeMemory();
        // maxMemory is the -Xmx ceiling; stop with headroom for the connections already in flight.
        return used > rt.maxMemory() * 85 / 100;
    }

    private static long usedHeapMb() {
        Runtime rt = Runtime.getRuntime();
        return (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024);
    }

    private static long maxHeapMb() {
        return Runtime.getRuntime().maxMemory() / (1024 * 1024);
    }

    private void hold(HttpConn conn) {
        lock.lock();
        try {
            held.add(conn);
        } finally {
            lock.unlock();
        }
        opened.incrementAndGet();
        Thread.ofVirtual().start(() -> {
            try {
                conn.socket().setSoTimeout(0);
                InputStream in = conn.input();
                while (true) {
                    int b = in.read();
                    if (b < 0) break;
                }
            } catch (SocketTimeoutException e) {
                return;
            } catch (IOException e) {
                // Reset, or closed by release().
            }
            if (!conn.socket().isClosed()) closedByPeer.incrementAndGet();
            conn.close();
        });
    }

    /** The counts, without opening anything. */
    public Map<String, Object> status() {
        return Map.of("held", alive(), "closedByPeer", closedByPeer.get(), "opened", opened.get());
    }

    /** Closes every held connection. */
    public void release() {
        lock.lock();
        try {
            for (HttpConn c : held) {
                // Closed here, so its watcher does not count it as closed by the proxy.
                c.close();
            }
            held.clear();
            opened.set(0);
            closedByPeer.set(0);
        } finally {
            lock.unlock();
        }
    }
}
