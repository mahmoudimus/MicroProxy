package org.microproxy.loadtest.client;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;
import org.HdrHistogram.Histogram;

/**
 * Open-loop load at a fixed rate, corrected for coordinated omission as wrk2 does it.
 *
 * <p>The schedule is fixed before the first request: request {@code k} is due at
 * {@code start + k / rate}, and requests are dealt round-robin to the pool's connections, each run
 * by its own virtual thread. A connection sends each of its requests at its due time, or at once
 * if it is still busy with the previous one, and the latency is measured from the due (intended)
 * time, not from when it was sent: a stall of the proxy shows as the latency every request
 * scheduled during it would have seen, instead of being hidden by a client that waits.
 *
 * <p>The client's own health is measured too: when a connection is free but wakes up late for a
 * due time (the load generator is short of CPU), the lag is recorded; a run whose lag is large is
 * flagged {@code clientSaturated}, and its numbers are not the proxy's. Requests still unsent when
 * the step ends are counted as {@code backlog}.
 */
public final class OpenLoop {

    /** A free connection waking up later than this for a due time counts as a late send. */
    static final long LATE_NANOS = 10_000_000L;

    private OpenLoop() {}

    /** Keep-alive connections reused across steps. */
    public static final class Pool {
        private final InetSocketAddress proxy;
        private final List<InetAddress> sources;
        private final int connectTimeoutMs;
        private final int readTimeoutMs;
        private final ReentrantLock lock = new ReentrantLock();
        private final List<HttpConn> conns = new ArrayList<>();

        /** A pool of connections to {@code proxy}, spread over {@code sources} (may be empty). */
        public Pool(InetSocketAddress proxy, List<InetAddress> sources, int connectTimeoutMs, int readTimeoutMs) {
            this.proxy = proxy;
            this.sources = sources;
            this.connectTimeoutMs = connectTimeoutMs;
            this.readTimeoutMs = readTimeoutMs;
        }

        void resize(int n) {
            lock.lock();
            try {
                while (conns.size() > n) {
                    HttpConn c = conns.remove(conns.size() - 1);
                    if (c != null) c.close();
                }
                while (conns.size() < n) conns.add(null);
            } finally {
                lock.unlock();
            }
        }

        HttpConn get(int i) throws IOException {
            lock.lock();
            HttpConn c;
            try {
                c = conns.get(i);
            } finally {
                lock.unlock();
            }
            if (c != null && c.usable()) return c;
            if (c != null) c.close();
            InetAddress source = sources.isEmpty() ? null : sources.get(i % sources.size());
            c = HttpConn.open(proxy, source, connectTimeoutMs, readTimeoutMs, 0);
            lock.lock();
            try {
                conns.set(i, c);
            } finally {
                lock.unlock();
            }
            return c;
        }

        /** Closes every connection. */
        public void close() {
            resize(0);
        }
    }

    /** The per-thread tallies, merged at the end. */
    private static final class Tally {
        final Histogram latency = Histograms.create();
        final Histogram lag = Histograms.create();
        final EnumMap<Outcome, Long> outcomes = new EnumMap<>(Outcome.class);
        final Map<Integer, Long> statuses = new LinkedHashMap<>();
        long attempted;
        long backlog;
        long behind;
        long late;
        String firstError;

        void count(Outcome o) {
            outcomes.merge(o, 1L, Long::sum);
        }
    }

    /**
     * Runs {@code rate} requests a second of {@code target} for {@code durationNanos} over
     * {@code connections} of {@code pool}; returns the step's results.
     */
    public static Map<String, Object> run(Pool pool, HttpConn.Target target, double rate, int connections,
            long durationNanos) throws InterruptedException {
        pool.resize(connections);
        double interval = 1e9 / rate;
        long start = System.nanoTime() + 20_000_000L;
        long end = start + durationNanos;
        double slots = durationNanos / interval;
        List<Tally> tallies = new ArrayList<>();
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < connections; i++) {
            Tally t = new Tally();
            tallies.add(t);
            int index = i;
            threads.add(Thread.ofVirtual().name("load-" + i).start(
                    () -> connectionLoop(pool, target, index, connections, start, end, interval, slots, t)));
        }
        for (Thread t : threads) t.join();
        long elapsed = System.nanoTime() - start;

        Tally all = new Tally();
        for (Tally t : tallies) {
            all.latency.add(t.latency);
            all.lag.add(t.lag);
            t.outcomes.forEach((k, v) -> all.outcomes.merge(k, v, Long::sum));
            t.statuses.forEach((k, v) -> all.statuses.merge(k, v, Long::sum));
            all.attempted += t.attempted;
            all.backlog += t.backlog;
            all.behind += t.behind;
            all.late += t.late;
            if (all.firstError == null) all.firstError = t.firstError;
        }
        long ok = all.outcomes.getOrDefault(Outcome.OK, 0L);
        Map<String, Object> errors = new LinkedHashMap<>();
        all.outcomes.forEach((k, v) -> {
            if (k != Outcome.OK) errors.put(k.name(), v);
        });
        long intended = (long) Math.floor(slots);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("targetRate", rate);
        m.put("connections", connections);
        m.put("durationS", durationNanos / 1e9);
        m.put("intended", intended);
        m.put("attempted", all.attempted);
        m.put("ok", ok);
        m.put("errors", errors);
        m.put("errorCount", all.attempted - ok);
        m.put("statuses", stringKeys(all.statuses));
        m.put("backlog", all.backlog);
        m.put("behind", all.behind);
        m.put("achievedRate", Math.round(ok * 1e10 / Math.max(durationNanos, 1)) / 10.0);
        m.put("latencyMs", Histograms.summary(all.latency));
        m.put("percentilesMs", Histograms.spectrum(all.latency));
        m.put("hist", Histograms.encode(all.latency));
        Map<String, Object> lag = Histograms.summary(all.lag);
        lag.put("late", all.late);
        m.put("clientLagMs", lag);
        // The client could not keep its own schedule: more than 1% of free connections woke late.
        boolean saturated = all.attempted > 0 && all.late > Math.max(5, all.attempted / 100);
        m.put("clientSaturated", saturated);
        m.put("elapsedS", elapsed / 1e9);
        if (all.firstError != null) m.put("firstError", all.firstError);
        return m;
    }

    private static Map<String, Object> stringKeys(Map<Integer, Long> m) {
        Map<String, Object> out = new LinkedHashMap<>();
        m.forEach((k, v) -> out.put(Integer.toString(k), v));
        return out;
    }

    private static void connectionLoop(Pool pool, HttpConn.Target target, int index, int connections, long start,
            long end, double interval, double slots, Tally t) {
        long j = 0;
        while (true) {
            long k = index + j * (long) connections;
            if (k >= slots) return;
            long intended = start + (long) (k * interval);
            long now = System.nanoTime();
            if (now >= end) {
                // Due requests this connection never got to send: the proxy held it up.
                long remaining = (long) Math.ceil((slots - index) / connections) - j;
                t.backlog += Math.max(0, remaining);
                return;
            }
            if (now < intended) {
                sleepUntil(intended);
                long lag = System.nanoTime() - intended;
                Histograms.recordNanos(t.lag, lag);
                if (lag > LATE_NANOS) t.late++;
            } else {
                t.behind++;
            }
            j++;
            t.attempted++;
            HttpConn conn;
            try {
                conn = pool.get(index);
            } catch (IOException e) {
                Outcome o = Outcome.of(e, true, false);
                t.count(o);
                if (t.firstError == null) t.firstError = o + ": " + e.getMessage();
                continue;
            }
            HttpConn.Result r = conn.exchange(target);
            long done = System.nanoTime();
            t.count(r.outcome());
            if (r.status() > 0) t.statuses.merge(r.status(), 1L, Long::sum);
            if (r.outcome() == Outcome.OK) {
                Histograms.recordNanos(t.latency, done - intended);
            } else if (t.firstError == null) {
                t.firstError = r.outcome() + (r.status() > 0 ? " " + r.status() : "") + (r.detail() != null ? ": " + r.detail() : "");
            }
        }
    }

    static void sleepUntil(long deadline) {
        while (true) {
            long left = deadline - System.nanoTime();
            if (left <= 0) return;
            LockSupport.parkNanos(left);
            if (Thread.interrupted()) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }
}
