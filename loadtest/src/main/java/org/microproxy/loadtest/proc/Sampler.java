package org.microproxy.loadtest.proc;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Samples the harness's processes every second from {@code /proc} (see {@link ProcStats}): the
 * full series of the proxy under test, and the CPU use of the origin and the load generator, so
 * that a saturated client or origin shows in the results.
 */
public final class Sampler implements AutoCloseable {

    private final Map<String, Long> pids = new LinkedHashMap<>();
    private final Map<String, List<Map<String, Object>>> series = new LinkedHashMap<>();
    private final Map<String, long[]> lastCpu = new LinkedHashMap<>();
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition stopped = lock.newCondition();
    private final long startNanos = System.nanoTime();
    private final long intervalMs;
    private boolean running = true;
    private final Thread thread;

    /** Starts sampling {@code pids} (name to pid) every {@code intervalMs}. */
    public Sampler(Map<String, Long> pids, long intervalMs) {
        this.pids.putAll(pids);
        this.intervalMs = intervalMs;
        for (String name : pids.keySet()) series.put(name, new ArrayList<>());
        sampleOnce();
        this.thread = Thread.ofPlatform().daemon().name("sampler").start(this::loop);
    }

    /** Seconds since sampling started. */
    public double elapsed() {
        return (System.nanoTime() - startNanos) / 1e9;
    }

    private void loop() {
        lock.lock();
        try {
            while (running) {
                stopped.awaitNanos(intervalMs * 1_000_000L);
                if (!running) break;
                lock.unlock();
                try {
                    sampleOnce();
                } finally {
                    lock.lock();
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            lock.unlock();
        }
    }

    private void sampleOnce() {
        double t = elapsed();
        long now = System.nanoTime();
        for (Map.Entry<String, Long> e : pids.entrySet()) {
            ProcStats.Sample s = ProcStats.sample(e.getValue());
            if (s == null) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("t", Math.round(t * 10) / 10.0);
            m.putAll(s.toMap());
            long[] prev = lastCpu.get(e.getKey());
            if (prev != null && s.cpuMs() >= 0 && now > prev[1]) {
                double pct = (s.cpuMs() - prev[0]) * 1e8 / (now - prev[1]);
                m.put("cpuPct", Math.round(pct * 10) / 10.0);
            }
            lastCpu.put(e.getKey(), new long[] {s.cpuMs(), now});
            lock.lock();
            try {
                series.get(e.getKey()).add(m);
            } finally {
                lock.unlock();
            }
        }
    }

    /** A copy of {@code name}'s samples so far. */
    public List<Map<String, Object>> series(String name) {
        lock.lock();
        try {
            return new ArrayList<>(series.getOrDefault(name, List.of()));
        } finally {
            lock.unlock();
        }
    }

    /** {@code name}'s samples taken from {@code fromSeconds} on. */
    public List<Map<String, Object>> since(String name, double fromSeconds) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> m : series(name)) {
            if (((Number) m.get("t")).doubleValue() >= fromSeconds) out.add(m);
        }
        return out;
    }

    /** The mean of {@code key} over {@code name}'s samples from {@code fromSeconds} on, or -1. */
    public double mean(String name, String key, double fromSeconds) {
        double sum = 0;
        int n = 0;
        for (Map<String, Object> m : since(name, fromSeconds)) {
            Object v = m.get(key);
            if (v instanceof Number num) {
                sum += num.doubleValue();
                n++;
            }
        }
        return n == 0 ? -1 : sum / n;
    }

    /** The largest {@code key} over {@code name}'s samples from {@code fromSeconds} on, or -1. */
    public double max(String name, String key, double fromSeconds) {
        double max = -1;
        for (Map<String, Object> m : since(name, fromSeconds)) {
            Object v = m.get(key);
            if (v instanceof Number num) max = Math.max(max, num.doubleValue());
        }
        return max;
    }

    /** Every series, for the results file. */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        for (String name : pids.keySet()) m.put(name, series(name));
        return m;
    }

    @Override
    public void close() {
        lock.lock();
        try {
            running = false;
            stopped.signalAll();
        } finally {
            lock.unlock();
        }
        try {
            thread.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        sampleOnce();
    }
}
