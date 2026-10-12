package org.microproxy.stats;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.management.ManagementFactory;
import org.junit.jupiter.api.Test;

/**
 * Counting allocates nothing: the no-op metrics of a proxy without metrics, and the registry's own
 * once they are made (a {@link java.util.concurrent.atomic.LongAdder} add, an {@link
 * java.util.concurrent.atomic.AtomicLong} update, a bucket search). Only making a metric, once,
 * allocates.
 */
class StatsFastPathTest {

    private static final int CALLS = 1_000_000;
    /** Bytes the measurement itself may allocate (the MXBean's own bookkeeping). */
    private static final long SLACK = 4096;

    private static final com.sun.management.ThreadMXBean THREADS =
            (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();

    private static long allocated() {
        return THREADS.getThreadAllocatedBytes(Thread.currentThread().threadId());
    }

    /** Bytes {@code CALLS} rounds of counting allocate, after a warm-up. */
    private static long allocatedBy(Counter counter, Gauge gauge, Histogram histogram) {
        for (int round = 0; round < 2; round++) {
            long before = allocated();
            for (int i = 0; i < CALLS; i++) {
                counter.inc();
                counter.add(3);
                gauge.inc();
                gauge.dec();
                gauge.set(i);
                histogram.recordNanos(i * 1_000L);
                histogram.record(i & 1023);
            }
            long used = allocated() - before;
            if (round == 1) return used;
        }
        throw new AssertionError();
    }

    @Test
    void theNoopMetricsAllocateNothing() {
        assertTrue(THREADS.isThreadAllocatedMemorySupported() && THREADS.isThreadAllocatedMemoryEnabled(),
                "this JVM cannot count allocated bytes");
        StatsRegistry r = StatsRegistry.NOOP;
        long used = allocatedBy(r.counter("a"), r.gauge("b"), r.histogram("c"));
        assertTrue(used < SLACK, used + " bytes for " + CALLS + " rounds of no-op counting");
    }

    @Test
    void theRegistrysMetricsAllocateNothingOnceMade() {
        assertTrue(THREADS.isThreadAllocatedMemorySupported() && THREADS.isThreadAllocatedMemoryEnabled(),
                "this JVM cannot count allocated bytes");
        StatsRegistry r = StatsRegistry.create();
        Counter c = r.counter("http.x.downstream_rq_total");
        long used = allocatedBy(c, r.gauge("http.x.downstream_rq_active"), r.histogram("http.x.downstream_rq_time"));
        assertTrue(used < SLACK, used + " bytes for " + CALLS + " rounds of counting");
        assertEquals(2L * CALLS * 4, c.value());
    }
}
