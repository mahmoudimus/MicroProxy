package org.microproxy;

import static org.microproxy.TestSupport.eventually;

import org.microproxy.stats.Counter;
import org.microproxy.stats.Gauge;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.Metric;
import org.microproxy.stats.StatsRegistry;

/** Reading metrics in tests: a counter's or gauge's value, a histogram's count. */
final class MetricsAssertions {

    private MetricsAssertions() {}

    /** A counter's or gauge's value, a histogram's count; 0 for a metric not registered. */
    static long value(StatsRegistry r, String name) {
        Metric m = r.get(name);
        return switch (m) {
            case null -> 0;
            case Counter c -> c.value();
            case Gauge g -> g.value();
            case Histogram h -> h.snapshot().count();
            default -> throw new AssertionError(m);
        };
    }

    /** Waits for the metric {@code name} to be {@code expected}. */
    static void awaitValue(StatsRegistry r, String name, long expected) {
        eventually(name + " = " + expected + " (is " + value(r, name) + ")", () -> value(r, name) == expected);
    }

    /** Waits for the metric {@code name} to be at least {@code least}. */
    static void awaitAtLeast(StatsRegistry r, String name, long least) {
        eventually(name + " >= " + least + " (is " + value(r, name) + ")", () -> value(r, name) >= least);
    }
}
