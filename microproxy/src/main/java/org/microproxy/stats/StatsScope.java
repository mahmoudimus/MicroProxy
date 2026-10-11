package org.microproxy.stats;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Metrics named {@code <prefix>.<name>} whose names come from outside the proxy, such as a
 * script's ({@code script.<name>}), and of which there may be at most a fixed number: past it, new
 * names get metrics that do nothing (and a warning is logged once), so their number stays bounded
 * whatever names are asked for. Names already made keep working. Made by {@link
 * StatsRegistry#scope}.
 */
public final class StatsScope {

    private static final System.Logger LOG = System.getLogger(StatsScope.class.getName());

    private final StatsRegistry registry;
    private final String prefix;
    private final int maxStats;
    private final Map<String, Metric> made = new ConcurrentHashMap<>();
    private final AtomicInteger count = new AtomicInteger();
    private final AtomicBoolean warned = new AtomicBoolean();

    StatsScope(StatsRegistry registry, String prefix, int maxStats) {
        this.registry = registry;
        this.prefix = prefix;
        this.maxStats = maxStats;
    }

    /** {@return the prefix of this scope's names} */
    public String prefix() {
        return prefix;
    }

    /** {@return how many metrics the scope may make} */
    public int maxStats() {
        return maxStats;
    }

    /** {@return how many metrics the scope has made} */
    public int size() {
        return made.size();
    }

    /**
     * The counter {@code <prefix>.<name>}, made the first time while there is room.
     *
     * @param name the name within the scope
     * @return the counter, or one that does nothing once the scope is full
     * @throws IllegalArgumentException if the name is not valid, or names a metric of another kind
     */
    public Counter counter(String name) {
        Metric m = make(name, Metric.Type.COUNTER);
        return m instanceof Counter c ? c : Instruments.NOOP_COUNTER;
    }

    /**
     * The gauge {@code <prefix>.<name>}, made the first time while there is room.
     *
     * @param name the name within the scope
     * @return the gauge, or one that does nothing once the scope is full
     * @throws IllegalArgumentException if the name is not valid, or names a metric of another kind
     */
    public Gauge gauge(String name) {
        Metric m = make(name, Metric.Type.GAUGE);
        return m instanceof Gauge g ? g : Instruments.NOOP_GAUGE;
    }

    /**
     * The histogram {@code <prefix>.<name>}, with the registry's bounds, made the first time while
     * there is room.
     *
     * @param name the name within the scope
     * @return the histogram, or one that does nothing once the scope is full
     * @throws IllegalArgumentException if the name is not valid, or names a metric of another kind
     */
    public Histogram histogram(String name) {
        Metric m = make(name, Metric.Type.HISTOGRAM);
        return m instanceof Histogram h ? h : Instruments.NOOP_HISTOGRAM;
    }

    private Metric make(String name, Metric.Type type) {
        if (!registry.enabled()) return null;
        StatsRegistry.checkName(name);
        Metric m = made.get(name);
        if (m == null) {
            m = made.computeIfAbsent(name, n -> {
                if (count.getAndIncrement() >= maxStats) {
                    count.decrementAndGet();
                    return null;
                }
                String full = prefix + "." + n;
                try {
                    return switch (type) {
                        case COUNTER -> registry.counter(full);
                        case GAUGE -> registry.gauge(full);
                        case HISTOGRAM -> registry.histogram(full);
                    };
                } catch (RuntimeException e) {
                    count.decrementAndGet();
                    throw e;
                }
            });
            if (m == null) {
                if (warned.compareAndSet(false, true)) {
                    LOG.log(System.Logger.Level.WARNING, "the " + prefix + " stats are full (" + maxStats
                            + "): " + prefix + "." + name + " and later new names are not counted");
                }
                return null;
            }
        }
        if (m.type() != type) {
            throw new IllegalArgumentException(m.name() + " is a " + m.type().prometheusName() + ", not a "
                    + type.prometheusName());
        }
        return m;
    }
}
