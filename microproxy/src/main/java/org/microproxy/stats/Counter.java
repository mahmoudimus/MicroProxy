package org.microproxy.stats;

/**
 * A count that only goes up, such as {@code downstream_rq_total}. Counters made by a registry are
 * backed by a {@link java.util.concurrent.atomic.LongAdder}, so many threads may add at once
 * without contending; those of {@link StatsRegistry#NOOP} do nothing.
 */
public interface Counter extends Metric {

    /** Adds one. */
    void inc();

    /**
     * Adds {@code n}.
     *
     * @param n how much to add, not negative
     */
    void add(long n);

    /** {@return the count so far} */
    long value();

    @Override
    default Type type() {
        return Type.COUNTER;
    }
}
