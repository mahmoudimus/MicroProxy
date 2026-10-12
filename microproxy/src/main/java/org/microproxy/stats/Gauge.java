package org.microproxy.stats;

/**
 * A value that goes up and down, such as {@code downstream_cx_active}. Gauges made by a registry
 * hold an {@link java.util.concurrent.atomic.AtomicLong}, or read a supplier when the value lives
 * elsewhere ({@link StatsRegistry#gauge(String, String, java.util.function.LongSupplier)}), which
 * cannot be changed through the gauge; those of {@link StatsRegistry#NOOP} do nothing.
 */
public interface Gauge extends Metric {

    /**
     * Sets the value.
     *
     * @param value the new value
     * @throws UnsupportedOperationException for a gauge that reads a supplier
     */
    void set(long value);

    /**
     * Adds {@code delta}, which may be negative.
     *
     * @param delta how much to add
     * @throws UnsupportedOperationException for a gauge that reads a supplier
     */
    void add(long delta);

    /**
     * Adds one.
     *
     * @throws UnsupportedOperationException for a gauge that reads a supplier
     */
    default void inc() {
        add(1);
    }

    /**
     * Subtracts one.
     *
     * @throws UnsupportedOperationException for a gauge that reads a supplier
     */
    default void dec() {
        add(-1);
    }

    /** {@return the current value} */
    long value();

    @Override
    default Type type() {
        return Type.GAUGE;
    }
}
