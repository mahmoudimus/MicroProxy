/*
 * Ported from quinn-proto src/connection/timer.rs (TimerTable) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.util.Arrays;

/**
 * The deadline of each {@link Timer}, in nanoseconds from the connection's {@link NanoClock}. The
 * connection layer sleeps until {@link #nextTimeout()}, then handles each timer {@link
 * #pollExpired(long)} returns.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class TimerTable {

    private static final Timer[] TIMERS = Timer.values();

    private final long[] deadlines = new long[TIMERS.length];

    /** A table with no timer set. */
    public TimerTable() {
        Arrays.fill(deadlines, NanoClock.NONE);
    }

    /**
     * Sets a timer.
     *
     * @param timer the timer
     * @param time its deadline
     */
    public void set(Timer timer, long time) {
        deadlines[timer.ordinal()] = time;
    }

    /**
     * A timer's deadline.
     *
     * @param timer the timer
     * @return the deadline, or {@link NanoClock#NONE} if it is not set
     */
    public long get(Timer timer) {
        return deadlines[timer.ordinal()];
    }

    /**
     * Whether a timer is set.
     *
     * @param timer the timer
     * @return true if it has a deadline
     */
    public boolean isSet(Timer timer) {
        return deadlines[timer.ordinal()] != NanoClock.NONE;
    }

    /**
     * Stops a timer.
     *
     * @param timer the timer
     */
    public void stop(Timer timer) {
        deadlines[timer.ordinal()] = NanoClock.NONE;
    }

    /** Stops every timer, as when the connection is closed. */
    public void stopAll() {
        Arrays.fill(deadlines, NanoClock.NONE);
    }

    /**
     * The earliest deadline.
     *
     * @return the time, or {@link NanoClock#NONE} if no timer is set
     */
    public long nextTimeout() {
        long min = NanoClock.NONE;
        for (long d : deadlines) {
            if (d != NanoClock.NONE && (min == NanoClock.NONE || d < min)) {
                min = d;
            }
        }
        return min;
    }

    /**
     * Whether a timer has expired.
     *
     * @param timer the timer
     * @param now the current time
     * @return true if it is set and its deadline is at or before {@code now}
     */
    public boolean isExpired(Timer timer, long now) {
        long d = deadlines[timer.ordinal()];
        return d != NanoClock.NONE && d <= now;
    }

    /**
     * Stops and returns the first expired timer, in {@link Timer} order.
     *
     * @param now the current time
     * @return the timer, or null if none has expired
     */
    public Timer pollExpired(long now) {
        for (Timer t : TIMERS) {
            if (isExpired(t, now)) {
                stop(t);
                return t;
            }
        }
        return null;
    }
}
