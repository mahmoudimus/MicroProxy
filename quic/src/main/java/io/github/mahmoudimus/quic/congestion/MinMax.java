/*
 * Ported from quinn-proto src/congestion/bbr/min_max.rs (Apache-2.0), itself based on code
 * released under a BSD license on the bbr-dev mailing list.
 */
package io.github.mahmoudimus.quic.congestion;

/**
 * A windowed maximum filter: Kathleen Nichols' algorithm for tracking the maximum of a data stream
 * over a fixed window, here of round trips. It keeps the best, second best and third best values,
 * with the measurement time of the n-th best at or after that of the (n-1)-th, widely separated in
 * the window, which bounds the error when the data rises monotonically across it. Constant space
 * and time per update; almost always the same answer as keeping every sample in the window.
 *
 * <p>A new maximum makes everything earlier worthless, so it restarts the filter, overwriting the
 * second and third choices; the same holds for the second and third best.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one controller.
 */
final class MinMax {

    /** The window, in round trips. */
    private final long window;
    /** Round numbers of the best, second and third best samples. */
    private final long[] times = new long[3];
    /** Values of the best, second and third best samples. */
    private final long[] values = new long[3];

    /** A filter over the last ten round trips. */
    MinMax() {
        this(10);
    }

    MinMax(long window) {
        this.window = window;
    }

    /** A copy of another filter. */
    MinMax(MinMax o) {
        window = o.window;
        System.arraycopy(o.times, 0, times, 0, 3);
        System.arraycopy(o.values, 0, values, 0, 3);
    }

    /** The current maximum, 0 if none. */
    long get() {
        return values[0];
    }

    /** Forgets every sample. */
    void reset() {
        fill(0, 0);
    }

    private void fill(long time, long value) {
        for (int i = 0; i < 3; i++) {
            times[i] = time;
            values[i] = value;
        }
    }

    private void set(int i, long time, long value) {
        times[i] = time;
        values[i] = value;
    }

    private void shift(long time, long value) {
        set(0, times[1], values[1]);
        set(1, times[2], values[2]);
        set(2, time, value);
    }

    /**
     * Adds a measurement.
     *
     * @param currentRound the round trip it was taken in, not a timestamp
     * @param measurement the value
     */
    void updateMax(long currentRound, long measurement) {
        if (values[0] == 0 // uninitialised
                || measurement >= values[0] // a new maximum
                || currentRound - times[2] > window) { // nothing left in the window
            fill(currentRound, measurement); // forget earlier samples
            return;
        }
        if (measurement >= values[1]) {
            set(2, currentRound, measurement);
            set(1, currentRound, measurement);
        } else if (measurement >= values[2]) {
            set(2, currentRound, measurement);
        }
        subwinUpdate(currentRound, measurement);
    }

    /** As time advances, updates the first, second and third choices. */
    private void subwinUpdate(long time, long value) {
        long dt = time - times[0];
        if (dt > window) {
            // A whole window passed without a new maximum: the second choice becomes the best,
            // the third the second, the sample the third. The new best may itself be outside the
            // window (the third was checked to be in it on entry), so this may happen twice.
            shift(time, value);
            if (time - times[0] > window) {
                shift(time, value);
            }
        } else if (times[1] == times[0] && dt > window / 4) {
            // A quarter of the window passed without a new sample: take a second choice from the
            // second quarter
            set(2, time, value);
            set(1, time, value);
        } else if (times[2] == times[1] && dt > window / 2) {
            // Half the window passed without a new sample: take a third choice from the last half
            set(2, time, value);
        }
    }
}
