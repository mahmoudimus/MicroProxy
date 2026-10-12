/*
 * Ported from quinn-proto src/connection/paths.rs (RttEstimator) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.congestion;

/**
 * Round-trip time estimation for one network path (RFC 9002 section 5): the latest sample, the
 * smoothed RTT and its variance (RFC 6298), and the minimum RTT. All durations are nanoseconds.
 *
 * <p><b>Threads.</b> Not thread-safe; an estimator belongs to one connection, which serializes
 * access.
 */
public final class RttEstimator {

    /** The system timer granularity assumed by loss detection, 1 ms (RFC 9002 section 6.1.2). */
    public static final long TIMER_GRANULARITY = 1_000_000L;

    /** The initial RTT before any sample, 333 ms (RFC 9002 section 6.2.2). */
    public static final long DEFAULT_INITIAL_RTT = 333_000_000L;

    /** The most recent sample. */
    private long latest;
    /** The smoothed RTT, or -1 before the first sample. */
    private long smoothed = -1;
    /** The RTT variance. */
    private long var;
    /** The minimum RTT seen, ignoring ACK delay. */
    private long min;

    /**
     * An estimator with no samples.
     *
     * @param initialRtt the RTT to assume until the first sample, in nanoseconds
     */
    public RttEstimator(long initialRtt) {
        latest = initialRtt;
        var = initialRtt / 2;
        min = initialRtt;
    }

    /**
     * A copy of another estimator.
     *
     * @param other the estimator to copy
     */
    public RttEstimator(RttEstimator other) {
        latest = other.latest;
        smoothed = other.smoothed;
        var = other.var;
        min = other.min;
    }

    /**
     * The best current estimate: the smoothed RTT, or the initial RTT before any sample.
     *
     * @return nanoseconds
     */
    public long get() {
        return smoothed >= 0 ? smoothed : latest;
    }

    /**
     * A conservative estimate, the larger of the smoothed and latest RTT (RFC 9002 section 6.1.2).
     *
     * @return nanoseconds
     */
    public long conservative() {
        return Math.max(get(), latest);
    }

    /**
     * The minimum RTT seen.
     *
     * @return nanoseconds
     */
    public long min() {
        return min;
    }

    /**
     * The most recent sample.
     *
     * @return nanoseconds
     */
    public long latest() {
        return latest;
    }

    /**
     * The RTT variance.
     *
     * @return nanoseconds
     */
    public long variance() {
        return var;
    }

    /**
     * Whether a sample has been taken.
     *
     * @return true after the first {@link #update}
     */
    public boolean hasSample() {
        return smoothed >= 0;
    }

    /**
     * The probe timeout before backoff and {@code max_ack_delay}: {@code smoothed_rtt +
     * max(4 * rttvar, kGranularity)} (RFC 9002 section 6.2.1).
     *
     * @return nanoseconds
     */
    public long ptoBase() {
        return get() + Math.max(4 * var, TIMER_GRANULARITY);
    }

    /**
     * Takes an RTT sample (RFC 9002 section 5.3). The ACK delay is subtracted only when that does
     * not take the sample below the minimum RTT; the first sample resets every estimate.
     *
     * @param ackDelay the peer's reported ACK delay, already limited to its {@code max_ack_delay}
     * @param rtt the time from sending the largest newly acknowledged packet to receiving the ACK
     */
    public void update(long ackDelay, long rtt) {
        latest = rtt;
        min = Math.min(min, latest); // ignores ACK delay
        if (smoothed >= 0) {
            long adjusted = min + ackDelay <= latest ? latest - ackDelay : latest;
            long varSample = Math.abs(smoothed - adjusted);
            var = (3 * var + varSample) / 4;
            smoothed = (7 * smoothed + adjusted) / 8;
        } else {
            smoothed = latest;
            var = latest / 2;
            min = latest;
        }
    }
}
