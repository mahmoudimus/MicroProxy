/*
 * Ported from quinn-proto src/congestion/bbr/bw_estimation.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.congestion;

/**
 * BBR's delivery rate estimate. Each acknowledgement gives a sample, the lower of the send rate
 * (bytes between the last two sends over the time between them) and the ack rate (bytes between
 * the last two acknowledgements over the time between them); samples taken while the connection
 * was application limited are left out. The estimate is the windowed maximum of the samples over
 * the last ten round trips ({@link MinMax}). Rates are bytes per second; times are nanoseconds.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one controller.
 */
final class BandwidthEstimation {

    /** An unset time. */
    private static final long NONE = Long.MIN_VALUE;

    private long totalAcked;
    private long prevTotalAcked;
    private long ackedTime = NONE;
    private long prevAckedTime = NONE;
    private long totalSent;
    private long prevTotalSent;
    private long sentTime = NONE;
    private long prevSentTime = NONE;
    private final MinMax maxFilter;
    private long ackedAtLastWindow;

    BandwidthEstimation() {
        maxFilter = new MinMax();
    }

    /** A copy of another estimator. */
    BandwidthEstimation(BandwidthEstimation o) {
        totalAcked = o.totalAcked;
        prevTotalAcked = o.prevTotalAcked;
        ackedTime = o.ackedTime;
        prevAckedTime = o.prevAckedTime;
        totalSent = o.totalSent;
        prevTotalSent = o.prevTotalSent;
        sentTime = o.sentTime;
        prevSentTime = o.prevSentTime;
        maxFilter = new MinMax(o.maxFilter);
        ackedAtLastWindow = o.ackedAtLastWindow;
    }

    /** Bytes were sent at {@code now}. */
    void onSent(long now, long bytes) {
        prevTotalSent = totalSent;
        totalSent += bytes;
        prevSentTime = sentTime;
        sentTime = now;
    }

    /**
     * A packet was acknowledged.
     *
     * @param now the current time
     * @param sent when the packet was sent (unused, as in quinn)
     * @param bytes the packet's size
     * @param round the current round trip count
     * @param appLimited whether the sample is application limited, and so left out of the estimate
     */
    void onAck(long now, long sent, long bytes, long round, boolean appLimited) {
        prevTotalAcked = totalAcked;
        totalAcked += bytes;
        prevAckedTime = ackedTime;
        ackedTime = now;

        if (prevSentTime == NONE) {
            return;
        }
        long sendRate;
        if (sentTime != NONE && sentTime > prevSentTime) {
            sendRate = Math.max(0, bwFromDelta(totalSent - prevTotalSent, sentTime - prevSentTime));
        } else {
            sendRate = Long.MAX_VALUE; // the minimum of send and ack rate is taken, so this skips it
        }
        long ackRate = prevAckedTime == NONE
                ? 0
                : Math.max(0, bwFromDelta(totalAcked - prevTotalAcked, now - prevAckedTime));

        long bandwidth = Math.min(sendRate, ackRate);
        if (!appLimited && maxFilter.get() < bandwidth) {
            maxFilter.updateMax(round, bandwidth);
        }
    }

    /** Bytes acknowledged since the last {@link #endAcks}. */
    long bytesAckedThisWindow() {
        return totalAcked - ackedAtLastWindow;
    }

    /** A batch of acknowledgements is complete. */
    void endAcks(long currentRound, boolean appLimited) {
        ackedAtLastWindow = totalAcked;
    }

    /** The bandwidth estimate in bytes per second, 0 before the first sample. */
    long estimate() {
        return maxFilter.get();
    }

    /**
     * A rate.
     *
     * @param bytes bytes delivered
     * @param deltaNanos over this time
     * @return bytes per second (saturating), or -1 if the time is not positive
     */
    static long bwFromDelta(long bytes, long deltaNanos) {
        if (deltaNanos <= 0) {
            return -1;
        }
        long hi = Math.multiplyHigh(bytes, 1_000_000_000L);
        long lo = bytes * 1_000_000_000L;
        if (hi == 0 && lo >= 0) {
            return lo / deltaNanos;
        }
        // Over 9.2 GB in one sample: compute in floating point (a cast saturates) rather than overflow
        return (long) (bytes * 1e9 / deltaNanos);
    }

    @Override
    public String toString() {
        return String.format("%.3f MB/s", estimate() / (1024.0 * 1024.0));
    }
}
