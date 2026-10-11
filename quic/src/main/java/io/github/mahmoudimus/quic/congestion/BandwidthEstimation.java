/*
 * Ported from quinn-proto src/congestion/bbr/bw_estimation.rs (Apache-2.0), with the sampling
 * replaced: see the class comment.
 */
package io.github.mahmoudimus.quic.congestion;

/**
 * BBR's bottleneck bandwidth estimate: the windowed maximum ({@link MinMax}) of the delivery rate
 * samples over the last ten round trips, as BBRv1 keeps {@code BtlBw}. Samples come from the
 * connection's delivery rate sampler ({@link RateSample}); an application-limited sample counts
 * only if it beats the estimate, since it can understate the path but not overstate it. Old
 * maxima expire with the window, so the estimate follows a path that slows down.
 *
 * <p>quinn's estimator took, per acknowledged packet, the lower of the rates between the last two
 * sends and the last two acknowledgements, and fed the filter only samples above the estimate:
 * its estimate never fell, and with ACKs covering two packets its samples were half the rate.
 * Rates are bytes per second.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one controller.
 */
final class BandwidthEstimation {

    private long totalAcked;
    private final MinMax maxFilter;
    private long ackedAtLastWindow;

    BandwidthEstimation() {
        maxFilter = new MinMax();
    }

    /** A copy of another estimator. */
    BandwidthEstimation(BandwidthEstimation o) {
        totalAcked = o.totalAcked;
        maxFilter = new MinMax(o.maxFilter);
        ackedAtLastWindow = o.ackedAtLastWindow;
    }

    /** A packet of {@code bytes} was acknowledged. */
    void onAck(long bytes) {
        totalAcked += bytes;
    }

    /**
     * Adds a delivery rate sample.
     *
     * @param round the current round trip count
     * @param rate the sample's rate, bytes per second
     * @param appLimited whether the sample was application limited
     */
    void onSample(long round, long rate, boolean appLimited) {
        if (rate < 0) {
            return;
        }
        if (!appLimited || rate >= maxFilter.get()) {
            maxFilter.updateMax(round, rate);
        }
    }

    /** Bytes acknowledged since the last {@link #endAcks}. */
    long bytesAckedThisWindow() {
        return totalAcked - ackedAtLastWindow;
    }

    /** A batch of acknowledgements is complete. */
    void endAcks() {
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
