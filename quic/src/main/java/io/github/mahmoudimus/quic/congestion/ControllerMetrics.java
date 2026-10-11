/*
 * Ported from quinn-proto src/congestion.rs (ControllerMetrics) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.congestion;

/**
 * Congestion controller metrics.
 *
 * @param congestionWindow the congestion window, in bytes
 * @param slowStartThreshold the slow start threshold in bytes, {@link Long#MAX_VALUE} before the
 *     first congestion event, or -1 if the controller has none
 * @param pacingRate the pacing rate in bits per second, or -1 if the controller sets none
 * @param bandwidthEstimate the estimated sustainable bandwidth of the path in bits per second, or
 *     -1 if the controller keeps no estimate or has no sample yet
 */
public record ControllerMetrics(long congestionWindow, long slowStartThreshold, long pacingRate,
        long bandwidthEstimate) {

    /**
     * Metrics without a bandwidth estimate.
     *
     * @param congestionWindow the congestion window, in bytes
     * @param slowStartThreshold the slow start threshold in bytes, or -1
     * @param pacingRate the pacing rate in bits per second, or -1
     */
    public ControllerMetrics(long congestionWindow, long slowStartThreshold, long pacingRate) {
        this(congestionWindow, slowStartThreshold, pacingRate, -1);
    }
}
