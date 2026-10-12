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
 */
public record ControllerMetrics(long congestionWindow, long slowStartThreshold, long pacingRate) {}
