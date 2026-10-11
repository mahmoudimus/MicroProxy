package io.github.mahmoudimus.quic.congestion;

/**
 * A delivery rate sample (draft-cheng-iccrg-delivery-rate-estimation), taken when an ACK
 * acknowledges packets that were in flight. It describes the newest of them: the bytes delivered
 * between its sending and its acknowledgement, over the longer of its send and ACK intervals.
 *
 * @param deliveryRate bytes per second, or -1 if the interval was shorter than the minimum RTT
 *     (or zero), which makes the sample unreliable
 * @param delivered the bytes delivered over the interval
 * @param interval the interval, in nanoseconds
 * @param rtt the round-trip time of the newest packet acknowledged, in nanoseconds, without any
 *     ACK delay removed
 * @param appLimited whether that packet was sent while the application, not the congestion
 *     window, limited sending: such a sample may understate the path's bandwidth
 * @param priorDelivered the bytes delivered on the connection when that packet was sent
 */
public record RateSample(long deliveryRate, long delivered, long interval, long rtt, boolean appLimited,
        long priorDelivered) {

    /**
     * Whether the sample gives a rate.
     *
     * @return true if {@link #deliveryRate()} is not -1
     */
    public boolean hasRate() {
        return deliveryRate >= 0;
    }
}
