/*
 * Ported from quinn-proto src/congestion.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.congestion;

/**
 * A congestion controller (RFC 9002 section 7): decides how many ack-eliciting bytes may be in
 * flight. Times are nanoseconds from the connection's monotonic clock.
 *
 * <p><b>Threads.</b> Implementations are not thread-safe; a controller belongs to one path of one
 * connection, which serializes access.
 */
public interface Controller {

    /** The datagram size the initial windows are computed from (RFC 9002 section 7.2). */
    long BASE_DATAGRAM_SIZE = 1200;

    /**
     * One or more packets were just sent.
     *
     * @param now the current time
     * @param bytes the bytes sent
     * @param lastPacketNumber the number of the last packet sent
     */
    default void onSent(long now, long bytes, long lastPacketNumber) {}

    /**
     * A packet's delivery was confirmed.
     *
     * @param now the current time
     * @param sent when the packet was sent
     * @param bytes the packet's size
     * @param appLimited whether the connection was limited by the application, not the window,
     *     before these acknowledgements
     * @param rtt the path's RTT estimate
     */
    default void onAck(long now, long sent, long bytes, boolean appLimited, RttEstimator rtt) {}

    /**
     * A batch of acknowledgements, all with the same {@code now}, is complete.
     *
     * @param now the current time
     * @param inFlight the bytes still in flight
     * @param appLimited whether the connection was application limited
     * @param largestPacketNumberAcked the largest packet number ever acknowledged in the space,
     *     or -1
     */
    default void onEndAcks(long now, long inFlight, boolean appLimited, long largestPacketNumberAcked) {}

    /**
     * Packets were deemed lost, or marked with ECN congestion experienced.
     *
     * @param now the current time
     * @param sent when the most recent lost packet was sent
     * @param persistentCongestion whether every packet in the persistent congestion period ending
     *     with that packet was lost (RFC 9002 section 7.6)
     * @param ecn whether this is an ECN signal rather than loss
     * @param lostBytes the bytes lost, zero for ECN
     */
    void onCongestionEvent(long now, long sent, boolean persistentCongestion, boolean ecn, long lostBytes);

    /** Packets deemed lost were all acknowledged after all: the last congestion event was spurious. */
    default void onSpuriousCongestionEvent() {}

    /**
     * The path's MTU changed.
     *
     * @param newMtu the new maximum UDP payload size
     */
    void onMtuUpdate(int newMtu);

    /**
     * The congestion window.
     *
     * @return the ack-eliciting bytes that may be in flight
     */
    long window();

    /**
     * The rate the controller wants packets paced at. The connection's pacer sends at no more than
     * this, nor than 1.25 congestion windows per smoothed RTT; a controller without a rate of its
     * own leaves pacing to the window. quinn has no such method: its pacer always paces the window,
     * and BBR's rate only reaches its metrics.
     *
     * @return bytes per second, or -1 to pace by the window alone
     */
    default long pacingRate() {
        return -1;
    }

    /**
     * Metrics for statistics and tracing.
     *
     * @return the window and, where known, the slow start threshold
     */
    default ControllerMetrics metrics() {
        return new ControllerMetrics(window(), -1, -1);
    }

    /**
     * A copy of the controller's state, for a new path that starts from this one.
     *
     * @return an independent copy
     */
    Controller copy();

    /**
     * The initial window.
     *
     * @return bytes
     */
    long initialWindow();
}
