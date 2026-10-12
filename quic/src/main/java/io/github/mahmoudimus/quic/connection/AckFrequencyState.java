/*
 * Ported from quinn-proto src/connection/ack_frequency.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.congestion.RttEstimator;
import io.github.mahmoudimus.quic.frame.Frame;

/**
 * State of the QUIC ACK frequency extension, as quinn implements it: the {@code max_ack_delay} the
 * peer uses (its transport parameter, or what we last asked for in an ACK_FREQUENCY frame once it
 * is acknowledged) and the one we use (ours, or what the peer asked for). Durations are
 * nanoseconds.
 *
 * <p>Without the extension this simply holds both endpoints' {@code max_ack_delay}.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class AckFrequencyState {

    /**
     * The largest relative difference between the requested and the desired {@code max_ack_delay}
     * before a new request is sent.
     */
    static final double MAX_RTT_ERROR = 0.2;

    /** The smallest {@code max_ack_delay} requested automatically, 25 ms. */
    static final long MIN_AUTOMATIC_ACK_DELAY = 25_000_000L;

    /** The packet number of an unacknowledged ACK_FREQUENCY frame, or -1, and the delay it asked for. */
    private long inFlightFramePacket = -1;
    private long inFlightFrameMaxAckDelay;
    private long nextOutgoingSequenceNumber;
    /** The peer's {@code max_ack_delay}. */
    private long peerMaxAckDelay;
    /** The highest sequence number of an ACK_FREQUENCY frame received, or -1. */
    private long lastAckFrequencyFrame = -1;
    /** Our {@code max_ack_delay}. */
    private long maxAckDelay;

    /**
     * The state before any ACK_FREQUENCY frame.
     *
     * @param defaultMaxAckDelay the default {@code max_ack_delay}, 25 ms, used for both endpoints
     *     until their transport parameters are known
     */
    public AckFrequencyState(long defaultMaxAckDelay) {
        this.peerMaxAckDelay = defaultMaxAckDelay;
        this.maxAckDelay = defaultMaxAckDelay;
    }

    /**
     * The peer's {@code max_ack_delay}.
     *
     * @return nanoseconds
     */
    public long peerMaxAckDelay() {
        return peerMaxAckDelay;
    }

    /**
     * Sets the peer's {@code max_ack_delay}, from its transport parameters.
     *
     * @param delay nanoseconds
     */
    public void setPeerMaxAckDelay(long delay) {
        peerMaxAckDelay = delay;
    }

    /**
     * Our {@code max_ack_delay}.
     *
     * @return nanoseconds
     */
    public long maxAckDelay() {
        return maxAckDelay;
    }

    /**
     * Sets our {@code max_ack_delay}.
     *
     * @param delay nanoseconds
     */
    public void setMaxAckDelay(long delay) {
        maxAckDelay = delay;
    }

    /**
     * The {@code max_ack_delay} to ask the peer for: the configured one or the peer's own, at most
     * the RTT (but not below 25 ms) and at least the peer's {@code min_ack_delay}.
     *
     * @param rtt the RTT estimate, in nanoseconds
     * @param configuredMaxAckDelay a configured delay in nanoseconds, or -1 to use the peer's
     * @param peerMinAckDelayMicros the peer's {@code min_ack_delay} in microseconds, or -1
     * @return nanoseconds
     */
    public long candidateMaxAckDelay(long rtt, long configuredMaxAckDelay, long peerMinAckDelayMicros) {
        long minAckDelay = Math.max(peerMinAckDelayMicros, 0) * 1_000;
        long candidate = configuredMaxAckDelay >= 0 ? configuredMaxAckDelay : peerMaxAckDelay;
        return Math.max(Math.min(candidate, Math.max(rtt, MIN_AUTOMATIC_ACK_DELAY)), minAckDelay);
    }

    /**
     * The {@code max_ack_delay} to compute the PTO with: the larger of the peer's and any requested
     * but unacknowledged one, which the peer may already use.
     *
     * @return nanoseconds
     */
    public long maxAckDelayForPto() {
        return inFlightFramePacket >= 0 ? Math.max(peerMaxAckDelay, inFlightFrameMaxAckDelay) : peerMaxAckDelay;
    }

    /**
     * Allocates the next ACK_FREQUENCY sequence number.
     *
     * @return the sequence number
     */
    public long nextSequenceNumber() {
        return nextOutgoingSequenceNumber++;
    }

    /**
     * Whether to send an ACK_FREQUENCY frame: always first, then when the desired delay differs
     * from the current request by more than 20%.
     *
     * @param rtt the RTT estimate, in nanoseconds
     * @param configuredMaxAckDelay a configured delay in nanoseconds, or -1
     * @param peerMinAckDelayMicros the peer's {@code min_ack_delay} in microseconds, or -1
     * @return true if a frame should be sent
     */
    public boolean shouldSendAckFrequency(long rtt, long configuredMaxAckDelay, long peerMinAckDelayMicros) {
        if (nextOutgoingSequenceNumber == 0) {
            return true;
        }
        long current = inFlightFramePacket >= 0 ? inFlightFrameMaxAckDelay : peerMaxAckDelay;
        long desired = candidateMaxAckDelay(rtt, configuredMaxAckDelay, peerMinAckDelayMicros);
        double error = (double) desired / current - 1.0;
        return Math.abs(error) > MAX_RTT_ERROR;
    }

    /**
     * Records that a packet carried an ACK_FREQUENCY frame.
     *
     * @param pn the packet number
     * @param requestedMaxAckDelay the delay it asked for, in nanoseconds
     */
    public void ackFrequencySent(long pn, long requestedMaxAckDelay) {
        inFlightFramePacket = pn;
        inFlightFrameMaxAckDelay = requestedMaxAckDelay;
    }

    /**
     * Records an acknowledged application data packet; acknowledging the ACK_FREQUENCY frame makes
     * its delay the peer's.
     *
     * @param pn the packet number
     */
    public void onAcked(long pn) {
        if (inFlightFramePacket >= 0 && inFlightFramePacket == pn) {
            inFlightFramePacket = -1;
            peerMaxAckDelay = inFlightFrameMaxAckDelay;
        }
    }

    /**
     * Applies a received ACK_FREQUENCY frame, unless an equal or newer one was applied already.
     *
     * @param frame the frame
     * @param pendingAcks the application data space's ACK state, which takes the thresholds
     * @return false if the frame was stale and ignored
     * @throws QuicException {@code PROTOCOL_VIOLATION} if the requested delay is below the timer
     *     granularity, which is our {@code min_ack_delay}
     */
    public boolean ackFrequencyReceived(Frame.AckFrequency frame, PendingAcks pendingAcks) throws QuicException {
        if (lastAckFrequencyFrame >= 0 && frame.sequenceNumber() <= lastAckFrequencyFrame) {
            return false;
        }
        lastAckFrequencyFrame = frame.sequenceNumber();
        long micros = frame.requestMaxAckDelay();
        long requested = micros > Long.MAX_VALUE / 1_000 ? Long.MAX_VALUE : micros * 1_000;
        if (requested < RttEstimator.TIMER_GRANULARITY) {
            throw new QuicException(QuicException.PROTOCOL_VIOLATION,
                    "Requested Max Ack Delay in ACK_FREQUENCY frame is less than min_ack_delay");
        }
        maxAckDelay = requested;
        pendingAcks.setAckFrequencyParams(frame);
        return true;
    }
}
