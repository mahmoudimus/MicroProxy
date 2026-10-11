/*
 * Ported from quinn-proto src/connection/spaces.rs (PendingAcks) and the ACK frame assembly of
 * src/connection/mod.rs (try_populate_acks) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.frame.Frame;
import java.util.ArrayList;
import java.util.List;

/**
 * The packets of one space waiting to be acknowledged, and when an ACK must go out (RFC 9000
 * section 13.2): after more than {@code ack_eliciting_threshold} ack-eliciting packets (one, by
 * default, so every second one is acknowledged at once), on reordering, or once {@code
 * max_ack_delay} has passed since the first unacknowledged ack-eliciting packet.
 *
 * <p>At most {@value #MAX_ACK_BLOCKS} ranges are kept, so an ACK frame always fits a minimum-size
 * packet; the oldest are dropped first.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class PendingAcks {

    /** The most ACK ranges kept. */
    public static final int MAX_ACK_BLOCKS = 64;

    /** Non-ack-eliciting packets received after which a packet sent anyway should carry an ACK. */
    static final long LAZY_ACK_THRESHOLD = 10;

    /** Whether to send an ACK now, even in a packet of its own. */
    boolean immediateAckRequired;
    private long ackElicitingSinceLastAckSent;
    private long nonAckElicitingSinceLastAckSent;
    private long ackElicitingThreshold = 1;
    /**
     * 0: never ACK at once for reordering; 1: as RFC 9000 section 13.2.1; more: when the ACK
     * frequency draft says a loss would otherwise go unnoticed.
     */
    private long reorderingThreshold = 1;
    /** When the first ack-eliciting packet since the last ACK arrived, or {@link NanoClock#NONE}. */
    private long earliestAckElicitingSinceLastAckSent = NanoClock.NONE;
    /** Packet numbers to acknowledge. */
    private final RangeSet ranges = new RangeSet();
    /** The largest packet number received, or -1, and when it arrived. */
    private long largestPacket = -1;
    private long largestPacketTime;
    /** The largest ack-eliciting packet number received, or -1. */
    private long largestAckElicitingPacket = -1;
    /** The largest packet number acknowledged in an ACK sent, or -1. */
    private long largestAcked = -1;

    /** Nothing to acknowledge. */
    public PendingAcks() {}

    /**
     * Applies an ACK_FREQUENCY frame's thresholds.
     *
     * @param frame the frame
     */
    public void setAckFrequencyParams(Frame.AckFrequency frame) {
        ackElicitingThreshold = frame.ackElicitingThreshold();
        reorderingThreshold = frame.reorderingThreshold();
    }

    /** Requires an immediate ACK, as for an IMMEDIATE_ACK frame or an ECN-CE mark. */
    public void setImmediateAckRequired() {
        immediateAckRequired = true;
    }

    /** Handles the expiry of the {@link Timer#MAX_ACK_DELAY} timer. */
    public void onMaxAckDelayTimeout() {
        immediateAckRequired = ackElicitingSinceLastAckSent > 0;
    }

    /**
     * When an ACK is due because {@code max_ack_delay} expires.
     *
     * @param maxAckDelay this endpoint's {@code max_ack_delay}, in nanoseconds
     * @return the deadline, or {@link NanoClock#NONE} if no ack-eliciting packet is unacknowledged
     */
    public long maxAckDelayTimeout(long maxAckDelay) {
        return earliestAckElicitingSinceLastAckSent == NanoClock.NONE
                ? NanoClock.NONE
                : earliestAckElicitingSinceLastAckSent + maxAckDelay;
    }

    /**
     * Whether an ACK must be sent, even in a packet of its own.
     *
     * @return true if one is required and there is something to acknowledge
     */
    public boolean canSend() {
        return immediateAckRequired && !ranges.isEmpty();
    }

    /**
     * Whether an ACK can ride along in a packet sent for other reasons.
     *
     * @return true if there is something to acknowledge
     */
    public boolean canSendWithOtherFrames() {
        return !ranges.isEmpty();
    }

    /**
     * The time since the largest packet arrived, for the ACK Delay field.
     *
     * @param now the current time
     * @return nanoseconds, zero if nothing was received
     */
    public long ackDelay(long now) {
        return largestPacket < 0 ? 0 : now - largestPacketTime;
    }

    /**
     * Handles a received packet's ACK requirements; call {@link #insertOne} for it too.
     *
     * @param now the current time
     * @param packetNumber the packet number
     * @param ackEliciting whether the packet is ack-eliciting
     * @param dedup the space's duplicate detector, which already holds the packet
     * @return true if the {@link Timer#MAX_ACK_DELAY} timer should be armed
     */
    public boolean packetReceived(long now, long packetNumber, boolean ackEliciting, Dedup dedup) {
        if (!ackEliciting) {
            nonAckElicitingSinceLastAckSent++;
            return false;
        }
        long prevLargestAckEliciting = Math.max(largestAckElicitingPacket, 0);
        largestAckElicitingPacket = Math.max(largestAckElicitingPacket, packetNumber);
        ackElicitingSinceLastAckSent++;
        immediateAckRequired |= ackElicitingSinceLastAckSent > ackElicitingThreshold;
        immediateAckRequired |= isOutOfOrder(packetNumber, prevLargestAckEliciting, dedup);
        if (earliestAckElicitingSinceLastAckSent == NanoClock.NONE && !canSend()) {
            earliestAckElicitingSinceLastAckSent = now;
            return true;
        }
        return false;
    }

    private boolean isOutOfOrder(long packetNumber, long prevLargestAckEliciting, Dedup dedup) {
        if (reorderingThreshold == 0) {
            return false;
        }
        if (reorderingThreshold == 1) {
            // RFC 9000 section 13.2.1
            return packetNumber < prevLargestAckEliciting || dedup.missingInInterval(prevLargestAckEliciting, packetNumber);
        }
        // ACK frequency draft section 6.1: ACK at once if that lets the sender detect a new loss
        if (largestAcked < 0 || largestAckElicitingPacket < 0 || reorderingThreshold > largestAcked) {
            return false;
        }
        long largestReported = largestAcked - reorderingThreshold + 1;
        long smallestMissingUnreported = dedup.smallestMissingInInterval(largestReported, largestAckElicitingPacket);
        if (smallestMissingUnreported < 0) {
            return false;
        }
        return largestAckElicitingPacket - smallestMissingUnreported >= reorderingThreshold;
    }

    /**
     * Records that an ACK was sent, suppressing more until new ack-eliciting packets arrive. The ACK
     * is assumed to have covered everything; anything it missed is acknowledged later.
     */
    public void acksSent() {
        immediateAckRequired = false;
        ackElicitingSinceLastAckSent = 0;
        nonAckElicitingSinceLastAckSent = 0;
        earliestAckElicitingSinceLastAckSent = NanoClock.NONE;
        largestAcked = largestAckElicitingPacket;
    }

    /**
     * Adds a packet to acknowledge.
     *
     * @param packet the packet number
     * @param now when it arrived
     */
    public void insertOne(long packet, long now) {
        ranges.insertOne(packet);
        if (largestPacket < 0 || packet > largestPacket) {
            largestPacket = packet;
            largestPacketTime = now;
        }
        if (ranges.size() > MAX_ACK_BLOCKS) {
            ranges.popMin();
        }
    }

    /**
     * Stops acknowledging packets numbered at or below {@code max}: the peer received an ACK of them.
     *
     * @param max the largest packet number to drop
     */
    public void subtractBelow(long max) {
        ranges.remove(0, max + 1);
    }

    /**
     * The packet numbers to acknowledge.
     *
     * @return a live view; do not modify
     */
    public RangeSet ranges() {
        return ranges;
    }

    /**
     * Requires an ACK in the next packet if many non-ack-eliciting packets went unacknowledged,
     * which helps a peer that sends nothing ack-eliciting detect loss. Call it just before
     * building a packet that will be sent anyway.
     */
    public void maybeAckNonEliciting() {
        if (nonAckElicitingSinceLastAckSent > LAZY_ACK_THRESHOLD) {
            immediateAckRequired = true;
        }
    }

    /**
     * Builds the ACK frame for the pending ranges.
     *
     * @param now the current time
     * @param ackDelayExponent this endpoint's {@code ack_delay_exponent}
     * @param ecn the ECN counts to report, or null
     * @return the frame, or null if there is nothing to acknowledge
     */
    public Frame.Ack ackFrame(long now, long ackDelayExponent, Frame.EcnCounts ecn) {
        if (ranges.isEmpty()) {
            return null;
        }
        List<Frame.AckRange> list = new ArrayList<>(ranges.size());
        for (RangeSet.Range r : ranges.descending()) {
            list.add(new Frame.AckRange(r.start(), r.end() - 1));
        }
        long delayMicros = ackDelay(now) / 1_000;
        return new Frame.Ack(list, delayMicros >> ackDelayExponent, ecn);
    }
}
