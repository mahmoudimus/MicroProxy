/*
 * Ported from quinn-proto src/connection/spaces.rs (PacketSpace) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.crypto.Keys;
import io.github.mahmoudimus.quic.frame.Frame;
import java.util.Map;
import java.util.TreeMap;

/**
 * One packet number space (RFC 9000 section 12.3, RFC 9002 appendix A): its keys, the packets
 * received and to acknowledge, the next packet number, the packets sent and not yet acknowledged
 * or lost, the frames waiting to be sent, the CRYPTO stream, and the loss detection state that
 * {@link Recovery} keeps per space.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class PacketSpace {

    /**
     * What a space has to send.
     *
     * @param acks whether an ACK must be sent, even alone
     * @param other whether frames other than ACK are waiting
     */
    public record Sendable(boolean acks, boolean other) {

        /**
         * Whether nothing is waiting.
         *
         * @return true if neither ACKs nor other frames are due
         */
        public boolean isEmpty() {
            return !acks && !other;
        }
    }

    /**
     * Non-ack-eliciting packets sent after the last ack-eliciting one that are kept; older ones are
     * forgotten, since nothing guarantees they will ever be acknowledged.
     */
    static final long MAX_UNACKED_NON_ACK_ELICITING_TAIL = 1_000;

    private final SpaceId id;
    /** The space's keys, or null before they are available and once discarded. */
    Keys keys;
    /** Duplicate detection of received packet numbers. */
    final Dedup dedup = new Dedup();
    /** The highest packet number received. */
    long rxPacket;
    /** Frames waiting to be sent. */
    final Retransmits pending = new Retransmits();
    /** Packets waiting to be acknowledged. */
    final PendingAcks pendingAcks = new PendingAcks();
    /** The number of the next packet sent. */
    long nextPacketNumber;
    /** The largest packet number the peer acknowledged, or -1. */
    long largestAckedPacket = -1;
    /** When {@code largestAckedPacket} was sent. */
    long largestAckedPacketSent;
    /** The highest ack-eliciting packet number sent. */
    long largestAckElicitingSent;
    /** Packets tracked above {@code largestAckElicitingSent}, none of them ack-eliciting. */
    long unackedNonAckElicitingTail;
    /** Sent and not acknowledged or lost. */
    final SentPackets sentPackets = new SentPackets();
    /** When recently lost packets were sent, to spot spurious losses; old entries are drained. */
    final TreeMap<Long, Long> lostPackets = new TreeMap<>();
    /** ECN codepoints counted on received packets. */
    long ecnEct0;
    long ecnEct1;
    long ecnCe;
    /** The ECN counts of the last ACK that acknowledged a new largest packet. */
    Frame.EcnCounts ecnFeedback = new Frame.EcnCounts(0, 0, 0);
    /** The incoming CRYPTO stream. */
    final Assembler cryptoStream = new Assembler();
    /** The offset of the next outgoing CRYPTO byte. */
    long cryptoOffset;
    /** When the last ack-eliciting packet was sent, or {@link NanoClock#NONE}. */
    long timeOfLastAckElicitingPacket = NanoClock.NONE;
    /**
     * When the earliest unacknowledged packet sent before an acknowledged one is deemed lost by the
     * time threshold, or {@link NanoClock#NONE}.
     */
    long lossTime = NanoClock.NONE;
    /** Probe packets to send after a PTO. */
    int lossProbes;
    /** Whether a PING is needed. */
    boolean pingPending;
    /** Whether an IMMEDIATE_ACK is needed. */
    boolean immediateAckPending;
    /** Packets sent with the current keys. */
    long sentWithKeys;

    /**
     * An empty space.
     *
     * @param id which space this is
     * @param now the current time
     */
    public PacketSpace(SpaceId id, long now) {
        this.id = id;
        this.largestAckedPacketSent = now;
    }

    /**
     * Which space this is.
     *
     * @return the space
     */
    public SpaceId id() {
        return id;
    }

    /**
     * The space's keys.
     *
     * @return the keys, or null before they are installed and after they are discarded
     */
    public Keys keys() {
        return keys;
    }

    /**
     * Installs keys.
     *
     * @param keys the keys
     */
    public void setKeys(Keys keys) {
        this.keys = keys;
    }

    /**
     * The duplicate detector of received packet numbers.
     *
     * @return the detector
     */
    public Dedup dedup() {
        return dedup;
    }

    /**
     * The frames waiting to be sent in this space.
     *
     * @return the pending frames
     */
    public Retransmits pending() {
        return pending;
    }

    /**
     * The packets waiting to be acknowledged.
     *
     * @return the pending ACK state
     */
    public PendingAcks pendingAcks() {
        return pendingAcks;
    }

    /**
     * The incoming CRYPTO stream.
     *
     * @return its assembler
     */
    public Assembler cryptoStream() {
        return cryptoStream;
    }

    /**
     * The offset of the next outgoing CRYPTO byte.
     *
     * @return the offset
     */
    public long cryptoOffset() {
        return cryptoOffset;
    }

    /**
     * Advances the outgoing CRYPTO offset.
     *
     * @param length the bytes queued
     */
    public void advanceCryptoOffset(long length) {
        cryptoOffset += length;
    }

    /**
     * The packets sent and not yet acknowledged or lost.
     *
     * @return the packets
     */
    public SentPackets sentPackets() {
        return sentPackets;
    }

    /**
     * The number of the next packet to send.
     *
     * @return the packet number
     */
    public long nextPacketNumber() {
        return nextPacketNumber;
    }

    /**
     * The largest packet number the peer acknowledged.
     *
     * @return the packet number, or -1
     */
    public long largestAckedPacket() {
        return largestAckedPacket;
    }

    /**
     * The highest packet number received.
     *
     * @return the packet number
     */
    public long rxPacket() {
        return rxPacket;
    }

    /**
     * Records the receipt of an authenticated packet: duplicate detection, ACK bookkeeping and the
     * highest packet number.
     *
     * @param now the current time
     * @param packetNumber the packet number
     * @param ackEliciting whether the packet is ack-eliciting
     * @return true if the packet is a duplicate and must be dropped unprocessed
     */
    public boolean onPacketReceived(long now, long packetNumber, boolean ackEliciting) {
        if (dedup.insert(packetNumber)) {
            return true;
        }
        pendingAcks.insertOne(packetNumber, now);
        pendingAcks.packetReceived(now, packetNumber, ackEliciting, dedup);
        rxPacket = Math.max(rxPacket, packetNumber);
        return false;
    }

    /**
     * Records an ECN codepoint on a received packet (RFC 9000 section 13.4.1). A CE mark asks for an
     * immediate ACK.
     *
     * @param codepoint 1 for ECT(1), 2 for ECT(0), 3 for CE; 0 (not ECT) is ignored
     */
    public void onEcnReceived(int codepoint) {
        switch (codepoint) {
            case 1 -> ecnEct1++;
            case 2 -> ecnEct0++;
            case 3 -> {
                ecnCe++;
                pendingAcks.setImmediateAckRequired();
            }
            default -> {}
        }
    }

    /**
     * The ECN counts to report in ACK frames.
     *
     * @return the counts of received ECT(0), ECT(1) and CE codepoints
     */
    public Frame.EcnCounts ecnCounters() {
        return new Frame.EcnCounts(ecnEct0, ecnEct1, ecnCe);
    }

    /**
     * Whether time-threshold loss detection is pending.
     *
     * @return the loss time, or {@link NanoClock#NONE}
     */
    public long lossTime() {
        return lossTime;
    }

    /**
     * The probes to send after a PTO.
     *
     * @return the count
     */
    public int lossProbes() {
        return lossProbes;
    }

    /** Records that one probe packet was sent. */
    public void probeSent() {
        if (lossProbes > 0) {
            lossProbes--;
        }
    }

    /**
     * Whether a PING must be sent.
     *
     * @return true if pending
     */
    public boolean pingPending() {
        return pingPending;
    }

    /**
     * Sets whether a PING must be sent.
     *
     * @param pending whether one is needed
     */
    public void setPingPending(boolean pending) {
        pingPending = pending;
    }

    /**
     * Whether an IMMEDIATE_ACK must be sent.
     *
     * @return true if pending
     */
    public boolean immediateAckPending() {
        return immediateAckPending;
    }

    /**
     * Sets whether an IMMEDIATE_ACK must be sent.
     *
     * @param pending whether one is needed
     */
    public void setImmediateAckPending(boolean pending) {
        immediateAckPending = pending;
    }

    /**
     * When the last ack-eliciting packet was sent.
     *
     * @return the time, or {@link NanoClock#NONE}
     */
    public long timeOfLastAckElicitingPacket() {
        return timeOfLastAckElicitingPacket;
    }

    /**
     * Fills a loss probe after a PTO (RFC 9002 section 6.2.4): if no new data is waiting, the
     * oldest in-flight packet's control frames are queued again (and taken from that packet, so they
     * are not resent twice), and failing that a PING.
     *
     * @param requestImmediateAck whether to ask for an immediate ACK (application data space, with a
     *     peer that supports the ACK frequency extension)
     * @param hasAckElicitingData whether other ack-eliciting data, such as a DATAGRAM, will be sent
     * @param streams the connection's streams
     */
    public void maybeQueueProbe(boolean requestImmediateAck, boolean hasAckElicitingData, StreamsState streams) {
        if (lossProbes == 0) {
            return;
        }
        if (requestImmediateAck) {
            immediateAckPending = true;
        }
        if (!pending.isEmpty(streams) || hasAckElicitingData) {
            return; // real data to send
        }
        for (SentPacket packet : sentPackets.values()) {
            if (packet.hasRetransmits(streams)) {
                pending.merge(packet.takeRetransmits());
                return;
            }
        }
        // Nothing to send or resend: a PING, which mostly happens when a server is blocked by
        // the anti-amplification limit during the handshake
        if (!immediateAckPending) {
            pingPending = true;
        }
    }

    /**
     * Allocates the next packet number. In the application data space use {@link
     * PacketNumberFilter#allocate} instead.
     *
     * @return the packet number
     * @throws IllegalStateException if packet numbers are exhausted
     */
    public long getTxNumber() {
        if (nextPacketNumber >= 1L << 62) {
            throw new IllegalStateException("packet numbers exhausted");
        }
        sentWithKeys++;
        return nextPacketNumber++;
    }

    /**
     * Whether anything can be sent in this space.
     *
     * @param streams the connection's streams
     * @return whether an ACK must be sent, and whether other frames are waiting
     */
    public Sendable canSend(StreamsState streams) {
        boolean acks = pendingAcks.canSend();
        boolean other = !pending.isEmpty(streams) || pingPending || immediateAckPending;
        return new Sendable(acks, other);
    }

    /**
     * Validates an ACK's ECN counts (RFC 9000 section 13.4.2.1) and records them.
     *
     * @param newlyAcked the packets the ACK newly acknowledged
     * @param ecn the counts
     * @return true if the CE count increased, a congestion signal
     * @throws IllegalArgumentException if the counts went backwards, show bleaching or corruption;
     *     ECN should then be disabled on the path
     */
    public boolean detectEcn(long newlyAcked, Frame.EcnCounts ecn) {
        long ect0Increase = ecn.ect0() - ecnFeedback.ect0();
        long ect1Increase = ecn.ect1() - ecnFeedback.ect1();
        long ceIncrease = ecn.ce() - ecnFeedback.ce();
        if (ect0Increase < 0 || ect1Increase < 0 || ceIncrease < 0) {
            throw new IllegalArgumentException("peer ECN count regression");
        }
        long totalIncrease = ect0Increase + ect1Increase + ceIncrease;
        if (totalIncrease < newlyAcked) {
            throw new IllegalArgumentException("ECN bleaching");
        }
        if (ect0Increase + ceIncrease < newlyAcked || ect1Increase != 0) {
            throw new IllegalArgumentException("ECN corruption");
        }
        ecnFeedback = ecn;
        return ceIncrease != 0;
    }

    /**
     * Stops tracking a sent packet.
     *
     * @param number the packet number
     * @return what was known about it, or null if it was not tracked
     */
    public SentPacket take(long number) {
        SentPacket packet = sentPackets.remove(number);
        if (packet != null && !packet.ackEliciting() && number > largestAckElicitingSent) {
            unackedNonAckElicitingTail--;
        }
        return packet;
    }

    /**
     * Tracks a sent packet. Of the packets after the last ack-eliciting one, at most {@value
     * #MAX_UNACKED_NON_ACK_ELICITING_TAIL} are kept, since nothing guarantees an ACK for them.
     *
     * @param number the packet number
     * @param packet the packet
     * @return a packet to forget (remove from the in-flight counts), or null
     */
    public SentPacket sent(long number, SentPacket packet) {
        SentPacket forgotten = null;
        if (packet.ackEliciting()) {
            unackedNonAckElicitingTail = 0;
            largestAckElicitingSent = number;
        } else if (unackedNonAckElicitingTail > MAX_UNACKED_NON_ACK_ELICITING_TAIL) {
            // Such packets carry only PADDING, ACK and CONNECTION_CLOSE, which need nothing on
            // loss beyond leaving the in-flight counts
            Map.Entry<Long, SentPacket> oldest = sentPackets.higher(largestAckElicitingSent);
            forgotten = sentPackets.remove(oldest.getKey());
        } else {
            unackedNonAckElicitingTail++;
        }
        sentPackets.insert(number, packet);
        return forgotten;
    }

    /**
     * Whether any congestion-controlled packet of this space is unacknowledged and not lost.
     *
     * @return true if one is in flight
     */
    public boolean hasInFlight() {
        return sentPackets.hasInFlight();
    }
}
