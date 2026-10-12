/*
 * Ported from quinn-proto src/connection/spaces.rs (SentPacket) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.util.List;

/**
 * What loss recovery remembers about a sent packet until it is acknowledged or deemed lost (RFC
 * 9002 appendix A.1.1). Stream data is not copied: {@link #streamFrames()} only names the ranges.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class SentPacket {

    private final long timeSent;
    private final int size;
    private final boolean ackEliciting;
    private final long largestAcked;
    private Retransmits retransmits;
    private final List<StreamMeta> streamFrames;
    // Delivery rate state when sent (draft-cheng-iccrg-delivery-rate-estimation), set by DeliveryRate
    private long delivered;
    private long deliveredTime = Long.MIN_VALUE;
    private long firstSentTime = Long.MIN_VALUE;
    private boolean appLimited;
    /** The generation of the path the packet was sent on, set by {@link Recovery#onPacketSent}. */
    private long pathGeneration;

    /**
     * A sent packet.
     *
     * @param timeSent when it was sent, in nanoseconds
     * @param size its size in bytes, QUIC framing included but not UDP or IP; zero if it is not
     *     counted in flight (an ACK-only packet that is not padded)
     * @param ackEliciting whether it must be acknowledged
     * @param largestAcked the largest packet number its ACK frame acknowledged, or -1
     * @param retransmits the control frames it carried, to queue again if it is lost; may be null
     * @param streamFrames the STREAM frames it carried
     */
    public SentPacket(long timeSent, int size, boolean ackEliciting, long largestAcked, Retransmits retransmits,
            List<StreamMeta> streamFrames) {
        this.timeSent = timeSent;
        this.size = size;
        this.ackEliciting = ackEliciting;
        this.largestAcked = largestAcked;
        this.retransmits = retransmits;
        this.streamFrames = List.copyOf(streamFrames);
    }

    /**
     * A packet without frames to track, for tests and ACK-only packets.
     *
     * @param timeSent when it was sent
     * @param size its size, zero if not in flight
     * @param ackEliciting whether it must be acknowledged
     * @return the packet
     */
    public static SentPacket of(long timeSent, int size, boolean ackEliciting) {
        return new SentPacket(timeSent, size, ackEliciting, -1, null, List.of());
    }

    /**
     * When the packet was sent.
     *
     * @return nanoseconds
     */
    public long timeSent() {
        return timeSent;
    }

    /**
     * The bytes the packet counts in flight.
     *
     * @return the size, zero if not in flight
     */
    public int size() {
        return size;
    }

    /**
     * Whether the packet must be acknowledged.
     *
     * @return true if it carried a frame other than ACK, PADDING and CONNECTION_CLOSE
     */
    public boolean ackEliciting() {
        return ackEliciting;
    }

    /**
     * The largest packet number the packet's ACK frame acknowledged.
     *
     * @return the packet number, or -1 if it carried no ACK
     */
    public long largestAcked() {
        return largestAcked;
    }

    /**
     * The control frames the packet carried.
     *
     * @return the frames, or null if none
     */
    public Retransmits retransmits() {
        return retransmits;
    }

    /**
     * The STREAM frames the packet carried.
     *
     * @return what each one carried
     */
    public List<StreamMeta> streamFrames() {
        return streamFrames;
    }

    /**
     * The bytes the connection had delivered when this packet was sent ({@code P.delivered}).
     *
     * @return bytes
     */
    public long delivered() {
        return delivered;
    }

    /**
     * When the connection's delivered count last changed before this packet was sent ({@code
     * P.delivered_time}).
     *
     * @return the time, or {@link Long#MIN_VALUE} if the packet was not in flight
     */
    public long deliveredTime() {
        return deliveredTime;
    }

    /**
     * The send time of the first packet of the flight this one was sent in ({@code
     * P.first_sent_time}).
     *
     * @return the time, or {@link Long#MIN_VALUE} if the packet was not in flight
     */
    public long firstSentTime() {
        return firstSentTime;
    }

    /**
     * Whether the packet was sent while sending was application limited ({@code
     * P.is_app_limited}).
     *
     * @return the flag
     */
    public boolean isAppLimited() {
        return appLimited;
    }

    void setDeliveryState(long delivered, long deliveredTime, long firstSentTime, boolean appLimited) {
        this.delivered = delivered;
        this.deliveredTime = deliveredTime;
        this.firstSentTime = firstSentTime;
        this.appLimited = appLimited;
    }

    /** Whether the control frames still matter for {@code streams}. */
    /**
     * The generation of the path the packet was sent on.
     *
     * @return the generation
     */
    public long pathGeneration() {
        return pathGeneration;
    }

    void setPathGeneration(long generation) {
        this.pathGeneration = generation;
    }

    boolean hasRetransmits(StreamsState streams) {
        return retransmits != null && !retransmits.isEmpty(streams);
    }

    /** Takes the control frames, so that a probe that resends them does not resend them twice. */
    Retransmits takeRetransmits() {
        Retransmits r = retransmits;
        retransmits = null;
        return r;
    }
}
