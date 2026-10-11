/*
 * Ported from quinn-proto src/frame.rs (FrameType and its frame_types! table) (Apache-2.0), with
 * the packet types of RFC 9000 Table 3, RFC 9221 and the QUIC ACK frequency draft.
 */
package io.github.mahmoudimus.quic.frame;

import io.github.mahmoudimus.quic.packet.PacketType;

/**
 * The QUIC frame types (RFC 9000 section 19 and Table 3), with the type codes each covers and
 * the packet types it may appear in. Types that carry flags in their low bits (ACK, STREAM,
 * MAX_STREAMS, STREAMS_BLOCKED, DATAGRAM) cover a range of codes; the two CONNECTION_CLOSE codes
 * are separate constants because they are allowed in different packets.
 */
public enum FrameType {
    /** PADDING (0x00). */
    PADDING(0x00, 0x00, "IH01", false),
    /** PING (0x01). */
    PING(0x01, 0x01, "IH01", true),
    /** ACK (0x02) and ACK with ECN counts (0x03). */
    ACK(0x02, 0x03, "IH_1", false),
    /** RESET_STREAM (0x04). */
    RESET_STREAM(0x04, 0x04, "__01", true),
    /** STOP_SENDING (0x05). */
    STOP_SENDING(0x05, 0x05, "__01", true),
    /** CRYPTO (0x06). */
    CRYPTO(0x06, 0x06, "IH_1", true),
    /** NEW_TOKEN (0x07), sent by servers only. */
    NEW_TOKEN(0x07, 0x07, "___1", true),
    /** STREAM (0x08 to 0x0f): the low bits flag OFF (0x04), LEN (0x02) and FIN (0x01). */
    STREAM(0x08, 0x0f, "__01", true),
    /** MAX_DATA (0x10). */
    MAX_DATA(0x10, 0x10, "__01", true),
    /** MAX_STREAM_DATA (0x11). */
    MAX_STREAM_DATA(0x11, 0x11, "__01", true),
    /** MAX_STREAMS for bidirectional (0x12) and unidirectional (0x13) streams. */
    MAX_STREAMS(0x12, 0x13, "__01", true),
    /** DATA_BLOCKED (0x14). */
    DATA_BLOCKED(0x14, 0x14, "__01", true),
    /** STREAM_DATA_BLOCKED (0x15). */
    STREAM_DATA_BLOCKED(0x15, 0x15, "__01", true),
    /** STREAMS_BLOCKED for bidirectional (0x16) and unidirectional (0x17) streams. */
    STREAMS_BLOCKED(0x16, 0x17, "__01", true),
    /** NEW_CONNECTION_ID (0x18). */
    NEW_CONNECTION_ID(0x18, 0x18, "__01", true),
    /** RETIRE_CONNECTION_ID (0x19). */
    RETIRE_CONNECTION_ID(0x19, 0x19, "__01", true),
    /** PATH_CHALLENGE (0x1a). */
    PATH_CHALLENGE(0x1a, 0x1a, "__01", true),
    /** PATH_RESPONSE (0x1b). */
    PATH_RESPONSE(0x1b, 0x1b, "___1", true),
    /** CONNECTION_CLOSE for transport errors (0x1c), the only close allowed in Initial and Handshake. */
    CONNECTION_CLOSE(0x1c, 0x1c, "IH01", false),
    /** CONNECTION_CLOSE for application errors (0x1d). */
    APPLICATION_CLOSE(0x1d, 0x1d, "__01", false),
    /** HANDSHAKE_DONE (0x1e), sent by servers only. */
    HANDSHAKE_DONE(0x1e, 0x1e, "___1", true),
    /** IMMEDIATE_ACK (0x1f) of the QUIC ACK frequency extension. */
    IMMEDIATE_ACK(0x1f, 0x1f, "__01", true),
    /** DATAGRAM (0x30, and 0x31 with a Length field) of RFC 9221. */
    DATAGRAM(0x30, 0x31, "__01", true),
    /** ACK_FREQUENCY (0xaf) of the QUIC ACK frequency extension. */
    ACK_FREQUENCY(0xaf, 0xaf, "__01", true);

    private final int first;
    private final int last;
    private final boolean initial;
    private final boolean handshake;
    private final boolean zeroRtt;
    private final boolean oneRtt;
    private final boolean ackEliciting;

    FrameType(int first, int last, String packets, boolean ackEliciting) {
        this.first = first;
        this.last = last;
        this.initial = packets.charAt(0) == 'I';
        this.handshake = packets.charAt(1) == 'H';
        this.zeroRtt = packets.charAt(2) == '0';
        this.oneRtt = packets.charAt(3) == '1';
        this.ackEliciting = ackEliciting;
    }

    /**
     * The lowest type code of this frame type.
     *
     * @return the code, such as {@code 0x08} for STREAM
     */
    public int code() {
        return first;
    }

    /**
     * The highest type code of this frame type.
     *
     * @return the code, such as {@code 0x0f} for STREAM
     */
    public int lastCode() {
        return last;
    }

    /**
     * Whether a packet containing this frame must be acknowledged (RFC 9000 section 13.2).
     *
     * @return false for PADDING, ACK and CONNECTION_CLOSE
     */
    public boolean isAckEliciting() {
        return ackEliciting;
    }

    /**
     * Whether this frame may appear in a packet type (RFC 9000 Table 3); receiving it elsewhere
     * is a {@code PROTOCOL_VIOLATION}.
     *
     * @param packetType the packet type
     * @return true if allowed
     */
    public boolean isAllowedIn(PacketType packetType) {
        return switch (packetType) {
            case INITIAL -> initial;
            case HANDSHAKE -> handshake;
            case ZERO_RTT -> zeroRtt;
            case ONE_RTT -> oneRtt;
            case RETRY, VERSION_NEGOTIATION -> false;
        };
    }

    /**
     * The frame type with a type code.
     *
     * @param code the type code read from the wire
     * @return the type, or null for an unknown code
     */
    public static FrameType forCode(long code) {
        if (code >= 0 && code < LOW_CODES.length) return LOW_CODES[(int) code];
        if (code == 0x30 || code == 0x31) return DATAGRAM;
        if (code == 0xaf) return ACK_FREQUENCY;
        return null;
    }

    private static final FrameType[] LOW_CODES = new FrameType[0x20];

    static {
        for (FrameType t : values()) {
            for (int c = t.first; c <= t.last && c < LOW_CODES.length; c++) {
                LOW_CODES[c] = t;
            }
        }
    }
}
