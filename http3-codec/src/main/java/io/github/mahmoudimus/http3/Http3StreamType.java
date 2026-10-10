package io.github.mahmoudimus.http3;

import java.io.IOException;
import java.io.InputStream;

/**
 * The types of unidirectional streams (RFC 9114 §6.2, RFC 9204 §4.2): each such stream starts
 * with its type as a variable-length integer. Bidirectional streams have no type; in HTTP/3 they
 * are all request streams. {@link Http3StreamValidator.UnidirectionalStreams} checks the rules on
 * how many of each type a peer may open.
 */
public final class Http3StreamType {

    /** The control stream: SETTINGS first, then GOAWAY, MAX_PUSH_ID, CANCEL_PUSH and extensions. */
    public static final long CONTROL = 0x00;
    /** A push stream: a push ID, then the pushed response (server to client only). */
    public static final long PUSH = 0x01;
    /** The QPACK encoder stream: encoder instructions, for {@link QpackDecoder#onEncoderStream}. */
    public static final long QPACK_ENCODER = 0x02;
    /** The QPACK decoder stream: decoder instructions, for {@link QpackEncoder#onDecoderStream}. */
    public static final long QPACK_DECODER = 0x03;

    private Http3StreamType() {}

    /**
     * Whether the type is reserved for greasing, 0x1f * N + 0x21 (§6.2.3). Such streams carry no
     * meaning; the receiver discards or abandons them.
     *
     * @param type the stream type
     * @return whether it is reserved
     */
    public static boolean isReserved(long type) {
        return Http3FrameType.isReserved(type);
    }

    /**
     * Whether the type is one of the four defined ones.
     *
     * @param type the stream type
     * @return whether it is defined
     */
    public static boolean isKnown(long type) {
        return type == CONTROL || type == PUSH || type == QPACK_ENCODER || type == QPACK_DECODER;
    }

    /**
     * Whether closing a stream of this type is a connection error H3_CLOSED_CRITICAL_STREAM.
     *
     * @param type the stream type
     * @return whether the connection needs the stream
     */
    public static boolean isCritical(long type) {
        return type == CONTROL || type == QPACK_ENCODER || type == QPACK_DECODER;
    }

    /**
     * Reads a stream type from the start of a unidirectional stream.
     *
     * @param in the stream
     * @return the type, or -1 if the stream ended before all of it arrived, which a receiver must
     *     tolerate (§6.2)
     * @throws IOException if reading fails
     */
    public static long read(InputStream in) throws IOException {
        int first = in.read();
        if (first < 0) return -1;
        int n = QuicVarInt.lengthOf(first);
        long v = first & 0x3f;
        for (int i = 1; i < n; i++) {
            int b = in.read();
            if (b < 0) return -1;
            v = (v << 8) | b;
        }
        return v;
    }

    /**
     * The bytes that open a unidirectional stream of this type.
     *
     * @param type the stream type
     * @return its encoding
     */
    public static byte[] encode(long type) {
        return QuicVarInt.encode(type);
    }

    /**
     * A readable name for a stream type, for messages.
     *
     * @param type the stream type
     * @return its name
     */
    public static String name(long type) {
        if (type == CONTROL) return "control";
        if (type == PUSH) return "push";
        if (type == QPACK_ENCODER) return "QPACK encoder";
        if (type == QPACK_DECODER) return "QPACK decoder";
        if (isReserved(type)) return "reserved(0x" + Long.toHexString(type) + ")";
        return "unknown(0x" + Long.toHexString(type) + ")";
    }
}
