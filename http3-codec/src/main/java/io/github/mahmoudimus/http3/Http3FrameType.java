package io.github.mahmoudimus.http3;

/** HTTP/3 frame type codes (RFC 9114 §7.2, §11.2.1). */
public final class Http3FrameType {

    public static final long DATA = 0x00;
    public static final long HEADERS = 0x01;
    public static final long CANCEL_PUSH = 0x03;
    public static final long SETTINGS = 0x04;
    public static final long PUSH_PROMISE = 0x05;
    public static final long GOAWAY = 0x07;
    public static final long MAX_PUSH_ID = 0x0d;

    /**
     * HTTP/2 frame types with no HTTP/3 equivalent: PRIORITY (0x02), PING (0x06), WINDOW_UPDATE
     * (0x08) and CONTINUATION (0x09). Receiving one is a connection error H3_FRAME_UNEXPECTED
     * (RFC 9114 §7.2.8).
     */
    public static final long H2_PRIORITY = 0x02;
    public static final long H2_PING = 0x06;
    public static final long H2_WINDOW_UPDATE = 0x08;
    public static final long H2_CONTINUATION = 0x09;

    private Http3FrameType() {}

    /** Whether the type is one this codec parses into its own {@link Http3Frame} record. */
    public static boolean isKnown(long type) {
        return type == DATA || type == HEADERS || type == CANCEL_PUSH || type == SETTINGS
                || type == PUSH_PROMISE || type == GOAWAY || type == MAX_PUSH_ID;
    }

    /** Whether the type is an HTTP/2 frame type that is forbidden in HTTP/3. */
    public static boolean isHttp2Only(long type) {
        return type == H2_PRIORITY || type == H2_PING || type == H2_WINDOW_UPDATE || type == H2_CONTINUATION;
    }

    /**
     * Whether {@code value} has the form 0x1f * N + 0x21 that HTTP/3 reserves for greasing frame
     * types, stream types, setting identifiers and error codes (RFC 9114 §7.2.8, §6.2.3, §7.2.4.1,
     * §8.1). Such values have no meaning and must be ignored.
     */
    public static boolean isReserved(long value) {
        return value >= 0x21 && (value - 0x21) % 0x1f == 0;
    }

    /** The {@code n}th reserved value, 0x1f * n + 0x21. */
    public static long reserved(long n) {
        if (n < 0 || n > (QuicVarInt.MAX_VALUE - 0x21) / 0x1f) throw new IllegalArgumentException("n out of range: " + n);
        return 0x1f * n + 0x21;
    }

    /** A readable name for a frame type, for messages. */
    public static String name(long type) {
        if (type == DATA) return "DATA";
        if (type == HEADERS) return "HEADERS";
        if (type == CANCEL_PUSH) return "CANCEL_PUSH";
        if (type == SETTINGS) return "SETTINGS";
        if (type == PUSH_PROMISE) return "PUSH_PROMISE";
        if (type == GOAWAY) return "GOAWAY";
        if (type == MAX_PUSH_ID) return "MAX_PUSH_ID";
        if (type == H2_PRIORITY) return "PRIORITY (HTTP/2)";
        if (type == H2_PING) return "PING (HTTP/2)";
        if (type == H2_WINDOW_UPDATE) return "WINDOW_UPDATE (HTTP/2)";
        if (type == H2_CONTINUATION) return "CONTINUATION (HTTP/2)";
        if (isReserved(type)) return "RESERVED(0x" + Long.toHexString(type) + ")";
        return "UNKNOWN(0x" + Long.toHexString(type) + ")";
    }
}
