package io.github.mahmoudimus.http2;

/** Frame type codes (RFC 9113 §6) and frame flags. */
public final class FrameType {

    public static final int DATA = 0x0;
    public static final int HEADERS = 0x1;
    public static final int PRIORITY = 0x2;
    public static final int RST_STREAM = 0x3;
    public static final int SETTINGS = 0x4;
    public static final int PUSH_PROMISE = 0x5;
    public static final int PING = 0x6;
    public static final int GOAWAY = 0x7;
    public static final int WINDOW_UPDATE = 0x8;
    public static final int CONTINUATION = 0x9;

    /** DATA, HEADERS: the last frame the sender will send on the stream. */
    public static final int FLAG_END_STREAM = 0x1;
    /** SETTINGS, PING: an acknowledgement. */
    public static final int FLAG_ACK = 0x1;
    /** HEADERS, PUSH_PROMISE, CONTINUATION: the field block is complete. */
    public static final int FLAG_END_HEADERS = 0x4;
    /** DATA, HEADERS, PUSH_PROMISE: the payload starts with a pad length and ends in padding. */
    public static final int FLAG_PADDED = 0x8;
    /** HEADERS: the payload carries a (deprecated) priority signal. */
    public static final int FLAG_PRIORITY = 0x20;

    /** The size of every frame header. */
    public static final int FRAME_HEADER_LENGTH = 9;

    private FrameType() {}

    /** A readable name for a frame type code, for messages. */
    public static String name(int type) {
        return switch (type) {
            case DATA -> "DATA";
            case HEADERS -> "HEADERS";
            case PRIORITY -> "PRIORITY";
            case RST_STREAM -> "RST_STREAM";
            case SETTINGS -> "SETTINGS";
            case PUSH_PROMISE -> "PUSH_PROMISE";
            case PING -> "PING";
            case GOAWAY -> "GOAWAY";
            case WINDOW_UPDATE -> "WINDOW_UPDATE";
            case CONTINUATION -> "CONTINUATION";
            default -> "UNKNOWN(0x" + Integer.toHexString(type) + ")";
        };
    }
}
