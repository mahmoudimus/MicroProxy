package io.github.mahmoudimus.http2;

/** The error codes of RFC 9113 §7, carried by RST_STREAM and GOAWAY frames. */
public enum ErrorCode {
    NO_ERROR(0x0),
    PROTOCOL_ERROR(0x1),
    INTERNAL_ERROR(0x2),
    FLOW_CONTROL_ERROR(0x3),
    SETTINGS_TIMEOUT(0x4),
    STREAM_CLOSED(0x5),
    FRAME_SIZE_ERROR(0x6),
    REFUSED_STREAM(0x7),
    CANCEL(0x8),
    COMPRESSION_ERROR(0x9),
    CONNECT_ERROR(0xa),
    ENHANCE_YOUR_CALM(0xb),
    INADEQUATE_SECURITY(0xc),
    HTTP_1_1_REQUIRED(0xd);

    private static final ErrorCode[] BY_CODE = values();

    private final int code;

    ErrorCode(int code) {
        this.code = code;
    }

    /** The 32-bit value sent on the wire. */
    public int code() {
        return code;
    }

    /**
     * The error code for a wire value. Unknown codes must not trigger special behaviour (RFC 9113
     * §7), so they map to {@link #INTERNAL_ERROR}.
     */
    public static ErrorCode forCode(int code) {
        return code >= 0 && code < BY_CODE.length ? BY_CODE[code] : INTERNAL_ERROR;
    }
}
