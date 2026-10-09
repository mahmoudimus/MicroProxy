package io.github.mahmoudimus.http2;

/** The error codes of RFC 9113 §7, carried by RST_STREAM and GOAWAY frames. */
public enum ErrorCode {
    /**
     * Graceful completion without an error.
     */
    NO_ERROR(0x0),
    /**
     * A violation of the HTTP/2 protocol.
     */
    PROTOCOL_ERROR(0x1),
    /**
     * An unexpected internal failure.
     */
    INTERNAL_ERROR(0x2),
    /**
     * A violation of flow-control limits.
     */
    FLOW_CONTROL_ERROR(0x3),
    /**
     * A SETTINGS acknowledgement took too long.
     */
    SETTINGS_TIMEOUT(0x4),
    /**
     * A frame arrived for a closed stream.
     */
    STREAM_CLOSED(0x5),
    /**
     * A frame payload has an invalid size.
     */
    FRAME_SIZE_ERROR(0x6),
    /**
     * The stream was refused before application processing.
     */
    REFUSED_STREAM(0x7),
    /**
     * The stream is no longer needed.
     */
    CANCEL(0x8),
    /**
     * The HPACK compression state is invalid.
     */
    COMPRESSION_ERROR(0x9),
    /**
     * The connection established by CONNECT failed.
     */
    CONNECT_ERROR(0xa),
    /**
     * The peer is generating excessive load.
     */
    ENHANCE_YOUR_CALM(0xb),
    /**
     * The connection does not meet security requirements.
     */
    INADEQUATE_SECURITY(0xc),
    /**
     * The peer requires HTTP/1.1 instead.
     */
    HTTP_1_1_REQUIRED(0xd);

    private static final ErrorCode[] BY_CODE = values();

    private final int code;

    ErrorCode(int code) {
        this.code = code;
    }

    /**
     * The 32-bit value sent on the wire.
     *
     * @return the raw 32-bit error code
     */
    public int code() {
        return code;
    }

    /**
     * The error code for a wire value. Unknown codes must not trigger special behaviour (RFC 9113
     * §7), so they map to {@link #INTERNAL_ERROR}.
     *
     * @param code the raw wire error code
     * @return the matching code, or INTERNAL_ERROR if unknown
     */
    public static ErrorCode forCode(int code) {
        return code >= 0 && code < BY_CODE.length ? BY_CODE[code] : INTERNAL_ERROR;
    }
}
