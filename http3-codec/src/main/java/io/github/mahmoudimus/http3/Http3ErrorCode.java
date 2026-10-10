package io.github.mahmoudimus.http3;

/**
 * The HTTP/3 error codes (RFC 9114 §8.1), the QPACK error codes (RFC 9204 §6) and
 * H3_DATAGRAM_ERROR (RFC 9297 §5.2). QUIC carries them: CONNECTION_CLOSE for a connection error,
 * RESET_STREAM and STOP_SENDING for a stream error.
 */
public enum Http3ErrorCode {
    /** An HTTP Datagram or the Capsule Protocol was misused (RFC 9297 §5.2). */
    H3_DATAGRAM_ERROR(0x33),
    /** No error: the connection or stream is closing without one. */
    H3_NO_ERROR(0x0100),
    /** A protocol violation no more specific code covers. */
    H3_GENERAL_PROTOCOL_ERROR(0x0101),
    /** An internal error in the HTTP stack. */
    H3_INTERNAL_ERROR(0x0102),
    /** The peer created a stream that will not be accepted. */
    H3_STREAM_CREATION_ERROR(0x0103),
    /** A stream the connection needs was closed or reset. */
    H3_CLOSED_CRITICAL_STREAM(0x0104),
    /** A frame not permitted in the current state or on the current stream. */
    H3_FRAME_UNEXPECTED(0x0105),
    /** A frame that fails its layout requirements, or of the wrong size. */
    H3_FRAME_ERROR(0x0106),
    /** The peer is generating excessive load. */
    H3_EXCESSIVE_LOAD(0x0107),
    /** A stream or push identifier was used incorrectly. */
    H3_ID_ERROR(0x0108),
    /** An error in the payload of a SETTINGS frame. */
    H3_SETTINGS_ERROR(0x0109),
    /** No SETTINGS frame at the start of the control stream. */
    H3_MISSING_SETTINGS(0x010a),
    /** The server rejected a request without processing any of it. */
    H3_REQUEST_REJECTED(0x010b),
    /** The request or its response is cancelled. */
    H3_REQUEST_CANCELLED(0x010c),
    /** The client's stream ended without a complete request. */
    H3_REQUEST_INCOMPLETE(0x010d),
    /** A malformed HTTP message. */
    H3_MESSAGE_ERROR(0x010e),
    /** The connection of a CONNECT request was reset or closed abnormally. */
    H3_CONNECT_ERROR(0x010f),
    /** The request should be retried over HTTP/1.1. */
    H3_VERSION_FALLBACK(0x0110),
    /** A field section could not be decoded (RFC 9204 §6). */
    QPACK_DECOMPRESSION_FAILED(0x0200),
    /** An instruction on the encoder stream could not be processed. */
    QPACK_ENCODER_STREAM_ERROR(0x0201),
    /** An instruction on the decoder stream could not be processed. */
    QPACK_DECODER_STREAM_ERROR(0x0202);

    private final long code;

    Http3ErrorCode(long code) {
        this.code = code;
    }

    /**
     * The value sent on the wire, a variable-length integer.
     *
     * @return the wire value
     */
    public long code() {
        return code;
    }

    /**
     * The error code for a wire value. Unknown codes, including the reserved ones, must be treated
     * as {@link #H3_NO_ERROR} (RFC 9114 §9).
     *
     * @param code the wire value
     * @return its error code, or {@link #H3_NO_ERROR} for an unknown one
     */
    public static Http3ErrorCode forCode(long code) {
        for (Http3ErrorCode c : values()) {
            if (c.code == code) return c;
        }
        return H3_NO_ERROR;
    }

    /**
     * Whether {@code code} is a reserved (greasing) error code, 0x1f * N + 0x21 (RFC 9114 §8.1).
     *
     * @param code the wire value
     * @return whether it is reserved
     */
    public static boolean isReserved(long code) {
        return Http3FrameType.isReserved(code);
    }
}
