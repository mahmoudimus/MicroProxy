package io.github.mahmoudimus.http3;

/**
 * The HTTP/3 error codes (RFC 9114 §8.1), the QPACK error codes (RFC 9204 §6) and
 * H3_DATAGRAM_ERROR (RFC 9297 §5.2). QUIC carries them: CONNECTION_CLOSE for a connection error,
 * RESET_STREAM and STOP_SENDING for a stream error.
 */
public enum Http3ErrorCode {
    H3_DATAGRAM_ERROR(0x33),
    H3_NO_ERROR(0x0100),
    H3_GENERAL_PROTOCOL_ERROR(0x0101),
    H3_INTERNAL_ERROR(0x0102),
    H3_STREAM_CREATION_ERROR(0x0103),
    H3_CLOSED_CRITICAL_STREAM(0x0104),
    H3_FRAME_UNEXPECTED(0x0105),
    H3_FRAME_ERROR(0x0106),
    H3_EXCESSIVE_LOAD(0x0107),
    H3_ID_ERROR(0x0108),
    H3_SETTINGS_ERROR(0x0109),
    H3_MISSING_SETTINGS(0x010a),
    H3_REQUEST_REJECTED(0x010b),
    H3_REQUEST_CANCELLED(0x010c),
    H3_REQUEST_INCOMPLETE(0x010d),
    H3_MESSAGE_ERROR(0x010e),
    H3_CONNECT_ERROR(0x010f),
    H3_VERSION_FALLBACK(0x0110),
    QPACK_DECOMPRESSION_FAILED(0x0200),
    QPACK_ENCODER_STREAM_ERROR(0x0201),
    QPACK_DECODER_STREAM_ERROR(0x0202);

    private final long code;

    Http3ErrorCode(long code) {
        this.code = code;
    }

    /** The value sent on the wire, a variable-length integer. */
    public long code() {
        return code;
    }

    /**
     * The error code for a wire value. Unknown codes, including the reserved ones, must be treated
     * as {@link #H3_NO_ERROR} (RFC 9114 §9).
     */
    public static Http3ErrorCode forCode(long code) {
        for (Http3ErrorCode c : values()) {
            if (c.code == code) return c;
        }
        return H3_NO_ERROR;
    }

    /** Whether {@code code} is a reserved (greasing) error code, 0x1f * N + 0x21 (RFC 9114 §8.1). */
    public static boolean isReserved(long code) {
        return Http3FrameType.isReserved(code);
    }
}
