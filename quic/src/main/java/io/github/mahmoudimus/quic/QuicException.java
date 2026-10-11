package io.github.mahmoudimus.quic;

import java.io.Serial;

/**
 * A QUIC connection error (RFC 9000 section 20), carrying the error code a {@code CONNECTION_CLOSE}
 * frame sends to the peer. TLS alerts map to the {@code CRYPTO_ERROR} range {@code 0x0100}–{@code
 * 0x01ff} (RFC 9001 section 4.8).
 */
public class QuicException extends Exception {

    @Serial
    private static final long serialVersionUID = 1L;

    /** No error. */
    public static final long NO_ERROR = 0x00;
    /** An implementation error. */
    public static final long INTERNAL_ERROR = 0x01;
    /** The server refused the connection. */
    public static final long CONNECTION_REFUSED = 0x02;
    /** The peer sent more data than its flow-control limits allowed. */
    public static final long FLOW_CONTROL_ERROR = 0x03;
    /** The peer opened more streams than allowed. */
    public static final long STREAM_LIMIT_ERROR = 0x04;
    /** A frame arrived for a stream in a state that does not permit it. */
    public static final long STREAM_STATE_ERROR = 0x05;
    /** A stream's final size changed or was exceeded. */
    public static final long FINAL_SIZE_ERROR = 0x06;
    /** A frame could not be decoded. */
    public static final long FRAME_ENCODING_ERROR = 0x07;
    /** Transport parameters were malformed, missing or invalid. */
    public static final long TRANSPORT_PARAMETER_ERROR = 0x08;
    /** The peer used more connection IDs than allowed. */
    public static final long CONNECTION_ID_LIMIT_ERROR = 0x09;
    /** Any other protocol violation. */
    public static final long PROTOCOL_VIOLATION = 0x0a;
    /** An invalid address-validation token. */
    public static final long INVALID_TOKEN = 0x0b;
    /** The application asked for the connection to close. */
    public static final long APPLICATION_ERROR = 0x0c;
    /** More CRYPTO data than could be buffered. */
    public static final long CRYPTO_BUFFER_EXCEEDED = 0x0d;
    /** A key update error. */
    public static final long KEY_UPDATE_ERROR = 0x0e;
    /** The AEAD confidentiality or integrity limit was reached. */
    public static final long AEAD_LIMIT_REACHED = 0x0f;
    /** No viable network path. */
    public static final long NO_VIABLE_PATH = 0x10;
    /** The base of the TLS alert range: {@code CRYPTO_ERROR + alert}. */
    public static final long CRYPTO_ERROR = 0x0100;

    private final long code;

    /**
     * A connection error.
     *
     * @param code the transport error code
     * @param reason the reason phrase, sent to the peer
     */
    public QuicException(long code, String reason) {
        super(reason);
        this.code = code;
    }

    /**
     * A TLS alert as a connection error.
     *
     * @param alert the TLS alert description, such as 40 ({@code handshake_failure})
     * @param reason the reason phrase
     * @return the error, with code {@code 0x0100 + alert}
     */
    public static QuicException tlsAlert(int alert, String reason) {
        return new QuicException(CRYPTO_ERROR + (alert & 0xff), reason);
    }

    /**
     * The transport error code.
     *
     * @return the code
     */
    public long code() {
        return code;
    }
}
