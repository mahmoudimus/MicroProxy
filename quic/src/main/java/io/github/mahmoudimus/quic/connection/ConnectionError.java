/*
 * Ported from quinn-proto src/connection/mod.rs (ConnectionError) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.QuicException;
import java.util.Objects;

/**
 * Why a connection ended.
 *
 * @param kind what ended it
 * @param code the error code: a transport error code (RFC 9000 section 20) for {@link
 *     Kind#TRANSPORT_ERROR} and {@link Kind#CONNECTION_CLOSED}, an application code for {@link
 *     Kind#APPLICATION_CLOSED} and {@link Kind#LOCALLY_CLOSED}; 0 otherwise
 * @param frameType the frame type a transport error was about, or 0
 * @param reason the reason phrase, possibly empty
 */
public record ConnectionError(Kind kind, long code, long frameType, String reason) {

    /** What ended a connection. */
    public enum Kind {
        /** This endpoint detected a protocol error and closed the connection. */
        TRANSPORT_ERROR,
        /** The peer closed the connection with a transport error (CONNECTION_CLOSE 0x1c). */
        CONNECTION_CLOSED,
        /** The peer's application closed the connection (CONNECTION_CLOSE 0x1d). */
        APPLICATION_CLOSED,
        /** The local application closed the connection. */
        LOCALLY_CLOSED,
        /** The idle timeout expired. */
        TIMED_OUT,
        /** The peer sent a stateless reset. */
        RESET,
        /** The server supports none of the client's versions. */
        VERSION_MISMATCH
    }

    /**
     * The error.
     *
     * @param kind what ended the connection
     * @param code the error code
     * @param frameType the frame type, or 0
     * @param reason the reason phrase
     */
    public ConnectionError {
        Objects.requireNonNull(kind, "kind");
        reason = reason == null ? "" : reason;
    }

    /**
     * An error of a kind that has no code.
     *
     * @param kind the kind
     * @return the error
     */
    public static ConnectionError of(Kind kind) {
        return new ConnectionError(kind, 0, 0, "");
    }

    /**
     * A protocol error this endpoint detected.
     *
     * @param e the error
     * @return the error
     */
    public static ConnectionError transport(QuicException e) {
        long frameType = e instanceof io.github.mahmoudimus.quic.frame.FrameException f ? f.frameType() : 0;
        return new ConnectionError(Kind.TRANSPORT_ERROR, e.code(), frameType, e.getMessage());
    }

    @Override
    public String toString() {
        return switch (kind) {
            case TRANSPORT_ERROR -> "transport error 0x" + Long.toHexString(code) + ": " + reason;
            case CONNECTION_CLOSED -> "closed by peer: transport error 0x" + Long.toHexString(code)
                    + (reason.isEmpty() ? "" : ": " + reason);
            case APPLICATION_CLOSED -> "closed by peer: application code " + code + (reason.isEmpty() ? "" : ": " + reason);
            case LOCALLY_CLOSED -> "closed locally";
            case TIMED_OUT -> "timed out";
            case RESET -> "reset by peer";
            case VERSION_MISMATCH -> "peer supports none of our versions";
        };
    }
}
