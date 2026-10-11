/*
 * Ported from quinn-proto src/connection/streams/mod.rs, send.rs and recv.rs (ClosedStream,
 * WriteError, FinishError, ReadError, ReadableError) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.io.Serial;

/**
 * An application-level stream operation that cannot proceed. These are not connection errors:
 * the connection stays open. {@link Kind#BLOCKED} is routine flow control, so the exception has no
 * stack trace.
 */
public final class StreamException extends Exception {

    @Serial
    private static final long serialVersionUID = 1L;

    /** Why the operation failed. */
    public enum Kind {
        /**
         * No progress is possible now: a write is limited by flow control or the send window, or a
         * read found no data. A later {@link StreamEvent.Writable} or {@link StreamEvent.Readable}
         * says when to retry.
         */
        BLOCKED,
        /** The peer sent STOP_SENDING; {@link #errorCode()} is its error code. */
        STOPPED,
        /** The peer reset the stream with RESET_STREAM; {@link #errorCode()} is its error code. */
        RESET,
        /** The stream was never opened, or was already finished, reset, stopped or released. */
        CLOSED_STREAM,
        /** An ordered read was attempted after an unordered one. */
        ILLEGAL_ORDERED_READ
    }

    /** Why the operation failed. */
    private final Kind kind;
    /** The peer's application error code, or -1. */
    private final long errorCode;

    /**
     * An exception.
     *
     * @param kind why the operation failed
     * @param errorCode the peer's application error code for {@link Kind#STOPPED} and {@link
     *     Kind#RESET}, otherwise -1
     */
    public StreamException(Kind kind, long errorCode) {
        super(message(kind, errorCode), null, false, false);
        this.kind = kind;
        this.errorCode = errorCode;
    }

    /**
     * An exception without an error code.
     *
     * @param kind why the operation failed
     */
    public StreamException(Kind kind) {
        this(kind, -1);
    }

    /**
     * Why the operation failed.
     *
     * @return the kind
     */
    public Kind kind() {
        return kind;
    }

    /**
     * The peer's application error code.
     *
     * @return the code for {@link Kind#STOPPED} and {@link Kind#RESET}, otherwise -1
     */
    public long errorCode() {
        return errorCode;
    }

    private static String message(Kind kind, long errorCode) {
        return switch (kind) {
            case BLOCKED -> "blocked";
            case STOPPED -> "stopped by peer: code " + errorCode;
            case RESET -> "reset by peer: code " + errorCode;
            case CLOSED_STREAM -> "closed stream";
            case ILLEGAL_ORDERED_READ -> "ordered read after unordered read";
        };
    }
}
