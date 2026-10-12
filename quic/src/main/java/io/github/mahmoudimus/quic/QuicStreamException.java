package io.github.mahmoudimus.quic;

import java.io.IOException;
import java.io.Serial;

/**
 * A stream operation failed because the peer abandoned the stream: it reset the stream (RESET_STREAM,
 * seen by a reader) or asked this side to stop sending (STOP_SENDING, seen by a writer).
 */
public class QuicStreamException extends IOException {

    @Serial
    private static final long serialVersionUID = 1L;

    /** How the peer abandoned the stream. */
    public enum Kind {
        /** The peer reset its sending side; the data that was not read is lost. */
        RESET,
        /** The peer asked this side to stop sending. */
        STOPPED
    }

    /** How the peer abandoned the stream. */
    private final Kind kind;
    /** The peer's application error code. */
    private final long errorCode;

    /**
     * An exception.
     *
     * @param kind how the peer abandoned the stream
     * @param errorCode the peer's application error code
     */
    public QuicStreamException(Kind kind, long errorCode) {
        super((kind == Kind.RESET ? "stream reset by peer" : "stream stopped by peer") + ": code " + errorCode);
        this.kind = kind;
        this.errorCode = errorCode;
    }

    /**
     * How the peer abandoned the stream.
     *
     * @return the kind
     */
    public Kind kind() {
        return kind;
    }

    /**
     * The peer's application error code.
     *
     * @return the code
     */
    public long errorCode() {
        return errorCode;
    }
}
