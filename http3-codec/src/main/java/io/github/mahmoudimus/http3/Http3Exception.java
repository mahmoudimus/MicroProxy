package io.github.mahmoudimus.http3;

import java.io.IOException;
import java.util.Objects;

/**
 * A violation of HTTP/3 or QPACK by the peer (or a limit it exceeded), with the error code to send
 * back and the scope of the error (RFC 9114 §8).
 *
 * <ul>
 *   <li>A <em>connection error</em> ({@link #isConnectionError()}) leaves the connection unusable:
 *       close it with {@link #errorCode()} (a QUIC CONNECTION_CLOSE, after a GOAWAY if possible).
 *       The reader, encoder or decoder that threw it must not be used again.
 *   <li>A <em>stream error</em> affects only {@link #streamId()}: reset the stream and stop reading
 *       it with {@link #errorCode()}, and carry on with the connection.
 * </ul>
 *
 * <p>QUIC stream IDs start at 0, so a connection error has a {@link #streamId()} of -1. Any stream
 * error may be treated as a connection error by a caller that prefers to.
 */
public class Http3Exception extends IOException {

    private static final long serialVersionUID = 1L;

    /** The {@link #streamId()} of a connection error. */
    public static final long NO_STREAM = -1;

    /** The code to send. */
    private final Http3ErrorCode errorCode;
    /** The stream in error, or {@link #NO_STREAM}. */
    private final long streamId;

    /**
     * Creates an error; {@link #connectionError} and {@link #streamError} are the usual way.
     *
     * @param errorCode the code to send
     * @param streamId the stream in error, or {@link #NO_STREAM} for a connection error
     * @param message what went wrong
     */
    protected Http3Exception(Http3ErrorCode errorCode, long streamId, String message) {
        super(message);
        this.errorCode = Objects.requireNonNull(errorCode, "errorCode");
        this.streamId = streamId;
    }

    /**
     * An error that ends the connection.
     *
     * @param errorCode the code to close the connection with
     * @param message what went wrong
     * @return the exception
     */
    public static Http3Exception connectionError(Http3ErrorCode errorCode, String message) {
        return new Http3Exception(errorCode, NO_STREAM, message);
    }

    /**
     * An error that ends only the given stream.
     *
     * @param streamId the stream, 0 to 2^62-1
     * @param errorCode the code to reset the stream with
     * @param message what went wrong
     * @return the exception
     */
    public static Http3Exception streamError(long streamId, Http3ErrorCode errorCode, String message) {
        if (streamId < 0 || streamId > QuicVarInt.MAX_VALUE) {
            throw new IllegalArgumentException("a stream error needs a stream, got " + streamId);
        }
        return new Http3Exception(errorCode, streamId, message);
    }

    /**
     * The code to close the connection (connection error) or reset the stream (stream error) with.
     *
     * @return the error code
     */
    public Http3ErrorCode errorCode() {
        return errorCode;
    }

    /**
     * The stream in error, or {@link #NO_STREAM} for a connection error.
     *
     * @return the stream id, or -1
     */
    public long streamId() {
        return streamId;
    }

    /**
     * Whether the error ends the connection rather than one stream.
     *
     * @return whether this is a connection error
     */
    public boolean isConnectionError() {
        return streamId == NO_STREAM;
    }

    @Override
    public String getMessage() {
        String scope = isConnectionError() ? "connection error" : "stream " + streamId + " error";
        return scope + " " + errorCode + ": " + super.getMessage();
    }
}
