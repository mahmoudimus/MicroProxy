package io.github.mahmoudimus.http2;

import java.io.IOException;
import java.util.Objects;

/**
 * A violation of HTTP/2 or HPACK by the peer (or a limit it exceeded), with the error code to send
 * back and the scope of the error (RFC 9113 §5.4).
 *
 * <ul>
 *   <li>A <em>connection error</em> ({@link #isConnectionError()}) leaves the connection unusable:
 *       send GOAWAY with {@link #errorCode()} and close it. The reader that threw it must not be
 *       used again.
 *   <li>A <em>stream error</em> affects only {@link #streamId()}: send RST_STREAM with
 *       {@link #errorCode()} and carry on. When a {@link FrameReader} throws one it has consumed the
 *       whole offending frame, so reading can continue.
 * </ul>
 *
 * <p>Any stream error may be treated as a connection error by a caller that prefers to.
 */
public class Http2Exception extends IOException {

    private static final long serialVersionUID = 1L;

    /**
     * The error code to report to the peer.
     */
    private final ErrorCode errorCode;
    /**
     * The affected stream identifier, or 0 for the connection.
     */
    private final int streamId;
    /**
     * Whether the error invalidates the entire connection.
     */
    private final boolean connectionError;

    /**
     * Creates an error with an explicit protocol scope.
     *
     * @param errorCode the non-null code to report to the peer
     * @param message the diagnostic message
     * @param streamId the affected stream identifier, or 0 for the connection
     * @param connectionError whether the entire connection is unusable
     */
    protected Http2Exception(ErrorCode errorCode, int streamId, boolean connectionError, String message) {
        super(message);
        this.errorCode = Objects.requireNonNull(errorCode, "errorCode");
        this.streamId = streamId;
        this.connectionError = connectionError;
    }

    /**
     * An error that ends the connection.
     *
     * @param errorCode the non-null code to report to the peer
     * @param message the diagnostic message
     * @return a connection-scoped exception
     */
    public static Http2Exception connectionError(ErrorCode errorCode, String message) {
        return new Http2Exception(errorCode, 0, true, message);
    }

    /**
     * An error that ends only the given stream.
     *
     * @param streamId the positive identifier of the affected stream
     * @param errorCode the non-null code to report to the peer
     * @param message the diagnostic message
     * @return a stream-scoped exception
     */
    public static Http2Exception streamError(int streamId, ErrorCode errorCode, String message) {
        if (streamId <= 0) {
            throw new IllegalArgumentException("a stream error needs a stream, got " + streamId);
        }
        return new Http2Exception(errorCode, streamId, false, message);
    }

    /**
     * The code to send in GOAWAY (connection error) or RST_STREAM (stream error).
     *
     * @return the code to report to the peer
     */
    public ErrorCode errorCode() {
        return errorCode;
    }

    /**
     * The stream in error, or 0 for a connection error.
     *
     * @return the affected stream identifier, or 0 for a connection error
     */
    public int streamId() {
        return streamId;
    }

    /**
     * Reports whether the connection must be closed.
     *
     * @return true for a connection error, false for a stream error
     */
    public boolean isConnectionError() {
        return connectionError;
    }

    @Override
    public String getMessage() {
        String scope = connectionError ? "connection error" : "stream " + streamId + " error";
        return scope + " " + errorCode + ": " + super.getMessage();
    }
}
