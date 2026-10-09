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

    private final ErrorCode errorCode;
    private final int streamId;
    private final boolean connectionError;

    protected Http2Exception(ErrorCode errorCode, int streamId, boolean connectionError, String message) {
        super(message);
        this.errorCode = Objects.requireNonNull(errorCode, "errorCode");
        this.streamId = streamId;
        this.connectionError = connectionError;
    }

    /** An error that ends the connection. */
    public static Http2Exception connectionError(ErrorCode errorCode, String message) {
        return new Http2Exception(errorCode, 0, true, message);
    }

    /** An error that ends only the given stream. */
    public static Http2Exception streamError(int streamId, ErrorCode errorCode, String message) {
        if (streamId <= 0) {
            throw new IllegalArgumentException("a stream error needs a stream, got " + streamId);
        }
        return new Http2Exception(errorCode, streamId, false, message);
    }

    /** The code to send in GOAWAY (connection error) or RST_STREAM (stream error). */
    public ErrorCode errorCode() {
        return errorCode;
    }

    /** The stream in error, or 0 for a connection error. */
    public int streamId() {
        return streamId;
    }

    public boolean isConnectionError() {
        return connectionError;
    }

    @Override
    public String getMessage() {
        String scope = connectionError ? "connection error" : "stream " + streamId + " error";
        return scope + " " + errorCode + ": " + super.getMessage();
    }
}
