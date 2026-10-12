/*
 * Ported from quinn-proto src/frame.rs (InvalidFrame and its conversion to TransportError)
 * (Apache-2.0).
 */
package io.github.mahmoudimus.quic.frame;

import io.github.mahmoudimus.quic.QuicException;
import java.io.Serial;

/**
 * A connection error caused by a received frame, carrying the frame type for the Frame Type field
 * of the CONNECTION_CLOSE frame that reports it (RFC 9000 section 19.19).
 */
public final class FrameException extends QuicException {

    @Serial
    private static final long serialVersionUID = 1L;

    /** The type code of the offending frame, or 0. */
    private final long frameType;

    /**
     * A frame error.
     *
     * @param code the transport error code, such as {@code FRAME_ENCODING_ERROR}
     * @param frameType the type code of the offending frame, or 0 if it could not be read
     * @param reason the reason phrase
     */
    public FrameException(long code, long frameType, String reason) {
        super(code, reason);
        this.frameType = frameType;
    }

    /**
     * The type code of the frame that caused the error.
     *
     * @return the frame type, or 0 if it could not be read
     */
    public long frameType() {
        return frameType;
    }
}
