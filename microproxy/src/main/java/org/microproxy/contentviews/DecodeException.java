package org.microproxy.contentviews;

/**
 * Data that a decoder or {@link ContentView} cannot make sense of: malformed protobuf, a
 * truncated gRPC frame, an unknown compression, invalid msgpack, JSON or multipart data. It is
 * the only exception decoders throw for bad input; any other exception is a bug.
 */
public final class DecodeException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Creates an exception describing what was wrong with the data.
     *
     * @param message what could not be decoded, and why
     */
    public DecodeException(String message) {
        super(message);
    }

    /**
     * Creates an exception describing what was wrong with the data, caused by {@code cause}.
     *
     * @param message what could not be decoded, and why
     * @param cause the underlying failure, such as a corrupt compressed stream
     */
    public DecodeException(String message, Throwable cause) {
        super(message, cause);
    }
}
