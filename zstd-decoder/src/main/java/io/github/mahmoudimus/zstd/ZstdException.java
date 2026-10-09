package io.github.mahmoudimus.zstd;

import java.io.IOException;

/** The input is not valid Zstandard data, or needs more than the decoder is allowed to use. */
public class ZstdException extends IOException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates a decoder failure with a diagnostic message.
     *
     * @param message description of the invalid data or exceeded limit
     */
    public ZstdException(String message) {
        super(message);
    }

    /**
     * Creates a decoder failure caused by another exception.
     *
     * @param message description of the decoder failure
     * @param cause underlying failure
     */
    public ZstdException(String message, Throwable cause) {
        super(message, cause);
    }

    static ZstdException corrupt(String what) {
        return new ZstdException("corrupt zstd data: " + what);
    }
}
