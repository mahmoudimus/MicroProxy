package io.github.mahmoudimus.zstd;

import java.io.IOException;

/** The input is not valid Zstandard data, or needs more than the decoder is allowed to use. */
public class ZstdException extends IOException {

    private static final long serialVersionUID = 1L;

    public ZstdException(String message) {
        super(message);
    }

    public ZstdException(String message, Throwable cause) {
        super(message, cause);
    }

    static ZstdException corrupt(String what) {
        return new ZstdException("corrupt zstd data: " + what);
    }
}
