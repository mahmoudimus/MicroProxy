package org.microproxy.impl;

import java.io.IOException;
import org.microproxy.http.HttpResponseStatus;

/** A malformed or oversized HTTP message. Carries the status to answer the peer with. */
final class HttpParseException extends IOException {

    private final HttpResponseStatus status;

    HttpParseException(HttpResponseStatus status, String message) {
        super(message);
        this.status = status;
    }

    HttpParseException(String message) {
        this(HttpResponseStatus.BAD_REQUEST, message);
    }

    HttpResponseStatus status() {
        return status;
    }
}
