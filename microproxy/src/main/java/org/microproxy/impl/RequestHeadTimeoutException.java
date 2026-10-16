package org.microproxy.impl;

import java.net.SocketTimeoutException;

/** The client did not finish its HTTP/1 request head before its absolute deadline. */
@SuppressWarnings("serial")
final class RequestHeadTimeoutException extends SocketTimeoutException {

    RequestHeadTimeoutException() {
        super("HTTP/1 request head not complete before its deadline");
    }

    RequestHeadTimeoutException(Throwable cause) {
        this();
        initCause(cause);
    }
}
