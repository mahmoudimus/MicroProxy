package org.microproxy.impl;

import java.io.IOException;
import java.net.SocketException;

/**
 * The proxy could not send its ClientHello to a server: the connection (to the server, or the
 * tunnel through a chained proxy) was reset, or failed otherwise, before the handshake's first
 * write. Its message is the cause's, the socket's own exception. It is in the cause chain of the
 * handshake's failure ({@link org.microproxy.ProxyFailure.TlsFailed#cause()}), which {@link
 * org.microproxy.ProxyFailure.TlsFailed.Reason#CLOSED_BEFORE_CLIENT_HELLO} names.
 */
public final class ClientHelloNotSentException extends SocketException {

    ClientHelloNotSentException(IOException cause) {
        super(cause.getMessage());
        initCause(cause);
    }
}
