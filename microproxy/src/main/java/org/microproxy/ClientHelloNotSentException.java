package org.microproxy;

import java.io.IOException;
import java.net.SocketException;

/**
 * The proxy could not send its ClientHello to a server: the connection (to the server, or the
 * tunnel through a chained proxy) was reset, or failed otherwise, before the handshake's first
 * write. Its message is the cause's, the socket's own exception. It is in the cause chain of the
 * handshake's failure ({@link ProxyFailure.TlsFailed#cause()}), which {@link
 * ProxyFailure.TlsFailed.Reason#CLOSED_BEFORE_CLIENT_HELLO} names.
 */
public final class ClientHelloNotSentException extends SocketException {

    /**
     * The ClientHello could not be sent.
     *
     * @param cause the socket's exception, whose message this one keeps
     */
    public ClientHelloNotSentException(IOException cause) {
        super(cause.getMessage());
        initCause(cause);
    }
}
