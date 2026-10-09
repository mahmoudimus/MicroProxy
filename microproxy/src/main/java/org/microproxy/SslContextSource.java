package org.microproxy;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/** Supplies TLS configuration for one side of a connection. */
public interface SslContextSource {

    /** {@return the TLS context for this connection} */
    SSLContext getSslContext();

    /**
     * Customizes a socket created from {@link #getSslContext()} before its handshake (protocols,
     * cipher suites, client authentication, ...). The default does nothing.
     *
     * @param clientMode whether the proxy acts as the TLS client on this socket
     *
     * @param socket the TLS socket to configure
     */
    default void configure(SSLSocket socket, boolean clientMode) {}
}
