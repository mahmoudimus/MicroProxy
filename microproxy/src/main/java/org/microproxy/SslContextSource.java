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

    /**
     * The certificate chain and private key this source presents as a TLS server, for listeners
     * whose TLS is not the JDK's {@link SSLContext}: the HTTP/3 listener ({@link
     * HttpProxyServerBootstrap#withHttp3}) runs the TLS 1.3 handshake inside QUIC itself, and
     * takes the certificate of the proxy's TLS listener from here. {@link
     * org.microproxy.tls.SelfSignedSslContextSource} and {@link
     * org.microproxy.tls.KeyStoreSslContextSource} provide it; the default provides none, which
     * leaves HTTP/3 off for this source.
     *
     * @param serverName the server name the client asked for (SNI), or null if it sent none
     * @return the chain and key to present, or null if this source has none
     */
    default KeyMaterial getKeyMaterial(String serverName) {
        return null;
    }
}
