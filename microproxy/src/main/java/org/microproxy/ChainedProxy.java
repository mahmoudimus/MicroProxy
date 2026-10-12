package org.microproxy;

import java.net.InetSocketAddress;
import javax.net.ssl.SSLContext;
import org.microproxy.http.HttpObject;

/** An upstream proxy that requests are forwarded through. */
public interface ChainedProxy extends SslContextSource {

    /** {@return the upstream proxy address} */
    InetSocketAddress getChainedProxyAddress();

    /** {@return the local address to bind when connecting, or {@code null} for any} */
    default InetSocketAddress getLocalAddress() {
        return null;
    }

    /** {@return the protocol spoken by the upstream proxy} */
    default ChainedProxyType getChainedProxyType() {
        return ChainedProxyType.HTTP;
    }

    /** {@return user name for upstream authentication (HTTP Basic or SOCKS), or {@code null}} */
    default String getUsername() {
        return null;
    }

    /** {@return the upstream authentication password, or {@code null}} */
    default String getPassword() {
        return null;
    }

    /** {@return whether the connection to the chained proxy itself uses TLS (see {@link #getSslContext})} */
    default boolean requiresEncryption() {
        return false;
    }

    /**
     * Whether to speak HTTP/2 to this proxy (an {@link ChainedProxyType#HTTP} one) rather than
     * HTTP/1.1: its connections are then shared, each {@code CONNECT} tunnel and each plain-HTTP
     * request a stream of one (RFC 9113 section 8.5), up to the proxy's
     * SETTINGS_MAX_CONCURRENT_STREAMS, with another connection opened when they are full. Over TLS
     * ({@link #requiresEncryption()}) {@code h2} is offered with ALPN, next to {@code http/1.1},
     * which the proxy may choose instead; over plain TCP the proxy must speak HTTP/2 with prior
     * knowledge ({@code h2c}). The connections are shared by every client, and by every chained
     * proxy with the same address, TLS, {@link #getSslContext() SSLContext} instance, credentials
     * and local address. Needs the http2-codec module on the class path, without which the proxy
     * is reached over HTTP/1.1. The default is false.
     *
     * @return whether to speak HTTP/2 to this proxy
     */
    default boolean http2() {
        return false;
    }

    @Override
    default SSLContext getSslContext() {
        return null;
    }

    /**
     * Last chance to modify each request object before it is sent to this proxy.
     *
     * @param httpObject the request head or body piece
     */
    default void filterRequest(HttpObject httpObject) {}

    /**
     * Called when the upstream proxy connection succeeds.
     */
    default void connectionSucceeded() {}

    /**
     * Called when connecting fails; the proxy then tries the next chained proxy, if any.
     *
     * @param cause the failure that triggered this event
     */
    default void connectionFailed(Throwable cause) {}

    /**
     * Called when the upstream proxy connection closes.
     */
    default void disconnected() {}
}
