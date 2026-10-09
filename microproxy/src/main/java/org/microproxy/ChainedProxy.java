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
