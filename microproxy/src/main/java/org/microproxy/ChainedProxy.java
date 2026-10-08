package org.microproxy;

import java.net.InetSocketAddress;
import javax.net.ssl.SSLContext;
import org.microproxy.http.HttpObject;

/** An upstream proxy that requests are forwarded through. */
public interface ChainedProxy extends SslContextSource {

    InetSocketAddress getChainedProxyAddress();

    /** The local address to bind when connecting, or {@code null} for any. */
    default InetSocketAddress getLocalAddress() {
        return null;
    }

    default ChainedProxyType getChainedProxyType() {
        return ChainedProxyType.HTTP;
    }

    /** User name for upstream authentication (HTTP Basic or SOCKS), or {@code null}. */
    default String getUsername() {
        return null;
    }

    default String getPassword() {
        return null;
    }

    /** Whether the connection to the chained proxy itself uses TLS (see {@link #getSslContext}). */
    default boolean requiresEncryption() {
        return false;
    }

    @Override
    default SSLContext getSslContext() {
        return null;
    }

    /** Last chance to modify each request object before it is sent to this proxy. */
    default void filterRequest(HttpObject httpObject) {}

    default void connectionSucceeded() {}

    /** Called when connecting fails; the proxy then tries the next chained proxy, if any. */
    default void connectionFailed(Throwable cause) {}

    default void disconnected() {}
}
