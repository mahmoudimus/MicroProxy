package org.microproxy;

/** The protocol spoken to an upstream (chained) proxy. */
public enum ChainedProxyType {
    /** HTTP CONNECT upstream proxy, over HTTP/1.1 or (with {@link ChainedProxy#http2()}) HTTP/2. */
    HTTP,
    /** SOCKS version 4 upstream proxy. */
    SOCKS4,
    /** SOCKS version 5 upstream proxy. */
    SOCKS5
}
