package org.microproxy;

/**
 * When the proxy runs its TLS handshake with the server for a {@code CONNECT} it intercepts:
 * after answering the {@code CONNECT} and reading the client's ClientHello, or before answering.
 * A field of a {@link ProtocolPolicy} ({@link ProtocolPolicy#mitmServerHandshake()}), which a
 * request's filters can override ({@link HttpFilters#proxyToServerMitmHandshake()}). Either way,
 * a handshake that fails is one more failed attempt at its route: the next chained proxy (or the
 * direct fallback) the {@link ChainedProxyManager} offered is tried, after the {@link
 * RetryBackoff} wait, as when the connection itself fails.
 *
 * <p>Proxy authentication happens on the {@code CONNECT} in both: the choice is about what the
 * server's handshake can use and what the client sees when it fails.
 */
public enum MitmServerHandshake {
    /**
     * The {@code CONNECT} is answered once the proxy is connected to the server (or through a
     * chained proxy's tunnel), and the server's handshake waits for the client's ClientHello, so
     * that it can mirror it: the protocols the client offers by ALPN, and the server name it
     * sends when the {@code CONNECT} named an IP address. That ClientHello also decides whether
     * the session is intercepted at all (host rules, {@link MitmManager#shouldIntercept}, {@link
     * HttpFilters#proxyToServerAllowMitm(ClientHello)}), before any handshake with the server.
     * When every route's handshake fails, the client's handshake still completes, with the
     * proxy's certificate, and its first request in the session is answered {@code 502} for the
     * TLS failure ({@link ProxyFailure.TlsFailed}); a client whose handshake cannot complete is
     * disconnected. The default.
     */
    DEFERRED,
    /**
     * The proxy connects and runs the server's handshake before it answers the {@code CONNECT},
     * as LittleProxy does: its {@code ProxyToServerConnection.initializeConnectionFlow} runs the
     * server's {@code EncryptChannel} step before {@code RespondCONNECTSuccessful}, so that its
     * {@code MitmManager.clientSslEngineFor(HttpRequest, SSLSession)} has the server's session to
     * make the client's certificate from. The handshake sends the {@code CONNECT}'s host (or the
     * request's {@link TlsServerIdentity}) as SNI and offers the protocols the proxy would offer
     * on its own ({@code h2} and {@code http/1.1} with HTTP/2 to servers on), since the client's
     * ClientHello has not come yet: neither can be mirrored (a client that then offers only
     * HTTP/1.1 has its requests sent on a second connection that offers what it offered, when the
     * server chose HTTP/2 on the first). A server that speaks no TLS and never answers the
     * proxy's ClientHello holds the {@code CONNECT} until the TLS handshake timeout. When every
     * route's handshake fails,
     * the {@code CONNECT} itself is answered {@code 502} ({@link ProxyFailure.TlsFailed}), and no
     * tunnel opens. A session that the client's ClientHello then decides not to intercept (host
     * rules, the MITM manager, a filter) is tunnelled over a new connection, the one made for the
     * handshake being closed.
     */
    EAGER;

    /**
     * The value a configuration names: {@code deferred} or {@code eager} (any case).
     *
     * @param value the configuration value
     * @return the value it names
     * @throws IllegalArgumentException for any other value
     */
    public static MitmServerHandshake parse(String value) {
        return switch (ProtocolPolicy.token(value)) {
            case "deferred" -> DEFERRED;
            case "eager" -> EAGER;
            default -> throw new IllegalArgumentException("mitm_server_handshake must be deferred or eager: "
                    + value.strip());
        };
    }
}
