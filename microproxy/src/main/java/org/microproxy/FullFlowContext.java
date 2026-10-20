package org.microproxy;

import java.net.InetSocketAddress;
import java.util.Objects;
import java.util.function.Supplier;
import javax.net.ssl.SSLSession;

/** A {@link FlowContext} that also knows the server side of the flow. */
public class FullFlowContext extends FlowContext {

    private final FlowContext clientContext;
    private final String serverHostAndPort;
    private final ChainedProxy chainedProxy;
    private final InetSocketAddress remoteAddress;
    private final Supplier<SSLSession> serverSslSession;

    /**
     * Creates a server-side view of a client exchange.
     *
     * @param clientContext the client connection or exchange context
     * @param serverHostAndPort the requested server host and port
     * @param chainedProxy the upstream proxy in use, or {@code null} for direct routing
     * @param remoteAddress the connected server or upstream proxy address
     */
    public FullFlowContext(
            FlowContext clientContext,
            String serverHostAndPort,
            ChainedProxy chainedProxy,
            InetSocketAddress remoteAddress) {
        this(clientContext, serverHostAndPort, chainedProxy, remoteAddress, () -> null);
    }

    /**
     * Creates a server-side view of a client exchange that knows the TLS session with the server.
     *
     * @param clientContext the client connection or exchange context
     * @param serverHostAndPort the requested server host and port
     * @param chainedProxy the upstream proxy in use, or {@code null} for direct routing
     * @param remoteAddress the connected server or upstream proxy address
     * @param serverSslSession the supplier of the TLS session with the server, which may return
     *     {@code null}; asked each time, so it follows the connection in use
     */
    public FullFlowContext(
            FlowContext clientContext,
            String serverHostAndPort,
            ChainedProxy chainedProxy,
            InetSocketAddress remoteAddress,
            Supplier<SSLSession> serverSslSession) {
        super(clientContext);
        this.clientContext = clientContext;
        this.serverHostAndPort = serverHostAndPort;
        this.chainedProxy = chainedProxy;
        this.remoteAddress = remoteAddress;
        this.serverSslSession = Objects.requireNonNull(serverSslSession);
    }

    /** {@return the client-side context this server-side view was made from} */
    public FlowContext getClientContext() {
        return clientContext;
    }

    /** {@return the {@code host:port} the client asked for} */
    public String getServerHostAndPort() {
        return serverHostAndPort;
    }

    /** {@return the upstream proxy in use, or {@code null} for a direct connection} */
    public ChainedProxy getChainedProxy() {
        return chainedProxy;
    }

    /** {@return the address the proxy is connected to: the server, or the chained proxy} */
    public InetSocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    /**
     * The TLS session with the server this flow's requests go to, end to end: with the origin
     * server, whether the proxy intercepts the client's TLS or opens its own TLS connection to the
     * server, and through a TLS chained proxy the session with the server inside the tunnel, not
     * the one with the chained proxy. It is the session of the connection the requests are sent on
     * (a reused pooled connection's, or the one a retry without SNI made), and an HTTP/2 stream's
     * is its connection's. It is already established in {@link
     * ActivityTracker#requestSentToServer}.
     *
     * <p>HTTP/3 (QUIC) flows have no {@link SSLSession}: this is {@code null} for them.
     *
     * @return the TLS session with the server this flow's requests go to, or {@code null} when the
     *     connection to it is not TLS (plain HTTP, a tunnel the proxy does not intercept) or its
     *     handshake has not completed
     */
    public SSLSession getServerSslSession() {
        return serverSslSession.get();
    }
}
