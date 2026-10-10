package org.microproxy;

import java.util.Objects;
import java.util.function.Function;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import org.microproxy.http.HttpRequest;

/**
 * Enables man-in-the-middle interception of CONNECT tunnels. The proxy opens its own TLS
 * connection to the server, then completes the client's handshake with a certificate supplied
 * here, and finally proxies the decrypted requests through the normal {@link HttpFilters}.
 *
 * <p>The proxy calls the overloads that take a {@link FlowContext}; by default they delegate to
 * the ones without it. Override them to decide per client connection (by its authenticated user,
 * {@link FlowContext#getClientDetails()}, or its address, {@link FlowContext#getClientAddress()})
 * which CA impersonates servers, how servers are validated, or which client certificate is
 * presented to them. To keep a separate manager per tenant instead, see {@link #perConnection}.
 *
 * <p>With {@link HttpProxyServerBootstrap#withPoolSharedMitmConnections}, a server connection made
 * for one client may serve another. A manager that overrides {@link #serverSslContext(String, int,
 * FlowContext)} or {@link #configureServerSocket(SSLSocket, FlowContext)} may make different
 * decisions for different clients, so its server connections are kept per client connection
 * rather than pooled; managers chosen by {@link #forConnection} only share pooled connections
 * with clients that were given the same manager.
 *
 * @see org.microproxy.tls.CertificateAuthorityMitmManager
 */
public interface MitmManager {

    /**
     * TLS configuration for the proxy's connection to the real server (proxy is TLS client).
     *
     * @param peerHost the real server host name
     * @param peerPort the real server port
     * @return the TLS context used towards the real server
     */
    SSLContext serverSslContext(String peerHost, int peerPort);

    /**
     * TLS configuration for the proxy's connection to the real server, for the client connection
     * {@code flow}: the trust store servers are validated against, and the key the proxy
     * authenticates with when a server asks for a client certificate. Defaults to {@link
     * #serverSslContext(String, int)}.
     *
     * @param flow a {@link FullFlowContext} naming the server and the chained proxy, if any
     *
     * @param peerHost the real server host name
     * @param peerPort the real server port
     * @return the TLS context used towards the real server
     */
    default SSLContext serverSslContext(String peerHost, int peerPort, FlowContext flow) {
        return serverSslContext(peerHost, peerPort);
    }

    /**
     * TLS configuration presented to the client (proxy is TLS server), typically holding a
     * certificate for the requested host signed by a CA the client trusts.
     *
     * @param connectRequest the client's CONNECT request
     * @param serverSslSession the established session with the real server
     *
     * @return the TLS context presented to the client
     */
    SSLContext clientSslContextFor(HttpRequest connectRequest, SSLSession serverSslSession);

    /**
     * TLS configuration presented to the client connection {@code flow}, e.g. with a certificate
     * from that client's CA. Defaults to {@link #clientSslContextFor(HttpRequest, SSLSession)}.
     *
     * @param serverSslSession the established session with the real server, or {@code null} when
     *     intercepting without one ({@link HttpFilters#proxyToServerAllowOfflineMitm})
     * @param flow the client connection's context
     *
     * @param connectRequest the CONNECT request naming the server
     * @return the TLS context presented to the client
     */
    default SSLContext clientSslContextFor(HttpRequest connectRequest, SSLSession serverSslSession, FlowContext flow) {
        return clientSslContextFor(connectRequest, serverSslSession);
    }

    /**
     * Customizes the socket to the real server before its handshake. By default the proxy enables
     * SNI and HTTPS host-name verification; override to relax that.
     *
     * @param socket the TLS socket to configure
     */
    default void configureServerSocket(SSLSocket socket) {}

    /**
     * Customizes the socket to the real server for the client connection {@code flow}. Defaults
     * to {@link #configureServerSocket(SSLSocket)}.
     *
     * @param flow a {@link FullFlowContext} naming the server and the chained proxy, if any
     *
     * @param socket the TLS socket to configure
     */
    default void configureServerSocket(SSLSocket socket, FlowContext flow) {
        configureServerSocket(socket);
    }

    /**
     * Whether to intercept a TLS connection, once its client's {@code ClientHello} is known: return
     * false to tunnel it untouched, so the client sees the real server's certificate. Decide by the
     * server name the client asked for ({@link ClientHello#sni()}), its ALPN protocols, or the
     * client ({@code flow}). Called on the manager chosen for the connection ({@link
     * #forConnection}), after the host rules ({@link HttpProxyServerBootstrap#withIgnoreHosts},
     * {@link HttpProxyServerBootstrap#withAllowHosts}) and before {@link
     * HttpFilters#proxyToServerAllowMitm(ClientHello)}. True by default.
     *
     * @param clientHello the client's ClientHello
     * @param flow the client connection's context; {@link FlowContext#getClientHello()} returns
     *     {@code clientHello}
     * @return whether to intercept the connection
     */
    default boolean shouldIntercept(ClientHello clientHello, FlowContext flow) {
        return true;
    }

    /**
     * The manager that intercepts for the client connection {@code flow}; this one by default.
     * The proxy asks once per client connection, when it is about to intercept the connection's
     * first CONNECT (after proxy authentication, so the user is known), and uses the answer for
     * every interception on that connection. {@code null} declines: the connection's CONNECTs are
     * tunnelled without interception.
     *
     * @param flow the client connection or exchange context
     * @return the manager to use for this client connection
     */
    default MitmManager forConnection(FlowContext flow) {
        return this;
    }

    /**
     * A manager that lets {@code choose} pick the manager for each client connection (see {@link
     * #forConnection}), e.g. a {@link org.microproxy.tls.CertificateAuthorityMitmManager} per
     * tenant with its own CA and upstream trust store. Return the same instance for clients that
     * may share pooled server connections; a {@code null} answer declines interception.
     *
     * <p>The returned manager only selects: its own methods throw {@link
     * UnsupportedOperationException}.
     *
     * @param choose the function selecting a manager for each client connection
     * @return the manager delegating selection to {@code choose}
     */
    static MitmManager perConnection(Function<? super FlowContext, ? extends MitmManager> choose) {
        Objects.requireNonNull(choose);
        return new MitmManager() {
            @Override
            public MitmManager forConnection(FlowContext flow) {
                return choose.apply(flow);
            }

            @Override
            public SSLContext serverSslContext(String peerHost, int peerPort) {
                throw new UnsupportedOperationException("chosen per connection: use forConnection");
            }

            @Override
            public SSLContext clientSslContextFor(HttpRequest connectRequest, SSLSession serverSslSession) {
                throw new UnsupportedOperationException("chosen per connection: use forConnection");
            }

            @Override
            public String toString() {
                return "MitmManager.perConnection(" + choose + ")";
            }
        };
    }
}
