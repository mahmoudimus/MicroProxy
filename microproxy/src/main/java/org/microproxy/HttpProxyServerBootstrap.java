package org.microproxy;

import java.net.InetSocketAddress;
import java.time.Duration;
import org.microproxy.cache.HttpCache;

/** Configures and starts a {@link HttpProxyServer}. */
public interface HttpProxyServerBootstrap {

    /** Name used for thread names and logging. */
    HttpProxyServerBootstrap withName(String name);

    HttpProxyServerBootstrap withAddress(InetSocketAddress address);

    /** Port to listen on; 0 picks an ephemeral port. */
    HttpProxyServerBootstrap withPort(int port);

    /** Listen on the loopback interface only. */
    HttpProxyServerBootstrap withAllowLocalOnly(boolean allowLocalOnly);

    /** Serve the proxy itself over TLS (an "HTTPS proxy"). */
    HttpProxyServerBootstrap withSslContextSource(SslContextSource sslContextSource);

    /** Require client certificates on the proxy's TLS listener. */
    HttpProxyServerBootstrap withAuthenticateSslClients(boolean authenticateSslClients);

    /**
     * Requires clients to authenticate: with Basic credentials by default, or with any scheme
     * through {@link ProxyAuthenticator#authenticate(org.microproxy.http.HttpRequest, FlowContext)}.
     */
    HttpProxyServerBootstrap withProxyAuthenticator(ProxyAuthenticator proxyAuthenticator);

    HttpProxyServerBootstrap withChainProxyManager(ChainedProxyManager chainProxyManager);

    /** The chained proxy manager configured so far, or {@code null}; lets extensions wrap it. */
    default ChainedProxyManager getChainProxyManager() {
        return null;
    }

    /**
     * Intercepts CONNECT tunnels with {@code mitmManager}. To decide per client connection (per
     * user, client address, ...), override its {@link FlowContext} overloads or use {@link
     * MitmManager#perConnection}.
     */
    HttpProxyServerBootstrap withManInTheMiddle(MitmManager mitmManager);

    HttpProxyServerBootstrap withFiltersSource(HttpFiltersSource filtersSource);

    /**
     * Adds a filters source after those already configured; they run as a {@link
     * HttpFiltersChain}.
     */
    HttpProxyServerBootstrap plusFiltersSource(HttpFiltersSource filtersSource);

    /** The filters source configured so far (never null). */
    HttpFiltersSource getFiltersSource();

    /**
     * Caches responses ({@link org.microproxy.cache.HttpCache}). The cache always runs after the
     * filters sources, whichever order they were configured in.
     */
    HttpProxyServerBootstrap withHttpCache(HttpCache cache);

    /**
     * Makes the proxy's own answers when requests fail (see {@link ProxyFailure}): unreachable or
     * misbehaving servers, timeouts, an exhausted connection pool, refused requests. Filters'
     * {@link HttpFilters#proxyToServerFailure} answers take precedence; {@code null} (the
     * default) or a responder returning {@code null} keeps the proxy's plain-text answers.
     */
    HttpProxyServerBootstrap withFailureResponder(FailureResponder responder);

    /** Forward messages without adding {@code Via} or stripping hop-by-hop headers. */
    HttpProxyServerBootstrap withTransparent(boolean transparent);

    HttpProxyServerBootstrap withIdleConnectionTimeout(int idleConnectionTimeoutInSeconds);

    HttpProxyServerBootstrap withIdleConnectionTimeout(Duration idleConnectionTimeout);

    /** Connect timeout for outbound connections in milliseconds. */
    HttpProxyServerBootstrap withConnectTimeout(int connectTimeoutMs);

    /**
     * The longest a TLS handshake may take, with clients and with servers (default 10 seconds;
     * zero for no limit). The idle timeout alone does not bound it, since it restarts with every
     * byte received.
     */
    HttpProxyServerBootstrap withTlsHandshakeTimeout(Duration timeout);

    /**
     * The TLS versions allowed on every TLS socket the proxy creates: its TLS listener ({@link
     * #withSslContextSource}), both sides of an intercepted session, and connections to TLS chained
     * proxies. Default {@code TLSv1.3} and {@code TLSv1.2}. Each socket enables those of them that
     * its {@link javax.net.ssl.SSLContext} supports; if it supports none, the handshake fails with
     * an error naming both lists. The protocols are set right after the socket is created, before
     * {@link SslContextSource#configure}, {@link MitmManager#configureServerSocket(javax.net.ssl.SSLSocket,
     * FlowContext)} or {@link ChainedProxy#configure} run, so a hook that sets its own protocols
     * wins. No protocols leaves every context's own defaults; the JDK's {@code
     * jdk.tls.disabledAlgorithms} applies either way.
     */
    default HttpProxyServerBootstrap withTlsProtocols(String... protocols) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support TLS protocol pinning");
    }

    /**
     * Behaves like LittleProxy where MicroProxy deliberately differs, for filters that depend on
     * it:
     *
     * <ul>
     *   <li>The server is resolved before {@link HttpFilters#proxyToServerRequest} rather than
     *       after it; a name that does not resolve gets {@code 502} without that hook being called.
     *   <li>A PROXY header sent without one received ({@link #withSendProxyProtocol}) names the
     *       server connection's remote address as its destination, not the address the client
     *       connected to; and none is sent when the client and that address are of different
     *       address families.
     * </ul>
     *
     * <p>Security fixes (strict request parsing, error pages that do not echo the request) are not
     * affected. Off by default.
     */
    HttpProxyServerBootstrap withLittleProxyCompatibility(boolean compatible);

    /** Same as {@code withLittleProxyCompatibility(true)}. */
    default HttpProxyServerBootstrap withLittleProxyCompatibility() {
        return withLittleProxyCompatibility(true);
    }

    HttpProxyServerBootstrap withServerResolver(HostResolver serverResolver);

    /**
     * Removes these headers (case-insensitively) from every request right before it is written
     * upstream: after all filters, so headers that filters added are removed too. It applies to
     * plain requests, requests inside intercepted (MITM) sessions, upgrade requests, and the
     * {@code CONNECT} requests sent to HTTP chained proxies; the bytes of an uninspected tunnel
     * are never touched. Replaces the names set so far; no names turns it off.
     */
    default HttpProxyServerBootstrap withStrippedRequestHeaders(String... names) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support stripping headers");
    }

    /** Adds to the headers removed from requests sent upstream (see {@link #withStrippedRequestHeaders}). */
    default HttpProxyServerBootstrap plusStrippedRequestHeaders(String... names) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support stripping headers");
    }

    /**
     * Removes distributed tracing headers ({@link org.microproxy.http.HttpHeaderNames#TRACING_HEADERS}:
     * {@code traceparent}, {@code tracestate}, {@code baggage}, the B3 headers, {@code uber-trace-id},
     * {@code X-Amzn-Trace-Id}, {@code X-Cloud-Trace-Context}, {@code grpc-trace-bin}, {@code
     * sentry-trace}) from requests sent upstream, so clients' trace
     * ids and baggage do not leak to servers. Adds to {@link #plusStrippedRequestHeaders}.
     */
    default HttpProxyServerBootstrap withoutTracingHeadersUpstream() {
        return plusStrippedRequestHeaders(org.microproxy.http.HttpHeaderNames.TRACING_HEADERS.toArray(String[]::new));
    }

    /**
     * Waits between attempts when a connection through one chained proxy (or the direct
     * fallback) fails and the next candidate from the {@link ChainedProxyManager} is tried. Before
     * attempt {@code n + 1} the proxy sleeps a random time between zero and {@code initial *
     * 2^(n-1)}, capped at {@code max} ("full jitter"). It never sleeps before the first attempt or
     * after the last, stops waiting (and gives up on the request) when the client disconnects
     * meanwhile, and sleeps at most 30 seconds or the connect timeout in total per request,
     * whichever is less; once that is spent, the remaining candidates are tried without waiting.
     * The wait counts towards the connect phase of {@link FlowContext#timings()}. Off by default;
     * {@code null} turns it off again.
     */
    default HttpProxyServerBootstrap withChainedProxyRetryBackoff(Duration initial, Duration max) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support retry backoff");
    }

    HttpProxyServerBootstrap plusActivityTracker(ActivityTracker activityTracker);

    /** Global bandwidth limits for server traffic; 0 means unlimited. */
    HttpProxyServerBootstrap withThrottling(
            long readThrottleBytesPerSecond, long writeThrottleBytesPerSecond);

    /** Local address to bind for outbound connections. */
    HttpProxyServerBootstrap withNetworkInterface(InetSocketAddress inetSocketAddress);

    HttpProxyServerBootstrap withMaxInitialLineLength(int maxInitialLineLength);

    HttpProxyServerBootstrap withMaxHeaderSize(int maxHeaderSize);

    /** Largest body piece handed to filters when streaming. */
    HttpProxyServerBootstrap withMaxChunkSize(int maxChunkSize);

    /** Accept origin-form requests ({@code GET /path}) as if the proxy were the origin. */
    HttpProxyServerBootstrap withAllowRequestToOriginServer(boolean allowRequestToOriginServer);

    /** Name used in the {@code Via} header; defaults to the host name. */
    HttpProxyServerBootstrap withProxyAlias(String alias);

    /** Require a PROXY protocol (v1 or v2) header on every inbound connection. */
    HttpProxyServerBootstrap withAcceptProxyProtocol(boolean acceptProxyProtocol);

    /**
     * Send a PROXY protocol v1 header to the final server: first on a direct connection, or
     * through the tunnel once an HTTP chained proxy has accepted the CONNECT. It is not sent where
     * there is no tunnel to the final server: through SOCKS chained proxies, or with plain
     * requests forwarded to an HTTP chained proxy. Server connections that carry the header belong
     * to one client, so the shared server connection pool is not used while this is on.
     */
    HttpProxyServerBootstrap withSendProxyProtocol(boolean sendProxyProtocol);

    /**
     * Largest WebSocket frame payload buffered for {@link
     * HttpFilters#webSocketFrameReceived(org.microproxy.http.WebSocketFrame, boolean)}; larger
     * frames are streamed and reported as truncated. Default 1 MiB.
     */
    HttpProxyServerBootstrap withMaxWebSocketFrameBufferSize(int maxBytes);

    /**
     * Shares server connections between all clients instead of keeping them per client
     * connection. A connection is leased for one exchange and returned to the pool when the
     * response completes with keep-alive. Disabled by default.
     */
    HttpProxyServerBootstrap withSharedServerConnectionPool(boolean useSharedServerConnectionPool);

    HttpProxyServerBootstrap withServerConnectionPoolType(ServerConnectionPoolType poolType);

    /** Pooled connections per target ({@code host:port}); default 10. */
    HttpProxyServerBootstrap withMaxConnectionsPerHost(int maxConnectionsPerHost);

    /**
     * Pooled connections in total; default 200. When the limit is reached, requests wait up to the
     * connect timeout for a connection and then get {@code 503}.
     */
    HttpProxyServerBootstrap withMaxConnections(int maxConnections);

    /** Closes pooled connections idle for longer than this; {@code null} keeps them. */
    HttpProxyServerBootstrap withPoolIdleTimeout(Duration idleTimeout);

    /**
     * Lets intercepted (MITM) sessions take their server connection from the pool and return it
     * when the client disconnects, so other clients can reuse it. Requires the shared pool.
     * Connections are only shared by clients given the same {@link MitmManager#forConnection
     * manager}, and not at all when the manager sets up server connections per client (see {@link
     * MitmManager}).
     */
    HttpProxyServerBootstrap withPoolSharedMitmConnections(boolean poolSharedMitmConnections);

    /**
     * With {@link #withPoolSharedMitmConnections}, leases the server connection per intercepted
     * request rather than per session.
     */
    HttpProxyServerBootstrap withPoolPerRequestInMitm(boolean poolPerRequestInMitm);

    /**
     * Resolves server names with the validating DNSSEC resolver ({@link
     * org.microproxy.dns.DnssecHostResolver}) instead of the system resolver.
     */
    HttpProxyServerBootstrap withUseDnsSec(boolean useDnsSec);

    HttpProxyServer start();
}
