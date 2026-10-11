package org.microproxy;

import java.net.InetSocketAddress;
import java.time.Duration;
import org.microproxy.cache.HttpCache;
import org.microproxy.frames.FrameInterceptor;
import org.microproxy.quic.QuicFraming;
import org.microproxy.quic.QuicInterceptor;
import org.microproxy.tcp.TcpInterceptor;
import org.microproxy.udp.UdpInterceptor;

/** Configures and starts a {@link HttpProxyServer}. */
public interface HttpProxyServerBootstrap {

    /**
     * Name used for thread names and logging.
     *
     * @param name the name used for logging and thread names
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withName(String name);

    /**
     * Sets the proxy listener address.
     *
     * @param address the proxy listener address
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withAddress(InetSocketAddress address);

    /**
     * Port to listen on; 0 picks an ephemeral port.
     *
     * @param port the listening port, or zero for an ephemeral port
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withPort(int port);

    /**
     * Listen on the loopback interface only.
     *
     * @param allowLocalOnly whether to listen only on the loopback interface
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withAllowLocalOnly(boolean allowLocalOnly);

    /**
     * Serve the proxy itself over TLS (an "HTTPS proxy").
     *
     * @param sslContextSource the TLS context provider for the proxy listener
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withSslContextSource(SslContextSource sslContextSource);

    /**
     * Require client certificates on the proxy's TLS listener.
     *
     * @param authenticateSslClients whether the TLS listener requires client certificates
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withAuthenticateSslClients(boolean authenticateSslClients);

    /**
     * Requires clients to authenticate: with Basic credentials by default, or with any scheme
     * through {@link ProxyAuthenticator#authenticate(org.microproxy.http.HttpRequest, FlowContext)}.
     *
     * @param proxyAuthenticator the client authentication policy
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withProxyAuthenticator(ProxyAuthenticator proxyAuthenticator);

    /**
     * Sets the manager selecting upstream proxies.
     *
     * @param chainProxyManager the manager selecting upstream proxies
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withChainProxyManager(ChainedProxyManager chainProxyManager);

    /**
     * The chained proxy manager configured so far, or {@code null}; lets extensions wrap it.
     *
     * @return the configured chained proxy manager, or {@code null}
     */
    default ChainedProxyManager getChainProxyManager() {
        return null;
    }

    /**
     * Intercepts CONNECT tunnels with {@code mitmManager}. To decide per client connection (per
     * user, client address, ...), override its {@link FlowContext} overloads or use {@link
     * MitmManager#perConnection}.
     *
     * @param mitmManager the manager providing interception TLS contexts
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withManInTheMiddle(MitmManager mitmManager);

    /**
     * Sets the source of per-request filters.
     *
     * @param filtersSource the source of per-request filters
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withFiltersSource(HttpFiltersSource filtersSource);

    /**
     * Adds a filters source after those already configured; they run as a {@link
     * HttpFiltersChain}.
     *
     * @param filtersSource the source of per-request filters
     * @return this bootstrap
     */
    HttpProxyServerBootstrap plusFiltersSource(HttpFiltersSource filtersSource);

    /** {@return the filters source configured so far (never null)} */
    HttpFiltersSource getFiltersSource();

    /**
     * Caches responses ({@link org.microproxy.cache.HttpCache}). The cache always runs after the
     * filters sources, whichever order they were configured in.
     *
     * @param cache the HTTP cache to use
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withHttpCache(HttpCache cache);

    /**
     * Makes the proxy's own answers when requests fail (see {@link ProxyFailure}): unreachable or
     * misbehaving servers, timeouts, an exhausted connection pool, refused requests. Filters'
     * {@link HttpFilters#proxyToServerFailure} answers take precedence; {@code null} (the
     * default) or a responder returning {@code null} keeps the proxy's plain-text answers.
     *
     * @param responder the function creating a rejection or failure response
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withFailureResponder(FailureResponder responder);

    /**
     * Transparent proxying: forward messages without adding {@code Via} or stripping hop-by-hop
     * headers, and accept TLS connections that arrive without a {@code CONNECT}, such as ones a
     * firewall redirects to the proxy. Such a connection is routed by its {@code ClientHello}'s
     * server name (SNI) to that host's port 443 (see {@link #withTransparentTlsPort}), and is
     * intercepted or tunnelled as a {@code CONNECT} to that host would be. Java cannot read a
     * redirected connection's original destination address, so a ClientHello without SNI cannot
     * be routed: the connection is refused with a TLS {@code unrecognized_name} alert. Plain HTTP
     * is routed by its {@code Host} field when {@link #withAllowRequestToOriginServer} allows
     * origin-form requests.
     *
     * @param transparent whether to proxy transparently
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withTransparent(boolean transparent);

    /**
     * The port that TLS connections arriving without a {@code CONNECT} in {@linkplain
     * #withTransparent transparent} mode are routed to, on the host their SNI names (default 443).
     *
     * @param port the server port, 1 to 65535
     * @return this bootstrap
     * @throws IllegalArgumentException if the port is out of range
     */
    default HttpProxyServerBootstrap withTransparentTlsPort(int port) {
        if (port == 443) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support transparent TLS");
    }

    /**
     * Opens a transparent QUIC listener on UDP {@code port} (0 for any): the UDP counterpart of
     * {@linkplain #withTransparent transparent} TLS, for QUIC (HTTP/3, UDP 443) that a firewall
     * redirects to the proxy, such as {@code iptables -t nat -A PREROUTING -p udp --dport 443 -j
     * REDIRECT --to-ports <port>}. Needs transparent mode and the optional {@code quic} and {@code
     * http3-codec} modules.
     *
     * <p>Java cannot read a redirected datagram's original destination either, so each new client
     * flow (a client address and the Destination Connection ID of its Initial packets) is routed by
     * the SNI of the ClientHello in its Initial packets, which the proxy decrypts, to that host's
     * {@linkplain #withTransparentTlsPort transparent TLS port}. The rules and hooks that decide on
     * TLS decide on it too: {@linkplain #withIgnoreHosts ignored} and {@linkplain #withAllowHosts
     * allowed} hosts, {@link HttpFilters#proxyToServerAllowMitm()} and {@link
     * HttpFilters#proxyToServerAllowMitm(ClientHello)} on a {@code CONNECT} the proxy makes up, and
     * {@link MitmManager#shouldIntercept}. An intercepted client offering ALPN {@code h3} gets a
     * certificate the {@link org.microproxy.tls.CertificateAuthorityMitmManager} issues for its SNI
     * and is served HTTP/3 like any client, with its requests going to that host (over HTTP/3 with
     * {@link #withHttp3Upstream}, else over TCP). Everything else (no MITM manager, a declined or
     * ignored host, other ALPN protocols) is relayed untouched to the server as UDP, from a socket
     * per flow, until the flow is idle for {@link Http3Options#transparentRelayIdleTimeout()}.
     *
     * @param port the UDP port, 0 for any
     * @return this bootstrap
     * @throws IllegalArgumentException if the port is out of range
     * @see HttpProxyServer#getTransparentQuicAddress()
     */
    default HttpProxyServerBootstrap withTransparentQuicPort(int port) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support transparent QUIC");
    }

    /**
     * Hosts whose TLS connections are never intercepted, but tunnelled untouched, so their clients
     * see the real server's certificate (mitmproxy's {@code ignore_hosts}). Each pattern is a
     * regular expression searched for, ignoring case, in {@code host:port} names of the
     * connection: the {@code CONNECT} target and the client's SNI with that port. For example,
     * {@code example\.com} ignores {@code example.com:443} and {@code www.example.com:443}; {@code
     * ^example\.com:443$} ignores only that one. A connection whose {@code CONNECT} target matches
     * is tunnelled without waiting for its ClientHello. Replaces earlier patterns; none by default.
     * Only matters with a {@link #withManInTheMiddle MITM manager}.
     *
     * @param patterns the regular expressions
     * @return this bootstrap
     * @throws IllegalArgumentException if a pattern is not a valid regular expression
     */
    default HttpProxyServerBootstrap withIgnoreHosts(String... patterns) {
        if (patterns.length == 0) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support host rules");
    }

    /**
     * Hosts whose TLS connections are intercepted; all others are tunnelled untouched (mitmproxy's
     * {@code allow_hosts}). Patterns are matched as for {@link #withIgnoreHosts}, which still
     * applies to the allowed hosts. Replaces earlier patterns; none (everything allowed) by
     * default.
     *
     * @param patterns the regular expressions
     * @return this bootstrap
     * @throws IllegalArgumentException if a pattern is not a valid regular expression
     */
    default HttpProxyServerBootstrap withAllowHosts(String... patterns) {
        if (patterns.length == 0) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support host rules");
    }

    /**
     * Runs as a reverse proxy for one upstream server (see {@link ReverseProxyMode}); {@code null}
     * (the default) is a forward proxy.
     *
     * @param mode the upstream, or {@code null}
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withReverseProxy(ReverseProxyMode mode) {
        if (mode == null) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support reverse proxying");
    }

    /**
     * Runs as a reverse proxy for the upstream {@code spec}, such as {@code https://example.com}
     * (see {@link ReverseProxyMode#parse}).
     *
     * @param spec the upstream, {@code [scheme://]host[:port]}
     * @return this bootstrap
     * @throws IllegalArgumentException if the specification is invalid
     */
    default HttpProxyServerBootstrap withReverseProxy(String spec) {
        return withReverseProxy(ReverseProxyMode.parse(spec));
    }

    /**
     * Makes the listener a SOCKS server (mitmproxy's {@code socks5} mode): SOCKS5 (RFC 1928), and
     * SOCKS4 and 4a, with the {@code CONNECT} command only. With a {@link #withProxyAuthenticator
     * proxy authenticator}, SOCKS5 clients authenticate with a username and password (RFC 1929),
     * which the authenticator sees as {@code Proxy-Authorization: Basic}; a client without
     * credentials, SOCKS4's included, may proceed only if the authenticator accepts a request
     * without them.
     *
     * <p>Each request is served as a {@code CONNECT} to its destination would be, a {@code CONNECT}
     * that filters and trackers see but that the client never sent: routing and chained proxies,
     * the server connection, then the client's first bytes decide (see {@link
     * HttpFilters#proxyToServerAllowMitm(ClientHello)}): TLS is intercepted or tunnelled, plain HTTP
     * is served as HTTP, through the filters, even without a {@link #withManInTheMiddle MITM
     * manager}, and anything else is tunnelled. The client is answered once the server is
     * connected, with a reply code that tells why it could not be. {@link
     * FlowContext#socksVersion()} tells such clients apart. Off by default; starting fails with
     * {@link #withReverseProxy} or {@link #withSslContextSource}.
     *
     * @param socks whether the listener serves SOCKS clients only
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withSocksServer(boolean socks) {
        if (!socks) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support SOCKS clients");
    }

    /**
     * Serves SOCKS clients on the listener besides HTTP ones, told apart by their first byte: 5
     * for SOCKS5, 4 for SOCKS4 and 4a, which no HTTP request starts with. They are served as with
     * {@link #withSocksServer}, and not with a reverse proxy or a TLS listener either. Off by
     * default.
     *
     * @param detect whether to serve SOCKS clients too
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withSocksDetection(boolean detect) {
        if (!detect) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support SOCKS clients");
    }

    /**
     * In {@linkplain #withReverseProxy reverse proxy} mode, keeps the {@code Host} field the client
     * sent instead of setting it to the upstream's (mitmproxy's {@code keep_host_header}). Off by
     * default.
     *
     * @param keep whether to keep the client's {@code Host}
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withKeepHostHeader(boolean keep) {
        if (!keep) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support reverse proxying");
    }

    /**
     * Sets the maximum idle time for client and server connections.
     *
     * @param idleConnectionTimeoutInSeconds the maximum idle time in seconds
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withIdleConnectionTimeout(int idleConnectionTimeoutInSeconds);

    /**
     * Sets the maximum idle time for client and server connections.
     *
     * @param idleConnectionTimeout the maximum time a connection may remain idle
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withIdleConnectionTimeout(Duration idleConnectionTimeout);

    /**
     * Connect timeout for outbound connections in milliseconds.
     *
     * @param connectTimeoutMs the outbound connect timeout in milliseconds; zero uses the system default
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withConnectTimeout(int connectTimeoutMs);

    /**
     * The longest a TLS handshake may take, with clients and with servers (default 10 seconds;
     * zero for no limit). The idle timeout alone does not bound it, since it restarts with every
     * byte received.
     *
     * @param timeout the maximum TLS handshake duration
     * @return this bootstrap
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
     *
     * @param protocols the enabled TLS protocol names, such as {@code TLSv1.3}
     * @return this bootstrap
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
     *
     * @param compatible whether to enable the documented LittleProxy compatibility behaviors
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withLittleProxyCompatibility(boolean compatible);

    /**
     * Same as {@code withLittleProxyCompatibility(true)}.
     *
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withLittleProxyCompatibility() {
        return withLittleProxyCompatibility(true);
    }

    /**
     * Sets the resolver used for upstream host names.
     *
     * @param serverResolver the resolver for upstream host names
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withServerResolver(HostResolver serverResolver);

    /**
     * Removes these headers (case-insensitively) from every request right before it is written
     * upstream: after all filters, so headers that filters added are removed too. It applies to
     * plain requests, requests inside intercepted (MITM) sessions, upgrade requests, and the
     * {@code CONNECT} requests sent to HTTP chained proxies; the bytes of an uninspected tunnel
     * are never touched. Replaces the names set so far; no names turns it off.
     *
     * @param names the request header names to strip before forwarding
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withStrippedRequestHeaders(String... names) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support stripping headers");
    }

    /**
     * Adds to the headers removed from requests sent upstream (see {@link #withStrippedRequestHeaders}).
     *
     * @param names the additional request header names to strip before forwarding
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap plusStrippedRequestHeaders(String... names) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support stripping headers");
    }

    /**
     * Removes distributed tracing headers ({@link org.microproxy.http.HttpHeaderNames#TRACING_HEADERS}:
     * {@code traceparent}, {@code tracestate}, {@code baggage}, the B3 headers, {@code uber-trace-id},
     * {@code X-Amzn-Trace-Id}, {@code X-Cloud-Trace-Context}, {@code grpc-trace-bin}, {@code
     * sentry-trace}) from requests sent upstream, so clients' trace
     * ids and baggage do not leak to servers. Adds to {@link #plusStrippedRequestHeaders}.
     *
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withoutTracingHeadersUpstream() {
        return plusStrippedRequestHeaders(org.microproxy.http.HttpHeaderNames.TRACING_HEADERS.toArray(String[]::new));
    }

    /**
     * Whether to remove HTTP/3 alternatives ({@code h3}, {@code h3-29}, {@code h3-Q050}, ...,
     * and Google QUIC's {@code quic}) from {@code Alt-Svc} response headers, keeping the other
     * alternatives (such as {@code h2=":443"}) and their parameters as they are. A header left
     * with no alternative is removed; {@code Alt-Svc: clear} is never touched.
     *
     * <p>A client that learns an origin speaks HTTP/3 may move to QUIC over UDP, which bypasses
     * the proxy: browsers never send QUIC through an HTTP proxy, and a transparent deployment
     * often redirects only TCP. Where the proxy is meant to see the traffic, that is a hole, so this
     * is on by default when {@link #withManInTheMiddle interception} or {@link #withTransparent
     * transparent mode} is configured, and off otherwise; except, with a {@linkplain
     * #withTransparentQuicPort transparent QUIC listener}, for clients whose traffic was redirected
     * to the proxy, whose QUIC reaches it too. Clients can still learn about HTTP/3 from DNS {@code
     * HTTPS} records, so transparent deployments without a QUIC listener should also block UDP
     * port 443, which makes clients fall back to TCP. Setting this applies to every client.
     *
     * <p>Responses from servers are rewritten before {@link HttpFilters#proxyToClientResponse}
     * sees them; short-circuit responses from filters (and the cache) after it.
     *
     * @param strip whether to remove HTTP/3 and QUIC advertisements from Alt-Svc headers
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withAltSvcH3Stripping(boolean strip) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support Alt-Svc rewriting");
    }

    /**
     * Same as {@code withAltSvcH3Stripping(true)}: clients are not told about HTTP/3 (see there).
     *
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withoutHttp3Advertisement() {
        return withAltSvcH3Stripping(true);
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
     *
     * @param initial the delay before the first retry
     * @param max the maximum retry delay
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withChainedProxyRetryBackoff(Duration initial, Duration max) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support retry backoff");
    }

    /**
     * Serves HTTP/2 to clients on intercepted TLS ({@link #withManInTheMiddle}) and the proxy
     * TLS listener ({@link #withSslContextSource}): the client
     * handshake offers {@code h2} and {@code http/1.1} through ALPN, and a client that picks
     * {@code h2} has each of its streams handled as an exchange of its own, concurrently, with the
     * same filters, cache, authentication, failure answers and trackers as HTTP/1 requests.
     * Requests reach servers as HTTP/1.1, each stream on a server connection of its own, unless
     * {@link #withHttp2Upstream} lets them share an HTTP/2 connection. Off by default; limits are
     * set with {@link #withHttp2Options}.
     *
     * <p>Needs the optional {@code http2-codec} module on the class path: starting a server with
     * HTTP/2 enabled without it fails with {@link IllegalStateException}.
     *
     * @param enabled whether the feature is enabled
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withHttp2(boolean enabled) {
        if (!enabled) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support HTTP/2");
    }

    /**
     * Speaks HTTP/2 to origin servers that offer it: TLS connections to servers (intercepted
     * HTTPS and secure WebSocket extended CONNECT) offer {@code h2} and {@code http/1.1} through ALPN, and a server that picks {@code h2}
     * gets every exchange for it as a stream on one connection, shared by concurrent exchanges up
     * to the server's stream limit; others keep HTTP/1.1. Independent of {@link #withHttp2}, which
     * is about clients. Off by default.
     *
     * <p>Needs the optional {@code http2-codec} module on the class path: starting a server with
     * it enabled without the module fails with {@link IllegalStateException}.
     *
     * @param enabled whether the feature is enabled
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withHttp2Upstream(boolean enabled) {
        if (!enabled) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support HTTP/2");
    }

    /**
     * Serves HTTP/2 with prior knowledge ({@code h2c}, RFC 9113 section 3.3) on the plain listener:
     * a connection that starts with the HTTP/2 connection preface is served as HTTP/2, its streams
     * being proxy requests like HTTP/1 ones ({@code :scheme} and {@code :authority} name the
     * target). Other connections stay HTTP/1.x; {@code Upgrade: h2c} is not supported. Off by
     * default; limits are set with {@link #withHttp2Options}.
     *
     * <p>Needs the optional {@code http2-codec} module on the class path: starting a server with
     * it enabled without the module fails with {@link IllegalStateException}.
     *
     * @param enabled whether the feature is enabled
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withHttp2Cleartext(boolean enabled) {
        if (!enabled) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support HTTP/2");
    }

    /** {@return the HTTP/2 limits configured so far (never null)} */
    default Http2Options getHttp2Options() {
        return Http2Options.DEFAULT;
    }

    /**
     * Limits for HTTP/2 connections (see {@link Http2Options}); null restores the defaults.
     *
     * @param options the HTTP/2 connection limits
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withHttp2Options(Http2Options options) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support HTTP/2");
    }

    /**
     * Serves HTTP/3 (RFC 9114, over QUIC): a UDP listener on the TCP listener's port number takes
     * QUIC connections with ALPN {@code h3}, and each request stream is an exchange of its own,
     * concurrently, with the same filters, cache, authentication, failure answers, logging and
     * trackers as HTTP/1 and HTTP/2 requests. Off by default; limits are set with {@link
     * #withHttp3Options}.
     *
     * <p>A reverse proxy ({@link #withReverseProxy}) serves its upstream this way: requests reach it
     * as HTTP/1.1, HTTP/2 ({@link #withHttp2Upstream}) or HTTP/3 ({@link #withHttp3Upstream}), as it
     * speaks, and responses sent over TCP advertise the listener with {@code Alt-Svc:
     * h3=":<port>"} (see {@link Http3Options.Builder#altSvc}).
     *
     * <p>A forward proxy serves HTTP/3 next to its own TLS listener ({@link #withSslContextSource}),
     * to clients that know it does, such as MASQUE clients: requests name their targets with
     * {@code :scheme} and {@code :authority}, {@code CONNECT} (RFC 9114 section 4.4) opens a tunnel
     * as an HTTP/1 or HTTP/2 one does, and CONNECT-UDP (RFC 9298) proxies UDP in HTTP Datagrams
     * (see {@link Http3Options.Builder#connectUdpTemplate}). Every HTTP/3 connection to clients
     * takes WebSockets over extended {@code CONNECT} (RFC 9220).
     *
     * <p>The listener presents the certificate of the proxy's TLS listener, which must provide it
     * as {@link KeyMaterial} ({@link SslContextSource#getKeyMaterial}), or, for a reverse proxy
     * without a TLS listener, one that a {@link org.microproxy.tls.CertificateAuthorityMitmManager}
     * issues for the name the client asks for. A forward proxy without a TLS listener, a
     * transparent proxy (its clients' QUIC goes to {@link #withTransparentQuicPort}) and a {@code
     * reverse:tcp://} proxy fail to start with HTTP/3 enabled.
     *
     * <p>Needs the optional {@code quic} and {@code http3-codec} modules on the class path:
     * starting a server with HTTP/3 enabled without them fails with {@link IllegalStateException}.
     *
     * @param enabled whether the feature is enabled
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withHttp3(boolean enabled) {
        if (!enabled) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support HTTP/3");
    }

    /**
     * Speaks HTTP/3 to origin servers known to support it, whatever the client spoke: one QUIC
     * connection per server, shared by concurrent exchanges as streams. A server is known to
     * support HTTP/3 once one of its responses over TLS advertised {@code h3} on the same host in
     * {@code Alt-Svc} (remembered for its {@code ma}, and learned before the advertisement is
     * removed for clients), or when its host matches {@link #withHttp3UpstreamHosts}. A QUIC
     * handshake that fails or takes longer than {@link Http3Options#upstreamHandshakeTimeout()}
     * sends the request over TCP instead, and keeps the server on TCP for {@link
     * Http3Options#upstreamFailureTimeout()}. Only direct connections use HTTP/3: not those
     * through chained proxies or tunnels, nor those with a PROXY protocol header. Off by default.
     *
     * <p>Servers are validated with the MITM manager's trust ({@link
     * MitmManager#serverTrustManager}), or the JDK's default trust store without one.
     *
     * <p>Needs the optional {@code quic} and {@code http3-codec} modules on the class path:
     * starting a server with it enabled without them fails with {@link IllegalStateException}.
     *
     * @param enabled whether the feature is enabled
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withHttp3Upstream(boolean enabled) {
        if (!enabled) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support HTTP/3");
    }

    /**
     * Servers reached over HTTP/3 without waiting for an {@code Alt-Svc} advertisement, on the
     * port of their {@code https} URI: those whose {@code host:port} one of these regular
     * expressions is found in, case-insensitively, as for {@link #withIgnoreHosts}. Takes effect with {@link #withHttp3Upstream}; replaces any
     * previous patterns, and none (the default) relies on {@code Alt-Svc} alone.
     *
     * @param patterns regular expressions for {@code host:port} names
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withHttp3UpstreamHosts(String... patterns) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support HTTP/3");
    }

    /** {@return the HTTP/3 limits configured so far (never null)} */
    default Http3Options getHttp3Options() {
        return Http3Options.DEFAULT;
    }

    /**
     * Limits and timers for HTTP/3 (see {@link Http3Options}); null restores the defaults.
     *
     * @param options the HTTP/3 options
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withHttp3Options(Http3Options options) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support HTTP/3");
    }

    /**
     * Shows every HTTP/2 frame the proxy receives or sends, on the client side and on connections
     * to servers, to {@code interceptor}, which may edit, drop and add frames within the rules
     * {@link FrameInterceptor} describes. One per proxy: a later call replaces it, and null removes
     * it. Without one (the default), frames cost nothing extra. It takes effect where HTTP/2 is
     * enabled ({@link #withHttp2}, {@link #withHttp2Upstream}, {@link #withHttp2Cleartext}), and
     * sees HTTP/3 frames where HTTP/3 is ({@link #withHttp3}, {@link #withHttp3Upstream}); other
     * HTTP/3 traffic reaches an interceptor through an {@link
     * org.microproxy.frames.Http3FramePipeline}.
     *
     * @param interceptor the interceptor, or null for none
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withFrameInterceptor(FrameInterceptor interceptor) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support frame interception");
    }

    /** {@return the frame interceptor configured so far, or null} */
    default FrameInterceptor getFrameInterceptor() {
        return null;
    }

    /**
     * Shows the bytes of every raw TCP tunnel to {@code interceptor}, which may rewrite, drop and
     * add them (mitmproxy's {@code tcp_message} and related hooks; see {@link TcpInterceptor} for
     * which tunnels). One per proxy: a later call replaces it, and null removes it. Without one
     * (the default), tunnels copy bytes through pooled buffers and cost nothing extra.
     *
     * <p>With an interceptor, TLS that does not carry HTTP is intercepted too, so the hooks see it
     * decrypted: a client whose ALPN offers only other protocols ({@code imap}, {@code mqtt}, ...)
     * is intercepted, the server being offered the same protocols and the client getting the
     * server's choice, rather than tunnelled (unless the other rules decline it; {@code
     * acme-tls/1} never is). Whatever the interceptor, an intercepted session is relayed as raw
     * TCP rather than served as HTTP when its ALPN protocol is not HTTP's, when its host is a
     * {@linkplain #withTcpHosts TCP host}, or, without ALPN, when its decrypted bytes do not start
     * like an HTTP request or its server speaks first (an SMTP banner).
     *
     * @param interceptor the interceptor, or null for none
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withTcpInterceptor(TcpInterceptor interceptor) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support TCP interception");
    }

    /** {@return the TCP interceptor configured so far, or null} */
    default TcpInterceptor getTcpInterceptor() {
        return null;
    }

    /**
     * Shows the datagrams of every UDP flow the proxy relays (CONNECT-UDP, MASQUE, on a forward
     * proxy's HTTP/3 listener) to {@code interceptor}, which may rewrite, drop and add them; see
     * {@link UdpInterceptor}. One per proxy: a later call replaces it, and null removes it.
     *
     * @param interceptor the interceptor, or null for none
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withUdpInterceptor(UdpInterceptor interceptor) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support UDP interception");
    }

    /** {@return the UDP interceptor configured so far, or null} */
    default UdpInterceptor getUdpInterceptor() {
        return null;
    }

    /**
     * Hosts whose connections are relayed as raw TCP even when they look like HTTP (mitmproxy's
     * {@code tcp_hosts}): plain bytes after a {@code CONNECT} are not served as HTTP, and an
     * intercepted TLS session is relayed decrypted rather than served as HTTP, its bytes going
     * through the {@link #withTcpInterceptor TCP hooks}. TLS is still intercepted, as for other
     * hosts; use {@link #withIgnoreHosts} to leave it untouched. Each pattern is a regular
     * expression searched for, ignoring case, in the target's host name and in the client's SNI
     * (without the port, as mitmproxy matches them). Replaces earlier patterns; none by default.
     *
     * @param patterns the regular expressions
     * @return this bootstrap
     * @throws IllegalArgumentException if a pattern is not a valid regular expression
     */
    default HttpProxyServerBootstrap withTcpHosts(String... patterns) {
        if (patterns.length == 0) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support TCP hosts");
    }

    /**
     * Shows the streams and datagrams of QUIC connections that the proxy intercepts without
     * speaking their protocol to {@code interceptor}, which may rewrite, drop and add their bytes;
     * see {@link QuicInterceptor}. One per proxy: a later call replaces it, and null removes it.
     *
     * <p>With an interceptor, transparent QUIC (and QUIC inside CONNECT-UDP flows, with {@link
     * Http3Options.Builder#connectUdpInterceptQuic}) whose ClientHello offers no HTTP/3 is
     * intercepted, rather than relayed untouched, unless the host rules, {@link
     * MitmManager#shouldIntercept} or the filters decline it: the proxy terminates the client's
     * QUIC with a certificate its CA issues, connects to the server with the client's ALPN
     * protocols, and relays each stream through the hooks. HTTP/3 is still served as HTTP/3, except
     * for the {@linkplain #withQuicHosts QUIC hosts}.
     *
     * @param interceptor the interceptor, or null for none
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withQuicInterceptor(QuicInterceptor interceptor) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support QUIC interception");
    }

    /** {@return the QUIC interceptor configured so far, or null} */
    default QuicInterceptor getQuicInterceptor() {
        return null;
    }

    /**
     * Which intercepted QUIC connections' streams a {@link QuicInterceptor} that overrides {@link
     * QuicInterceptor#streamMessage} sees as whole messages, cut by a {@link
     * org.microproxy.quic.MessageFramer} chosen by ALPN or host; how large a message may be; and the
     * error code a stream is reset with when one is too large. {@link QuicFraming#defaults()} (DNS
     * over QUIC with its two-byte length prefix) by default.
     *
     * @param framing the framing
     * @return this bootstrap
     */
    default HttpProxyServerBootstrap withQuicFraming(QuicFraming framing) {
        throw new UnsupportedOperationException(getClass().getName() + " does not support QUIC framing");
    }

    /** {@return the QUIC framing configured so far} */
    default QuicFraming getQuicFraming() {
        return QuicFraming.defaults();
    }

    /**
     * Hosts whose intercepted QUIC is relayed stream by stream, as raw QUIC, whatever its ALPN: the
     * QUIC counterpart of {@link #withTcpHosts}. Their HTTP/3 is not served as HTTP/3 (filters
     * and frame hooks do not see it); its streams go through the {@link #withQuicInterceptor QUIC
     * hooks}, as other protocols' do, and QUIC that offers no HTTP/3 is intercepted even without
     * an interceptor. The other rules still decide whether to intercept at all; use {@link
     * #withIgnoreHosts} to relay a host untouched. Each pattern is a regular expression searched
     * for, ignoring case, in the server's host name and in the client's SNI (without the port).
     * Replaces earlier patterns; none by default.
     *
     * @param patterns the regular expressions
     * @return this bootstrap
     * @throws IllegalArgumentException if a pattern is not a valid regular expression
     */
    default HttpProxyServerBootstrap withQuicHosts(String... patterns) {
        if (patterns.length == 0) return this;
        throw new UnsupportedOperationException(getClass().getName() + " does not support QUIC hosts");
    }

    /**
     * Adds an observer alongside the configured activity trackers.
     *
     * @param activityTracker the observer to add
     * @return this bootstrap
     */
    HttpProxyServerBootstrap plusActivityTracker(ActivityTracker activityTracker);

    /**
     * Global bandwidth limits for server traffic; 0 means unlimited.
     *
     * @param readThrottleBytesPerSecond the inbound bandwidth limit in bytes per second, or zero for unlimited
     * @param writeThrottleBytesPerSecond the outbound bandwidth limit in bytes per second, or zero for unlimited
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withThrottling(
            long readThrottleBytesPerSecond, long writeThrottleBytesPerSecond);

    /**
     * Local address to bind for outbound connections.
     *
     * @param inetSocketAddress the local address to bind for outbound connections
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withNetworkInterface(InetSocketAddress inetSocketAddress);

    /**
     * Sets the maximum HTTP request or status line length in bytes.
     *
     * @param maxInitialLineLength the maximum request or status line length in bytes
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withMaxInitialLineLength(int maxInitialLineLength);

    /**
     * Sets the maximum HTTP header section size in bytes.
     *
     * @param maxHeaderSize the maximum header section size in bytes
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withMaxHeaderSize(int maxHeaderSize);

    /**
     * Largest body piece handed to filters when streaming.
     *
     * @param maxChunkSize the maximum streamed body chunk size in bytes
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withMaxChunkSize(int maxChunkSize);

    /**
     * Accept origin-form requests ({@code GET /path}) as if the proxy were the origin.
     *
     * @param allowRequestToOriginServer whether to accept origin-form requests
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withAllowRequestToOriginServer(boolean allowRequestToOriginServer);

    /**
     * Name used in the {@code Via} header; defaults to the host name.
     *
     * @param alias the name used in Via headers
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withProxyAlias(String alias);

    /**
     * Require a PROXY protocol (v1 or v2) header on every inbound connection.
     *
     * @param acceptProxyProtocol whether to accept PROXY protocol on client connections
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withAcceptProxyProtocol(boolean acceptProxyProtocol);

    /**
     * Send a PROXY protocol v1 header to the final server: first on a direct connection, or
     * through the tunnel once an HTTP chained proxy has accepted the CONNECT. It is not sent where
     * there is no tunnel to the final server: through SOCKS chained proxies, or with plain
     * requests forwarded to an HTTP chained proxy. Server connections that carry the header belong
     * to one client, so the shared server connection pool is not used while this is on.
     *
     * @param sendProxyProtocol whether to send PROXY protocol to upstream servers
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withSendProxyProtocol(boolean sendProxyProtocol);

    /**
     * Largest WebSocket frame payload buffered for {@link
     * HttpFilters#webSocketFrameReceived(org.microproxy.http.WebSocketFrame, boolean)}; larger
     * frames are streamed and reported as truncated. Default 1 MiB.
     *
     * @param maxBytes the maximum buffered WebSocket frame size in bytes
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withMaxWebSocketFrameBufferSize(int maxBytes);

    /**
     * Largest WebSocket message, in bytes, that the proxy joins from its frames for {@link
     * HttpFilters#filterWebSocketMessage(org.microproxy.http.WebSocketMessage, boolean)} or inflates
     * (permessage-deflate) for the frame and message hooks. A larger message, or one that inflates
     * past it (a decompression bomb), fails the connection with close code 1009. Default 16 MiB.
     *
     * @param maxBytes the maximum message size in bytes
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withMaxWebSocketMessageSize(int maxBytes);

    /**
     * Shares server connections between all clients instead of keeping them per client
     * connection. A connection is leased for one exchange and returned to the pool when the
     * response completes with keep-alive. Disabled by default.
     *
     * @param useSharedServerConnectionPool whether to share reusable upstream connections
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withSharedServerConnectionPool(boolean useSharedServerConnectionPool);

    /**
     * Selects the shared upstream connection pool implementation.
     *
     * @param poolType the shared connection pool implementation
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withServerConnectionPoolType(ServerConnectionPoolType poolType);

    /**
     * Pooled connections per target ({@code host:port}); default 10.
     *
     * @param maxConnectionsPerHost the maximum pooled connections per destination
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withMaxConnectionsPerHost(int maxConnectionsPerHost);

    /**
     * Pooled connections in total; default 200. When the limit is reached, requests wait up to the
     * connect timeout for a connection and then get {@code 503}.
     *
     * @param maxConnections the maximum pooled connections across destinations
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withMaxConnections(int maxConnections);

    /**
     * Closes pooled connections idle for longer than this; {@code null} keeps them.
     *
     * @param idleTimeout the maximum idle time before a pooled connection is closed
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withPoolIdleTimeout(Duration idleTimeout);

    /**
     * Lets intercepted (MITM) sessions take their server connection from the pool and return it
     * when the client disconnects, so other clients can reuse it. Requires the shared pool.
     * Connections are only shared by clients given the same {@link MitmManager#forConnection
     * manager}, and not at all when the manager sets up server connections per client (see {@link
     * MitmManager}).
     *
     * @param poolSharedMitmConnections whether intercepted sessions share upstream connections
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withPoolSharedMitmConnections(boolean poolSharedMitmConnections);

    /**
     * With {@link #withPoolSharedMitmConnections}, leases the server connection per intercepted
     * request rather than per session.
     *
     * @param poolPerRequestInMitm whether intercepted requests lease upstream connections individually
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withPoolPerRequestInMitm(boolean poolPerRequestInMitm);

    /**
     * Resolves server names with the validating DNSSEC resolver ({@link
     * org.microproxy.dns.DnssecHostResolver}) instead of the system resolver.
     *
     * @param useDnsSec whether to validate DNSSEC locally
     * @return this bootstrap
     */
    HttpProxyServerBootstrap withUseDnsSec(boolean useDnsSec);

    /**
     * Starts the proxy with this configuration.
     *
     * @return the running proxy server
     */
    HttpProxyServer start();
}
