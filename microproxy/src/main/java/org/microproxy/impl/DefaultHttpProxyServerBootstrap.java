package org.microproxy.impl;

import java.io.IOException;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Properties;
import org.microproxy.ActivityTracker;
import org.microproxy.ChainedProxyManager;
import org.microproxy.DefaultHostResolver;
import org.microproxy.DrainStrategy;
import org.microproxy.FailureResponder;
import org.microproxy.FlowTracer;
import org.microproxy.HostResolver;
import org.microproxy.Http2Options;
import org.microproxy.Http3Options;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpFiltersSource;
import org.microproxy.HttpFiltersSourceAdapter;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MitmManager;
import org.microproxy.ProxyAuthenticator;
import org.microproxy.RetryBackoff;
import org.microproxy.ReverseProxyMode;
import org.microproxy.ScriptCallObserver;
import org.microproxy.NoProxyRules;
import org.microproxy.ServerConnectionPoolType;
import org.microproxy.UpstreamProxyManager;
import org.microproxy.SslContextSource;
import org.microproxy.cache.DiskCacheStore;
import org.microproxy.contentviews.ContentViews;
import org.microproxy.contentviews.ProtoSchema;
import org.microproxy.cache.HttpCache;
import org.microproxy.cache.MemoryCacheStore;
import org.microproxy.dns.DnssecHostResolver;
import org.microproxy.extras.ActivityLogger;
import org.microproxy.extras.ConcurrencyLimiter;
import org.microproxy.extras.HttpLogger;
import org.microproxy.extras.LogFormat;
import org.microproxy.frames.FrameInterceptor;
import org.microproxy.quic.QuicFraming;
import org.microproxy.quic.QuicInterceptor;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tcp.TcpInterceptor;
import org.microproxy.udp.UdpInterceptor;

/** Default {@link HttpProxyServerBootstrap}. */
public final class DefaultHttpProxyServerBootstrap implements HttpProxyServerBootstrap {

    static final List<String> DEFAULT_TLS_PROTOCOLS = List.of("TLSv1.3", "TLSv1.2");

    String name = "MicroProxy";
    InetSocketAddress requestedAddress;
    int port = 8080;
    boolean allowLocalOnly = true;
    SslContextSource sslContextSource;
    boolean authenticateSslClients;
    ProxyAuthenticator proxyAuthenticator;
    ChainedProxyManager chainProxyManager;
    MitmManager mitmManager;
    HttpFiltersSource filtersSource = new HttpFiltersSourceAdapter();
    HttpCache httpCache;
    /** Where the proxy keeps its metrics; {@link StatsRegistry#NOOP} when they are off. */
    StatsRegistry stats = StatsRegistry.NOOP;
    /** Traces exchanges and flows; {@link FlowTracer#NOOP} when tracing is off. */
    FlowTracer tracer = FlowTracer.NOOP;
    FailureResponder failureResponder;
    boolean transparent;
    /** The port transparent TLS connections are routed to, on the host their SNI names. */
    int transparentTlsPort = 443;
    /** The UDP port of the transparent QUIC listener (0 for any); -1 for none. */
    int transparentQuicPort = -1;
    /** Host patterns whose TLS is tunnelled untouched / the only ones intercepted. */
    List<String> ignoreHosts = List.of();
    /** Hosts relayed as raw TCP even when they look like HTTP (mitmproxy's tcp_hosts). */
    List<String> tcpHosts = List.of();
    List<String> quicHosts = List.of();
    List<String> allowHosts = List.of();
    /** The fixed upstream in reverse proxy mode; null for a forward proxy. */
    ReverseProxyMode reverseProxy;
    boolean keepHostHeader;
    /** The listener serves SOCKS clients only ({@code socks5} mode) / besides HTTP ones. */
    boolean socksServer;
    boolean socksDetection;
    Duration idleConnectionTimeout = Duration.ofSeconds(70);
    int connectTimeoutMs = 40_000;
    Duration tlsHandshakeTimeout = Duration.ofSeconds(10);
    boolean littleProxyCompatibility;
    HostResolver serverResolver = new DefaultHostResolver();
    final List<ActivityTracker> activityTrackers = new ArrayList<>();
    long readThrottleBytesPerSecond;
    long writeThrottleBytesPerSecond;
    InetSocketAddress localAddress;
    int maxInitialLineLength = 8192;
    int maxHeaderSize = 16384;
    int maxChunkSize = 16384;
    boolean allowRequestToOriginServer;
    /** Fetch clients' own {@code https://} requests over TLS (forward proxy). */
    boolean tlsOrigination = true;
    String proxyAlias;
    boolean acceptProxyProtocol;
    boolean sendProxyProtocol;
    int maxWebSocketFrameBufferSize = 1 << 20;
    int maxWebSocketMessageSize = 16 << 20;
    boolean sharedServerConnectionPool;
    ServerConnectionPoolType serverConnectionPoolType = ServerConnectionPoolType.CONCURRENT_MAP;
    int maxConnectionsPerHost = 10;
    int maxConnections = 200;
    Duration poolIdleTimeout;
    boolean poolSharedMitmConnections;
    boolean poolPerRequestInMitm;
    /** Backoff between chained proxy attempts; {@link RetryBackoff#none()} when off. */
    RetryBackoff chainedProxyBackoff = RetryBackoff.none();
    /** TLS versions enabled on every TLS socket before configuration hooks; empty for the contexts' defaults. */
    List<String> tlsProtocols = DEFAULT_TLS_PROTOCOLS;
    /** Headers removed from requests sent upstream, in the order given, without duplicates. */
    final java.util.LinkedHashMap<String, String> strippedRequestHeaders = new java.util.LinkedHashMap<>();
    /** Whether to remove HTTP/3 alternatives from Alt-Svc; null for the default (see {@link #stripsAltSvcH3()}). */
    Boolean altSvcH3Stripping;
    /**
     * Whether intercepted TLS and the TLS listener offer HTTP/2; null for the default (on when the
     * http2-codec module is present, see {@link DefaultHttpProxyServer}).
     */
    Boolean http2;
    /** Whether TLS connections to servers offer HTTP/2; null for the default, as for {@link #http2}. */
    Boolean http2Upstream;
    /** Whether the plain listener serves HTTP/2 with prior knowledge. */
    boolean http2Cleartext;
    /** Whether the plain listener serves nothing else (h2c whatever {@link #http2Cleartext} says). */
    boolean http2CleartextOnly;
    Http2Options http2Options = Http2Options.DEFAULT;
    /** Whether a reverse proxy serves HTTP/3 on UDP. */
    boolean http3;
    /** Whether servers known to speak HTTP/3 are reached over it. */
    boolean http3Upstream;
    /** Servers reached over HTTP/3 without an Alt-Svc advertisement. */
    List<String> http3UpstreamHosts = List.of();
    Http3Options http3Options = Http3Options.DEFAULT;
    /** Whether a forward proxy serves CONNECT-UDP on its TCP listener without HTTP/3 too. */
    boolean connectUdp;
    /** Sees every HTTP/2 and HTTP/3 frame; null for none. */
    FrameInterceptor frameInterceptor;
    ScriptCallObserver scriptCallObserver;
    /** Sees the bytes of raw TCP tunnels; null for none. */
    TcpInterceptor tcpInterceptor;
    UdpInterceptor udpInterceptor;
    QuicInterceptor quicInterceptor;
    QuicFraming quicFraming = QuicFraming.defaults();
    /** How long stopping lets exchanges finish, and how long a drain lasts. */
    Duration drainTime = Duration.ofSeconds(10);
    DrainStrategy drainStrategy = DrainStrategy.GRADUAL;
    /** The path the proxy answers health checks on; null for none. */
    String healthCheckPath;
    boolean healthCheckPassThrough;
    /** Where the admin listener listens; null for none. */
    InetSocketAddress adminAddress;
    /** What admin requests must present; null for nothing. */
    String adminToken;
    /** The command line, for the admin's {@code /server_info}. */
    List<String> commandLineOptions = List.of();

    DefaultHttpProxyServerBootstrap() {}

    DefaultHttpProxyServerBootstrap copy() {
        DefaultHttpProxyServerBootstrap c = new DefaultHttpProxyServerBootstrap();
        c.name = name;
        c.requestedAddress = requestedAddress;
        c.port = port;
        c.allowLocalOnly = allowLocalOnly;
        c.sslContextSource = sslContextSource;
        c.authenticateSslClients = authenticateSslClients;
        c.proxyAuthenticator = proxyAuthenticator;
        c.chainProxyManager = chainProxyManager;
        c.mitmManager = mitmManager;
        c.filtersSource = filtersSource;
        c.httpCache = httpCache;
        c.stats = stats;
        c.tracer = tracer;
        c.failureResponder = failureResponder;
        c.transparent = transparent;
        c.transparentTlsPort = transparentTlsPort;
        c.transparentQuicPort = transparentQuicPort;
        c.ignoreHosts = ignoreHosts;
        c.tcpHosts = tcpHosts;
        c.quicHosts = quicHosts;
        c.allowHosts = allowHosts;
        c.reverseProxy = reverseProxy;
        c.keepHostHeader = keepHostHeader;
        c.socksServer = socksServer;
        c.socksDetection = socksDetection;
        c.idleConnectionTimeout = idleConnectionTimeout;
        c.connectTimeoutMs = connectTimeoutMs;
        c.tlsHandshakeTimeout = tlsHandshakeTimeout;
        c.littleProxyCompatibility = littleProxyCompatibility;
        c.serverResolver = serverResolver;
        c.activityTrackers.addAll(activityTrackers);
        c.readThrottleBytesPerSecond = readThrottleBytesPerSecond;
        c.writeThrottleBytesPerSecond = writeThrottleBytesPerSecond;
        c.localAddress = localAddress;
        c.maxInitialLineLength = maxInitialLineLength;
        c.maxHeaderSize = maxHeaderSize;
        c.maxChunkSize = maxChunkSize;
        c.allowRequestToOriginServer = allowRequestToOriginServer;
        c.tlsOrigination = tlsOrigination;
        c.proxyAlias = proxyAlias;
        c.acceptProxyProtocol = acceptProxyProtocol;
        c.sendProxyProtocol = sendProxyProtocol;
        c.maxWebSocketFrameBufferSize = maxWebSocketFrameBufferSize;
        c.maxWebSocketMessageSize = maxWebSocketMessageSize;
        c.sharedServerConnectionPool = sharedServerConnectionPool;
        c.serverConnectionPoolType = serverConnectionPoolType;
        c.maxConnectionsPerHost = maxConnectionsPerHost;
        c.maxConnections = maxConnections;
        c.poolIdleTimeout = poolIdleTimeout;
        c.poolSharedMitmConnections = poolSharedMitmConnections;
        c.poolPerRequestInMitm = poolPerRequestInMitm;
        c.chainedProxyBackoff = chainedProxyBackoff;
        c.strippedRequestHeaders.putAll(strippedRequestHeaders);
        c.tlsProtocols = tlsProtocols;
        c.altSvcH3Stripping = altSvcH3Stripping;
        c.http2 = http2;
        c.http2Upstream = http2Upstream;
        c.http2Cleartext = http2Cleartext;
        c.http2CleartextOnly = http2CleartextOnly;
        c.http2Options = http2Options;
        c.http3 = http3;
        c.http3Upstream = http3Upstream;
        c.http3UpstreamHosts = http3UpstreamHosts;
        c.http3Options = http3Options;
        c.connectUdp = connectUdp;
        c.frameInterceptor = frameInterceptor;
        c.scriptCallObserver = scriptCallObserver;
        c.tcpInterceptor = tcpInterceptor;
        c.udpInterceptor = udpInterceptor;
        c.quicInterceptor = quicInterceptor;
        c.quicFraming = quicFraming;
        c.drainTime = drainTime;
        c.drainStrategy = drainStrategy;
        c.healthCheckPath = healthCheckPath;
        c.healthCheckPassThrough = healthCheckPassThrough;
        c.adminAddress = adminAddress;
        c.adminToken = adminToken;
        c.commandLineOptions = commandLineOptions;
        return c;
    }

    /** Reads the keys documented in docs/reference/properties.md from a properties file. */
    static DefaultHttpProxyServerBootstrap fromProperties(Path path) throws IOException {
        Properties props = new Properties();
        try (Reader r = Files.newBufferedReader(path)) {
            props.load(r);
        }
        return fromProperties(props);
    }

    static DefaultHttpProxyServerBootstrap fromProperties(Properties props) {
        DefaultHttpProxyServerBootstrap b = new DefaultHttpProxyServerBootstrap();
        b.applyProperties(props);
        return b;
    }

    void applyProperties(Properties p) {
        if (p.containsKey("name")) withName(p.getProperty("name"));
        if (p.containsKey("port")) withPort(Integer.parseInt(p.getProperty("port").strip()));
        if (p.containsKey("address")) withAddress(parseAddress(p.getProperty("address")));
        if (p.containsKey("allow_local_only")) withAllowLocalOnly(bool(p, "allow_local_only"));
        if (p.containsKey("transparent")) withTransparent(bool(p, "transparent"));
        if (p.containsKey("transparent_tls_port")) {
            withTransparentTlsPort(Integer.parseInt(p.getProperty("transparent_tls_port").strip()));
        }
        if (p.containsKey("transparent_quic_port")) {
            withTransparentQuicPort(Integer.parseInt(p.getProperty("transparent_quic_port").strip()));
        }
        if (p.containsKey("ignore_hosts")) {
            withIgnoreHosts(HostRules.split(p.getProperty("ignore_hosts")).toArray(String[]::new));
        }
        if (p.containsKey("allow_hosts")) {
            withAllowHosts(HostRules.split(p.getProperty("allow_hosts")).toArray(String[]::new));
        }
        if (p.containsKey("tcp_hosts")) {
            withTcpHosts(HostRules.split(p.getProperty("tcp_hosts")).toArray(String[]::new));
        }
        if (p.containsKey("quic_hosts")) {
            withQuicHosts(HostRules.split(p.getProperty("quic_hosts")).toArray(String[]::new));
        }
        if (p.containsKey("quic_framing")) withQuicFraming(quicFraming.withRules(p.getProperty("quic_framing")));
        if (p.containsKey("quic_max_message_size")) {
            withQuicFraming(quicFraming.withMaxMessageSize(Integer.parseInt(p.getProperty("quic_max_message_size").strip())));
        }
        if (p.containsKey("quic_message_error_code")) {
            withQuicFraming(quicFraming.withErrorCode(Long.decode(p.getProperty("quic_message_error_code").strip())));
        }
        if (p.containsKey("mode")) {
            String mode = p.getProperty("mode").strip();
            withReverseProxy(ReverseProxyMode.parseMode(mode));
            if (mode.equals("transparent")) withTransparent(true);
            withSocksServer(mode.equals("socks5"));
        }
        if (p.containsKey("socks")) withSocksDetection(bool(p, "socks"));
        if (p.containsKey("keep_host_header")) withKeepHostHeader(bool(p, "keep_host_header"));
        if (p.containsKey("idle_connection_timeout")) {
            withIdleConnectionTimeout(Integer.parseInt(p.getProperty("idle_connection_timeout").strip()));
        }
        if (p.containsKey("connect_timeout")) {
            withConnectTimeout(Integer.parseInt(p.getProperty("connect_timeout").strip()));
        }
        if (p.containsKey("littleproxy_compatibility")) {
            withLittleProxyCompatibility(bool(p, "littleproxy_compatibility"));
        }
        if (p.containsKey("tls_protocols")) {
            withTlsProtocols(p.getProperty("tls_protocols").split(","));
        }
        if (p.containsKey("tls_handshake_timeout")) {
            withTlsHandshakeTimeout(Duration.ofMillis(Long.parseLong(p.getProperty("tls_handshake_timeout").strip())));
        }
        if (p.containsKey("max_initial_line_length")) {
            withMaxInitialLineLength(Integer.parseInt(p.getProperty("max_initial_line_length").strip()));
        }
        if (p.containsKey("max_header_size")) {
            withMaxHeaderSize(Integer.parseInt(p.getProperty("max_header_size").strip()));
        }
        if (p.containsKey("max_chunk_size")) {
            withMaxChunkSize(Integer.parseInt(p.getProperty("max_chunk_size").strip()));
        }
        if (p.containsKey("nic")) withNetworkInterface(new InetSocketAddress(p.getProperty("nic").strip(), 0));
        if (p.containsKey("proxy_alias")) withProxyAlias(p.getProperty("proxy_alias").strip());
        if (p.containsKey("allow_requests_to_origin_server")) {
            withAllowRequestToOriginServer(bool(p, "allow_requests_to_origin_server"));
        }
        if (p.containsKey("originate_tls")) withTlsOrigination(bool(p, "originate_tls"));
        if (p.containsKey("allow_proxy_protocol")) withAcceptProxyProtocol(bool(p, "allow_proxy_protocol"));
        if (p.containsKey("send_proxy_protocol")) withSendProxyProtocol(bool(p, "send_proxy_protocol"));
        if (p.containsKey("use_shared_server_connection_pool")) {
            withSharedServerConnectionPool(bool(p, "use_shared_server_connection_pool"));
        }
        if (p.containsKey("server_connection_pool_type")) {
            withServerConnectionPoolType(ServerConnectionPoolType.valueOf(
                    p.getProperty("server_connection_pool_type").strip().toUpperCase(Locale.ROOT)));
        }
        if (p.containsKey("max_connections_per_host")) {
            withMaxConnectionsPerHost(Integer.parseInt(p.getProperty("max_connections_per_host").strip()));
        }
        if (p.containsKey("max_total_connections")) {
            withMaxConnections(Integer.parseInt(p.getProperty("max_total_connections").strip()));
        }
        if (p.containsKey("pool_idle_timeout")) {
            withPoolIdleTimeout(Duration.ofSeconds(Long.parseLong(p.getProperty("pool_idle_timeout").strip())));
        }
        if (p.containsKey("pool_shared_mitm_connections")) {
            withPoolSharedMitmConnections(bool(p, "pool_shared_mitm_connections"));
        }
        if (p.containsKey("pool_per_request_in_mitm")) {
            withPoolPerRequestInMitm(bool(p, "pool_per_request_in_mitm"));
        }
        if (p.containsKey("upstream_proxy") || p.containsKey("upstream_https_proxy")) {
            withChainProxyManager(new UpstreamProxyManager(p.getProperty("upstream_proxy"),
                    p.getProperty("upstream_https_proxy"), NoProxyRules.parse(p.getProperty("no_proxy")))
                    .withFallbackToDirect(bool(p, "upstream_fallback_to_direct")));
        } else if (bool(p, "use_env_proxy")) {
            UpstreamProxyManager fromEnv = UpstreamProxyManager.fromEnvironment(System.getenv());
            if (fromEnv != null) withChainProxyManager(fromEnv);
        }
        if (p.containsKey("chained_proxy_backoff_initial_ms")) {
            Duration initial = Duration.ofMillis(Long.parseLong(p.getProperty("chained_proxy_backoff_initial_ms").strip()));
            Duration max = p.containsKey("chained_proxy_backoff_max_ms")
                    ? Duration.ofMillis(Long.parseLong(p.getProperty("chained_proxy_backoff_max_ms").strip()))
                    : initial.multipliedBy(8);
            withChainedProxyRetryBackoff(!p.containsKey("chained_proxy_backoff_jitter") || bool(p, "chained_proxy_backoff_jitter")
                    ? RetryBackoff.exponentialWithJitter(initial, max) : RetryBackoff.exponential(initial, max));
        } else if (p.containsKey("chained_proxy_backoff_max_ms") || p.containsKey("chained_proxy_backoff_jitter")) {
            throw new IllegalArgumentException((p.containsKey("chained_proxy_backoff_max_ms")
                    ? "chained_proxy_backoff_max_ms" : "chained_proxy_backoff_jitter")
                    + " needs chained_proxy_backoff_initial_ms");
        }
        if (bool(p, "strip_tracing_headers")) withoutTracingHeadersUpstream();
        if (p.containsKey("strip_request_headers")) {
            plusStrippedRequestHeaders(p.getProperty("strip_request_headers").split(","));
        }
        if (p.containsKey("strip_alt_svc_h3")) withAltSvcH3Stripping(bool(p, "strip_alt_svc_h3"));
        if (p.containsKey("http2")) withHttp2(bool(p, "http2"));
        if (p.containsKey("http2_upstream")) withHttp2Upstream(bool(p, "http2_upstream"));
        if (p.containsKey("http2_cleartext")) withHttp2Cleartext(bool(p, "http2_cleartext"));
        if (p.containsKey("http2_cleartext_only")) withHttp2CleartextOnly(bool(p, "http2_cleartext_only"));
        if (p.containsKey("http2_max_concurrent_streams") || p.containsKey("http2_initial_window_size")
                || p.containsKey("http2_connection_window_size") || p.containsKey("http2_coalesce")) {
            Http2Options.Builder h2 = http2Options.toBuilder();
            if (p.containsKey("http2_max_concurrent_streams")) {
                h2.maxConcurrentStreams(Integer.parseInt(p.getProperty("http2_max_concurrent_streams").strip()));
            }
            if (p.containsKey("http2_initial_window_size")) {
                h2.initialWindowSize(Integer.parseInt(p.getProperty("http2_initial_window_size").strip()));
            }
            if (p.containsKey("http2_connection_window_size")) {
                h2.connectionWindowSize(Integer.parseInt(p.getProperty("http2_connection_window_size").strip()));
            }
            if (p.containsKey("http2_coalesce")) h2.coalesceConnections(bool(p, "http2_coalesce"));
            withHttp2Options(h2.build());
        }
        if (p.containsKey("http3")) withHttp3(bool(p, "http3"));
        if (p.containsKey("masque")) withConnectUdp(bool(p, "masque"));
        if (p.containsKey("http3_upstream")) withHttp3Upstream(bool(p, "http3_upstream"));
        if (p.containsKey("http3_upstream_hosts")) {
            withHttp3UpstreamHosts(HostRules.split(p.getProperty("http3_upstream_hosts")).toArray(String[]::new));
        }
        if (p.containsKey("http3_max_concurrent_streams") || p.containsKey("http3_alt_svc") || p.containsKey("http3_retry")
                || p.containsKey("http3_0rtt") || p.containsKey("http3_upstream_0rtt")
                || p.containsKey("transparent_quic_relay_idle_timeout") || p.containsKey("quic_congestion")
                || p.containsKey("masque_udp_template") || p.containsKey("masque_udp_idle_timeout")
                || p.containsKey("masque_max_udp_flows") || p.containsKey("masque_max_udp_flows_per_connection") || p.containsKey("masque_intercept_quic")
                || p.containsKey("masque_release_wait")
                || p.containsKey("masque_quic_ports") || p.containsKey("qlog_dir") || p.containsKey("qlog_max_files")) {
            Http3Options.Builder h3 = http3Options.toBuilder();
            if (p.containsKey("qlog_dir")) h3.qlogDirectory(Path.of(p.getProperty("qlog_dir").strip()));
            if (p.containsKey("qlog_max_files")) h3.qlogMaxFiles(Integer.parseInt(p.getProperty("qlog_max_files").strip()));
            if (p.containsKey("masque_intercept_quic")) h3.connectUdpInterceptQuic(bool(p, "masque_intercept_quic"));
            if (p.containsKey("masque_quic_ports")) h3.connectUdpQuicPorts(parsePorts(p.getProperty("masque_quic_ports")));
            if (p.containsKey("masque_udp_template")) h3.connectUdpTemplate(p.getProperty("masque_udp_template").strip());
            if (p.containsKey("masque_udp_idle_timeout")) {
                h3.connectUdpIdleTimeout(Duration.ofSeconds(Long.parseLong(p.getProperty("masque_udp_idle_timeout").strip())));
            }
            if (p.containsKey("masque_max_udp_flows") || p.containsKey("masque_max_udp_flows_per_connection")) {
                h3.connectUdpMaxFlows(
                        Integer.parseInt(p.getProperty("masque_max_udp_flows", Integer.toString(http3Options.connectUdpMaxFlows())).strip()),
                        Integer.parseInt(p.getProperty("masque_max_udp_flows_per_connection",
                                Integer.toString(http3Options.connectUdpMaxFlowsPerConnection())).strip()));
            }
            if (p.containsKey("masque_release_wait")) {
                h3.connectUdpReleaseWait(Duration.ofMillis(Long.parseLong(p.getProperty("masque_release_wait").strip())));
            }
            if (p.containsKey("http3_max_concurrent_streams")) {
                h3.maxConcurrentStreams(Integer.parseInt(p.getProperty("http3_max_concurrent_streams").strip()));
            }
            if (p.containsKey("http3_alt_svc")) h3.altSvc(bool(p, "http3_alt_svc"));
            if (p.containsKey("http3_retry")) h3.retry(bool(p, "http3_retry"));
            if (p.containsKey("http3_0rtt")) h3.zeroRtt(bool(p, "http3_0rtt"));
            if (p.containsKey("http3_upstream_0rtt")) h3.upstreamZeroRtt(bool(p, "http3_upstream_0rtt"));
            if (p.containsKey("transparent_quic_relay_idle_timeout")) {
                h3.transparentRelayIdleTimeout(Duration.ofSeconds(
                        Long.parseLong(p.getProperty("transparent_quic_relay_idle_timeout").strip())));
            }
            if (p.containsKey("quic_congestion")) {
                h3.quicCongestionControl(Http3Options.QuicCongestionControl.parse(p.getProperty("quic_congestion")));
            }
            withHttp3Options(h3.build());
        }
        if (p.containsKey("listener_keystore")) {
            String password = p.getProperty("listener_keystore_password", "");
            try {
                withSslContextSource(new org.microproxy.tls.KeyStoreSslContextSource(
                        Path.of(p.getProperty("listener_keystore").strip()), password.toCharArray()));
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        }
        if (p.containsKey("dnssec")) withUseDnsSec(bool(p, "dnssec"));
        if (p.containsKey("stats_prefix")) {
            withStats(StatsRegistry.builder().prefix(p.getProperty("stats_prefix")).build());
        } else if (bool(p, "metrics")) {
            withMetrics(true);
        }
        if (bool(p, "dnssec") && p.containsKey("dnssec_resolver")) {
            withServerResolver(DnssecHostResolver.builder().resolver(p.getProperty("dnssec_resolver")).build());
        }
        if (p.containsKey("activity_log_format")) {
            plusActivityTracker(new ActivityLogger(LogFormat.valueOf(
                    p.getProperty("activity_log_format").strip().toUpperCase(Locale.ROOT))));
        }
        if (p.containsKey("access_log") || p.containsKey("access_log_format") || p.containsKey("access_log_json")
                || p.containsKey("access_log_filter")) {
            if (p.containsKey("access_log_format") && p.containsKey("access_log_json")) {
                throw new IllegalArgumentException("access_log_format and access_log_json are exclusive");
            }
            ActivityLogger.Builder logger = ActivityLogger.builder();
            if (p.containsKey("access_log_format")) logger.format(LogFormat.parse(p.getProperty("access_log_format")));
            if (p.containsKey("access_log_json")) {
                logger.format(org.microproxy.extras.AccessLogFormat.envoyJson(p.getProperty("access_log_json")));
            }
            if (p.containsKey("access_log_filter")) {
                logger.filter(org.microproxy.extras.AccessLogFilter.parse(p.getProperty("access_log_filter")));
            }
            // Flushed line by line: a file left open until the process exits loses nothing.
            if (p.containsKey("access_log")) {
                logger.sink(org.microproxy.extras.AccessLogWriter.of(p.getProperty("access_log")));
            }
            plusActivityTracker(logger.build());
        }
        if (p.containsKey("max_concurrent_per_client")) {
            int n = Integer.parseInt(p.getProperty("max_concurrent_per_client").strip());
            if (n <= 0) throw new IllegalArgumentException("max_concurrent_per_client must be positive: " + n);
            // Before the other filters, so they do no work for refused requests.
            withFiltersSource(HttpFiltersChain.of(ConcurrencyLimiter.builder().permits(n).build(), filtersSource));
        }
        if (p.containsKey("log_http")) {
            String level = p.getProperty("log_http").strip();
            String format = p.getProperty("log_http_format", "text").strip();
            HttpLogger.Builder builder;
            try {
                builder = HttpLogger.builder()
                        .level(HttpLogger.Level.valueOf(level.toUpperCase(Locale.ROOT)))
                        .format(HttpLogger.Format.valueOf(format.toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("unknown log_http=" + level + " or log_http_format=" + format
                        + "; expected basic, headers or body, and text or json");
            }
            if (p.containsKey("proto_descriptors")) {
                Path descriptors = Path.of(p.getProperty("proto_descriptors").strip());
                try {
                    builder.contentViews(ContentViews.defaults().withSchema(ProtoSchema.load(descriptors)));
                } catch (IOException e) {
                    throw new IllegalArgumentException("proto_descriptors=" + descriptors + ": " + e.getMessage(), e);
                }
            }
            if (p.containsKey("log_http_view")) {
                builder.contentView(p.getProperty("log_http_view").strip());
            } else if (p.containsKey("proto_descriptors")) {
                builder.contentView(ContentViews.AUTO);
            }
            HttpLogger logger = builder.build();
            // First among the filters, so it sees requests as clients sent them.
            withFiltersSource(HttpFiltersChain.of(logger, filtersSource));
        }
        if (p.containsKey("cache_dir") || p.containsKey("cache_memory_mb") || bool(p, "offline")) {
            HttpCache.Builder cache = HttpCache.builder().offline(bool(p, "offline"));
            if (p.containsKey("cache_dir")) {
                long mb = Long.parseLong(p.getProperty("cache_max_mb", "1024").strip());
                try {
                    cache.store(new DiskCacheStore(
                            Path.of(p.getProperty("cache_dir").strip()), mb << 20));
                } catch (IOException e) {
                    throw new UncheckedIOException("cannot open cache_dir", e);
                }
            } else if (p.containsKey("cache_memory_mb")) {
                cache.store(new MemoryCacheStore(
                        Long.parseLong(p.getProperty("cache_memory_mb").strip()) << 20));
            }
            if (p.containsKey("cache_max_entry_mb")) {
                cache.maxEntrySize(Integer.parseInt(p.getProperty("cache_max_entry_mb").strip()) << 20);
            }
            withHttpCache(cache.build());
        }
        if (p.containsKey("drain_time")) withDrainTime(Duration.ofSeconds(Long.parseLong(p.getProperty("drain_time").strip())));
        if (p.containsKey("drain_strategy")) withDrainStrategy(DrainStrategy.parse(p.getProperty("drain_strategy")));
        if (p.containsKey("health_check_path")) {
            withHealthCheckPath(p.getProperty("health_check_path").strip(), bool(p, "health_check_pass_through"));
        }
        if (p.containsKey("admin_port")) {
            withAdmin(new InetSocketAddress(DefaultHttpProxyServer.loopback(),
                    Integer.parseInt(p.getProperty("admin_port").strip())));
        }
        if (p.containsKey("admin_address")) withAdmin(parseAddress(p.getProperty("admin_address")));
        if (p.containsKey("admin_token")) withAdminToken(p.getProperty("admin_token").strip());
        long read = Long.parseLong(p.getProperty("throttle_read_bytes_per_second", "0").strip());
        long write = Long.parseLong(p.getProperty("throttle_write_bytes_per_second", "0").strip());
        withThrottling(read, write);
    }

    private static boolean bool(Properties p, String key) {
        String v = p.getProperty(key, "").strip();
        return v.equalsIgnoreCase("true") || v.equalsIgnoreCase("on") || v.equals("1");
    }

    static InetSocketAddress parseAddress(String text) {
        String t = text.strip();
        if (t.endsWith(":0")) {
            // Port 0 (any free port) is fine for listening, though not in a request's authority.
            String host = t.substring(0, t.length() - 2);
            if (host.startsWith("[") || host.indexOf(':') < 0) {
                return new InetSocketAddress(HostAndPort.parse(host, 8080).host(), 0);
            }
        }
        HostAndPort hp = HostAndPort.parse(t, 8080);
        return new InetSocketAddress(hp.host(), hp.port());
    }

    InetSocketAddress address() {
        if (requestedAddress != null) return requestedAddress;
        return allowLocalOnly
                ? new InetSocketAddress(DefaultHttpProxyServer.loopback(), port)
                : new InetSocketAddress(port);
    }

    @Override
    public HttpProxyServerBootstrap withName(String name) {
        this.name = Objects.requireNonNull(name);
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withAddress(InetSocketAddress address) {
        this.requestedAddress = address;
        if (address != null) this.port = address.getPort();
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withPort(int port) {
        this.port = port;
        this.requestedAddress = null;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withAllowLocalOnly(boolean allowLocalOnly) {
        this.allowLocalOnly = allowLocalOnly;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withSslContextSource(SslContextSource sslContextSource) {
        this.sslContextSource = sslContextSource;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withAuthenticateSslClients(boolean authenticateSslClients) {
        this.authenticateSslClients = authenticateSslClients;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withProxyAuthenticator(ProxyAuthenticator proxyAuthenticator) {
        this.proxyAuthenticator = proxyAuthenticator;
        return this;
    }

    @Override
    public ChainedProxyManager getChainProxyManager() {
        return chainProxyManager;
    }

    @Override
    public HttpProxyServerBootstrap withChainProxyManager(ChainedProxyManager chainProxyManager) {
        this.chainProxyManager = chainProxyManager;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withManInTheMiddle(MitmManager mitmManager) {
        this.mitmManager = mitmManager;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withHttpCache(HttpCache cache) {
        this.httpCache = cache;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withStats(StatsRegistry registry) {
        this.stats = Objects.requireNonNull(registry, "registry");
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withMetrics(boolean enabled) {
        if (!enabled) {
            stats = StatsRegistry.NOOP;
        } else if (!stats.enabled()) {
            stats = StatsRegistry.create();
        }
        return this;
    }

    @Override
    public StatsRegistry getStats() {
        return stats;
    }

    @Override
    public HttpProxyServerBootstrap withTracer(FlowTracer tracer) {
        this.tracer = Objects.requireNonNull(tracer, "tracer");
        return this;
    }

    @Override
    public FlowTracer getTracer() {
        return tracer;
    }

    @Override
    public HttpFiltersSource getFiltersSource() {
        return filtersSource;
    }

    @Override
    public HttpProxyServerBootstrap plusFiltersSource(HttpFiltersSource filtersSource) {
        this.filtersSource = HttpFiltersChain.of(this.filtersSource, filtersSource);
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withFiltersSource(HttpFiltersSource filtersSource) {
        this.filtersSource = Objects.requireNonNullElseGet(filtersSource, HttpFiltersSourceAdapter::new);
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withFailureResponder(FailureResponder responder) {
        this.failureResponder = responder;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withTransparent(boolean transparent) {
        this.transparent = transparent;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withTransparentTlsPort(int port) {
        if (port < 1 || port > 65535) throw new IllegalArgumentException("invalid port: " + port);
        this.transparentTlsPort = port;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withTransparentQuicPort(int port) {
        if (port < 0 || port > 65535) throw new IllegalArgumentException("invalid port: " + port);
        this.transparentQuicPort = port;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withIgnoreHosts(String... patterns) {
        List<String> rules = List.of(patterns);
        HostRules.compile(rules);
        this.ignoreHosts = rules;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withAllowHosts(String... patterns) {
        List<String> rules = List.of(patterns);
        HostRules.compile(rules);
        this.allowHosts = rules;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withTcpHosts(String... patterns) {
        List<String> rules = List.of(patterns);
        HostRules.compile(rules);
        this.tcpHosts = rules;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withQuicHosts(String... patterns) {
        List<String> rules = List.of(patterns);
        HostRules.compile(rules);
        this.quicHosts = rules;
        return this;
    }

    /**
     * The UDP ports of a comma-separated list ({@code 443,8443}), as {@code masque_quic_ports} and
     * {@code --masque-quic-ports} give them; {@code any} (or nothing) for every port.
     *
     * @throws IllegalArgumentException if an entry is not a port
     */
    static int[] parsePorts(String list) {
        String trimmed = list.strip();
        if (trimmed.isEmpty() || trimmed.equalsIgnoreCase("any")) return new int[0];
        String[] parts = trimmed.split(",");
        int[] ports = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            try {
                ports[i] = Integer.parseInt(parts[i].strip());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("not a UDP port: " + parts[i].strip());
            }
        }
        return ports;
    }

    @Override
    public HttpProxyServerBootstrap withReverseProxy(ReverseProxyMode mode) {
        this.reverseProxy = mode;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withSocksServer(boolean socks) {
        this.socksServer = socks;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withSocksDetection(boolean detect) {
        this.socksDetection = detect;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withKeepHostHeader(boolean keep) {
        this.keepHostHeader = keep;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withIdleConnectionTimeout(int idleConnectionTimeoutInSeconds) {
        return withIdleConnectionTimeout(Duration.ofSeconds(Math.max(0, idleConnectionTimeoutInSeconds)));
    }

    @Override
    public HttpProxyServerBootstrap withIdleConnectionTimeout(Duration idleConnectionTimeout) {
        this.idleConnectionTimeout = idleConnectionTimeout == null ? Duration.ZERO : idleConnectionTimeout;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withConnectTimeout(int connectTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withLittleProxyCompatibility(boolean compatible) {
        this.littleProxyCompatibility = compatible;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withTlsHandshakeTimeout(Duration timeout) {
        if (timeout.isNegative()) throw new IllegalArgumentException("negative TLS handshake timeout");
        this.tlsHandshakeTimeout = timeout;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withChainedProxyRetryBackoff(RetryBackoff backoff) {
        chainedProxyBackoff = backoff == null ? RetryBackoff.none() : backoff;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withStrippedRequestHeaders(String... names) {
        strippedRequestHeaders.clear();
        return plusStrippedRequestHeaders(names);
    }

    @Override
    public HttpProxyServerBootstrap plusStrippedRequestHeaders(String... names) {
        for (String name : names) {
            String n = Objects.requireNonNull(name, "header name").strip();
            if (n.isEmpty()) continue;
            if (!n.chars().allMatch(c -> c > ' ' && c < 127 && "\"(),/:;<=>?@[\\]{}".indexOf(c) < 0)) {
                throw new IllegalArgumentException("not a header name: " + n);
            }
            strippedRequestHeaders.putIfAbsent(n.toLowerCase(Locale.ROOT), n);
        }
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withAltSvcH3Stripping(boolean strip) {
        this.altSvcH3Stripping = strip;
        return this;
    }

    /**
     * Whether HTTP/3 alternatives are removed from Alt-Svc for clients of the explicit proxy: as
     * configured, else whenever traffic is intercepted or the proxy is transparent, where a client
     * moving to QUIC would bypass it.
     */
    boolean stripsAltSvcH3() {
        return altSvcH3Stripping != null ? altSvcH3Stripping : mitmManager != null || transparent;
    }

    /**
     * Whether HTTP/3 alternatives are removed from Alt-Svc for clients whose traffic was redirected
     * to the proxy (transparent TLS, HTTP routed by Host, transparent QUIC): as for the explicit
     * proxy's, except that by default, with a transparent QUIC listener, the QUIC such clients move
     * to reaches the proxy too.
     */
    boolean stripsAltSvcH3ForTransparent() {
        return altSvcH3Stripping != null ? altSvcH3Stripping : stripsAltSvcH3() && transparentQuicPort < 0;
    }

    @Override
    public HttpProxyServerBootstrap withHttp2(boolean enabled) {
        this.http2 = enabled;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withHttp2Upstream(boolean enabled) {
        this.http2Upstream = enabled;
        return this;
    }

    /**
     * Whether intercepted TLS and the TLS listener offer clients HTTP/2: as configured, else
     * whenever the http2-codec module is present.
     */
    boolean offersHttp2() {
        return http2 != null ? http2 : Http2Support.available();
    }

    /**
     * Whether TLS connections to servers offer HTTP/2: as configured, else whenever the
     * http2-codec module is present.
     */
    boolean offersHttp2Upstream() {
        return http2Upstream != null ? http2Upstream : Http2Support.available();
    }

    @Override
    public HttpProxyServerBootstrap withHttp2Cleartext(boolean enabled) {
        this.http2Cleartext = enabled;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withHttp2CleartextOnly(boolean enabled) {
        this.http2CleartextOnly = enabled;
        return this;
    }

    @Override
    public Http2Options getHttp2Options() {
        return http2Options;
    }

    @Override
    public HttpProxyServerBootstrap withHttp2Options(Http2Options options) {
        this.http2Options = options == null ? Http2Options.DEFAULT : options;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withHttp3(boolean enabled) {
        this.http3 = enabled;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withConnectUdp(boolean enabled) {
        this.connectUdp = enabled;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withHttp3Upstream(boolean enabled) {
        this.http3Upstream = enabled;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withHttp3UpstreamHosts(String... patterns) {
        List<String> rules = List.of(patterns);
        HostRules.compile(rules);
        this.http3UpstreamHosts = rules;
        return this;
    }

    @Override
    public Http3Options getHttp3Options() {
        return http3Options;
    }

    @Override
    public HttpProxyServerBootstrap withHttp3Options(Http3Options options) {
        this.http3Options = options == null ? Http3Options.DEFAULT : options;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withFrameInterceptor(FrameInterceptor interceptor) {
        this.frameInterceptor = interceptor;
        return this;
    }

    @Override
    public FrameInterceptor getFrameInterceptor() {
        return frameInterceptor;
    }

    @Override
    public HttpProxyServerBootstrap withScriptCallObserver(ScriptCallObserver observer) {
        this.scriptCallObserver = observer;
        return this;
    }

    @Override
    public ScriptCallObserver getScriptCallObserver() {
        return scriptCallObserver;
    }

    @Override
    public HttpProxyServerBootstrap withTcpInterceptor(TcpInterceptor interceptor) {
        this.tcpInterceptor = interceptor;
        return this;
    }

    @Override
    public TcpInterceptor getTcpInterceptor() {
        return tcpInterceptor;
    }

    @Override
    public HttpProxyServerBootstrap withUdpInterceptor(UdpInterceptor interceptor) {
        this.udpInterceptor = interceptor;
        return this;
    }

    @Override
    public UdpInterceptor getUdpInterceptor() {
        return udpInterceptor;
    }

    @Override
    public HttpProxyServerBootstrap withQuicInterceptor(QuicInterceptor interceptor) {
        this.quicInterceptor = interceptor;
        return this;
    }

    @Override
    public QuicInterceptor getQuicInterceptor() {
        return quicInterceptor;
    }

    @Override
    public HttpProxyServerBootstrap withQuicFraming(QuicFraming framing) {
        this.quicFraming = Objects.requireNonNull(framing, "framing");
        return this;
    }

    @Override
    public QuicFraming getQuicFraming() {
        return quicFraming;
    }

    @Override
    public HttpProxyServerBootstrap withTlsProtocols(String... protocols) {
        List<String> chosen = new ArrayList<>();
        for (String protocol : protocols) {
            String p = Objects.requireNonNull(protocol, "protocol").strip();
            if (!p.isEmpty() && !chosen.contains(p)) chosen.add(p);
        }
        this.tlsProtocols = List.copyOf(chosen);
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withServerResolver(HostResolver serverResolver) {
        this.serverResolver = Objects.requireNonNull(serverResolver);
        return this;
    }

    @Override
    public HttpProxyServerBootstrap plusActivityTracker(ActivityTracker activityTracker) {
        activityTrackers.add(Objects.requireNonNull(activityTracker));
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withThrottling(long readThrottleBytesPerSecond, long writeThrottleBytesPerSecond) {
        this.readThrottleBytesPerSecond = readThrottleBytesPerSecond;
        this.writeThrottleBytesPerSecond = writeThrottleBytesPerSecond;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withNetworkInterface(InetSocketAddress inetSocketAddress) {
        this.localAddress = inetSocketAddress;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withMaxInitialLineLength(int maxInitialLineLength) {
        this.maxInitialLineLength = positive(maxInitialLineLength);
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withMaxHeaderSize(int maxHeaderSize) {
        this.maxHeaderSize = positive(maxHeaderSize);
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withMaxChunkSize(int maxChunkSize) {
        this.maxChunkSize = positive(maxChunkSize);
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withAllowRequestToOriginServer(boolean allowRequestToOriginServer) {
        this.allowRequestToOriginServer = allowRequestToOriginServer;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withTlsOrigination(boolean enabled) {
        this.tlsOrigination = enabled;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withProxyAlias(String alias) {
        this.proxyAlias = alias;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withAcceptProxyProtocol(boolean acceptProxyProtocol) {
        this.acceptProxyProtocol = acceptProxyProtocol;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withSendProxyProtocol(boolean sendProxyProtocol) {
        this.sendProxyProtocol = sendProxyProtocol;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withMaxWebSocketFrameBufferSize(int maxBytes) {
        if (maxBytes < 0) throw new IllegalArgumentException("must not be negative: " + maxBytes);
        this.maxWebSocketFrameBufferSize = maxBytes;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withMaxWebSocketMessageSize(int maxBytes) {
        if (maxBytes <= 0) throw new IllegalArgumentException("must be positive: " + maxBytes);
        this.maxWebSocketMessageSize = maxBytes;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withSharedServerConnectionPool(boolean useSharedServerConnectionPool) {
        this.sharedServerConnectionPool = useSharedServerConnectionPool;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withServerConnectionPoolType(ServerConnectionPoolType poolType) {
        this.serverConnectionPoolType = Objects.requireNonNull(poolType);
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withMaxConnectionsPerHost(int maxConnectionsPerHost) {
        this.maxConnectionsPerHost = positive(maxConnectionsPerHost);
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withMaxConnections(int maxConnections) {
        this.maxConnections = positive(maxConnections);
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withPoolIdleTimeout(Duration idleTimeout) {
        this.poolIdleTimeout = idleTimeout;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withPoolSharedMitmConnections(boolean poolSharedMitmConnections) {
        this.poolSharedMitmConnections = poolSharedMitmConnections;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withPoolPerRequestInMitm(boolean poolPerRequestInMitm) {
        this.poolPerRequestInMitm = poolPerRequestInMitm;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withUseDnsSec(boolean useDnsSec) {
        this.serverResolver = useDnsSec ? new DnssecHostResolver() : new DefaultHostResolver();
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withDrainTime(Duration drainTime) {
        if (Objects.requireNonNull(drainTime, "drainTime").isNegative()) {
            throw new IllegalArgumentException("the drain time must not be negative: " + drainTime);
        }
        this.drainTime = drainTime;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withDrainStrategy(DrainStrategy strategy) {
        this.drainStrategy = Objects.requireNonNull(strategy, "strategy");
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withHealthCheckPath(String path, boolean passThrough) {
        if (path != null && !path.startsWith("/")) {
            throw new IllegalArgumentException("a health-check path starts with /: " + path);
        }
        this.healthCheckPath = path;
        this.healthCheckPassThrough = passThrough;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withAdmin(InetSocketAddress address) {
        this.adminAddress = address;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withAdminToken(String token) {
        if (token != null && token.isEmpty()) throw new IllegalArgumentException("the admin token is empty");
        this.adminToken = token;
        return this;
    }

    @Override
    public HttpProxyServerBootstrap withCommandLineOptions(List<String> options) {
        this.commandLineOptions = List.copyOf(options);
        return this;
    }

    @Override
    public HttpProxyServer start() {
        return new DefaultHttpProxyServer(copy()).start();
    }

    private static int positive(int v) {
        if (v <= 0) throw new IllegalArgumentException("must be positive: " + v);
        return v;
    }
}
