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
import org.microproxy.HostResolver;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpFiltersSource;
import org.microproxy.HttpFiltersSourceAdapter;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MitmManager;
import org.microproxy.ProxyAuthenticator;
import org.microproxy.NoProxyRules;
import org.microproxy.ServerConnectionPoolType;
import org.microproxy.UpstreamProxyManager;
import org.microproxy.SslContextSource;
import org.microproxy.cache.DiskCacheStore;
import org.microproxy.cache.HttpCache;
import org.microproxy.cache.MemoryCacheStore;
import org.microproxy.dns.DnssecHostResolver;
import org.microproxy.extras.ActivityLogger;
import org.microproxy.extras.LogFormat;

/** Default {@link HttpProxyServerBootstrap}. */
public final class DefaultHttpProxyServerBootstrap implements HttpProxyServerBootstrap {

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
    boolean transparent;
    Duration idleConnectionTimeout = Duration.ofSeconds(70);
    int connectTimeoutMs = 40_000;
    HostResolver serverResolver = new DefaultHostResolver();
    final List<ActivityTracker> activityTrackers = new ArrayList<>();
    long readThrottleBytesPerSecond;
    long writeThrottleBytesPerSecond;
    InetSocketAddress localAddress;
    int maxInitialLineLength = 8192;
    int maxHeaderSize = 16384;
    int maxChunkSize = 16384;
    boolean allowRequestToOriginServer;
    String proxyAlias;
    boolean acceptProxyProtocol;
    boolean sendProxyProtocol;
    int maxWebSocketFrameBufferSize = 1 << 20;
    boolean sharedServerConnectionPool;
    ServerConnectionPoolType serverConnectionPoolType = ServerConnectionPoolType.CONCURRENT_MAP;
    int maxConnectionsPerHost = 10;
    int maxConnections = 200;
    Duration poolIdleTimeout;
    boolean poolSharedMitmConnections;
    boolean poolPerRequestInMitm;

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
        c.transparent = transparent;
        c.idleConnectionTimeout = idleConnectionTimeout;
        c.connectTimeoutMs = connectTimeoutMs;
        c.serverResolver = serverResolver;
        c.activityTrackers.addAll(activityTrackers);
        c.readThrottleBytesPerSecond = readThrottleBytesPerSecond;
        c.writeThrottleBytesPerSecond = writeThrottleBytesPerSecond;
        c.localAddress = localAddress;
        c.maxInitialLineLength = maxInitialLineLength;
        c.maxHeaderSize = maxHeaderSize;
        c.maxChunkSize = maxChunkSize;
        c.allowRequestToOriginServer = allowRequestToOriginServer;
        c.proxyAlias = proxyAlias;
        c.acceptProxyProtocol = acceptProxyProtocol;
        c.sendProxyProtocol = sendProxyProtocol;
        c.maxWebSocketFrameBufferSize = maxWebSocketFrameBufferSize;
        c.sharedServerConnectionPool = sharedServerConnectionPool;
        c.serverConnectionPoolType = serverConnectionPoolType;
        c.maxConnectionsPerHost = maxConnectionsPerHost;
        c.maxConnections = maxConnections;
        c.poolIdleTimeout = poolIdleTimeout;
        c.poolSharedMitmConnections = poolSharedMitmConnections;
        c.poolPerRequestInMitm = poolPerRequestInMitm;
        return c;
    }

    /** Reads the keys documented in the README from a properties file. */
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
        if (p.containsKey("idle_connection_timeout")) {
            withIdleConnectionTimeout(Integer.parseInt(p.getProperty("idle_connection_timeout").strip()));
        }
        if (p.containsKey("connect_timeout")) {
            withConnectTimeout(Integer.parseInt(p.getProperty("connect_timeout").strip()));
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
        if (p.containsKey("dnssec")) withUseDnsSec(bool(p, "dnssec"));
        if (bool(p, "dnssec") && p.containsKey("dnssec_resolver")) {
            withServerResolver(DnssecHostResolver.builder().resolver(p.getProperty("dnssec_resolver")).build());
        }
        if (p.containsKey("activity_log_format")) {
            plusActivityTracker(new ActivityLogger(LogFormat.valueOf(
                    p.getProperty("activity_log_format").strip().toUpperCase(Locale.ROOT))));
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
    public HttpProxyServerBootstrap withTransparent(boolean transparent) {
        this.transparent = transparent;
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
    public HttpProxyServer start() {
        return new DefaultHttpProxyServer(copy()).start();
    }

    private static int positive(int v) {
        if (v <= 0) throw new IllegalArgumentException("must be positive: " + v);
        return v;
    }
}
