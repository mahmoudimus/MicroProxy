package org.microproxy.impl;

import java.io.IOException;
import java.io.Reader;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import org.microproxy.ActivityTracker;
import org.microproxy.ChainedProxyManager;
import org.microproxy.DefaultHostResolver;
import org.microproxy.HostResolver;
import org.microproxy.HttpFiltersSource;
import org.microproxy.HttpFiltersSourceAdapter;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MitmManager;
import org.microproxy.ProxyAuthenticator;
import org.microproxy.SslContextSource;

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
        long read = Long.parseLong(p.getProperty("throttle_read_bytes_per_second", "0").strip());
        long write = Long.parseLong(p.getProperty("throttle_write_bytes_per_second", "0").strip());
        withThrottling(read, write);
    }

    private static boolean bool(Properties p, String key) {
        String v = p.getProperty(key, "").strip();
        return v.equalsIgnoreCase("true") || v.equalsIgnoreCase("on") || v.equals("1");
    }

    static InetSocketAddress parseAddress(String text) {
        HostAndPort hp = HostAndPort.parse(text.strip(), 8080);
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
    public HttpProxyServerBootstrap withFiltersSource(HttpFiltersSource filtersSource) {
        this.filtersSource = filtersSource == null ? new HttpFiltersSourceAdapter() : filtersSource;
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
    public HttpProxyServer start() {
        return new DefaultHttpProxyServer(copy()).start();
    }

    private static int positive(int v) {
        if (v <= 0) throw new IllegalArgumentException("must be positive: " + v);
        return v;
    }
}
