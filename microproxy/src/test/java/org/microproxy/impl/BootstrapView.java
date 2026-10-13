package org.microproxy.impl;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import org.microproxy.ActivityTracker;
import org.microproxy.ChainedProxyManager;
import org.microproxy.HostResolver;
import org.microproxy.HttpFiltersSource;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MitmManager;
import org.microproxy.ReverseProxyMode;
import org.microproxy.ServerConnectionPoolType;
import org.microproxy.cache.HttpCache;

/**
 * A read-only snapshot of a {@link DefaultHttpProxyServerBootstrap}'s settings, so tests outside
 * this package (such as the launcher's) can check what a command line or properties file
 * configured without starting a server.
 */
public record BootstrapView(
        String name,
        InetSocketAddress address,
        boolean allowLocalOnly,
        boolean transparent,
        Duration idleConnectionTimeout,
        int connectTimeoutMs,
        String proxyAlias,
        long readThrottle,
        long writeThrottle,
        boolean acceptProxyProtocol,
        boolean sendProxyProtocol,
        boolean authenticateSslClients,
        ChainedProxyManager chainProxyManager,
        MitmManager mitmManager,
        HttpFiltersSource filtersSource,
        HttpCache httpCache,
        HostResolver serverResolver,
        List<ActivityTracker> activityTrackers,
        boolean sharedServerConnectionPool,
        ServerConnectionPoolType poolType,
        int maxConnectionsPerHost,
        int maxConnections,
        Duration poolIdleTimeout,
        boolean poolSharedMitmConnections,
        boolean poolPerRequestInMitm,
        int maxInitialLineLength,
        int maxHeaderSize,
        int maxChunkSize,
        InetSocketAddress networkInterface,
        boolean allowRequestToOriginServer) {

    public static BootstrapView of(HttpProxyServerBootstrap bootstrap) {
        DefaultHttpProxyServerBootstrap b = (DefaultHttpProxyServerBootstrap) bootstrap;
        return new BootstrapView(b.name, b.address(), b.allowLocalOnly, b.transparent, b.idleConnectionTimeout,
                b.connectTimeoutMs, b.proxyAlias, b.readThrottleBytesPerSecond, b.writeThrottleBytesPerSecond,
                b.proxyProtocolMode != org.microproxy.ProxyProtocolMode.OFF, b.sendProxyProtocol, b.authenticateSslClients, b.chainProxyManager,
                b.mitmManager, b.filtersSource, b.httpCache, b.serverResolver, List.copyOf(b.activityTrackers),
                b.sharedServerConnectionPool, b.serverConnectionPoolType, b.maxConnectionsPerHost, b.maxConnections,
                b.poolIdleTimeout, b.poolSharedMitmConnections, b.poolPerRequestInMitm, b.maxInitialLineLength,
                b.maxHeaderSize, b.maxChunkSize, b.localAddress, b.allowRequestToOriginServer);
    }

    /** Whether the listener serves SOCKS clients only ({@code withSocksServer}, {@code socks5} mode). */
    public static boolean socksServer(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).socksServer;
    }

    /** Whether client connections start with a PROXY header ({@code withAcceptProxyProtocol}). */
    public static org.microproxy.ProxyProtocolMode proxyProtocolMode(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).proxyProtocolMode;
    }

    /** The peers whose PROXY headers count ({@code withProxyProtocolTrustedSources}); empty for all. */
    public static List<String> proxyProtocolTrustedSources(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).proxyProtocolTrustedSources.entries();
    }

    /** Whether requests with both Transfer-Encoding and Content-Length are accepted ({@code withAllowChunkedLength}). */
    public static boolean allowChunkedLength(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).allowChunkedLength;
    }

    /** Whether the listener serves SOCKS clients besides HTTP ones ({@code withSocksDetection}). */
    public static boolean socksDetection(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).socksDetection;
    }

    /** Whether HTTP/2 to clients is in effect ({@code withHttp2}, on by default with the codec). */
    public static boolean http2(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).offersHttp2();
    }

    /** HTTP/2 to clients as configured ({@code withHttp2}): null when left at the default. */
    public static Boolean http2Setting(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).http2;
    }

    /** Whether a reverse proxy serves HTTP/3 ({@code withHttp3}). */
    public static boolean http3(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).http3;
    }

    /** Whether CONNECT-UDP is served on the TCP listener without HTTP/3 too ({@code withConnectUdp}). */
    public static boolean connectUdp(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).connectUdp;
    }

    /** Whether HTTP/3 to servers is enabled ({@code withHttp3Upstream}). */
    public static boolean http3Upstream(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).http3Upstream;
    }

    /** The servers reached over HTTP/3 without Alt-Svc ({@code withHttp3UpstreamHosts}). */
    public static java.util.List<String> http3UpstreamHosts(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).http3UpstreamHosts;
    }

    /** The TLS listener's source ({@code withSslContextSource}), or null. */
    public static org.microproxy.SslContextSource sslContextSource(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).sslContextSource;
    }

    /** Whether HTTP/2 to servers is in effect ({@code withHttp2Upstream}, on by default with the codec). */
    public static boolean http2Upstream(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).offersHttp2Upstream();
    }

    /** HTTP/2 to servers as configured ({@code withHttp2Upstream}): null when left at the default. */
    public static Boolean http2UpstreamSetting(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).http2Upstream;
    }

    /** Whether h2c with prior knowledge is enabled ({@code withHttp2Cleartext}). */
    public static boolean http2Cleartext(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).http2Cleartext;
    }

    /** Whether the plain listener serves h2c alone ({@code withHttp2CleartextOnly}). */
    public static boolean http2CleartextOnly(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).http2CleartextOnly;
    }

    /** The headers removed from requests sent upstream, as configured. */
    public static List<String> strippedRequestHeaders(HttpProxyServerBootstrap bootstrap) {
        return List.copyOf(((DefaultHttpProxyServerBootstrap) bootstrap).strippedRequestHeaders.values());
    }

    /** The TLS versions every TLS socket starts with, as configured; empty for the contexts' defaults. */
    public static List<String> tlsProtocols(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).tlsProtocols;
    }

    /** Whether HTTP/3 alternatives would be removed from Alt-Svc response headers, defaults applied. */
    public static boolean stripsAltSvcH3(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).stripsAltSvcH3();
    }

    /** The drain time and strategy as configured ({@code withDrainTime}, {@code withDrainStrategy}). */
    public static Object[] drain(HttpProxyServerBootstrap bootstrap) {
        DefaultHttpProxyServerBootstrap b = (DefaultHttpProxyServerBootstrap) bootstrap;
        return new Object[] {b.drainTime, b.drainStrategy};
    }

    /** The health-check path, and whether it passes through, as configured ({@code withHealthCheckPath}). */
    public static Object[] healthCheck(HttpProxyServerBootstrap bootstrap) {
        DefaultHttpProxyServerBootstrap b = (DefaultHttpProxyServerBootstrap) bootstrap;
        return new Object[] {b.healthCheckPath, b.healthCheckPassThrough};
    }

    /** The admin listener's address and token as configured ({@code withAdmin}, {@code withAdminToken}). */
    public static Object[] admin(HttpProxyServerBootstrap bootstrap) {
        DefaultHttpProxyServerBootstrap b = (DefaultHttpProxyServerBootstrap) bootstrap;
        return new Object[] {b.adminAddress, b.adminToken};
    }

    /** The command line passed for the admin's {@code /server_info} ({@code withCommandLineOptions}). */
    public static List<String> commandLineOptions(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).commandLineOptions;
    }

    /** The chained proxy retry backoff as configured: {initial, max}, both null when off. */
    public static Duration[] chainedProxyBackoff(HttpProxyServerBootstrap bootstrap) {
        DefaultHttpProxyServerBootstrap b = (DefaultHttpProxyServerBootstrap) bootstrap;
        return new Duration[] {b.chainedProxyBackoffInitial, b.chainedProxyBackoffMax};
    }

    /** A running server's chained proxy retry backoff: {initial, max}, both zero when off. */
    public static Duration[] chainedProxyBackoff(HttpProxyServer server) {
        DefaultHttpProxyServer s = (DefaultHttpProxyServer) server;
        return new Duration[] {Duration.ofNanos(s.backoffInitialNanos), Duration.ofNanos(s.backoffMaxNanos)};
    }

    /** The host rules as configured: {ignore patterns, allow patterns}. */
    public static List<List<String>> hostRules(HttpProxyServerBootstrap bootstrap) {
        DefaultHttpProxyServerBootstrap b = (DefaultHttpProxyServerBootstrap) bootstrap;
        return List.of(b.ignoreHosts, b.allowHosts);
    }

    /** The {@code tcp_hosts} patterns, as configured. */
    public static List<String> tcpHosts(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).tcpHosts;
    }

    /** The {@code quic_hosts} patterns, as configured. */
    public static List<String> quicHosts(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).quicHosts;
    }

    /** The reverse proxy upstream as configured, or null. */
    public static ReverseProxyMode reverseProxy(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).reverseProxy;
    }

    /** Whether reverse proxying keeps the client's Host ({@code withKeepHostHeader}). */
    public static boolean keepHostHeader(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).keepHostHeader;
    }

    /** Whether clients' own {@code https://} requests are fetched over TLS ({@code withTlsOrigination}). */
    public static boolean tlsOrigination(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).tlsOrigination;
    }

    /** The port SNI-routed transparent TLS goes to. */
    public static int transparentTlsPort(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).transparentTlsPort;
    }

    /** The transparent QUIC listener's UDP port, -1 for none. */
    public static int transparentQuicPort(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).transparentQuicPort;
    }

    /** The HTTP/3 options as configured. */
    public static org.microproxy.Http3Options http3Options(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).http3Options;
    }

    /** Whether HTTP/3 alternatives would be removed for clients redirected to the proxy, defaults applied. */
    public static boolean stripsAltSvcH3ForTransparent(HttpProxyServerBootstrap bootstrap) {
        return ((DefaultHttpProxyServerBootstrap) bootstrap).stripsAltSvcH3ForTransparent();
    }

    /** Parses a properties text as a properties file would be read. */
    public static HttpProxyServerBootstrap fromProperties(java.util.Properties properties) {
        return DefaultHttpProxyServerBootstrap.fromProperties(properties);
    }

    /** The settings a running server was started with. */
    public static BootstrapView of(HttpProxyServer server) {
        return of(((DefaultHttpProxyServer) server).config);
    }

    /** The server's current throttle rates, which {@link HttpProxyServer#setThrottle} changes. */
    public static long[] currentThrottle(HttpProxyServer server) {
        DefaultHttpProxyServer s = (DefaultHttpProxyServer) server;
        return new long[] {s.readLimiter.rate(), s.writeLimiter.rate()};
    }
}
