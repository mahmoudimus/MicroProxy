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
                b.acceptProxyProtocol, b.sendProxyProtocol, b.authenticateSslClients, b.chainProxyManager,
                b.mitmManager, b.filtersSource, b.httpCache, b.serverResolver, List.copyOf(b.activityTrackers),
                b.sharedServerConnectionPool, b.serverConnectionPoolType, b.maxConnectionsPerHost, b.maxConnections,
                b.poolIdleTimeout, b.poolSharedMitmConnections, b.poolPerRequestInMitm, b.maxInitialLineLength,
                b.maxHeaderSize, b.maxChunkSize, b.localAddress, b.allowRequestToOriginServer);
    }

    /** The headers removed from requests sent upstream, as configured. */
    public static List<String> strippedRequestHeaders(HttpProxyServerBootstrap bootstrap) {
        return List.copyOf(((DefaultHttpProxyServerBootstrap) bootstrap).strippedRequestHeaders.values());
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
