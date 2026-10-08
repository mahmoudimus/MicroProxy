package org.microproxy;

import java.net.InetSocketAddress;
import java.time.Duration;

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

    HttpProxyServerBootstrap withProxyAuthenticator(ProxyAuthenticator proxyAuthenticator);

    HttpProxyServerBootstrap withChainProxyManager(ChainedProxyManager chainProxyManager);

    HttpProxyServerBootstrap withManInTheMiddle(MitmManager mitmManager);

    HttpProxyServerBootstrap withFiltersSource(HttpFiltersSource filtersSource);

    /** Forward messages without adding {@code Via} or stripping hop-by-hop headers. */
    HttpProxyServerBootstrap withTransparent(boolean transparent);

    HttpProxyServerBootstrap withIdleConnectionTimeout(int idleConnectionTimeoutInSeconds);

    HttpProxyServerBootstrap withIdleConnectionTimeout(Duration idleConnectionTimeout);

    /** Connect timeout for outbound connections in milliseconds. */
    HttpProxyServerBootstrap withConnectTimeout(int connectTimeoutMs);

    HttpProxyServerBootstrap withServerResolver(HostResolver serverResolver);

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

    /** Send a PROXY protocol v1 header on every outbound connection. */
    HttpProxyServerBootstrap withSendProxyProtocol(boolean sendProxyProtocol);

    HttpProxyServer start();
}
