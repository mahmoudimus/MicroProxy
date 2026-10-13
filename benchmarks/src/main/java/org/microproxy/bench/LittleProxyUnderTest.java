package org.microproxy.bench;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import java.net.InetSocketAddress;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.littleshoot.proxy.HttpFilters;
import org.littleshoot.proxy.HttpFiltersAdapter;
import org.littleshoot.proxy.HttpFiltersSourceAdapter;
import org.littleshoot.proxy.HttpProxyServer;
import org.littleshoot.proxy.HttpProxyServerBootstrap;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;
import org.littleshoot.proxy.impl.ThreadPoolConfiguration;

/**
 * LittleProxy, configured as {@link ProxyUnderTest} describes. Its Netty event-loop sizes are
 * LittleProxy's defaults unless the system property {@code bench.littleproxy.workers} sets both
 * worker pools' size.
 */
final class LittleProxyUnderTest implements ProxyUnderTest {

    /** Sets both of LittleProxy's worker pools to this many event loops, when positive. */
    static final String WORKERS_PROPERTY = "bench.littleproxy.workers";

    /**
     * Netty does not log through SLF4J's no-op provider, which it skips, but through {@code
     * java.util.logging}: warnings only, as for MicroProxy. Held here so the setting is not
     * collected.
     */
    private static final Logger NETTY_LOGGER = Logger.getLogger("io.netty");

    static {
        NETTY_LOGGER.setLevel(Level.WARNING);
    }

    private final HttpProxyServer server;

    private LittleProxyUnderTest(HttpProxyServer server) {
        this.server = server;
    }

    static LittleProxyUnderTest start(Options options) {
        HttpProxyServerBootstrap bootstrap = DefaultHttpProxyServer.bootstrap()
                .withName("littleproxy-bench")
                .withAddress(ProxyUnderTest.listenAddress())
                .withIdleConnectionTimeout(IDLE_TIMEOUT)
                .withConnectTimeout(CONNECT_TIMEOUT_MILLIS)
                .withMaxInitialLineLength(MAX_INITIAL_LINE_LENGTH)
                .withMaxHeaderSize(MAX_HEADER_SIZE)
                .withMaxChunkSize(MAX_CHUNK_SIZE)
                .withProxyAlias(ALIAS);
        int workers = Integer.getInteger(WORKERS_PROPERTY, 0);
        if (workers > 0) {
            bootstrap.withThreadPoolConfiguration(new ThreadPoolConfiguration()
                    .withClientToProxyWorkerThreads(workers)
                    .withProxyToServerWorkerThreads(workers));
        }
        if (options.mitm() != null) bootstrap.withManInTheMiddle(new LittleProxyMitmManager(options.mitm()));
        if (options.filter()) bootstrap.withFiltersSource(new Filters());
        return new LittleProxyUnderTest(bootstrap.start());
    }

    @Override
    public InetSocketAddress address() {
        return server.getListenAddress();
    }

    /**
     * Stops LittleProxy gracefully: aborting shuts its event loops down under connections that are
     * still closing, and Netty reports each of their listeners as rejected. Not measured.
     */
    @Override
    public void close() {
        server.stop();
    }

    @Override
    public String toString() {
        return LITTLEPROXY + " " + address();
    }

    /** The benchmark filter: one request header in, one response header out. */
    private static final class Filters extends HttpFiltersSourceAdapter {
        @Override
        public HttpFilters filterRequest(HttpRequest originalRequest, ChannelHandlerContext ctx) {
            return new HttpFiltersAdapter(originalRequest, ctx) {
                @Override
                public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                    if (httpObject instanceof HttpRequest request) request.headers().add(FILTER_REQUEST_HEADER, "1");
                    return null;
                }

                @Override
                public HttpObject proxyToClientResponse(HttpObject httpObject) {
                    if (httpObject instanceof HttpResponse response) response.headers().add(FILTER_RESPONSE_HEADER, "1");
                    return httpObject;
                }
            };
        }
    }
}
