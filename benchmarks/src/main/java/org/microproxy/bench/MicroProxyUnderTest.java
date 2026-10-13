package org.microproxy.bench;

import java.net.InetSocketAddress;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersAdapter;
import org.microproxy.HttpFiltersSourceAdapter;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/** MicroProxy, configured as {@link ProxyUnderTest} describes. */
final class MicroProxyUnderTest implements ProxyUnderTest {

    /**
     * MicroProxy logs through {@code java.util.logging}: warnings only, as LittleProxy (through
     * SLF4J's no-op provider) logs nothing. Held here so the setting is not collected.
     */
    private static final Logger LOGGER = Logger.getLogger("org.microproxy");

    static {
        LOGGER.setLevel(Level.WARNING);
    }

    private final HttpProxyServer server;

    private MicroProxyUnderTest(HttpProxyServer server) {
        this.server = server;
    }

    static MicroProxyUnderTest start(Options options) {
        HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap()
                .withName("microproxy-bench")
                .withAddress(ProxyUnderTest.listenAddress())
                .withIdleConnectionTimeout(IDLE_TIMEOUT)
                .withConnectTimeout(CONNECT_TIMEOUT_MILLIS)
                .withMaxInitialLineLength(MAX_INITIAL_LINE_LENGTH)
                .withMaxHeaderSize(MAX_HEADER_SIZE)
                .withMaxChunkSize(MAX_CHUNK_SIZE)
                .withProxyAlias(ALIAS);
        if (options.mitm() != null) {
            // Servers are validated against the benchmark CA, as LittleProxy's manager does.
            bootstrap.withManInTheMiddle(new CertificateAuthorityMitmManager(options.mitm(), options.mitm().clientContext()))
                    // On by default with interception; LittleProxy has no such rewrite.
                    .withAltSvcH3Stripping(false);
        }
        if (options.filter()) bootstrap.withFiltersSource(new Filters());
        return new MicroProxyUnderTest(bootstrap.start());
    }

    @Override
    public InetSocketAddress address() {
        return server.getListenAddress();
    }

    @Override
    public void close() {
        server.abort();
    }

    @Override
    public String toString() {
        return MICROPROXY + " " + address();
    }

    /** The benchmark filter: one request header in, one response header out. */
    private static final class Filters extends HttpFiltersSourceAdapter {
        @Override
        public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
            return new HttpFiltersAdapter(originalRequest, flowContext) {
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
