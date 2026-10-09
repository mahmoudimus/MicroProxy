package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.cache.HttpCache;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/** Where responses sent to clients came from, and the server's own status when it was changed. */
class ResponseSourceTest {

    private HttpServer origin;
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private final Sources sources = new Sources();

    /** Records {@code SOURCE status upstream=...} for each response sent to the client. */
    static final class Sources extends ActivityTrackerAdapter {
        final List<String> sent = new CopyOnWriteArrayList<>();
        final List<Integer> legacy = new CopyOnWriteArrayList<>();

        @Override
        public void responseSentToClient(FlowContext ctx, HttpResponse response, ResponseSource source) {
            String upstream = ctx.upstreamStatus().isPresent() ? String.valueOf(ctx.upstreamStatus().getAsInt()) : "-";
            sent.add(source + " " + response.status().code() + " upstream=" + upstream);
            super.responseSentToClient(ctx, response, source);
        }

        @Override
        public void responseSentToClient(FlowContext ctx, HttpResponse response) {
            legacy.add(response.status().code());
        }

        String await(int n) throws InterruptedException {
            for (int i = 0; i < 200 && sent.size() < n; i++) Thread.sleep(10);
            return sent.get(n - 1);
        }
    }

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(echo());
        origin.createContext("/error", TestSupport.fixed(500, "server broke"));
        origin.createContext("/cacheable", exchange -> {
            exchange.getResponseHeaders().set("Cache-Control", "max-age=60");
            TestSupport.fixed(200, "cached body").handle(exchange);
        });
    }

    @AfterEach
    void tearDown() {
        proxies.close();
        origin.stop(0);
    }

    private HttpProxyServer proxy(HttpFilters filters) {
        HttpProxyServerBootstrap b = MicroProxy.bootstrap().plusActivityTracker(sources);
        if (filters != null) b.withFiltersSource((request, ctx) -> filters);
        return proxies.start(b);
    }

    @Test
    void serverResponsesKeepTheirSourceWhenFiltersOnlyEditHeaders() throws Exception {
        HttpFilters filters = HttpFilters.builder()
                .onResponse(res -> {
                    res.headers().set("X-Edited", "1");
                    return res;
                })
                .build();
        assertEquals(200, get(client(proxy(filters)), url(origin, "/ok")).statusCode());
        assertEquals("SERVER 200 upstream=200", sources.await(1));
        assertEquals(List.of(200), sources.legacy);
    }

    @Test
    void proxyErrorsHaveNoUpstreamStatus() throws Exception {
        int port;
        try (ServerSocket s = new ServerSocket(0, 1, TestSupport.LOOPBACK)) {
            port = s.getLocalPort();
        }
        assertEquals(502, get(client(proxy(null)), "http://127.0.0.1:" + port + "/").statusCode());
        assertEquals("PROXY 502 upstream=-", sources.await(1));
    }

    @Test
    void aFilterThatRewritesAServerErrorIsTheSourceAndTheUpstreamStatusIsKept() throws Exception {
        HttpFilters filters = HttpFilters.builder()
                .onResponse(res -> res.status().code() == 500 ? res.setStatus(HttpResponseStatus.OK) : res)
                .build();
        assertEquals(200, get(client(proxy(filters)), url(origin, "/error")).statusCode());
        assertEquals("FILTER 200 upstream=500", sources.await(1));
    }

    @Test
    void aReplacedServerResponseIsTheFilters() throws Exception {
        HttpFilters filters = HttpFilters.builder()
                .beforeResponding(res -> new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, res.status(), "replaced"))
                .build();
        assertEquals("replaced", get(client(proxy(filters)), url(origin, "/ok")).body());
        assertEquals("FILTER 200 upstream=200", sources.await(1));
    }

    @Test
    void shortCircuitsAndFailureAnswersFromFilters() throws Exception {
        HttpFilters filters = HttpFilters.builder()
                .onRequest(req -> req.uri().endsWith("/blocked")
                        ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN, "no") : null)
                .onFailure(failure -> new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, failure.status(), "filter page"))
                .build();
        HttpProxyServer proxy = proxy(filters);
        assertEquals(403, get(client(proxy), url(origin, "/blocked")).statusCode());
        assertEquals("FILTER 403 upstream=-", sources.await(1));
        assertEquals("filter page", get(client(proxy), "http://127.0.0.1:1/").body());
        assertEquals("FILTER 502 upstream=-", sources.await(2));
    }

    @Test
    void cacheAnswers() throws Exception {
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().plusActivityTracker(sources)
                .withHttpCache(HttpCache.builder().build()));
        assertEquals("cached body", get(client(proxy), url(origin, "/cacheable")).body());
        assertEquals("SERVER 200 upstream=200", sources.await(1));
        assertEquals("cached body", get(client(proxy), url(origin, "/cacheable")).body());
        assertEquals("CACHE 200 upstream=-", sources.await(2));
    }

    @Test
    void offlineCacheMisses() throws Exception {
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().plusActivityTracker(sources)
                .withHttpCache(HttpCache.builder().offline(true).build()));
        assertEquals(504, get(client(proxy), url(origin, "/missing")).statusCode());
        assertEquals("CACHE 504 upstream=-", sources.await(1));
    }

    @Test
    void connectAndAuthenticationAnswersAreTheProxys() throws Exception {
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().plusActivityTracker(sources)
                .withProxyAuthenticator((user, password) -> "secret".equals(password)));
        try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
            assertEquals(407, ChainTestSupport.status(ChainTestSupport.connect(s, "127.0.0.1:1")));
        }
        assertEquals("PROXY 407 upstream=-", sources.await(1));

        HttpProxyServer open = proxy(null);
        try (Socket s = ChainTestSupport.open(open.getListenAddress())) {
            String target = "127.0.0.1:" + origin.getAddress().getPort();
            assertEquals(200, ChainTestSupport.status(ChainTestSupport.connect(s, target)));
        }
        assertEquals("PROXY 200 upstream=-", sources.await(2));
    }

    @Test
    void contextsMadeOutsideTheProxyHaveNoUpstreamStatus() {
        FlowContext ctx = new FlowContext(1, () -> null, () -> null, new ClientDetails());
        assertEquals(false, ctx.upstreamStatus().isPresent());
        assertEquals(false, new FullFlowContext(ctx, "h:1", null, null).upstreamStatus().isPresent());
    }
}
