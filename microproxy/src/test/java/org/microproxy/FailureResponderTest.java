package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.ChainTestSupport.encrypted;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.readUntil;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.SelfSignedSslContextSource;

/** Custom answers for the proxy's own failures: the responder, the filter hook and their defaults. */
class FailureResponderTest {

    private static final HttpResponseStatus CUSTOM = new HttpResponseStatus(599, "Custom Failure");

    private final List<ProxyFailure> failures = new CopyOnWriteArrayList<>();
    private final ServerFailures serverFailures = new ServerFailures();
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();

    /** Answers 599 with the failure's kind and default status, and a wrong Content-Length to fix. */
    private final FailureResponder responder = (request, failure) -> {
        failures.add(failure);
        DefaultFullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, CUSTOM,
                "custom " + failure.getClass().getSimpleName() + " " + failure.status().code());
        response.headers().set("Content-Type", "text/plain");
        response.headers().set("Content-Length", "1");
        return response;
    };

    /** Records server-side failures reported to trackers. */
    static final class ServerFailures extends ActivityTrackerAdapter {
        final List<FullFlowContext> contexts = new CopyOnWriteArrayList<>();
        final List<Throwable> causes = new CopyOnWriteArrayList<>();

        @Override
        public void serverConnectionExceptionCaught(FullFlowContext serverContext, Throwable cause) {
            contexts.add(serverContext);
            causes.add(cause);
        }
    }

    @AfterEach
    void tearDown() throws IOException {
        proxies.close();
        for (Socket r : refusing) r.close();
    }

    private HttpProxyServerBootstrap bootstrap() {
        return MicroProxy.bootstrap().plusActivityTracker(serverFailures);
    }

    private HttpProxyServer withResponder() {
        return proxies.start(bootstrap().withFailureResponder(responder));
    }

    /** Reserved until the test ends, so a server started meanwhile cannot be given the same port. */
    private final List<Socket> refusing = new ArrayList<>();

    /** A loopback port that refuses connections, reserved until the test ends. */
    private int closedPort() {
        Socket s = TestSupport.refusingPort();
        refusing.add(s);
        return s.getLocalPort();
    }

    private static void assertCustom(HttpResponse<String> response, String kind, int defaultStatus) {
        assertEquals(599, response.statusCode());
        assertEquals("custom " + kind + " " + defaultStatus, response.body());
    }

    @Test
    void unresolvedHost() {
        HttpProxyServer proxy = proxies.start(bootstrap().withFailureResponder(responder).withServerResolver((host, port) -> {
            throw new UnknownHostException(host);
        }));
        assertCustom(get(client(proxy), "http://nowhere.test/x"), "UnresolvedHost", 502);
        ProxyFailure.UnresolvedHost failure = assertInstanceOf(ProxyFailure.UnresolvedHost.class, failures.getFirst());
        assertEquals("nowhere.test:80", failure.hostAndPort());
        assertEquals("nowhere.test", failure.cause().getMessage());

        assertInstanceOf(UnknownHostException.class, serverFailures.causes.getFirst());
        assertEquals("nowhere.test:80", serverFailures.contexts.getFirst().getServerHostAndPort());
        assertNull(serverFailures.contexts.getFirst().getRemoteAddress());
    }

    @Test
    void refusedConnection() throws Exception {
        int port = closedPort();
        assertCustom(get(client(withResponder()), "http://127.0.0.1:" + port + "/"), "ConnectFailed", 502);
        ProxyFailure.ConnectFailed failure = assertInstanceOf(ProxyFailure.ConnectFailed.class, failures.getFirst());
        assertEquals("127.0.0.1:" + port, failure.hostAndPort());
        assertInstanceOf(ConnectException.class, failure.cause());

        assertEquals(1, serverFailures.causes.size());
        assertInstanceOf(ConnectException.class, serverFailures.causes.getFirst());
        assertEquals(port, serverFailures.contexts.getFirst().getRemoteAddress().getPort());
    }

    @Test
    void serverTimeout() throws Exception {
        try (TestSupport.RawServer silent = TestSupport.rawServer(s -> {
            readUntil(s.getInputStream(), "\r\n\r\n");
            Thread.sleep(5_000);
        })) {
            HttpProxyServer proxy = proxies.start(bootstrap().withFailureResponder(responder)
                    .withIdleConnectionTimeout(Duration.ofMillis(300)));
            assertCustom(get(client(proxy), "http://127.0.0.1:" + silent.port() + "/"), "ServerTimeout", 504);
            assertInstanceOf(SocketTimeoutException.class,
                    ((ProxyFailure.ServerTimeout) failures.getFirst()).cause());
            assertInstanceOf(SocketTimeoutException.class, serverFailures.causes.getFirst());
        }
    }

    @Test
    void malformedServerResponse() throws Exception {
        try (TestSupport.RawServer garbage = TestSupport.rawServer(s -> {
            readUntil(s.getInputStream(), "\r\n\r\n");
            write(s.getOutputStream(), "this is not HTTP\r\n\r\n");
        })) {
            assertCustom(get(client(withResponder()), "http://127.0.0.1:" + garbage.port() + "/"),
                    "BadServerResponse", 502);
            ProxyFailure.BadServerResponse failure =
                    assertInstanceOf(ProxyFailure.BadServerResponse.class, failures.getFirst());
            assertEquals("127.0.0.1:" + garbage.port(), failure.hostAndPort());
            assertEquals(1, serverFailures.causes.size());
            assertEquals(failure.cause(), serverFailures.causes.getFirst());
            assertEquals("127.0.0.1:" + garbage.port(), serverFailures.contexts.getFirst().getServerHostAndPort());
        }
    }

    @Test
    void untrustedChainedProxy() {
        SelfSignedSslContextSource upstreamTls = new SelfSignedSslContextSource();
        SelfSignedSslContextSource otherTls = new SelfSignedSslContextSource();
        InetSocketAddress upstream = proxies.start(MicroProxy.bootstrap().withSslContextSource(upstreamTls))
                .getListenAddress();
        HttpProxyServer proxy = proxies.start(bootstrap().withFailureResponder(responder)
                .withChainProxyManager(always(encrypted(upstream, otherTls.getSslContext()))));

        assertCustom(get(client(proxy), "http://127.0.0.1:1/"), "TlsFailed", 502);
        ProxyFailure.TlsFailed failure = assertInstanceOf(ProxyFailure.TlsFailed.class, failures.getFirst());
        assertEquals("127.0.0.1:1", failure.hostAndPort());
        assertInstanceOf(SSLHandshakeException.class, failure.cause());
        assertInstanceOf(SSLHandshakeException.class, serverFailures.causes.getFirst());
        assertEquals(upstream, serverFailures.contexts.getFirst().getRemoteAddress());
    }

    @Test
    void exhaustedPool() throws Exception {
        HttpServer slow = TestSupport.origin(exchange -> {
            try {
                Thread.sleep(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            TestSupport.fixed(200, "slow").handle(exchange);
        });
        try {
            HttpProxyServer proxy = proxies.start(bootstrap().withFailureResponder(responder)
                    .withSharedServerConnectionPool(true).withMaxConnectionsPerHost(1).withConnectTimeout(100));
            List<CompletableFuture<HttpResponse<String>>> futures = new ArrayList<>();
            for (int i = 0; i < 2; i++) {
                futures.add(client(proxy).sendAsync(
                        HttpRequest.newBuilder(URI.create(TestSupport.url(slow, "/" + i))).build(),
                        HttpResponse.BodyHandlers.ofString()));
                Thread.sleep(100);
            }
            assertEquals(200, futures.get(0).get().statusCode());
            assertCustom(futures.get(1).get(), "NoConnectionAvailable", 503);
            assertTrue(serverFailures.causes.isEmpty(), "an exhausted pool is no server failure");
        } finally {
            slow.stop(0);
        }
    }

    @Test
    void originFormRequestIsABadRequest() throws Exception {
        HttpProxyServer proxy = withResponder();
        String reply = TestSupport.rawExchange(proxy.getListenAddress(),
                "GET /x HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n");
        assertTrue(reply.startsWith("HTTP/1.1 599 Custom Failure\r\n"), reply);
        assertTrue(reply.contains("\r\nContent-Length: 21\r\n"), reply);
        assertTrue(reply.endsWith("\r\n\r\ncustom BadRequest 400"), reply);
        assertEquals(new ProxyFailure.BadRequest("the proxy needs an absolute URI"), failures.getFirst());
    }

    @Test
    void oversizedRequestBodyClosesTheConnection() throws Exception {
        HttpFilters buffering = HttpFilters.builder().bufferRequests(10).build();
        HttpProxyServer proxy = proxies.start(bootstrap().withFailureResponder(responder)
                .withFiltersSource((request, ctx) -> buffering));
        String reply = TestSupport.rawExchange(proxy.getListenAddress(),
                "POST http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\nContent-Length: 100\r\n\r\n");
        assertTrue(reply.startsWith("HTTP/1.1 599 Custom Failure\r\n"), reply);
        assertTrue(reply.contains("\r\nConnection: close\r\n"), reply);
        assertTrue(reply.endsWith("custom RequestTooLarge 413"), reply);
        assertEquals(new ProxyFailure.RequestTooLarge(10), failures.getFirst());
    }

    @Test
    void headAnswersKeepTheirLengthButNoBodyAndTheConnectionStaysOpen() throws Exception {
        int port = closedPort();
        HttpProxyServer proxy = withResponder();
        try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
            InputStream in = s.getInputStream();
            write(s.getOutputStream(), "HEAD http://127.0.0.1:" + port + "/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            String head = readUntil(in, "\r\n\r\n");
            assertTrue(head.startsWith("HTTP/1.1 599 "), head);
            assertTrue(head.contains("\r\nContent-Length: 24\r\n"), head);
            // The next answer follows directly: the HEAD answer had no body.
            write(s.getOutputStream(), "GET http://127.0.0.1:" + port + "/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            String next = readUntil(in, "\r\n\r\n");
            assertTrue(next.startsWith("HTTP/1.1 599 "), next);
        }
    }

    @Test
    void responderReturningNullKeepsTheDefault() throws Exception {
        HttpProxyServer proxy = proxies.start(bootstrap().withFailureResponder((request, failure) -> null));
        HttpResponse<String> response = get(client(proxy), "http://127.0.0.1:" + closedPort() + "/");
        assertEquals(502, response.statusCode());
        assertEquals("Bad Gateway", response.body());
        assertEquals("nosniff", response.headers().firstValue("X-Content-Type-Options").orElseThrow());
    }

    @Test
    void throwingResponderFallsBackToTheDefault() throws Exception {
        HttpProxyServer proxy = proxies.start(bootstrap().withFailureResponder((request, failure) -> {
            throw new IllegalStateException("responder bug");
        }).withIdleConnectionTimeout(Duration.ofMillis(300)));
        try (TestSupport.RawServer silent = TestSupport.rawServer(s -> {
            readUntil(s.getInputStream(), "\r\n\r\n");
            Thread.sleep(5_000);
        })) {
            HttpResponse<String> response = get(client(proxy), "http://127.0.0.1:" + silent.port() + "/");
            assertEquals(504, response.statusCode());
            assertEquals("Gateway Timeout", response.body());
        }
    }

    @Test
    void filtersAnswerBeforeTheResponderAndTheirAnswerStillPassesProxyToClientResponse() throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        HttpFilters filters = HttpFilters.builder()
                .onFailure(failure -> failure instanceof ProxyFailure.ConnectFailed
                        ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, new HttpResponseStatus(418, "Teapot"), "from filter")
                        : null)
                .beforeResponding(response -> {
                    seen.add(response.status().code() + "");
                    response.headers().set("X-Seen", "yes");
                    return response;
                })
                .build();
        HttpProxyServer proxy = proxies.start(bootstrap().withFailureResponder(responder)
                .withFiltersSource((request, ctx) -> filters));
        HttpResponse<String> response = get(client(proxy), "http://127.0.0.1:" + closedPort() + "/");
        assertEquals(418, response.statusCode());
        assertEquals("from filter", response.body());
        assertEquals("yes", response.headers().firstValue("X-Seen").orElseThrow());
        assertEquals(List.of("418"), seen);
        assertTrue(failures.isEmpty(), "the responder is not asked when a filter answers");

        // A failure the filter does not answer falls through to the responder, which filters also see.
        String reply = TestSupport.rawExchange(proxy.getListenAddress(),
                "GET /x HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n");
        assertTrue(reply.startsWith("HTTP/1.1 599 "), reply);
        assertTrue(reply.contains("\r\nX-Seen: yes\r\n"), reply);
    }

    @Test
    void chainedFiltersAndBuilderHooksTakeTheFirstAnswer() {
        ProxyFailure failure = new ProxyFailure.NoRoute("example.test:80");
        HttpFilters silent = HttpFilters.builder().onFailure(f -> null).build();
        HttpFilters first = HttpFilters.builder()
                .onFailure(f -> null)
                .onFailure(f -> new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(503)))
                .build();
        HttpFilters second = HttpFilters.builder()
                .onFailure(f -> new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(500)))
                .build();
        HttpFiltersSource chain = HttpFiltersChain.of((r, c) -> silent, (r, c) -> first, (r, c) -> second);
        HttpFilters filters = chain.filterRequest(
                new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "http://example.test/"), null);
        assertEquals(503, filters.proxyToServerFailure(failure).status().code());
        assertNull(silent.proxyToServerFailure(failure));
        assertNull(HttpFiltersAdapter.NOOP_FILTER.proxyToServerFailure(failure));
    }

    @Test
    void defaultStatuses() {
        assertEquals(502, new ProxyFailure.UnresolvedHost("h:1", new UnknownHostException()).status().code());
        assertEquals(502, new ProxyFailure.ConnectFailed("h:1", new ConnectException()).status().code());
        assertEquals(502, new ProxyFailure.TlsFailed("h:1", new SSLHandshakeException("x")).status().code());
        assertEquals(504, new ProxyFailure.ServerTimeout("h:1", new SocketTimeoutException()).status().code());
        assertEquals(502, new ProxyFailure.BadServerResponse("h:1", new IOException()).status().code());
        assertEquals(502, new ProxyFailure.NoRoute(null).status().code());
        assertEquals(503, new ProxyFailure.NoConnectionAvailable("h:1").status().code());
        assertEquals(400, new ProxyFailure.BadRequest("why").status().code());
        assertEquals(413, new ProxyFailure.RequestTooLarge(1).status().code());
        assertFalse(failures.iterator().hasNext());
    }

    @Test
    void responseStartedBeforeAFailureIsNotAnsweredAgain() throws Exception {
        try (TestSupport.RawServer truncated = TestSupport.rawServer(s -> {
            readUntil(s.getInputStream(), "\r\n\r\n");
            write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial");
        })) {
            HttpProxyServer proxy = withResponder();
            String reply = TestSupport.rawExchange(proxy.getListenAddress(), "GET http://127.0.0.1:" + truncated.port()
                    + "/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            assertTrue(reply.startsWith("HTTP/1.1 200 OK\r\n"), reply);
            assertTrue(failures.isEmpty());
            for (int i = 0; i < 50 && serverFailures.causes.isEmpty(); i++) Thread.sleep(20);
            assertEquals(1, serverFailures.causes.size(), "trackers still hear of the failure");
        }
    }

    @Test
    void aBugWhileTheServerConnectionIsInUseIsReportedOnBothSidesAndClosesTheConnection() throws Exception {
        List<Throwable> clientSide = new CopyOnWriteArrayList<>();
        HttpServer origin = TestSupport.origin(TestSupport.fixed(200, "fine"));
        try {
            HttpFilters buggy = HttpFilters.builder().onResponse(res -> {
                throw new IllegalStateException("filter bug");
            }).build();
            HttpProxyServer proxy = proxies.start(bootstrap().withFailureResponder(responder)
                    .withFiltersSource((request, ctx) -> buggy)
                    .plusActivityTracker(new ActivityTrackerAdapter() {
                        @Override
                        public void connectionExceptionCaught(FlowContext ctx, Throwable cause) {
                            clientSide.add(cause);
                        }
                    }));
            String reply = TestSupport.rawExchange(proxy.getListenAddress(),
                    "GET " + TestSupport.url(origin, "/") + " HTTP/1.1\r\nHost: x\r\n\r\n");
            assertEquals("", reply, "the connection closes without an answer");
            for (int i = 0; i < 100 && clientSide.isEmpty(); i++) Thread.sleep(10);
            assertInstanceOf(IllegalStateException.class, serverFailures.causes.getFirst());
            assertInstanceOf(IllegalStateException.class, clientSide.getFirst());
            assertTrue(failures.isEmpty(), "a bug is no ProxyFailure");
        } finally {
            origin.stop(0);
        }
    }

    @Test
    void connectFailuresAreAnsweredForConnectRequestsToo() throws Exception {
        HttpProxyServer proxy = withResponder();
        int port = closedPort();
        try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
            String head = ChainTestSupport.connect(s, "127.0.0.1:" + port);
            assertTrue(head.startsWith("HTTP/1.1 599 "), head);
        }
        assertEquals(new ProxyFailure.ConnectFailed("127.0.0.1:" + port, ((ProxyFailure.ConnectFailed) failures.getFirst()).cause()),
                failures.getFirst());
    }
}
