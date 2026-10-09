package org.microproxy.extras;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.eventually;
import static org.microproxy.TestSupport.get;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicIntegerArray;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.microproxy.ClientDetails;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.ProxyAuthenticator;
import org.microproxy.TestSupport;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

class ConcurrencyLimiterTest {

    private final List<AutoCloseable> closeables = new ArrayList<>();
    /** Released by the test to let the blocking origin answer. */
    private final CountDownLatch release = new CountDownLatch(1);
    /** How many requests the blocking origin is holding. */
    private final AtomicInteger held = new AtomicInteger();

    @AfterEach
    void tearDown() throws Exception {
        release.countDown();
        for (AutoCloseable c : closeables.reversed()) c.close();
    }

    private HttpProxyServer start(HttpProxyServerBootstrap bootstrap) {
        HttpProxyServer proxy = bootstrap.withPort(0).start();
        closeables.add(proxy::abort);
        return proxy;
    }

    /** Answers {@code /slow...} once the test releases it, everything else at once. */
    private HttpHandler blocking() {
        return exchange -> {
            if (exchange.getRequestURI().getPath().startsWith("/slow")) {
                held.incrementAndGet();
                try {
                    release.await(20, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            TestSupport.fixed(200, "ok").handle(exchange);
        };
    }

    private HttpServer origin(HttpHandler handler) {
        HttpServer origin = TestSupport.origin(handler);
        closeables.add(() -> origin.stop(0));
        return origin;
    }

    private static CompletableFuture<HttpResponse<String>> getAsync(HttpClient client, String url) {
        return client.sendAsync(java.net.http.HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(20))
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    private static int status(CompletableFuture<HttpResponse<String>> response) throws Exception {
        return response.get(20, TimeUnit.SECONDS).statusCode();
    }

    @Test
    void requestsOverTheLimitGet429UntilAPermitIsFree() throws Exception {
        HttpServer origin = origin(blocking());
        ConcurrencyLimiter limiter = ConcurrencyLimiter.builder().permits(1).build();
        HttpProxyServer proxy = start(MicroProxy.bootstrap().withFiltersSource(limiter));
        HttpClient client = client(proxy);

        CompletableFuture<HttpResponse<String>> first = getAsync(client, TestSupport.url(origin, "/slow"));
        eventually("the first request to reach the origin", () -> held.get() == 1);
        assertEquals(1, limiter.snapshot().inUse());
        assertEquals(new ConcurrencyLimiter.KeyStats(1, 1, 0, 0), limiter.snapshot().keys().get("127.0.0.1"));

        HttpResponse<String> refused = get(client, TestSupport.url(origin, "/fast"));
        assertEquals(429, refused.statusCode());
        assertEquals("Too Many Requests\n", refused.body());
        assertEquals("1", refused.headers().firstValue("Retry-After").orElse(null));
        assertTrue(refused.headers().firstValue("Content-Type").orElse("").startsWith("text/plain"));
        assertEquals(1, limiter.snapshot().keys().get("127.0.0.1").rejected());

        release.countDown();
        assertEquals(200, status(first));
        eventually("the permit to come back", () -> limiter.snapshot().keys().isEmpty());
        assertEquals(200, get(client, TestSupport.url(origin, "/fast")).statusCode());

        eventually("the key to be forgotten", () -> limiter.snapshot().keys().isEmpty());
        ConcurrencyLimiter.Snapshot snapshot = limiter.snapshot();
        assertEquals(0, snapshot.inUse());
        assertEquals(2, snapshot.acquired());
        assertEquals(1, snapshot.rejected());
        assertEquals(0, snapshot.reclaimed());
    }

    @Test
    void queuedRequestsWaitForAPermitAndTheQueueIsBounded() throws Exception {
        HttpServer origin = origin(blocking());
        ConcurrencyLimiter limiter = ConcurrencyLimiter.builder().permits(1).queue(1, Duration.ofSeconds(15)).build();
        HttpProxyServer proxy = start(MicroProxy.bootstrap().withFiltersSource(limiter));
        HttpClient client = client(proxy);

        CompletableFuture<HttpResponse<String>> first = getAsync(client, TestSupport.url(origin, "/slow"));
        eventually("the first request to reach the origin", () -> held.get() == 1);
        CompletableFuture<HttpResponse<String>> queued = getAsync(client, TestSupport.url(origin, "/fast"));
        eventually("the second request to queue", () -> limiter.snapshot().waiting() == 1);
        assertEquals(429, get(client, TestSupport.url(origin, "/fast")).statusCode(), "the queue holds one");

        release.countDown();
        assertEquals(200, status(first));
        assertEquals(200, status(queued), "the queued request got the permit");
        eventually("every permit to come back", () -> limiter.snapshot().keys().isEmpty());
        assertEquals(2, limiter.snapshot().acquired());
        assertEquals(1, limiter.snapshot().rejected());
    }

    @Test
    void queuedRequestsGiveUpAfterTheirWait() throws Exception {
        HttpServer origin = origin(blocking());
        ConcurrencyLimiter limiter = ConcurrencyLimiter.builder().permits(1).queue(5, Duration.ofMillis(300))
                .retryAfter(Duration.ofMillis(2500)).build();
        HttpProxyServer proxy = start(MicroProxy.bootstrap().withFiltersSource(limiter));
        HttpClient client = client(proxy);

        CompletableFuture<HttpResponse<String>> first = getAsync(client, TestSupport.url(origin, "/slow"));
        eventually("the first request to reach the origin", () -> held.get() == 1);
        long start = System.nanoTime();
        HttpResponse<String> refused = get(client, TestSupport.url(origin, "/fast"));
        long took = Duration.ofNanos(System.nanoTime() - start).toMillis();
        assertEquals(429, refused.statusCode());
        assertEquals("3", refused.headers().firstValue("Retry-After").orElse(null), "rounded up to seconds");
        assertTrue(took >= 250, "waited only " + took + " ms");
        assertTrue(took < 5000, "waited " + took + " ms");
        release.countDown();
        assertEquals(200, status(first));
    }

    @Test
    void shadowModeReportsButNeverRefuses() throws Exception {
        HttpServer origin = origin(blocking());
        List<String> reported = new CopyOnWriteArrayList<>();
        ConcurrencyLimiter limiter = ConcurrencyLimiter.builder().permits(1).shadow(true)
                .onReject((key, request, flow) -> reported.add(key + " " + request.uri())).build();
        HttpProxyServer proxy = start(MicroProxy.bootstrap().withFiltersSource(limiter));
        HttpClient client = client(proxy);

        CompletableFuture<HttpResponse<String>> first = getAsync(client, TestSupport.url(origin, "/slow1"));
        eventually("the first request to reach the origin", () -> held.get() == 1);
        CompletableFuture<HttpResponse<String>> second = getAsync(client, TestSupport.url(origin, "/slow2"));
        eventually("the second request to reach the origin too", () -> held.get() == 2);
        ConcurrencyLimiter.Snapshot busy = limiter.snapshot();
        assertEquals(new ConcurrencyLimiter.KeyStats(1, 2, 0, 1), busy.keys().get("127.0.0.1"));
        assertEquals(List.of("127.0.0.1 " + TestSupport.url(origin, "/slow2")), reported);

        release.countDown();
        assertEquals(200, status(first));
        assertEquals(200, status(second));
        eventually("every permit to come back", () -> limiter.snapshot().inUse() == 0);
        assertEquals(1, limiter.snapshot().rejected());
        assertTrue(limiter.shadow());
    }

    @Test
    void failuresShortCircuitsAndDisconnectsGiveThePermitBack() throws Exception {
        HttpServer origin = origin(blocking());
        Socket refusing = TestSupport.refusingPort();
        closeables.add(refusing);
        int refusedPort = refusing.getLocalPort();
        ConcurrencyLimiter limiter = ConcurrencyLimiter.builder().permits(1).build();
        HttpFilters blocker = HttpFilters.builder()
                .onRequest(r -> r.uri().endsWith("/blocked")
                        ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN, "no") : null)
                .build();
        HttpProxyServer proxy = start(MicroProxy.bootstrap().withFiltersSource(HttpFiltersChain.of(limiter,
                (request, flow) -> blocker)));
        HttpClient client = client(proxy);

        for (int i = 0; i < 3; i++) {
            assertEquals(502, get(client, "http://127.0.0.1:" + refusedPort + "/").statusCode());
            assertEquals(403, get(client, TestSupport.url(origin, "/blocked")).statusCode());
        }

        // A client that hangs up while its request is at the server.
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            TestSupport.write(s.getOutputStream(),
                    "GET " + TestSupport.url(origin, "/slow") + " HTTP/1.1\r\nHost: x\r\n\r\n");
            eventually("the request to reach the origin", () -> held.get() == 1);
        }
        release.countDown();
        eventually("the abandoned exchange's permit to come back", () -> limiter.snapshot().keys().isEmpty());
        assertEquals(200, get(client, TestSupport.url(origin, "/fast")).statusCode());
        assertEquals(0, limiter.snapshot().rejected());
        assertEquals(8, limiter.snapshot().acquired());
    }

    @Test
    void permitsHeldTooLongAreReclaimedOnce() throws Exception {
        HttpServer origin = origin(blocking());
        ConcurrencyLimiter limiter = ConcurrencyLimiter.builder().permits(1).permitTimeout(Duration.ofMillis(300))
                .build();
        HttpProxyServer proxy = start(MicroProxy.bootstrap().withFiltersSource(limiter));
        HttpClient client = client(proxy);

        CompletableFuture<HttpResponse<String>> stuck = getAsync(client, TestSupport.url(origin, "/slow"));
        eventually("the stuck request to reach the origin", () -> held.get() == 1);
        // Refused until the safety net reclaims the stuck request's permit.
        eventually("a request to get through", () -> get(client, TestSupport.url(origin, "/fast")).statusCode() == 200);
        assertEquals(1, limiter.snapshot().reclaimed());

        release.countDown();
        assertEquals(200, status(stuck));
        eventually("the key to be forgotten", () -> limiter.snapshot().keys().isEmpty());
        ConcurrencyLimiter.Snapshot snapshot = limiter.snapshot();
        assertEquals(0, snapshot.inUse(), "the late release did not count twice");
        assertEquals(1, snapshot.reclaimed());

        // The limit still holds afterwards.
        CountDownLatch again = new CountDownLatch(1);
        HttpServer second = origin(exchange -> {
            try {
                again.await(20, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            TestSupport.fixed(200, "ok").handle(exchange);
        });
        CompletableFuture<HttpResponse<String>> busy = getAsync(client, TestSupport.url(second, "/"));
        eventually("the request to take the permit", () -> limiter.snapshot().inUse() == 1);
        assertEquals(429, get(client, TestSupport.url(origin, "/fast")).statusCode());
        again.countDown();
        assertEquals(200, status(busy));
    }

    @Test
    void tunnelsHoldTheirPermitUntilTheyClose() throws Exception {
        TestSupport.RawServer echo = TestSupport.rawServer(s -> s.getInputStream().transferTo(s.getOutputStream()));
        closeables.add(echo);
        String target = "127.0.0.1:" + echo.port();
        ConcurrencyLimiter limiter = ConcurrencyLimiter.builder().permits(1).permitTimeout(Duration.ofMillis(100))
                .build();
        HttpProxyServer proxy = start(MicroProxy.bootstrap().withFiltersSource(limiter));
        InetSocketAddress address = proxy.getListenAddress();

        try (Socket tunnel = open(address)) {
            assertEquals(200, connect(tunnel, target));
            assertEquals(429, connectOnce(address, target), "the open tunnel holds the only permit");
            // Established tunnels are exempt from the permit timeout: let it pass.
            Thread.sleep(250);
            assertEquals(429, connectOnce(address, target));
            TestSupport.write(tunnel.getOutputStream(), "ping");
            assertEquals("ping", new String(tunnel.getInputStream().readNBytes(4)));
        }
        eventually("the closed tunnel's permit to come back", () -> limiter.snapshot().keys().isEmpty());
        try (Socket tunnel = open(address)) {
            assertEquals(200, connect(tunnel, target));
        }
        assertEquals(0, limiter.snapshot().reclaimed());

        ConcurrencyLimiter uncounted = ConcurrencyLimiter.builder().permits(1).countTunnels(false).build();
        HttpProxyServer other = start(MicroProxy.bootstrap().withFiltersSource(uncounted));
        try (Socket a = open(other.getListenAddress()); Socket b = open(other.getListenAddress())) {
            assertEquals(200, connect(a, target));
            assertEquals(200, connect(b, target));
        }
        assertEquals(0, uncounted.snapshot().acquired());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void interceptedRequestsAreCountedOneByOne(boolean countTunnels) throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("Limiter Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Limiter Proxy CA");
        HttpsServer origin = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), blocking());
        closeables.add(() -> origin.stop(0));
        ConcurrencyLimiter limiter = ConcurrencyLimiter.builder().permits(1).countTunnels(countTunnels).build();
        HttpProxyServer proxy = start(MicroProxy.bootstrap().withFiltersSource(limiter)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext())));
        HttpClient client = client(proxy, proxyCa.clientContext());

        assertEquals(200, get(client, TestSupport.url(origin, "/one")).statusCode());
        assertEquals(200, get(client, TestSupport.url(origin, "/two")).statusCode(),
                "the CONNECT gave its permit back when interception started");
        assertEquals(countTunnels ? 3 : 2, limiter.snapshot().acquired());

        CompletableFuture<HttpResponse<String>> slow = getAsync(client, TestSupport.url(origin, "/slow"));
        eventually("the slow request to reach the origin", () -> held.get() == 1);
        // The client needs a second session for another request meanwhile.
        if (countTunnels) {
            UncheckedIOException e = assertThrows(UncheckedIOException.class,
                    () -> get(client, TestSupport.url(origin, "/three")));
            assertTrue(e.getMessage().contains("429"), "its CONNECT is refused: " + e.getMessage());
        } else {
            assertEquals(429, get(client, TestSupport.url(origin, "/three")).statusCode(),
                    "the request inside the new session is refused");
        }
        release.countDown();
        assertEquals(200, status(slow));
        eventually("every permit to come back", () -> limiter.snapshot().keys().isEmpty());
    }

    @Test
    void authenticationComesFirst() throws Exception {
        HttpServer origin = origin(blocking());
        List<String> reported = new CopyOnWriteArrayList<>();
        ConcurrencyLimiter limiter = ConcurrencyLimiter.builder().key(ConcurrencyLimiter.byUser()).permits(0)
                .onReject((key, request, flow) -> reported.add(key))
                .response((key, request, flow) -> new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                        HttpResponseStatus.SERVICE_UNAVAILABLE, "busy, " + key))
                .build();
        HttpProxyServer proxy = start(MicroProxy.bootstrap().withFiltersSource(limiter)
                .withProxyAuthenticator(new ProxyAuthenticator() {
                    @Override
                    public boolean authenticate(String userName, String password) {
                        return "alice".equals(userName) && "pw".equals(password);
                    }
                }));
        String request = "GET " + TestSupport.url(origin, "/") + " HTTP/1.1\r\nHost: x\r\n";
        String anonymous = TestSupport.rawExchange(proxy.getListenAddress(), request + "Connection: close\r\n\r\n");
        assertTrue(anonymous.startsWith("HTTP/1.1 407"), anonymous);
        assertEquals(0, limiter.snapshot().rejected(), "refused before the limiter saw it");

        String alice = TestSupport.rawExchange(proxy.getListenAddress(), request
                + "Proxy-Authorization: Basic YWxpY2U6cHc=\r\nConnection: close\r\n\r\n");
        assertTrue(alice.startsWith("HTTP/1.1 503"), alice);
        assertTrue(alice.endsWith("busy, alice"), alice);
        assertEquals(List.of("alice"), reported);
    }

    @Test
    void keysByTargetHostAndPermitsPerKey() throws Exception {
        assertEquals("example.com", host("GET", "http://Example.com:8080/x?y", null));
        assertEquals("example.com", host("GET", "/x", "example.com:443"));
        assertEquals("example.com", host("CONNECT", "example.com:443", null));
        assertEquals("[::1]", host("CONNECT", "[::1]:443", null));
        assertEquals("example.com", host("GET", "http://user:pw@example.com/", null));

        ConcurrencyLimiter limiter = ConcurrencyLimiter.builder().key(ConcurrencyLimiter.byTargetHost()).permits(1)
                .permits(key -> key.equals("big.example") ? 2 : null).build();
        FlowContext flow = flow(1);
        HttpRequest big = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "http://big.example/");
        HttpRequest small = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "http://small.example/");
        HttpFilters b1 = limiter.filterRequest(big, flow);
        HttpFilters b2 = limiter.filterRequest(big, flow);
        HttpFilters b3 = limiter.filterRequest(big, flow);
        HttpFilters s1 = limiter.filterRequest(small, flow);
        HttpFilters s2 = limiter.filterRequest(small, flow);
        assertNull(b1.clientToProxyRequest(big));
        assertNull(b2.clientToProxyRequest(big));
        assertEquals(429, b3.clientToProxyRequest(big).status().code());
        assertNull(s1.clientToProxyRequest(small));
        assertEquals(429, s2.clientToProxyRequest(small).status().code());
        assertEquals(new ConcurrencyLimiter.KeyStats(2, 2, 0, 1), limiter.snapshot().keys().get("big.example"));
        assertEquals(new ConcurrencyLimiter.KeyStats(1, 1, 0, 1), limiter.snapshot().keys().get("small.example"));
        for (HttpFilters f : List.of(b1, b2, b3, s1, s2)) {
            f.exchangeEnded(true);
            f.exchangeEnded(false);
        }
        assertTrue(limiter.snapshot().keys().isEmpty());
        assertEquals(0, limiter.snapshot().inUse());
    }

    @Test
    void manyThreadsNeverExceedThePermitsAndLeaveNoKeysBehind() throws Exception {
        int permits = 3;
        int keys = 4;
        int threads = 64;
        int rounds = 200;
        ConcurrencyLimiter limiter = ConcurrencyLimiter.builder().permits(permits)
                .key((request, flow) -> "k" + (flow.getConnectionId() % keys))
                .queue(8, Duration.ofMillis(50)).build();
        AtomicIntegerArray running = new AtomicIntegerArray(keys);
        AtomicIntegerArray peak = new AtomicIntegerArray(keys);
        AtomicInteger admitted = new AtomicInteger();
        AtomicInteger refused = new AtomicInteger();
        HttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "http://example.com/");
        List<Thread> workers = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            FlowContext flow = flow(t);
            int key = t % keys;
            workers.add(Thread.ofVirtual().start(() -> {
                for (int i = 0; i < rounds; i++) {
                    HttpFilters f = limiter.filterRequest(request, flow);
                    HttpObject answer = f.clientToProxyRequest(request);
                    if (answer == null) {
                        admitted.incrementAndGet();
                        int now = running.incrementAndGet(key);
                        peak.accumulateAndGet(key, now, Math::max);
                        Thread.yield();
                        running.decrementAndGet(key);
                    } else {
                        refused.incrementAndGet();
                    }
                    f.exchangeEnded(answer == null);
                }
            }));
        }
        for (Thread w : workers) w.join(30_000);
        for (int k = 0; k < keys; k++) {
            assertTrue(peak.get(k) <= permits, "key " + k + " peaked at " + peak.get(k));
        }
        ConcurrencyLimiter.Snapshot snapshot = limiter.snapshot();
        assertTrue(snapshot.keys().isEmpty(), snapshot.toString());
        assertEquals(0, snapshot.inUse());
        assertEquals(0, snapshot.waiting());
        assertEquals(threads * rounds, admitted.get() + refused.get());
        assertEquals(admitted.get(), snapshot.acquired());
        assertEquals(refused.get(), snapshot.rejected());
    }

    private static String host(String method, String uri, String hostHeader) {
        HttpRequest r = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.valueOf(method), uri);
        if (hostHeader != null) r.headers().set("Host", hostHeader);
        return ConcurrencyLimiter.targetHost(r);
    }

    private static FlowContext flow(long id) {
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, 40000);
        return new FlowContext(id, () -> address, () -> null, new ClientDetails());
    }

    private static Socket open(InetSocketAddress proxy) throws Exception {
        Socket s = new Socket(proxy.getAddress(), proxy.getPort());
        s.setSoTimeout(20_000);
        return s;
    }

    private static int connectOnce(InetSocketAddress proxy, String target) throws Exception {
        try (Socket s = open(proxy)) {
            return connect(s, target);
        }
    }

    private static int connect(Socket socket, String target) throws Exception {
        TestSupport.write(socket.getOutputStream(), "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
        String head = TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
        return Integer.parseInt(head.substring(9, 12));
    }
}
