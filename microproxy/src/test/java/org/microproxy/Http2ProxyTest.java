package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.eventually;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.cache.HttpCache;
import org.microproxy.cache.MemoryCacheStore;
import org.microproxy.extras.ActivityLogger;
import org.microproxy.extras.HttpLogger;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * HTTP/2 between clients and the proxy, on intercepted TLS, with the JDK's HTTP/2 client: the
 * origin side stays HTTP/1.1, and everything the proxy does for HTTP/1 requests works per stream.
 */
class Http2ProxyTest {

    static CertificateAuthority originCa;
    static CertificateAuthority proxyCa;

    private HttpsServer origin;
    private HttpProxyServer proxy;
    private final AtomicInteger cacheHits = new AtomicInteger();
    private final Set<Integer> barrierPorts = ConcurrentHashMap.newKeySet();
    private volatile CyclicBarrier barrier = new CyclicBarrier(1);
    private final CountDownLatch release = new CountDownLatch(1);
    private final CountDownLatch slowArrived = new CountDownLatch(1);

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("H2 Origin CA");
        proxyCa = CertificateAuthority.generate("H2 Proxy CA");
    }

    @BeforeEach
    void startOrigin() throws IOException {
        // Platform threads: the JDK's HTTPS server pins virtual threads in its TLS code, and dozens
        // of concurrent handshakes would then starve the proxy's own virtual threads.
        origin = HttpsServer.create(new InetSocketAddress(TestSupport.LOOPBACK, 0), 100);
        origin.setHttpsConfigurator(new com.sun.net.httpserver.HttpsConfigurator(
                originCa.serverContext("localhost", "127.0.0.1")));
        origin.createContext("/", this::handle);
        origin.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        origin.start();
    }

    @AfterEach
    void tearDown() {
        release.countDown();
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    /** The origin: an echo, plus a few paths with special behaviour. */
    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        switch (path) {
            case "/protocol" -> respond(exchange, 200, exchange.getProtocol());
            case "/barrier" -> {
                barrierPorts.add(exchange.getRemoteAddress().getPort());
                try {
                    barrier.await(20, TimeUnit.SECONDS);
                } catch (Exception e) {
                    respond(exchange, 500, "barrier broken");
                    return;
                }
                respond(exchange, 200, exchange.getRequestURI().getQuery());
            }
            case "/cache" -> {
                cacheHits.incrementAndGet();
                exchange.getResponseHeaders().set("Cache-Control", "max-age=60");
                respond(exchange, 200, "cached body");
            }
            case "/slow" -> {
                slowArrived.countDown();
                try {
                    release.await(20, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                respond(exchange, 200, "slow");
            }
            case "/large" -> {
                byte[] body = new byte[3 << 20];
                new Random(7).nextBytes(body);
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            }
            case "/digest" -> {
                byte[] body = exchange.getRequestBody().readAllBytes();
                respond(exchange, 200, body.length + " " + sha256(body));
            }
            default -> TestSupport.echo().handle(exchange);
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        exchange.getRequestBody().readAllBytes();
        byte[] out = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, out.length == 0 ? -1 : out.length);
        if (out.length > 0) exchange.getResponseBody().write(out);
        exchange.close();
    }

    static String sha256(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private HttpProxyServerBootstrap mitm() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("h2proxy")
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp2(true);
    }

    static HttpClient h2Client(HttpProxyServer proxy, SSLContext trust) {
        return HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(Duration.ofSeconds(10))
                .proxy(ProxySelector.of(proxy.getListenAddress()))
                .sslContext(trust)
                .build();
    }

    private HttpClient client() {
        return h2Client(proxy, proxyCa.clientContext());
    }

    private String url(String path) {
        return TestSupport.url(origin, path);
    }

    private static HttpRequest get(String url) {
        return HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30)).build();
    }

    @Test
    void getIsServedOverHttp2AndForwardedAsHttp11() {
        List<String> versions = new CopyOnWriteArrayList<>();
        proxy = mitm().withFiltersSource((request, ctx) -> {
            versions.add(request.method() + " " + request.protocolVersion() + " stream=" + ctx.getStreamId());
            return null;
        }).start();
        HttpClient client = client();
        HttpResponse<String> response = TestSupport.send(client, get(url("/hello?x=1")));
        assertEquals(200, response.statusCode());
        assertEquals(HttpClient.Version.HTTP_2, response.version());
        assertEquals("/hello?x=1", echoedUri(response.body()));
        assertEquals(List.of("2 h2proxy"), echoedHeader(response.body(), "via"));
        // The origin was reached with HTTP/1.1.
        assertEquals("HTTP/1.1", TestSupport.send(client, get(url("/protocol"))).body());
        assertTrue(versions.get(0).startsWith("CONNECT HTTP/1.1 stream=0"), versions.toString());
        assertTrue(versions.get(1).startsWith("GET HTTP/2.0 stream="), versions.toString());
        assertTrue(!versions.get(1).endsWith("stream=0"), versions.toString());
    }

    @Test
    void largeBodiesBothWaysUseFlowControl() {
        proxy = mitm().start();
        byte[] upload = new byte[(2 << 20) + 12_345];
        new Random(1).nextBytes(upload);
        HttpClient client = client();
        HttpResponse<String> posted = TestSupport.send(client, HttpRequest.newBuilder(URI.create(url("/digest")))
                .timeout(Duration.ofSeconds(30)).POST(HttpRequest.BodyPublishers.ofByteArray(upload)).build());
        assertEquals(HttpClient.Version.HTTP_2, posted.version());
        assertEquals(upload.length + " " + sha256(upload), posted.body());

        HttpResponse<byte[]> download;
        try {
            download = client.send(get(url("/large")), HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException | InterruptedException e) {
            throw new AssertionError(e);
        }
        byte[] expected = new byte[3 << 20];
        new Random(7).nextBytes(expected);
        assertArrayEquals(expected, download.body());
    }

    @Test
    void concurrentStreamsShareOneClientConnectionButNotServerConnections() throws Exception {
        AtomicInteger clientConnections = new AtomicInteger();
        proxy = mitm().plusActivityTracker(new ActivityTrackerAdapter() {
            @Override
            public void clientConnected(FlowContext ctx) {
                clientConnections.incrementAndGet();
            }
        }).start();
        HttpClient client = client();
        assertEquals(200, TestSupport.send(client, get(url("/warm-up"))).statusCode());
        int n = 50;
        barrier = new CyclicBarrier(n);
        List<CompletableFuture<HttpResponse<String>>> futures = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            futures.add(client.sendAsync(get(url("/barrier?" + i)), HttpResponse.BodyHandlers.ofString()));
        }
        for (int i = 0; i < n; i++) {
            HttpResponse<String> r = futures.get(i).get(30, TimeUnit.SECONDS);
            assertEquals(200, r.statusCode(), "arrived " + barrierPorts.size() + " waiting " + barrier.getNumberWaiting());
            assertEquals(HttpClient.Version.HTTP_2, r.version());
            assertEquals(String.valueOf(i), r.body());
        }
        // All 50 waited at the origin at once: each had a server connection of its own.
        assertEquals(n, barrierPorts.size());
        assertEquals(1, clientConnections.get());
        // Idle server connections are reused by later streams.
        assertEquals(200, TestSupport.send(client, get(url("/again"))).statusCode());
    }

    @Test
    void filtersChangeHeadersAndBodiesOfStreams() {
        proxy = mitm().withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(org.microproxy.http.HttpRequest originalRequest, FlowContext ctx) {
                return new HttpFiltersAdapter(originalRequest, ctx) {
                    @Override
                    public org.microproxy.http.HttpResponse proxyToServerRequest(HttpObject o) {
                        if (o instanceof org.microproxy.http.HttpRequest r) r.headers().set("X-Added", "by-filter");
                        return null;
                    }

                    @Override
                    public HttpObject proxyToClientResponse(HttpObject o) {
                        if (o instanceof FullHttpResponse r) {
                            r.headers().set("X-Version", originalRequest.protocolVersion().text());
                            r.setContent((new String(r.content(), StandardCharsets.UTF_8) + "+filtered")
                                    .getBytes(StandardCharsets.UTF_8));
                        }
                        return o;
                    }
                };
            }

            @Override
            public int getMaximumResponseBufferSizeInBytes() {
                return 1 << 20;
            }
        }).start();
        HttpResponse<String> response = TestSupport.send(client(), HttpRequest.newBuilder(URI.create(url("/f")))
                .timeout(Duration.ofSeconds(30)).POST(HttpRequest.BodyPublishers.ofString("payload")).build());
        assertEquals(HttpClient.Version.HTTP_2, response.version());
        assertEquals("HTTP/2.0", response.headers().firstValue("x-version").orElseThrow());
        assertEquals(List.of("by-filter"), echoedHeader(response.body(), "x-added"));
        assertEquals("payload+filtered", echoedBody(response.body()));
    }

    @Test
    void shortCircuitAnswersOneStreamOnly() {
        proxy = mitm().withFiltersSource(HttpFilters.builder()
                .onRequest(r -> r.uri().equals("/blocked")
                        ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN,
                                "no".getBytes(StandardCharsets.UTF_8))
                        : null)
                .build()).start();
        HttpClient client = client();
        HttpResponse<String> blocked = TestSupport.send(client, get(url("/blocked")));
        assertEquals(403, blocked.statusCode());
        assertEquals("no", blocked.body());
        assertEquals(HttpClient.Version.HTTP_2, blocked.version());
        assertEquals("/open", echoedUri(TestSupport.send(client, get(url("/open"))).body()));
    }

    @Test
    void unreachableOriginFailsOnlyItsStream() throws Exception {
        try (Socket dead = TestSupport.refusingPort()) {
            int port = dead.getLocalPort();
            proxy = mitm()
                    .withFailureResponder((request, failure) -> {
                        FullHttpResponse r = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                                HttpResponseStatus.BAD_GATEWAY, ("custom " + failure.getClass().getSimpleName())
                                        .getBytes(StandardCharsets.UTF_8));
                        return r;
                    })
                    .withFiltersSource(new HttpFiltersSourceAdapter() {
                        @Override
                        public HttpFilters filterRequest(org.microproxy.http.HttpRequest req, FlowContext ctx) {
                            return new HttpFiltersAdapter(req, ctx) {
                                @Override
                                public boolean proxyToServerAllowOfflineMitm() {
                                    return true;
                                }

                                @Override
                                public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject o) {
                                    if (o instanceof org.microproxy.http.HttpRequest r && r.uri().startsWith("/ok")) {
                                        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                                                r.uri().getBytes(StandardCharsets.UTF_8));
                                    }
                                    return null;
                                }
                            };
                        }
                    }).start();
            HttpClient client = client();
            List<CompletableFuture<HttpResponse<String>>> futures = new ArrayList<>();
            for (int i = 0; i < 10; i++) {
                String path = (i % 2 == 0 ? "/ok/" : "/fail/") + i;
                futures.add(client.sendAsync(get("https://127.0.0.1:" + port + path), HttpResponse.BodyHandlers.ofString()));
            }
            for (int i = 0; i < 10; i++) {
                HttpResponse<String> r = futures.get(i).get(30, TimeUnit.SECONDS);
                assertEquals(HttpClient.Version.HTTP_2, r.version());
                if (i % 2 == 0) {
                    assertEquals(200, r.statusCode());
                    assertEquals("/ok/" + i, r.body());
                } else {
                    assertEquals(502, r.statusCode());
                    assertEquals("custom ConnectFailed", r.body());
                }
            }
        }
    }

    @Test
    void cacheAnswersStreams() {
        List<ResponseSource> sources = new CopyOnWriteArrayList<>();
        proxy = mitm().withHttpCache(HttpCache.builder().store(new MemoryCacheStore(1 << 20)).build())
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void responseSentToClient(FlowContext ctx, org.microproxy.http.HttpResponse r, ResponseSource s) {
                        if (ctx.getStreamId() != 0) sources.add(s);
                    }
                }).start();
        HttpClient client = client();
        assertEquals("cached body", TestSupport.send(client, get(url("/cache"))).body());
        HttpResponse<String> second = TestSupport.send(client, get(url("/cache")));
        assertEquals("cached body", second.body());
        assertEquals(HttpClient.Version.HTTP_2, second.version());
        assertEquals(1, cacheHits.get());
        eventually("two responses", () -> sources.size() == 2);
        assertEquals(List.of(ResponseSource.SERVER, ResponseSource.CACHE), sources);
    }

    @Test
    void httpLoggerAndActivityLoggerShowHttp2() {
        List<String> logged = new CopyOnWriteArrayList<>();
        List<String> access = new CopyOnWriteArrayList<>();
        proxy = mitm().withFiltersSource(HttpLogger.builder().level(HttpLogger.Level.HEADERS).sink(logged::add).build())
                .plusActivityTracker(new ActivityLogger(org.microproxy.extras.LogFormat.CLF, access::add))
                .start();
        assertEquals(200, TestSupport.send(client(), get(url("/logged"))).statusCode());
        eventually("the logged response", () -> logged.stream().anyMatch(m -> m.contains("<-- 200")
                && m.contains("/logged")));
        String request = logged.stream().filter(m -> m.contains("--> GET https://")).findFirst().orElseThrow();
        assertTrue(request.contains("/logged HTTP/2.0"), request);
        assertTrue(request.contains("--> forwarded as GET /logged HTTP/1.1"), request);
        assertTrue(request.startsWith("[conn ") && request.contains(" stream "), request);
        eventually("the access log line", () -> access.stream().anyMatch(l -> l.contains("/logged HTTP/2.0")));
    }

    @Test
    void streamsInheritTheAuthenticationOfTheirConnect() throws Exception {
        AtomicInteger asked = new AtomicInteger();
        proxy = mitm().withProxyAuthenticator(new ProxyAuthenticator() {
            @Override
            public boolean authenticate(String userName, String password) {
                asked.incrementAndGet();
                return "user".equals(userName) && "secret".equals(password);
            }

            @Override
            public String getRealm() {
                return "h2";
            }
        }).start();
        String target = "127.0.0.1:" + origin.getAddress().getPort();
        H2TestClient.ConnectRefused refused = org.junit.jupiter.api.Assertions.assertThrows(
                H2TestClient.ConnectRefused.class,
                () -> H2TestClient.connect(proxy.getListenAddress(), target, proxyCa.clientContext()));
        assertEquals(407, refused.status);
        String credentials = java.util.Base64.getEncoder().encodeToString("user:secret".getBytes(StandardCharsets.UTF_8));
        try (H2TestClient h2 = H2TestClient.connect(proxy.getListenAddress(), target, proxyCa.clientContext(),
                "Proxy-Authorization: Basic " + credentials).handshake()) {
            int before = asked.get();
            h2.get(1, "/one");
            h2.get(3, "/two");
            H2TestClient.Response one = h2.response(1);
            H2TestClient.Response two = h2.response(3);
            assertEquals(200, one.status());
            assertEquals("/one", echoedUri(one.text()));
            assertEquals("/two", echoedUri(two.text()));
            // No Proxy-Authorization reached the origin, and streams were not asked to authenticate.
            assertTrue(echoedHeader(one.text(), "proxy-authorization").isEmpty());
            assertEquals(before, asked.get());
        }
    }

    @Test
    void chunkedTrailersBecomeTrailingHeaders() throws Exception {
        SSLContext originTls = originCa.serverContext("127.0.0.1");
        try (javax.net.ssl.SSLServerSocket server = (javax.net.ssl.SSLServerSocket) originTls.getServerSocketFactory()
                .createServerSocket(0, 50, TestSupport.LOOPBACK)) {
            Thread.ofVirtual().start(() -> {
                while (!server.isClosed()) {
                    try {
                        Socket s = server.accept();
                        Thread.ofVirtual().start(() -> {
                            try (s) {
                                TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
                                TestSupport.write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                                        + "Trailer: X-Checksum\r\nContent-Type: text/plain\r\n\r\n"
                                        + "5\r\nhello\r\n6\r\n world\r\n0\r\nX-Checksum: abc123\r\n\r\n");
                                s.getInputStream().read();
                            } catch (IOException ignored) {
                                // test origin
                            }
                        });
                    } catch (IOException e) {
                        return;
                    }
                }
            });
            proxy = mitm().start();
            try (H2TestClient h2 = H2TestClient.connect(proxy.getListenAddress(), "127.0.0.1:" + server.getLocalPort(),
                    proxyCa.clientContext()).handshake()) {
                h2.get(1, "/trailers", "te", "trailers");
                H2TestClient.Response r = h2.response(1);
                assertEquals(200, r.status());
                assertEquals("hello world", r.text());
                assertEquals(null, r.header("transfer-encoding"));
                assertEquals(1, r.trailers().size(), r.trailers().toString());
                assertEquals("x-checksum", r.trailers().get(0).name());
                assertEquals("abc123", r.trailers().get(0).value());
            }
        }
    }

    @Test
    void clientResetClosesTheStreamsServerConnection() throws Exception {
        CountDownLatch serverClosed = new CountDownLatch(1);
        proxy = mitm().plusActivityTracker(new ActivityTrackerAdapter() {
            @Override
            public void serverDisconnected(FullFlowContext ctx, InetSocketAddress address) {
                if (ctx.getStreamId() == 1) serverClosed.countDown();
            }
        }).start();
        try (H2TestClient h2 = H2TestClient.connect(proxy.getListenAddress(), "127.0.0.1:" + origin.getAddress().getPort(),
                proxyCa.clientContext()).handshake()) {
            h2.get(1, "/slow");
            assertTrue(slowArrived.await(10, TimeUnit.SECONDS));
            h2.rst(1, io.github.mahmoudimus.http2.ErrorCode.CANCEL);
            assertTrue(serverClosed.await(10, TimeUnit.SECONDS), "the server connection was not closed");
            // The connection carries on.
            h2.get(3, "/after");
            assertEquals("/after", echoedUri(h2.response(3).text()));
        }
    }

    @Test
    void withoutHttp2ClientsGetHttp11() {
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .start();
        HttpResponse<String> response = TestSupport.send(client(), get(url("/plain")));
        assertEquals(200, response.statusCode());
        assertEquals(HttpClient.Version.HTTP_1_1, response.version());
    }

    @Test
    void clientsWithoutH2KeepHttp11() {
        proxy = mitm().start();
        HttpClient http1 = TestSupport.client(proxy, proxyCa.clientContext());
        HttpResponse<String> response = TestSupport.send(http1, get(url("/h1")));
        assertEquals(HttpClient.Version.HTTP_1_1, response.version());
        assertEquals("/h1", echoedUri(response.body()));
    }

    @Test
    void gracefulStopFinishesOpenStreams() throws Exception {
        proxy = mitm().start();
        HttpClient client = client();
        assertEquals(200, TestSupport.send(client, get(url("/first"))).statusCode());
        CompletableFuture<HttpResponse<String>> slow = client.sendAsync(get(url("/slow")), HttpResponse.BodyHandlers.ofString());
        assertTrue(slowArrived.await(10, TimeUnit.SECONDS));
        Thread stopper = Thread.ofVirtual().start(proxy::stop);
        Thread.sleep(200);
        release.countDown();
        HttpResponse<String> r = slow.get(20, TimeUnit.SECONDS);
        assertEquals("slow", r.body());
        stopper.join(20_000);
        assertNotNull(r);
    }

    @Test
    void curlSpeaksHttp2ThroughTheProxy() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(curlWithHttp2(), "curl with HTTP/2 support is not installed");
        proxy = mitm().start();
        java.nio.file.Path ca = java.nio.file.Files.createTempFile("h2-proxy-ca", ".pem");
        try {
            proxyCa.writeCertificatePem(ca);
            // --noproxy '': curl skips even -x for hosts in NO_PROXY, which often lists 127.0.0.1.
            ProcessBuilder curl = new ProcessBuilder("curl", "-sS", "--noproxy", "", "--http2",
                    "-x", "http://127.0.0.1:" + proxy.getListenAddress().getPort(),
                    "--cacert", ca.toString(), "-o", "/dev/null", "-w", "%{http_version} %{http_code}",
                    url("/curl")).redirectErrorStream(true);
            curl.environment().keySet().removeIf(k -> k.equalsIgnoreCase("no_proxy") || k.equalsIgnoreCase("https_proxy")
                    || k.equalsIgnoreCase("all_proxy"));
            Process p = curl.start();
            assertTrue(p.waitFor(30, TimeUnit.SECONDS));
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
            assertEquals("2 200", out);
        } finally {
            java.nio.file.Files.deleteIfExists(ca);
        }
    }

    static boolean curlWithHttp2() {
        try {
            Process p = new ProcessBuilder("curl", "--version").redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return p.waitFor(10, TimeUnit.SECONDS) && p.exitValue() == 0 && out.contains("HTTP2");
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
