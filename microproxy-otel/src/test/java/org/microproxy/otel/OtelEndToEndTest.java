package org.microproxy.otel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.http3.HeaderField;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyAdapter;
import org.microproxy.H3TestClient;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Tracing through the proxy, end to end, into a test OTLP collector: a SERVER span per exchange
 * over HTTP/1.1, HTTP/2 and HTTP/3, a CLIENT span per attempt to reach the server, parented as the
 * W3C context says, the context the origin gets, failures with their status and flags, and the
 * other propagators.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class OtelEndToEndTest {

    static final String TRACE = "0af7651916cd43dd8448eb211c80319c";
    static final String PARENT = "b7ad6b7169203331";

    private TestCollector collector;
    private HttpServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() throws Exception {
        collector = new TestCollector();
        origin = TestSupport.origin(TestSupport.echo());
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.stop();
        origin.stop(0);
        collector.close();
    }

    /** Telemetry exporting to the collector quickly: batches leave after 20 ms. */
    Telemetry.Builder telemetry() {
        return Telemetry.builder().endpoint(collector.endpoint()).metrics(false).logs(false)
                .spanQueue(2048, 512, Duration.ofMillis(20)).retry(2, Duration.ofMillis(10), Duration.ofMillis(50));
    }

    HttpProxyServer start(Telemetry telemetry, HttpProxyServerBootstrap bootstrap) {
        proxy = telemetry.install(bootstrap.withPort(0)).start();
        return proxy;
    }

    static HttpResponse<String> get(HttpClient client, String url, String... headers) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30));
        for (int i = 0; i < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        return TestSupport.send(client, b.build());
    }

    static TestCollector.Span kind(List<TestCollector.Span> spans, int kind) {
        return spans.stream().filter(s -> s.kind() == kind).findFirst().orElseThrow(() -> new AssertionError(spans));
    }

    @Test
    void anHttp1ExchangeIsAServerSpanWithAClientSpanUnderTheClientsTrace() {
        start(telemetry().build(), MicroProxy.bootstrap());
        HttpResponse<String> response = get(TestSupport.client(proxy), TestSupport.url(origin, "/items?id=7"),
                "traceparent", "00-" + TRACE + "-" + PARENT + "-01", "tracestate", "rojo=00f067aa0ba902b7",
                "User-Agent", "otel-test/1.0");
        assertEquals(200, response.statusCode());
        List<TestCollector.Span> spans = collector.awaitSpans("server and client spans", s -> s.size() >= 2);
        TestCollector.Span server = kind(spans, 2);
        TestCollector.Span client = kind(spans, 3);
        assertEquals(TRACE, server.traceId());
        assertEquals(PARENT, server.parentSpanId());
        assertEquals("rojo=00f067aa0ba902b7", server.traceState());
        assertEquals(TRACE, client.traceId());
        assertEquals(server.spanId(), client.parentSpanId());
        assertEquals("GET", server.name());
        assertEquals("GET", client.name());
        // The origin's parent is the proxy's CLIENT span, and the client's tracestate goes on.
        assertEquals(List.of("00-" + TRACE + "-" + client.spanId() + "-01"),
                TestSupport.echoedHeader(response.body(), "traceparent"));
        assertEquals(List.of("rojo=00f067aa0ba902b7"), TestSupport.echoedHeader(response.body(), "tracestate"));
        // The semantic conventions.
        int port = origin.getAddress().getPort();
        assertEquals("GET", server.attr("http.request.method"));
        assertEquals("http://127.0.0.1:" + port + "/items?id=7", server.attr("url.full"));
        assertEquals("/items", server.attr("url.path"));
        assertEquals("id=7", server.attr("url.query"));
        assertEquals("http", server.attr("url.scheme"));
        assertEquals("127.0.0.1", server.attr("server.address"));
        assertEquals((long) port, server.attr("server.port"));
        assertEquals(200L, server.attr("http.response.status_code"));
        assertEquals("1.1", server.attr("network.protocol.version"));
        assertEquals("http", server.attr("network.protocol.name"));
        assertEquals("127.0.0.1", server.attr("client.address"));
        assertEquals("otel-test/1.0", server.attr("user_agent.original"));
        assertEquals("SERVER", server.attr("microproxy.response_source"));
        assertEquals("via_upstream", server.attr("microproxy.response_code_details"));
        assertEquals("h1", server.attr("microproxy.flow"));
        assertEquals("127.0.0.1:" + port, server.attr("upstream_cluster"));
        assertNull(server.attr("error.type"));
        assertNull(server.attr("response_flags"));
        assertEquals(0, server.statusCode());
        assertEquals("http://127.0.0.1:" + port + "/items?id=7", client.attr("url.full"));
        assertEquals("127.0.0.1", client.attr("server.address"));
        assertEquals(200L, client.attr("http.response.status_code"));
        assertEquals(0, client.statusCode());
        // The request id the proxy added reached the origin, and the span.
        String requestId = TestSupport.echoedHeader(response.body(), "x-request-id").getFirst();
        assertEquals(requestId, server.attr("guid:x-request-id"));
        assertEquals(4, java.util.UUID.fromString(requestId).version());
        // Events from the timings, inside the span; the client span inside the server span.
        assertNotNull(server.event("connect"), server.events().toString());
        assertNotNull(server.event("first_byte"));
        assertTrue(server.event("connect").attributes().get("microproxy.duration_ms") instanceof Double);
        for (TestCollector.Event e : server.events()) {
            assertTrue(e.time() >= server.start() && e.time() <= server.end(), e + " in " + server);
        }
        assertTrue(client.start() >= server.start() && client.end() <= server.end(), client + " in " + server);
        // Sampled, with a remote parent: the span flags say so.
        assertEquals(0x301, server.flags());
        assertEquals(0x101, client.flags());
        assertEquals("microproxy", server.resource().get("service.name"));
        assertNotNull(server.resource().get("host.name"));
        assertNotNull(server.resource().get("process.runtime.version"));
    }

    @Test
    void aNewTraceStartsWithoutAContextAndTheProxysRequestIdIsKept() {
        start(telemetry().build(), MicroProxy.bootstrap());
        HttpResponse<String> response = get(TestSupport.client(proxy), TestSupport.url(origin, "/new"),
                "X-Request-Id", "client-chosen-id");
        List<TestCollector.Span> spans = collector.awaitSpans("spans", s -> s.size() >= 2);
        TestCollector.Span server = kind(spans, 2);
        assertNull(server.parentSpanId());
        assertEquals(0x101, server.flags());
        assertEquals(List.of("client-chosen-id"), TestSupport.echoedHeader(response.body(), "x-request-id"));
        assertEquals("client-chosen-id", server.attr("guid:x-request-id"));
        String traceparent = TestSupport.echoedHeader(response.body(), "traceparent").getFirst();
        assertTrue(traceparent.startsWith("00-" + server.traceId() + "-"), traceparent);
        assertTrue(traceparent.endsWith("-01"));
    }

    @Test
    void anUnsampledRequestOnlyPropagates() {
        start(telemetry().build(), MicroProxy.bootstrap());
        HttpResponse<String> response = get(TestSupport.client(proxy), TestSupport.url(origin, "/unsampled"),
                "traceparent", "00-" + TRACE + "-" + PARENT + "-00");
        String traceparent = TestSupport.echoedHeader(response.body(), "traceparent").getFirst();
        assertTrue(traceparent.startsWith("00-" + TRACE + "-") && traceparent.endsWith("-00"), traceparent);
        assertNotEquals(PARENT, traceparent.substring(36, 52), "the proxy's span id, not the client's");
        // A sampled request afterwards is exported; the unsampled one never was.
        get(TestSupport.client(proxy), TestSupport.url(origin, "/sampled"));
        collector.awaitSpans("the sampled request's spans", s -> s.size() >= 2);
        proxy.stop();
        assertTrue(collector.spans.stream().noneMatch(s -> s.traceId().equals(TRACE)), collector.spans.toString());
    }

    @Test
    void theForceTraceHeaderSamplesWhatTheSamplerWouldNot() {
        start(telemetry().sampler(Sampler.alwaysOff()).forceTraceHeader("x-force-trace").build(), MicroProxy.bootstrap());
        get(TestSupport.client(proxy), TestSupport.url(origin, "/not-traced"));
        get(TestSupport.client(proxy), TestSupport.url(origin, "/forced"), "x-force-trace", "1");
        TestCollector.Span forced = collector.awaitSpan("the forced span", s -> s.kind() == 2);
        assertEquals("/forced", forced.attr("url.path"));
        proxy.stop();
        assertEquals(2, collector.spans.size(), collector.spans.toString());
    }

    @Test
    void aRefusedConnectionIsAnErrorWithItsResponseFlag() throws Exception {
        try (Socket refusing = TestSupport.refusingPort()) {
            start(telemetry().build(), MicroProxy.bootstrap());
            int port = refusing.getLocalPort();
            assertEquals(502, get(TestSupport.client(proxy), "http://127.0.0.1:" + port + "/").statusCode());
            List<TestCollector.Span> spans = collector.awaitSpans("spans", s -> s.size() >= 2);
            TestCollector.Span server = kind(spans, 2);
            TestCollector.Span client = kind(spans, 3);
            assertEquals(2, server.statusCode());
            assertEquals("proxy_failure:connect_failed", server.statusMessage());
            assertEquals("502", server.attr("error.type"));
            assertEquals("UF", server.attr("response_flags"));
            assertEquals("PROXY", server.attr("microproxy.response_source"));
            assertEquals(502L, server.attr("http.response.status_code"));
            assertEquals(2, client.statusCode());
            assertEquals("connect_failed", client.attr("error.type"));
            assertNull(client.attr("http.response.status_code"));
        }
    }

    @Test
    void aServerErrorIsAnErrorOnBothSpans() throws Exception {
        HttpServer failing = TestSupport.origin(TestSupport.fixed(503, "busy"));
        try {
            start(telemetry().build(), MicroProxy.bootstrap());
            assertEquals(503, get(TestSupport.client(proxy), TestSupport.url(failing, "/")).statusCode());
            List<TestCollector.Span> spans = collector.awaitSpans("spans", s -> s.size() >= 2);
            assertEquals(2, kind(spans, 2).statusCode());
            assertEquals("503", kind(spans, 2).attr("error.type"));
            assertEquals(2, kind(spans, 3).statusCode());
            assertEquals("503", kind(spans, 3).attr("error.type"));
        } finally {
            failing.stop(0);
        }
    }

    @Test
    void aClientErrorIsAnErrorForTheClientSpanOnly() throws Exception {
        HttpServer missing = TestSupport.origin(TestSupport.fixed(404, "no"));
        try {
            start(telemetry().build(), MicroProxy.bootstrap());
            assertEquals(404, get(TestSupport.client(proxy), TestSupport.url(missing, "/")).statusCode());
            List<TestCollector.Span> spans = collector.awaitSpans("spans", s -> s.size() >= 2);
            assertEquals(0, kind(spans, 2).statusCode());
            assertNull(kind(spans, 2).attr("error.type"));
            assertEquals(2, kind(spans, 3).statusCode());
            assertEquals("404", kind(spans, 3).attr("error.type"));
        } finally {
            missing.stop(0);
        }
    }

    @Test
    void failingOverToTheNextChainedProxyIsAClientSpanPerAttempt() throws Exception {
        try (Socket refusing = TestSupport.refusingPort()) {
            ChainedProxy dead = new ChainedProxyAdapter() {
                @Override
                public InetSocketAddress getChainedProxyAddress() {
                    return (InetSocketAddress) refusing.getLocalSocketAddress();
                }
            };
            start(telemetry().build(), MicroProxy.bootstrap().withChainProxyManager((request, chain, flow) -> {
                chain.add(dead);
                chain.add(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
            }));
            HttpResponse<String> response = get(TestSupport.client(proxy), TestSupport.url(origin, "/failover"));
            assertEquals(200, response.statusCode());
            List<TestCollector.Span> spans = collector.awaitSpans("three spans", s -> s.size() >= 3);
            TestCollector.Span server = kind(spans, 2);
            List<TestCollector.Span> clients = spans.stream().filter(s -> s.kind() == 3)
                    .sorted(java.util.Comparator.comparingLong(TestCollector.Span::start)).toList();
            assertEquals(2, clients.size(), spans.toString());
            TestCollector.Span failed = clients.get(0);
            TestCollector.Span direct = clients.get(1);
            assertEquals("connect_failed", failed.attr("error.type"));
            assertEquals("127.0.0.1:" + refusing.getLocalPort(), failed.attr("microproxy.chained_proxy"));
            assertNull(failed.attr("http.request.resend_count"));
            assertEquals(1L, direct.attr("http.request.resend_count"));
            assertEquals(200L, direct.attr("http.response.status_code"));
            assertEquals(server.spanId(), failed.parentSpanId());
            assertEquals(server.spanId(), direct.parentSpanId());
            assertEquals(List.of("00-" + server.traceId() + "-" + direct.spanId() + "-01"),
                    TestSupport.echoedHeader(response.body(), "traceparent"));
        }
    }

    @Test
    void strippedTracingHeadersCarryOnlyTheProxysContext() {
        start(telemetry().build(), MicroProxy.bootstrap().withoutTracingHeadersUpstream());
        HttpResponse<String> response = get(TestSupport.client(proxy), TestSupport.url(origin, "/stripped"),
                "traceparent", "00-" + TRACE + "-" + PARENT + "-01", "tracestate", "rojo=1", "baggage", "user=alice",
                "b3", TRACE + "-" + PARENT + "-1");
        TestCollector.Span client = collector.awaitSpan("the client span", s -> s.kind() == 3);
        assertEquals(List.of("00-" + TRACE + "-" + client.spanId() + "-01"),
                TestSupport.echoedHeader(response.body(), "traceparent"));
        assertEquals(List.of(), TestSupport.echoedHeader(response.body(), "tracestate"));
        assertEquals(List.of(), TestSupport.echoedHeader(response.body(), "baggage"));
        assertEquals(List.of(), TestSupport.echoedHeader(response.body(), "b3"));
    }

    @Test
    void strippedTracingHeadersCanCarryNothing() {
        start(telemetry().whenStripped(Telemetry.WhenStripped.NONE).build(),
                MicroProxy.bootstrap().withoutTracingHeadersUpstream());
        HttpResponse<String> response = get(TestSupport.client(proxy), TestSupport.url(origin, "/nothing"),
                "traceparent", "00-" + TRACE + "-" + PARENT + "-01");
        assertEquals(List.of(), TestSupport.echoedHeader(response.body(), "traceparent"));
        // The trace is still recorded, as the client's.
        assertEquals(TRACE, collector.awaitSpan("the server span", s -> s.kind() == 2).traceId());
    }

    @Test
    void ignoringIncomingContextStartsANewTrace() {
        start(telemetry().trustIncoming(false).build(), MicroProxy.bootstrap());
        get(TestSupport.client(proxy), TestSupport.url(origin, "/boundary"), "traceparent", "00-" + TRACE + "-" + PARENT + "-01");
        TestCollector.Span server = collector.awaitSpan("the server span", s -> s.kind() == 2);
        assertNotEquals(TRACE, server.traceId());
        assertNull(server.parentSpanId());
    }

    @Test
    void b3AndJaegerAreReadAndWritten() {
        start(telemetry().propagators(List.of(Propagators.B3_MULTI, Propagators.JAEGER)).build(), MicroProxy.bootstrap());
        HttpResponse<String> response = get(TestSupport.client(proxy), TestSupport.url(origin, "/b3"),
                "X-B3-TraceId", TRACE, "X-B3-SpanId", PARENT, "X-B3-Sampled", "1");
        List<TestCollector.Span> spans = collector.awaitSpans("spans", s -> s.size() >= 2);
        TestCollector.Span server = kind(spans, 2);
        TestCollector.Span client = kind(spans, 3);
        assertEquals(TRACE, server.traceId());
        assertEquals(PARENT, server.parentSpanId());
        assertEquals(List.of(client.spanId()), TestSupport.echoedHeader(response.body(), "x-b3-spanid"));
        assertEquals(List.of("1"), TestSupport.echoedHeader(response.body(), "x-b3-sampled"));
        assertEquals(List.of(TRACE + ":" + client.spanId() + ":0:1"),
                TestSupport.echoedHeader(response.body(), "uber-trace-id"));
        assertEquals(List.of(), TestSupport.echoedHeader(response.body(), "traceparent"));

        collector.spans.clear();
        response = get(TestSupport.client(proxy), TestSupport.url(origin, "/jaeger"),
                "uber-trace-id", "6d1f:1a:0:1");
        server = collector.awaitSpan("the jaeger-parented span", s -> s.kind() == 2);
        assertEquals("00000000000000000000000000006d1f", server.traceId());
        assertEquals("000000000000001a", server.parentSpanId());
    }

    @Test
    void jsonExportCarriesTheSameSpans() {
        start(telemetry().protocol(Telemetry.Protocol.HTTP_JSON).compression(true).build(), MicroProxy.bootstrap());
        get(TestSupport.client(proxy), TestSupport.url(origin, "/json"), "traceparent", "00-" + TRACE + "-" + PARENT + "-01");
        List<TestCollector.Span> spans = collector.awaitSpans("spans", s -> s.size() >= 2);
        assertEquals(TRACE, kind(spans, 2).traceId());
        assertEquals(PARENT, kind(spans, 2).parentSpanId());
        assertEquals(kind(spans, 2).spanId(), kind(spans, 3).parentSpanId());
        assertEquals("/json", kind(spans, 2).attr("url.path"));
        assertEquals(200L, kind(spans, 2).attr("http.response.status_code"));
        TestCollector.Request request = collector.requests.getFirst();
        assertEquals("application/json", request.contentType());
        assertEquals("gzip", request.contentEncoding());
    }

    @Test
    void aTunnelIsAnInternalSpanWithItsConnection() throws Exception {
        start(telemetry().build(), MicroProxy.bootstrap());
        try (TestSupport.RawServer echo = TestSupport.rawServer(s -> {
            byte[] b = s.getInputStream().readNBytes(5);
            s.getOutputStream().write(b);
            s.getOutputStream().flush();
        }); Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            int port = echo.port();
            TestSupport.write(s.getOutputStream(), "CONNECT 127.0.0.1:" + port + " HTTP/1.1\r\nHost: 127.0.0.1:" + port
                    + "\r\ntraceparent: 00-" + TRACE + "-" + PARENT + "-01\r\n\r\n");
            assertTrue(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
            TestSupport.write(s.getOutputStream(), "hello");
            assertEquals("hello", new String(s.getInputStream().readNBytes(5), java.nio.charset.StandardCharsets.US_ASCII));
            s.shutdownOutput();
            s.getInputStream().readAllBytes();
            List<TestCollector.Span> spans = collector.awaitSpans("the tunnel's spans", l -> l.size() >= 2);
            TestCollector.Span tunnel = kind(spans, 1);
            TestCollector.Span connection = kind(spans, 3);
            assertEquals("tunnel 127.0.0.1:" + port, tunnel.name());
            assertEquals(TRACE, tunnel.traceId());
            assertEquals(PARENT, tunnel.parentSpanId());
            assertEquals("tunnel", tunnel.attr("microproxy.flow"));
            assertEquals("tcp", tunnel.attr("network.transport"));
            assertEquals(5L, tunnel.attr("microproxy.bytes_received"));
            assertEquals(5L, tunnel.attr("microproxy.bytes_sent"));
            assertEquals(200L, tunnel.attr("http.response.status_code"));
            assertEquals(tunnel.spanId(), connection.parentSpanId());
            assertEquals("CONNECT", connection.name());
            assertEquals(tunnel.end(), connection.end());
        }
    }

    @Test
    void aReverseProxysHttpsUpstreamIsHttpsOnTheClientSpanWhateverItsPort() throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("Otel Reverse Origin CA");
        HttpsServer tls = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), TestSupport.echo());
        try {
            int port = tls.getAddress().getPort();
            assertNotEquals(443, port);
            start(telemetry().build(), MicroProxy.bootstrap().withReverseProxy("https://localhost:" + port)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(
                            CertificateAuthority.generate("Otel Reverse Proxy CA"), originCa.clientContext())));
            HttpResponse<String> response = get(HttpClient.newHttpClient(),
                    "http://127.0.0.1:" + proxy.getListenAddress().getPort() + "/reverse?q=1");
            assertEquals(200, response.statusCode());
            TestCollector.Span server = collector.awaitSpan("the server span", s -> s.kind() == 2);
            TestCollector.Span client = collector.awaitSpan("the client span", s -> s.kind() == 3);
            // The client spoke plain HTTP to the proxy; the proxy spoke TLS to the server.
            assertEquals("http", server.attr("url.scheme"));
            assertEquals("https://localhost:" + port + "/reverse?q=1", client.attr("url.full"));
            assertEquals("http", client.attr("network.protocol.name"));
            assertEquals("1.1", client.attr("network.protocol.version"));
            assertEquals((long) port, client.attr("server.port"));
            assertEquals(List.of("00-" + server.traceId() + "-" + client.spanId() + "-01"),
                    TestSupport.echoedHeader(response.body(), "traceparent"));
        } finally {
            tls.stop(0);
        }
    }

    @Test
    void aPlainUpstreamOnPort443IsStillHttp() throws Exception {
        // Nothing listens there: the attempt fails, and its URL says what the proxy tried.
        try (Socket refusing = TestSupport.refusingPort()) {
            start(telemetry().build(), MicroProxy.bootstrap().withServerResolver((host, port) ->
                    new InetSocketAddress(TestSupport.LOOPBACK, refusing.getLocalPort())));
            assertEquals(502, get(TestSupport.client(proxy), "http://plain.test:443/x").statusCode());
            TestCollector.Span client = collector.awaitSpan("the client span", s -> s.kind() == 3);
            assertEquals("http://plain.test:443/x", client.attr("url.full"));
            assertNull(client.attr("network.protocol.version"), "no request went out");
        }
    }

    @Test
    void aSocksClientIsAnInternalSpan() throws Exception {
        start(telemetry().build(), MicroProxy.bootstrap().withSocksServer(true));
        try (TestSupport.RawServer echo = TestSupport.rawServer(s -> {
            s.getOutputStream().write(s.getInputStream().readNBytes(4));
            s.getOutputStream().flush();
        })) {
            try (org.microproxy.SocksClient c = new org.microproxy.SocksClient(proxy)) {
                assertEquals(0, c.open("127.0.0.1", echo.port()));
                c.out.write("ping".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                c.out.flush();
                assertEquals("ping", new String(c.in.readNBytes(4), java.nio.charset.StandardCharsets.US_ASCII));
            }
            TestCollector.Span socks = collector.awaitSpan("the SOCKS span", s -> s.kind() == 1);
            assertEquals("socks 127.0.0.1:" + echo.port(), socks.name());
            assertEquals("socks", socks.attr("microproxy.flow"));
            assertEquals(5L, socks.attr("microproxy.socks_version"));
            assertEquals(4L, socks.attr("microproxy.bytes_received"));
            assertNull(socks.parentSpanId());
            TestCollector.Span connection = collector.awaitSpan("its connection", s -> s.kind() == 3);
            assertEquals(socks.spanId(), connection.parentSpanId());
            assertEquals("127.0.0.1", connection.attr("server.address"));
        }
    }

    @Test
    void anHttp2StreamIsAServerSpanOfItsOwn() throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("Otel H2 Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Otel H2 Proxy CA");
        HttpsServer tls = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), TestSupport.echo());
        try {
            start(telemetry().build(), MicroProxy.bootstrap().withHttp2(true)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext())));
            HttpClient h2 = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2)
                    .proxy(ProxySelector.of(proxy.getListenAddress())).sslContext(proxyCa.clientContext()).build();
            HttpResponse<String> response = get(h2, "https://localhost:" + tls.getAddress().getPort() + "/h2",
                    "traceparent", "00-" + TRACE + "-" + PARENT + "-01");
            assertEquals(HttpClient.Version.HTTP_2, response.version());
            TestCollector.Span server = collector.awaitSpan("the h2 span",
                    s -> s.kind() == 2 && "/h2".equals(s.attr("url.path")));
            assertEquals("2", server.attr("network.protocol.version"));
            assertEquals("h2", server.attr("microproxy.flow"));
            assertEquals("https", server.attr("url.scheme"));
            assertEquals("localhost", server.attr("server.address"));
            assertTrue(server.attr("microproxy.stream_id") instanceof Long);
            assertEquals(TRACE, server.traceId());
            assertEquals(PARENT, server.parentSpanId());
            TestCollector.Span client = collector.awaitSpan("its client span",
                    s -> s.kind() == 3 && server.spanId().equals(s.parentSpanId()));
            assertEquals("https://localhost:" + tls.getAddress().getPort() + "/h2", client.attr("url.full"));
            assertEquals(List.of("00-" + TRACE + "-" + client.spanId() + "-01"),
                    TestSupport.echoedHeader(response.body(), "traceparent"));
        } finally {
            tls.stop(0);
        }
    }

    @Test
    void anHttp3RequestIsAServerSpanOfItsOwn() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("Otel H3 CA");
        start(telemetry().build(), MicroProxy.bootstrap()
                .withReverseProxy("http://127.0.0.1:" + origin.getAddress().getPort())
                .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
                .withHttp3(true));
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        try (H3TestClient client = H3TestClient.connect(address, "localhost", ca.getCertificate())) {
            H3TestClient.Response r = client.request("GET", "/h3?q=1",
                    List.of(new HeaderField("traceparent", "00-" + TRACE + "-" + PARENT + "-01")), null, List.of());
            assertEquals(200, r.status());
            TestCollector.Span server = collector.awaitSpan("the h3 span",
                    s -> s.kind() == 2 && "/h3".equals(s.attr("url.path")));
            assertEquals("3", server.attr("network.protocol.version"));
            assertEquals("h3", server.attr("microproxy.flow"));
            assertEquals("https", server.attr("url.scheme"));
            assertEquals("h3-test-client", server.attr("user_agent.original"));
            assertEquals(TRACE, server.traceId());
            assertEquals(PARENT, server.parentSpanId());
            TestCollector.Span upstream = collector.awaitSpan("its client span",
                    s -> s.kind() == 3 && server.spanId().equals(s.parentSpanId()));
            assertEquals(List.of("00-" + TRACE + "-" + upstream.spanId() + "-01"),
                    TestSupport.echoedHeader(r.text(), "traceparent"));
            assertFalse(TestSupport.echoedHeader(r.text(), "x-request-id").isEmpty());
        }
    }
}
