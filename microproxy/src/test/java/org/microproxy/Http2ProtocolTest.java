package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echoedUri;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.http2.ErrorCode;
import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.Http2Settings;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpObject;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * HTTP/2 protocol edge cases, written frame by frame: the connection preface, stream limits, the
 * hardening against floods and resets, flow control, and malformed requests.
 */
class Http2ProtocolTest {

    static CertificateAuthority originCa;
    static CertificateAuthority proxyCa;

    private HttpsServer origin;
    private HttpProxyServer proxy;
    private final CountDownLatch release = new CountDownLatch(1);
    private String target;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("H2 Protocol Origin CA");
        proxyCa = CertificateAuthority.generate("H2 Protocol Proxy CA");
    }

    @BeforeEach
    void startOrigin() throws IOException {
        origin = HttpsServer.create(new InetSocketAddress(TestSupport.LOOPBACK, 0), 100);
        origin.setHttpsConfigurator(new HttpsConfigurator(originCa.serverContext("127.0.0.1")));
        origin.createContext("/", this::handle);
        origin.setExecutor(Executors.newCachedThreadPool());
        origin.start();
        target = "127.0.0.1:" + origin.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        release.countDown();
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        if (exchange.getRequestURI().getPath().equals("/slow")) {
            try {
                release.await(20, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        TestSupport.echo().handle(exchange);
    }

    private HttpProxyServer start(Http2Options options) {
        return start(options, MicroProxy.bootstrap());
    }

    private HttpProxyServer start(Http2Options options, HttpProxyServerBootstrap bootstrap) {
        proxy = bootstrap.withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp2(true)
                .withHttp2Options(options)
                .start();
        return proxy;
    }

    private H2TestClient connect() throws IOException {
        return H2TestClient.connect(proxy.getListenAddress(), target, proxyCa.clientContext());
    }

    @Test
    void serverSettingsAdvertiseTheLimits() throws IOException {
        start(Http2Options.builder().maxConcurrentStreams(7).initialWindowSize(100_000).build());
        try (H2TestClient h2 = connect().handshake()) {
            assertEquals(0L, h2.setting(Http2Settings.ENABLE_PUSH));
            // Extended CONNECT (RFC 8441), for WebSockets over HTTP/2, inside intercepted sessions too.
            assertEquals(1L, h2.setting(Http2Settings.ENABLE_CONNECT_PROTOCOL));
            assertEquals(7L, h2.setting(Http2Settings.MAX_CONCURRENT_STREAMS));
            assertEquals(100_000L, h2.setting(Http2Settings.INITIAL_WINDOW_SIZE));
            // max_header_size + max_initial_line_length
            assertEquals(16_384L + 8_192L, h2.setting(Http2Settings.MAX_HEADER_LIST_SIZE));
            h2.get(1, "/x");
            assertEquals("/x", echoedUri(h2.response(1).text()));
        }
    }

    @Test
    void badPrefaceGetsGoAway() throws IOException {
        start(Http2Options.DEFAULT);
        try (H2TestClient h2 = connect()) {
            TestSupport.write(h2.tls.getOutputStream(), "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
            Frame.GoAway goAway = h2.awaitGoAway();
            assertEquals(ErrorCode.PROTOCOL_ERROR, goAway.error());
            assertTrue(h2.closedByServer());
        }
    }

    @Test
    void streamsBeyondTheLimitAreRefused() throws Exception {
        start(Http2Options.builder().maxConcurrentStreams(2).build());
        try (H2TestClient h2 = connect().handshake()) {
            h2.get(1, "/slow");
            h2.get(3, "/slow");
            h2.get(5, "/refused");
            assertEquals(ErrorCode.REFUSED_STREAM, h2.awaitReset(5).error());
            release.countDown();
            assertEquals(200, h2.response(1).status());
            assertEquals(200, h2.response(3).status());
            // Room again.
            h2.get(7, "/after");
            assertEquals("/after", echoedUri(h2.response(7).text()));
        }
    }

    @Test
    void rapidResetEndsTheConnection() throws IOException {
        start(Http2Options.builder().maxRapidResets(10).build());
        try (H2TestClient h2 = connect().handshake()) {
            for (int id = 1; id <= 41; id += 2) {
                h2.get(id, "/slow");
                h2.rst(id, ErrorCode.CANCEL);
            }
            Frame.GoAway goAway = h2.awaitGoAway();
            assertEquals(ErrorCode.ENHANCE_YOUR_CALM, goAway.error());
        }
    }

    @Test
    void pingFloodEndsTheConnection() throws IOException {
        start(Http2Options.builder().maxPings(10).build());
        try (H2TestClient h2 = connect().handshake()) {
            for (int i = 0; i < 20; i++) h2.ping(i);
            assertEquals(ErrorCode.ENHANCE_YOUR_CALM, h2.awaitGoAway().error());
        }
    }

    @Test
    void settingsFloodEndsTheConnection() throws IOException {
        start(Http2Options.builder().maxSettings(5).build());
        try (H2TestClient h2 = connect().handshake()) {
            for (int i = 0; i < 10; i++) h2.writer.writeSettings(java.util.Map.of());
            h2.writer.flush();
            assertEquals(ErrorCode.ENHANCE_YOUR_CALM, h2.awaitGoAway().error());
        }
    }

    @Test
    void pingsAreAnswered() throws IOException {
        start(Http2Options.DEFAULT);
        try (H2TestClient h2 = connect().handshake()) {
            h2.ping(0x1234_5678_9abcL);
            Frame.Ping pong = (Frame.Ping) h2.awaitFrame(f -> f instanceof Frame.Ping p && p.ack());
            assertEquals(0x1234_5678_9abcL, pong.opaqueData());
        }
    }

    @Test
    void oversizedHeaderListResetsTheStreamOnly() throws IOException {
        start(Http2Options.DEFAULT);
        try (H2TestClient h2 = connect().handshake()) {
            h2.get(1, "/big", "x-big", "a".repeat(30_000));
            assertEquals(ErrorCode.PROTOCOL_ERROR, h2.awaitReset(1).error());
            h2.get(3, "/small");
            assertEquals("/small", echoedUri(h2.response(3).text()));
        }
    }

    @Test
    void dataBeyondTheWindowIsAFlowControlError() throws Exception {
        CountDownLatch hold = new CountDownLatch(1);
        start(Http2Options.builder().initialWindowSize(65_535).build(),
                MicroProxy.bootstrap().withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(org.microproxy.http.HttpRequest req, FlowContext ctx) {
                        return new HttpFiltersAdapter(req, ctx) {
                            @Override
                            public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject o) {
                                // Hold the stream, so none of its body is read and credited back.
                                if (o instanceof org.microproxy.http.HttpRequest r && !r.method().name().equals("CONNECT")) {
                                    try {
                                        hold.await(10, TimeUnit.SECONDS);
                                    } catch (InterruptedException e) {
                                        Thread.currentThread().interrupt();
                                    }
                                }
                                return null;
                            }
                        };
                    }
                }));
        try (H2TestClient h2 = connect().handshake()) {
            h2.headers(1, h2.request("POST", "/upload"), false);
            byte[] chunk = new byte[16_384];
            for (int i = 0; i < 5; i++) h2.data(1, chunk, false);
            assertEquals(ErrorCode.FLOW_CONTROL_ERROR, h2.awaitReset(1).error());
            hold.countDown();
            // The connection survives the stream error.
            h2.get(3, "/after");
            assertEquals("/after", echoedUri(h2.response(3).text()));
        }
    }

    @Test
    void connectionSpecificHeaderIsMalformed() throws IOException {
        start(Http2Options.DEFAULT);
        try (H2TestClient h2 = connect().handshake()) {
            h2.get(1, "/bad", "connection", "keep-alive");
            assertEquals(ErrorCode.PROTOCOL_ERROR, h2.awaitReset(1).error());
            h2.get(3, "/upgrade", "upgrade", "websocket");
            assertEquals(ErrorCode.PROTOCOL_ERROR, h2.awaitReset(3).error());
            h2.get(5, "/fine");
            assertEquals("/fine", echoedUri(h2.response(5).text()));
        }
    }

    @Test
    void dataBeyondTheContentLengthResetsTheStream() throws IOException {
        start(Http2Options.DEFAULT);
        try (H2TestClient h2 = connect().handshake()) {
            h2.headers(1, h2.request("POST", "/cl", "content-length", "3"), false);
            h2.data(1, "too long".getBytes(StandardCharsets.UTF_8), true);
            assertEquals(ErrorCode.PROTOCOL_ERROR, h2.awaitReset(1).error());
            h2.get(3, "/fine");
            assertEquals("/fine", echoedUri(h2.response(3).text()));
        }
    }

    @Test
    void evenStreamIdIsAConnectionError() throws IOException {
        start(Http2Options.DEFAULT);
        try (H2TestClient h2 = connect().handshake()) {
            h2.get(2, "/even");
            assertEquals(ErrorCode.PROTOCOL_ERROR, h2.awaitGoAway().error());
        }
    }

    @Test
    void decreasingStreamIdIsAConnectionError() throws IOException {
        start(Http2Options.DEFAULT);
        try (H2TestClient h2 = connect().handshake()) {
            h2.get(5, "/five");
            assertEquals(200, h2.response(5).status());
            h2.get(3, "/three");
            assertEquals(ErrorCode.STREAM_CLOSED, h2.awaitGoAway().error());
        }
    }

    @Test
    void missingSettingsAckEndsTheConnection() throws IOException {
        start(Http2Options.builder().settingsAckTimeout(Duration.ofMillis(300)).build());
        try (H2TestClient h2 = connect()) {
            h2.writer.writeClientPreface();
            h2.writer.writeSettings(java.util.Map.of());
            h2.writer.flush();
            // Never acknowledge the server's SETTINGS.
            Frame.GoAway goAway = (Frame.GoAway) h2.awaitFrame(f -> f instanceof Frame.GoAway);
            assertEquals(ErrorCode.SETTINGS_TIMEOUT, goAway.error());
        }
    }

    @Test
    void idleConnectionsAreClosedWithGoAway() throws IOException {
        start(Http2Options.DEFAULT, MicroProxy.bootstrap().withIdleConnectionTimeout(Duration.ofMillis(500)));
        try (H2TestClient h2 = connect().handshake()) {
            h2.get(1, "/once");
            assertEquals(200, h2.response(1).status());
            Frame.GoAway goAway = h2.awaitGoAway();
            assertEquals(ErrorCode.NO_ERROR, goAway.error());
            assertEquals(1, goAway.lastStreamId());
        }
    }

    @Test
    void connectCannotEscapeTheInterceptedAuthority() throws IOException {
        start(Http2Options.DEFAULT);
        try (H2TestClient h2 = connect().handshake()) {
            h2.headers(1, List.of(new HeaderField(":method", "CONNECT"), new HeaderField(":authority", "example.com:443")), false);
            H2TestClient.Response r = h2.response(1);
            assertEquals(421, r.status());
        }
    }

    @Test
    void otherAuthoritiesGetMisdirectedRequest() throws IOException {
        start(Http2Options.DEFAULT);
        try (H2TestClient h2 = connect().handshake()) {
            List<HeaderField> fields = new ArrayList<>(h2.request("GET", "/x"));
            fields.set(2, new HeaderField(":authority", "other.example:443"));
            h2.headers(1, fields, true);
            assertEquals(421, h2.response(1).status());
        }
    }

    @Test
    void expectContinueGetsAnInterim100() throws IOException {
        start(Http2Options.DEFAULT);
        try (H2TestClient h2 = connect().handshake()) {
            h2.headers(1, h2.request("POST", "/expect", "expect", "100-continue"), false);
            Frame.Headers interim = (Frame.Headers) h2.awaitFrame(f -> f instanceof Frame.Headers h && h.streamId() == 1);
            assertEquals("100", h2.fields(interim).get(0).value());
            h2.data(1, "body".getBytes(StandardCharsets.UTF_8), true);
            H2TestClient.Response r = h2.response(1);
            assertEquals(200, r.status());
            assertEquals("body", TestSupport.echoedBody(r.text()));
            // Without a content-length, the body went upstream chunked.
            assertEquals(List.of("chunked"), TestSupport.echoedHeader(r.text(), "transfer-encoding"));
        }
    }

    @Test
    void requestTrailersReachTheServer() throws Exception {
        java.util.concurrent.CompletableFuture<String> received = new java.util.concurrent.CompletableFuture<>();
        try (javax.net.ssl.SSLServerSocket server = (javax.net.ssl.SSLServerSocket) originCa.serverContext("127.0.0.1")
                .getServerSocketFactory().createServerSocket(0, 50, TestSupport.LOOPBACK)) {
            Thread.ofVirtual().start(() -> {
                try (java.net.Socket s = server.accept()) {
                    String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
                    String body = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
                    received.complete(head + body);
                    TestSupport.write(s.getOutputStream(), "HTTP/1.1 204 No Content\r\n\r\n");
                    s.getInputStream().read();
                } catch (IOException e) {
                    received.completeExceptionally(e);
                }
            });
            target = "127.0.0.1:" + server.getLocalPort();
            start(Http2Options.DEFAULT);
            try (H2TestClient h2 = connect().handshake()) {
                h2.headers(1, h2.request("POST", "/trailers", "te", "trailers"), false);
                h2.data(1, "body".getBytes(StandardCharsets.UTF_8), false);
                h2.headers(1, List.of(new HeaderField("x-trailer", "t")), true);
                assertEquals(204, h2.response(1).status());
                String request = received.get(10, TimeUnit.SECONDS);
                assertTrue(request.startsWith("POST /trailers HTTP/1.1\r\n"), request);
                assertTrue(request.contains("\r\nTransfer-Encoding: chunked\r\n"), request);
                assertTrue(request.endsWith("4\r\nbody\r\n0\r\nx-trailer: t\r\n\r\n"), request);
            }
        }
    }

    @Test
    void framesAfterTheClientResetAStreamAreStreamClosed() throws Exception {
        start(Http2Options.DEFAULT);
        try (H2TestClient h2 = connect().handshake()) {
            h2.headers(1, h2.request("POST", "/slow"), false);
            h2.rst(1, ErrorCode.CANCEL);
            // RFC 9113 section 5.1: a frame other than PRIORITY after RST_STREAM is a stream error.
            h2.data(1, "late".getBytes(StandardCharsets.UTF_8), false);
            assertEquals(ErrorCode.STREAM_CLOSED, h2.awaitReset(1).error());
            // Answered once: more late frames are ignored, and the connection goes on.
            h2.data(1, "later".getBytes(StandardCharsets.UTF_8), true);
            h2.get(3, "/after");
            assertEquals(200, h2.response(3).status());
        }
    }

    @Test
    void headersOnAHalfClosedStreamAreStreamClosed() throws Exception {
        start(Http2Options.DEFAULT);
        try (H2TestClient h2 = connect().handshake()) {
            h2.headers(1, h2.request("GET", "/slow"), true);
            // A complete request header block again, where only nothing (or a reset) may follow.
            h2.headers(1, h2.request("GET", "/slow"), true);
            assertEquals(ErrorCode.STREAM_CLOSED, h2.awaitReset(1).error());
        }
    }

    @Test
    void aStreamThatDependsOnItselfIsMalformed() throws Exception {
        start(Http2Options.DEFAULT);
        try (H2TestClient h2 = connect().handshake()) {
            byte[] block = h2.encoder.encode(h2.request("GET", "/self"));
            h2.writer.writeFrame(new Frame.Headers(1, block, true, true, new Frame.PrioritySpec(1, false, 16), 0));
            h2.writer.flush();
            assertEquals(ErrorCode.PROTOCOL_ERROR, h2.awaitReset(1).error());
            h2.get(3, "/next");
            assertEquals(200, h2.response(3).status());
        }
    }
}
