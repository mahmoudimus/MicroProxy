package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.eventually;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpServer;
import io.github.mahmoudimus.http2.ErrorCode;
import io.github.mahmoudimus.http2.Http2Settings;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;

/**
 * {@code CONNECT} inside HTTP/2 streams (RFC 9113 section 8.5), on {@code h2c} and on the proxy's
 * own TLS listener, which offers {@code h2}: tunnels to raw TCP servers, interception with TLS
 * layered over the stream (HTTP/1.1 or HTTP/2 inside), chained proxies, filters and hooks, proxy
 * authentication, flow control and teardown.
 */
@Timeout(60)
class Http2ConnectTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("H2 CONNECT Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("H2 CONNECT Proxy CA");
    /** The proxy's own TLS listener's identity. */
    static final SslContextSource LISTENER_TLS = () -> proxyCa.serverContext("localhost", "127.0.0.1");

    private HttpProxyServer proxy;
    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    private <T extends AutoCloseable> T closing(T c) {
        closeables.add(c);
        return c;
    }

    /** A raw TCP server that echoes what it reads until the client half-closes, then closes. */
    private TestSupport.RawServer echoServer(AtomicInteger ended) {
        return closing(TestSupport.rawServer(s -> {
            try {
                s.getInputStream().transferTo(s.getOutputStream());
            } finally {
                if (ended != null) ended.incrementAndGet();
            }
        }));
    }

    private static HttpProxyServerBootstrap h2c() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("cx").withHttp2Cleartext(true);
    }

    private static HttpProxyServerBootstrap tlsListener() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("cx").withSslContextSource(LISTENER_TLS).withHttp2(true);
    }

    private H2StreamClient h2c(String authority) throws IOException {
        return H2StreamClient.cleartext(proxy.getListenAddress(), authority);
    }

    private H2StreamClient tls(String authority) throws IOException {
        return H2StreamClient.tls(proxy.getListenAddress(), proxyCa.clientContext(), authority);
    }

    private static String target(TestSupport.RawServer server) {
        return "127.0.0.1:" + server.port();
    }

    /** Sends {@code text}, ends the stream, and returns everything the tunnel sends back. */
    private static String roundTrip(H2StreamClient.Stream tunnel, String text) throws IOException {
        tunnel.out().write(text.getBytes(StandardCharsets.UTF_8));
        tunnel.end();
        return tunnel.text();
    }

    // -------------------------------------------------------------------------------------------
    // Tunnels to raw TCP servers
    // -------------------------------------------------------------------------------------------

    @Test
    void aConnectStreamTunnelsToARawServer() throws Exception {
        AtomicInteger ended = new AtomicInteger();
        TestSupport.RawServer echo = echoServer(ended);
        proxy = h2c().start();
        try (H2StreamClient c = h2c("unused:1")) {
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(echo)), false);
            assertEquals(200, tunnel.status());
            assertNull(tunnel.header("content-length"));
            assertEquals("1.1 cx", tunnel.header("via"));
            // Half-close: END_STREAM reaches the server as a FIN; its close comes back as END_STREAM.
            assertEquals("hello through h2c", roundTrip(tunnel, "hello through h2c"));
            assertNull(tunnel.awaitEnd());
            eventually("the server connection to end", () -> ended.get() == 1);
        }
    }

    @Test
    void manyMegabytesFlowUnderFlowControl() throws Exception {
        TestSupport.RawServer echo = echoServer(null);
        proxy = h2c().start();
        byte[] payload = H2TestOrigin.bytes(3_000_000, 3);
        try (H2StreamClient c = h2c("unused:1")) {
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(echo)), false);
            assertEquals(200, tunnel.status());
            CompletableFuture<byte[]> back = CompletableFuture.supplyAsync(() -> {
                try {
                    return tunnel.readAll();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            tunnel.out().write(payload);
            tunnel.end();
            assertArrayEquals(payload, back.get(30, TimeUnit.SECONDS));
        }
    }

    @Test
    void aServerResetResetsTheStream() throws Exception {
        TestSupport.RawServer server = closing(TestSupport.rawServer(s -> {
            s.getInputStream().read();
            s.setSoLinger(true, 0);
        }));
        proxy = h2c().start();
        try (H2StreamClient c = h2c("unused:1")) {
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(server)), false);
            assertEquals(200, tunnel.status());
            tunnel.out().write('x');
            assertEquals(ErrorCode.CANCEL, tunnel.awaitReset());
        }
    }

    @Test
    void endingTunnelsWithResetsIsNotARapidReset() throws Exception {
        TestSupport.RawServer echo = echoServer(null);
        proxy = h2c().withHttp2Options(Http2Options.builder().maxRapidResets(3).build()).start();
        try (H2StreamClient c = h2c("unused:1")) {
            for (int i = 0; i < 10; i++) {
                H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(echo)), false);
                assertEquals(200, tunnel.status());
                tunnel.reset(ErrorCode.CANCEL);
            }
            H2StreamClient.Stream last = c.open(H2StreamClient.connect(target(echo)), false);
            assertEquals(200, last.status());
            assertEquals("still open", roundTrip(last, "still open"));
            assertNull(c.goAway());
        }
    }

    @Test
    void anUnreachableTargetIsABadGateway() throws Exception {
        proxy = h2c().start();
        try (Socket refusing = TestSupport.refusingPort(); H2StreamClient c = h2c("unused:1")) {
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect("127.0.0.1:" + refusing.getLocalPort()), false);
            assertEquals(502, tunnel.status());
        }
    }

    @Test
    void filtersAndHooksSeeTheConnect() throws Exception {
        TestSupport.RawServer echo = echoServer(null);
        List<String> seen = new CopyOnWriteArrayList<>();
        List<String> tracked = new CopyOnWriteArrayList<>();
        proxy = h2c().withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public HttpResponse clientToProxyRequest(HttpObject o) {
                if (o instanceof HttpRequest r) {
                    seen.add(r.method() + " " + r.uri() + " " + r.protocolVersion() + " stream=" + ctx.getStreamId());
                    if (r.uri().startsWith("blocked.test")) {
                        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN,
                                "no".getBytes(StandardCharsets.UTF_8));
                    }
                }
                return null;
            }

            @Override
            public void proxyToServerConnectionSucceeded(FullFlowContext serverCtx) {
                seen.add("connected " + serverCtx.getServerHostAndPort());
            }
        }).plusActivityTracker(new ActivityTrackerAdapter() {
            @Override
            public void requestReceivedFromClient(FlowContext ctx, HttpRequest request) {
                tracked.add("request " + request.method() + " " + ctx.getStreamId());
            }

            @Override
            public void responseSentToClient(FlowContext ctx, HttpResponse response, ResponseSource source) {
                tracked.add("response " + response.status().code() + " " + source);
            }
        }).start();
        try (H2StreamClient c = h2c("unused:1")) {
            H2StreamClient.Stream blocked = c.open(H2StreamClient.connect("blocked.test:443"), false);
            assertEquals(403, blocked.status());
            assertEquals("no", blocked.text());
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(echo)), false);
            assertEquals(200, tunnel.status());
            assertEquals("ok", roundTrip(tunnel, "ok"));
        }
        assertEquals(List.of("CONNECT blocked.test:443 HTTP/2.0 stream=1", "CONNECT " + target(echo) + " HTTP/2.0 stream=3",
                "connected " + target(echo)), seen);
        assertEquals(List.of("request CONNECT 1", "response 403 FILTER", "request CONNECT 3", "response 200 PROXY"), tracked);
    }

    @Test
    void aConnectStreamGoesThroughAChainedProxy() throws Exception {
        TestSupport.RawServer echo = echoServer(null);
        try (ChainTestSupport.RecordingConnectProxy upstream = new ChainTestSupport.RecordingConnectProxy()) {
            proxy = h2c().withChainProxyManager(ChainTestSupport.always(ChainTestSupport.authenticated(upstream.address(),
                    "chain", "pw"))).start();
            try (H2StreamClient c = h2c("unused:1")) {
                H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(echo)), false);
                assertEquals(200, tunnel.status());
                assertEquals("chained", roundTrip(tunnel, "chained"));
            }
            String head = upstream.firstHeads.getFirst();
            // The chained proxy gets an HTTP/1.1 CONNECT, with its own credentials.
            assertTrue(head.startsWith("CONNECT " + target(echo) + " HTTP/1.1\r\n"), head);
            assertEquals("Basic " + Base64.getEncoder().encodeToString("chain:pw".getBytes(StandardCharsets.UTF_8)),
                    WebSocketTestSupport.header(head, "Proxy-Authorization"));
        }
    }

    // -------------------------------------------------------------------------------------------
    // Proxy authentication
    // -------------------------------------------------------------------------------------------

    private static ProxyAuthenticator basic() {
        return new ProxyAuthenticator() {
            @Override
            public boolean authenticate(String userName, String password) {
                return "user".equals(userName) && "secret".equals(password);
            }

            @Override
            public String getRealm() {
                return "cx";
            }
        };
    }

    private static final String CREDENTIALS =
            "Basic " + Base64.getEncoder().encodeToString("user:secret".getBytes(StandardCharsets.UTF_8));

    @Test
    void connectStreamsAuthenticateOnH2c() throws Exception {
        TestSupport.RawServer echo = echoServer(null);
        proxy = h2c().withProxyAuthenticator(basic()).start();
        try (H2StreamClient c = h2c("unused:1")) {
            H2StreamClient.Stream refused = c.open(H2StreamClient.connect(target(echo)), false);
            assertEquals(407, refused.status());
            assertEquals("Basic realm=\"cx\"", refused.header("proxy-authenticate"));
            H2StreamClient.Stream accepted = c.open(H2StreamClient.connect(target(echo), "proxy-authorization", CREDENTIALS),
                    false);
            assertEquals(200, accepted.status());
            assertEquals("authenticated", roundTrip(accepted, "authenticated"));
        }
    }

    @Test
    void requestsAndConnectStreamsAuthenticateOnTheTlsListener() throws Exception {
        TestSupport.RawServer echo = echoServer(null);
        HttpServer origin = TestSupport.origin(TestSupport.echo());
        closeables.add(() -> origin.stop(0));
        proxy = tlsListener().withProxyAuthenticator(basic()).start();
        String authority = "127.0.0.1:" + origin.getAddress().getPort();
        try (H2StreamClient c = tls(authority)) {
            H2StreamClient.Stream get = c.open(c.request("GET", "/x"), true);
            assertEquals(407, get.status());
            assertEquals("Basic realm=\"cx\"", get.header("proxy-authenticate"));
            assertEquals(407, c.open(H2StreamClient.connect(target(echo)), false).status());

            List<io.github.mahmoudimus.http2.HeaderField> request = c.request("GET", "/x", "proxy-authorization", CREDENTIALS);
            request.set(1, new io.github.mahmoudimus.http2.HeaderField(":scheme", "http"));
            H2StreamClient.Stream ok = c.open(request, true);
            assertEquals(200, ok.status());
            String body = ok.text();
            assertEquals("/x", echoedUri(body));
            assertEquals(List.of(), echoedHeader(body, "proxy-authorization"));
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(echo), "proxy-authorization", CREDENTIALS), false);
            assertEquals(200, tunnel.status());
            assertEquals("tls listener", roundTrip(tunnel, "tls listener"));
        }
    }

    // -------------------------------------------------------------------------------------------
    // The TLS listener
    // -------------------------------------------------------------------------------------------

    @Test
    void theTlsListenerServesHttp2AsAForwardProxy() throws Exception {
        TestSupport.RawServer echo = echoServer(null);
        HttpServer origin = TestSupport.origin(TestSupport.echo());
        closeables.add(() -> origin.stop(0));
        proxy = tlsListener().start();
        String authority = "127.0.0.1:" + origin.getAddress().getPort();
        try (H2StreamClient c = tls(authority)) {
            assertEquals(1L, c.setting(Http2Settings.ENABLE_CONNECT_PROTOCOL));
            List<io.github.mahmoudimus.http2.HeaderField> request = c.request("GET", "/over-tls?q=1", "x-test", "yes");
            request.set(1, new io.github.mahmoudimus.http2.HeaderField(":scheme", "http"));
            H2StreamClient.Stream get = c.open(request, true);
            assertEquals(200, get.status());
            String body = get.text();
            assertEquals("/over-tls?q=1", echoedUri(body));
            assertEquals(List.of("yes"), echoedHeader(body, "x-test"));
            assertEquals(List.of("2 cx"), echoedHeader(body, "via"));
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(echo)), false);
            assertEquals(200, tunnel.status());
            assertEquals("tunnelled", roundTrip(tunnel, "tunnelled"));
        }
    }

    @Test
    void http11ClientsKeepTheTlsListener() throws Exception {
        HttpServer origin = TestSupport.origin(TestSupport.echo());
        closeables.add(() -> origin.stop(0));
        proxy = tlsListener().start();
        // A client that offers only http/1.1, and one that offers no ALPN at all.
        for (String[] alpn : new String[][] {{"http/1.1"}, null}) {
            try (Socket raw = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
                SSLSocket tls = (SSLSocket) proxyCa.clientContext().getSocketFactory()
                        .createSocket(raw, "localhost", proxy.getListenAddress().getPort(), true);
                if (alpn != null) {
                    javax.net.ssl.SSLParameters params = tls.getSSLParameters();
                    params.setApplicationProtocols(alpn);
                    tls.setSSLParameters(params);
                }
                tls.setSoTimeout(10_000);
                tls.startHandshake();
                assertTrue(tls.getApplicationProtocol() == null || !tls.getApplicationProtocol().equals("h2"));
                write(tls.getOutputStream(), "GET " + TestSupport.url(origin, "/h1") + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
                String response = new String(tls.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
                assertTrue(response.startsWith("HTTP/1.1 200"), response);
            }
        }
    }

    @Test
    void withoutHttp2TheTlsListenerOffersNoH2() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withSslContextSource(LISTENER_TLS).start();
        try (Socket raw = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            SSLSocket tls = (SSLSocket) proxyCa.clientContext().getSocketFactory()
                    .createSocket(raw, "localhost", proxy.getListenAddress().getPort(), true);
            javax.net.ssl.SSLParameters params = tls.getSSLParameters();
            params.setApplicationProtocols(new String[] {"h2", "http/1.1"});
            tls.setSSLParameters(params);
            tls.startHandshake();
            assertFalse("h2".equals(tls.getApplicationProtocol()));
        }
    }

    @Test
    void aWebSocketOverTheTlsListener() throws Exception {
        proxy = tlsListener().start();
        try (WebSocketTestSupport.EchoServer server = new WebSocketTestSupport.EchoServer();
                H2StreamClient c = tls("127.0.0.1:" + server.raw().port())) {
            List<io.github.mahmoudimus.http2.HeaderField> fields = c.webSocket("/chat");
            fields.set(2, new io.github.mahmoudimus.http2.HeaderField(":scheme", "http"));
            H2StreamClient.Stream ws = c.open(fields, false);
            assertEquals(200, ws.status());
            WebSocketTestSupport.sendFromClient(ws.out(), org.microproxy.http.WebSocketFrame.text("ping tls"));
            assertEquals("echo:ping tls", WebSocketTestSupport.readFrame(ws.in()).payloadAsText());
            ws.reset(ErrorCode.CANCEL);
        }
    }
}
