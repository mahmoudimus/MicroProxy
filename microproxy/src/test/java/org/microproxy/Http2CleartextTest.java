package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;

import com.sun.net.httpserver.HttpServer;
import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.Http2Settings;
import java.io.IOException;
import java.net.Socket;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/**
 * HTTP/2 with prior knowledge ({@code h2c}) on the proxy's plain listener: connections that start
 * with the connection preface are served as HTTP/2, their streams being proxy requests for any
 * target; every other connection is HTTP/1 as before.
 */
class Http2CleartextTest {

    private HttpServer origin;
    private HttpServer other;
    private HttpProxyServer proxy;

    @BeforeEach
    void startOrigins() {
        origin = TestSupport.origin(TestSupport.echo());
        other = TestSupport.origin(TestSupport.fixed(200, "other origin"));
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
        other.stop(0);
    }

    private HttpProxyServerBootstrap h2c() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("h2c").withHttp2Cleartext(true);
    }

    private String authority(HttpServer server) {
        return "127.0.0.1:" + server.getAddress().getPort();
    }

    private H2TestClient client(HttpServer target) throws IOException {
        return H2TestClient.cleartext(proxy.getListenAddress(), authority(target)).handshake();
    }

    @Test
    void streamsAreProxyRequestsForAnyTarget() throws Exception {
        proxy = h2c().start();
        try (H2TestClient c = client(origin)) {
            // The settings are the HTTP/2 ones, as on intercepted sessions.
            assertEquals(100L, c.setting(Http2Settings.MAX_CONCURRENT_STREAMS));
            c.get(1, "/first?x=1", "x-test", "yes");
            // Another server on the same connection: no 421, any authority is a target.
            c.headers(3, new ArrayList<>(List.of(new HeaderField(":method", "GET"), new HeaderField(":scheme", "http"),
                    new HeaderField(":authority", authority(other)), new HeaderField(":path", "/"))), true);
            H2TestClient.Response first = c.response(1);
            H2TestClient.Response second = c.response(3);
            assertEquals(200, first.status());
            assertEquals("/first?x=1", echoedUri(first.text()));
            assertEquals(List.of("yes"), echoedHeader(first.text(), "x-test"));
            assertEquals(List.of(authority(origin)), echoedHeader(first.text(), "host"));
            assertEquals(List.of("2 h2c"), echoedHeader(first.text(), "via"));
            assertEquals(200, second.status());
            assertEquals("other origin", second.text());
        }
    }

    @Test
    void requestBodiesAndTrailersOfStreams() throws Exception {
        proxy = h2c().start();
        try (H2TestClient c = client(origin)) {
            c.headers(1, c.request("POST", "/upload", "content-type", "text/plain"), false);
            c.data(1, "streamed ".getBytes(StandardCharsets.UTF_8), false);
            c.data(1, "body".getBytes(StandardCharsets.UTF_8), true);
            H2TestClient.Response r = c.response(1);
            assertEquals(200, r.status());
            assertEquals("streamed body", echoedBody(r.text()));
        }
    }

    @Test
    void http1StillWorksOnTheSameListener() throws Exception {
        proxy = h2c().start();
        HttpClient client = TestSupport.client(proxy);
        assertEquals(200, TestSupport.get(client, TestSupport.url(origin, "/get")).statusCode());
        // Requests whose first bytes look like the preface's ('P') are still HTTP/1.
        HttpResponse<String> post = TestSupport.send(client, java.net.http.HttpRequest.newBuilder(
                        java.net.URI.create(TestSupport.url(origin, "/post")))
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString("hi")).build());
        assertEquals("hi", echoedBody(post.body()));
        String raw = TestSupport.rawExchange(proxy.getListenAddress(), "PUT " + TestSupport.url(origin, "/put")
                + " HTTP/1.1\r\nHost: " + authority(origin) + "\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        assertTrue(raw.startsWith("HTTP/1.1 200"), raw);
    }

    @Test
    void upgradeToH2cIsNotSupported() throws Exception {
        proxy = h2c().start();
        String raw = TestSupport.rawExchange(proxy.getListenAddress(), "GET " + TestSupport.url(origin, "/up")
                + " HTTP/1.1\r\nHost: " + authority(origin) + "\r\nConnection: Upgrade, HTTP2-Settings\r\n"
                + "Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\nConnection: close\r\n\r\n");
        assertTrue(raw.startsWith("HTTP/1.1 200"), raw);
        assertTrue(!raw.contains("101"), raw);
    }

    @Test
    void offByDefault() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).start();
        try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(10_000);
            s.getOutputStream().write("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            s.getOutputStream().flush();
            String answer = new String(s.getInputStream().readNBytes(12), StandardCharsets.ISO_8859_1);
            // An HTTP/1 answer (505 HTTP Version Not Supported), not HTTP/2 frames.
            assertTrue(answer.startsWith("HTTP/1.1 505"), answer);
        }
    }

    @Test
    void streamsAuthenticateOneByOne() throws Exception {
        proxy = h2c().withProxyAuthenticator(new ProxyAuthenticator() {
            @Override
            public boolean authenticate(String userName, String password) {
                return "user".equals(userName) && "secret".equals(password);
            }

            @Override
            public String getRealm() {
                return "h2c";
            }
        }).start();
        String credentials = "Basic " + Base64.getEncoder().encodeToString("user:secret".getBytes(StandardCharsets.UTF_8));
        try (H2TestClient c = client(origin)) {
            c.get(1, "/no-credentials");
            c.get(3, "/credentials", "proxy-authorization", credentials);
            H2TestClient.Response refused = c.response(1);
            H2TestClient.Response accepted = c.response(3);
            assertEquals(407, refused.status());
            assertEquals(200, accepted.status());
            // The credentials were the proxy's: not forwarded.
            assertEquals(List.of(), echoedHeader(accepted.text(), "proxy-authorization"));
        }
    }

    @Test
    void filtersSeeAbsoluteRequestsAndCanAnswerThem() throws Exception {
        List<String> uris = new java.util.concurrent.CopyOnWriteArrayList<>();
        proxy = h2c().withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
            @Override
            public org.microproxy.http.HttpResponse clientToProxyRequest(org.microproxy.http.HttpObject o) {
                if (o instanceof org.microproxy.http.HttpRequest r) {
                    uris.add(r.method() + " " + r.uri() + " " + r.protocolVersion() + " " + ctx.getStreamId());
                    if (r.uri().endsWith("/canned")) {
                        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                                "canned".getBytes(StandardCharsets.UTF_8));
                    }
                }
                return null;
            }
        }).start();
        try (H2TestClient c = client(origin)) {
            c.get(1, "/canned");
            H2TestClient.Response r = c.response(1);
            assertEquals(200, r.status());
            assertEquals("canned", r.text());
            assertNull(r.reset());
        }
        assertEquals(List.of("GET http://" + authority(origin) + "/canned HTTP/2.0 1"), uris);
    }

    @Test
    void theConnectionClosesAfterGoAwayOnStop() throws Exception {
        proxy = h2c().start();
        try (H2TestClient c = client(origin)) {
            c.get(1, "/");
            assertEquals(200, c.response(1).status());
            proxy.stop();
            proxy = null;
            Frame.GoAway goAway = c.awaitGoAway();
            assertEquals(1, goAway.lastStreamId());
            assertTrue(c.closedByServer());
        }
    }
}
