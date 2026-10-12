package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.github.mahmoudimus.http3.HeaderField;
import java.net.InetSocketAddress;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.SelfSignedSslContextSource;

/** A reverse proxy serving HTTP/3 to clients, for an HTTP/1 upstream. */
class Http3ReverseProxyTest {

    private HttpServer origin;
    private HttpProxyServer proxy;
    private SelfSignedSslContextSource tls;

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(TestSupport.echo());
        tls = new SelfSignedSslContextSource();
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withReverseProxy("http://127.0.0.1:" + origin.getAddress().getPort())
                .withSslContextSource(tls)
                .withHttp3(true)
                .start();
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private H3TestClient client() throws Exception {
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        return H3TestClient.connect(address, "localhost", tls.getCertificate());
    }

    @Test
    void servesGetOverHttp3() throws Exception {
        try (H3TestClient client = client()) {
            H3TestClient.Response r = client.get("/hello?x=1");
            assertEquals(200, r.status());
            assertTrue(r.text().startsWith("method: GET\nuri: /hello?x=1\n"), r.text());
            assertEquals(List.of("h3-test-client"), TestSupport.echoedHeader(r.text(), "user-agent"));
            assertTrue(TestSupport.echoedHeader(r.text(), "via").getFirst().startsWith("3 "), "Via names HTTP/3");
            assertEquals(List.of("127.0.0.1:" + origin.getAddress().getPort()), TestSupport.echoedHeader(r.text(), "host"),
                    "the client's :authority becomes Host, which a reverse proxy sets to its upstream's");
            assertNull(r.header("alt-svc"), "no Alt-Svc over HTTP/3 itself");
        }
    }

    @Test
    void postsABodyAndGetsItBack() throws Exception {
        byte[] body = new byte[300_000];
        for (int i = 0; i < body.length; i++) body[i] = (byte) ('a' + i % 26);
        try (H3TestClient client = client()) {
            // Without content-length, the body goes on chunked to the HTTP/1.1 upstream.
            H3TestClient.Response r = client.post("/echo", body);
            assertEquals(200, r.status());
            assertArrayEquals(body, TestSupport.echoedBody(r.text()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            assertEquals(List.of("chunked"), TestSupport.echoedHeader(r.text(), "transfer-encoding"));
            // With it, as it is.
            r = client.request("POST", "/echo", List.of(new HeaderField("content-length", "300000")), body, List.of());
            assertArrayEquals(body, TestSupport.echoedBody(r.text()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            assertEquals(List.of("300000"), TestSupport.echoedHeader(r.text(), "content-length"));
        }
    }

    @Test
    void theServersOwnAltSvcWinsUnlessStrippingEmptiedIt() throws Exception {
        HttpServer advertising = TestSupport.origin(exchange -> {
            exchange.getResponseHeaders().set("Alt-Svc", exchange.getRequestURI().getPath().equals("/h2")
                    ? "h2=\":443\"" : "h3=\":443\"");
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        HttpProxyServer stripping = MicroProxy.bootstrap()
                .withPort(0)
                .withReverseProxy("http://127.0.0.1:" + advertising.getAddress().getPort())
                .withSslContextSource(tls)
                .withHttp3(true)
                .withAltSvcH3Stripping(true)
                .start();
        try {
            java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder().sslContext(tls.getSslContext()).build();
            String base = "https://localhost:" + stripping.getListenAddress().getPort();
            java.net.http.HttpResponse<String> h2 = TestSupport.send(client,
                    java.net.http.HttpRequest.newBuilder(java.net.URI.create(base + "/h2")).build());
            assertEquals("h2=\":443\"", h2.headers().firstValue("alt-svc").orElse(null));
            java.net.http.HttpResponse<String> h3 = TestSupport.send(client,
                    java.net.http.HttpRequest.newBuilder(java.net.URI.create(base + "/h3")).build());
            assertEquals("h3=\":" + stripping.getListenAddress().getPort() + "\"; ma=86400",
                    h3.headers().firstValue("alt-svc").orElse(null), "the upstream's own h3 is replaced by the proxy's");
        } finally {
            stripping.abort();
            advertising.stop(0);
        }
    }

    @Test
    void tcpResponsesAdvertiseTheHttp3Listener() throws Exception {
        java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder().sslContext(tls.getSslContext()).build();
        java.net.http.HttpResponse<String> r = TestSupport.send(client, java.net.http.HttpRequest.newBuilder(
                java.net.URI.create("https://localhost:" + proxy.getListenAddress().getPort() + "/")).build());
        assertEquals(200, r.statusCode());
        assertEquals("h3=\":" + proxy.getListenAddress().getPort() + "\"; ma=86400",
                r.headers().firstValue("alt-svc").orElse(null));
    }
}
