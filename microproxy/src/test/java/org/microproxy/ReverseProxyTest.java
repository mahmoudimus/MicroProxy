package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.tls.SslContexts;

/** Reverse proxy mode: every request goes to one upstream, over HTTP, HTTPS or raw TCP. */
class ReverseProxyTest {

    private static CertificateAuthority originCa;
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private HttpServer origin;

    @BeforeAll
    static void authority() {
        originCa = CertificateAuthority.generate("Reverse Origin CA");
    }

    @AfterEach
    void tearDown() {
        proxies.close();
        if (origin != null) origin.stop(0);
    }

    /** Sends an origin-form GET straight to the proxy, as a client of a server would. */
    private static String get(HttpProxyServer proxy, String path, String host) throws Exception {
        return TestSupport.rawExchange(proxy.getListenAddress(),
                "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n");
    }

    private static String body(String response) {
        return response.substring(response.indexOf("\r\n\r\n") + 4);
    }

    @Test
    void parsesMitmproxysSpecificationSyntax() {
        assertEquals(new ReverseProxyMode("https", "example.com", 443), ReverseProxyMode.parse("example.com"));
        assertEquals(new ReverseProxyMode("http", "example.com", 80), ReverseProxyMode.parse("http://example.com/"));
        assertEquals(new ReverseProxyMode("https", "::1", 8443), ReverseProxyMode.parse("https://[::1]:8443"));
        assertEquals("[::1]:8443", ReverseProxyMode.parse("https://[::1]:8443").hostAndPort());
        assertEquals("example.com:8080", ReverseProxyMode.parse("http://example.com:8080").hostHeader());
        assertEquals("example.com", ReverseProxyMode.parse("https://example.com:443").hostHeader());
        assertEquals(new ReverseProxyMode("tcp", "10.0.0.1", 22), ReverseProxyMode.parseMode("reverse:tcp://10.0.0.1:22"));
        assertThrows(IllegalArgumentException.class, () -> ReverseProxyMode.parse("tcp://10.0.0.1"));
        assertThrows(IllegalArgumentException.class, () -> ReverseProxyMode.parse("https://example.com/path"));
        assertThrows(IllegalArgumentException.class, () -> ReverseProxyMode.parse("quic://example.com"));
        assertThrows(IllegalArgumentException.class, () -> ReverseProxyMode.parse("http://example.com:99999"));
        assertThrows(IllegalArgumentException.class, () -> ReverseProxyMode.parseMode("upstream:http://proxy"));
    }

    @Test
    void originFormRequestsGoToAnHttpUpstreamWithItsHost() throws Exception {
        origin = TestSupport.origin(TestSupport.echo());
        String upstream = "127.0.0.1:" + origin.getAddress().getPort();
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withReverseProxy("http://" + upstream));
        String response = get(proxy, "/hello?x=1", "proxy.test");
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        assertEquals("/hello?x=1", echoedUri(body(response)));
        assertEquals(List.of(upstream), echoedHeader(body(response), "host"));

        // An absolute-form request (a client using it as a forward proxy) goes there too.
        HttpResponse<String> absolute = TestSupport.get(TestSupport.client(proxy), "http://elsewhere.invalid/abs");
        assertEquals(200, absolute.statusCode());
        assertEquals("/abs", echoedUri(absolute.body()));
        assertEquals(List.of(upstream), echoedHeader(absolute.body(), "host"));
    }

    @Test
    void theClientsHostIsKeptOnRequest() throws Exception {
        origin = TestSupport.origin(TestSupport.echo());
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap()
                .withReverseProxy("http://127.0.0.1:" + origin.getAddress().getPort()).withKeepHostHeader(true));
        String response = get(proxy, "/kept", "proxy.test");
        assertEquals(List.of("proxy.test"), echoedHeader(body(response), "host"));
    }

    @Test
    void anHttpsUpstreamIsReachedOverTls() throws Exception {
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), TestSupport.echo());
        origin = secure;
        int port = secure.getAddress().getPort();
        // The MITM manager's server context validates the upstream.
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withReverseProxy("https://localhost:" + port)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(CertificateAuthority.generate("unused"),
                        originCa.clientContext())));
        String response = get(proxy, "/secure", "proxy.test");
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        assertEquals("/secure", echoedUri(body(response)));
        assertEquals(List.of("localhost:" + port), echoedHeader(body(response), "host"));

        // Without that trust, the JVM's default refuses the upstream: 502.
        HttpProxyServer untrusting = proxies.start(MicroProxy.bootstrap().withReverseProxy("https://localhost:" + port));
        assertTrue(get(untrusting, "/secure", "proxy.test").startsWith("HTTP/1.1 502"));
    }

    @Test
    void filtersApply() throws Exception {
        origin = TestSupport.origin(TestSupport.echo());
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap()
                .withReverseProxy("http://127.0.0.1:" + origin.getAddress().getPort())
                .withFiltersSource((request, ctx) -> HttpFilters.builder()
                        .onRequest(r -> {
                            r.headers().set("X-Seen-Host", r.headers().get(HttpHeaderNames.HOST));
                            return r.uri().equals("/blocked")
                                    ? org.microproxy.impl.ProxyUtils.createFullHttpResponse(
                                            org.microproxy.http.HttpVersion.HTTP_1_1,
                                            org.microproxy.http.HttpResponseStatus.FORBIDDEN, "no")
                                    : null;
                        })
                        .onResponse(r -> {
                            r.headers().set("X-Filtered", "yes");
                            return r;
                        }).build()));
        String response = get(proxy, "/open", "proxy.test");
        assertTrue(response.toLowerCase().contains("x-filtered: yes"), response);
        // Filters see the Host the request goes upstream with.
        assertEquals(List.of("127.0.0.1:" + origin.getAddress().getPort()), echoedHeader(body(response), "x-seen-host"));
        assertTrue(get(proxy, "/blocked", "proxy.test").startsWith("HTTP/1.1 403"));
    }

    @Test
    void connectIsRefused() throws Exception {
        origin = TestSupport.origin(TestSupport.echo());
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap()
                .withReverseProxy("http://127.0.0.1:" + origin.getAddress().getPort()));
        assertEquals(400, ChainTestSupport.connectStatus(proxy.getListenAddress(), "example.com:443"));
    }

    @Test
    void aTcpUpstreamGetsTheRawBytes() throws Exception {
        try (TestSupport.RawServer echo = TestSupport.rawServer(ClientHelloInterceptionTest::echoBytes)) {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withReverseProxy("tcp://127.0.0.1:" + echo.port()));
            try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
                byte[] bytes = {0, 1, 2, 'n', 'o', 't', ' ', 'h', 't', 't', 'p'};
                s.getOutputStream().write(bytes);
                s.getOutputStream().flush();
                assertArrayEquals(bytes, s.getInputStream().readNBytes(bytes.length));
            }
        }
    }

    @Test
    void aTlsListenerTerminatesTlsWithHttp2() throws Exception {
        origin = TestSupport.origin(TestSupport.echo());
        SelfSignedSslContextSource listener = new SelfSignedSslContextSource(false, true, "localhost");
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap()
                .withReverseProxy("http://127.0.0.1:" + origin.getAddress().getPort())
                .withSslContextSource(listener).withHttp2(true));
        HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2)
                .sslContext(SslContexts.trusting(listener.getCertificate())).connectTimeout(Duration.ofSeconds(10)).build();
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(
                        URI.create("https://localhost:" + proxy.getListenAddress().getPort() + "/terminated"))
                .timeout(Duration.ofSeconds(20)).build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        assertEquals(200, response.statusCode());
        assertEquals(HttpClient.Version.HTTP_2, response.version());
        assertEquals("/terminated", echoedUri(response.body()));
        assertEquals(List.of("127.0.0.1:" + origin.getAddress().getPort()), echoedHeader(response.body(), "host"));
        assertFalse(echoedHeader(response.body(), "via").isEmpty(), "the proxy's Via");
    }
}
