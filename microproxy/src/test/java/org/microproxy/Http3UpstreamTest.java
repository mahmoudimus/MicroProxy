package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.http3.HeaderField;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * HTTP/3 to origin servers: learned from {@code Alt-Svc} (before it is stripped for the client) or
 * forced by host, one shared QUIC connection per server, falling back to TCP when QUIC fails, and
 * reached from clients of any protocol.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class Http3UpstreamTest {

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private HttpProxyServer proxy;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("H3 Upstream Origin CA");
        proxyCa = CertificateAuthority.generate("H3 Upstream Proxy CA");
    }

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    private HttpsServer tcpOrigin(HttpHandler handler) {
        HttpsServer server = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), handler);
        closeables.add(() -> server.stop(0));
        return server;
    }

    /** Answers {@code over tcp}, advertising HTTP/3 with {@code altSvc}. */
    private static HttpHandler advertising(String altSvc) {
        return exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] out = "over tcp".getBytes(StandardCharsets.US_ASCII);
            exchange.getResponseHeaders().set("Alt-Svc", altSvc);
            exchange.getResponseHeaders().set("X-Origin-Protocol", "tcp");
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        };
    }

    private H3TestOrigin h3Origin(int port) throws Exception {
        H3TestOrigin origin = new H3TestOrigin(originCa, port);
        closeables.add(origin);
        return origin;
    }

    private HttpProxyServerBootstrap mitmProxy() {
        return MicroProxy.bootstrap()
                .withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp3Upstream(true);
    }

    private HttpClient client() {
        return TestSupport.client(proxy, proxyCa.clientContext());
    }

    @Test
    void learnsHttp3FromAltSvcAndSharesOneConnection() throws Exception {
        H3TestOrigin h3 = h3Origin(0);
        HttpsServer tcp = tcpOrigin(advertising("h3=\":" + h3.port() + "\"; ma=60, h2=\":443\""));
        proxy = mitmProxy().start();
        HttpClient client = client();
        String url = TestSupport.localhostUrl(tcp, "/hello");

        HttpResponse<String> first = TestSupport.get(client, url);
        assertEquals("over tcp", first.body());
        // Learned from, then stripped for the client: it stays on TCP through the proxy.
        assertEquals("h2=\":443\"", first.headers().firstValue("alt-svc").orElse(null));

        HttpResponse<String> second = TestSupport.get(client, url);
        assertEquals(200, second.statusCode());
        assertEquals("hello over h3", second.body());
        assertEquals("h3", second.headers().firstValue("x-origin-protocol").orElse(null));

        // Another client (a TCP connection of its own) shares the QUIC connection.
        HttpClient other = client();
        for (int i = 0; i < 5; i++) assertEquals("hello over h3", TestSupport.get(other, url).body());
        assertEquals(1, h3.connections.get(), "one QUIC connection for every exchange");
        assertEquals(6, h3.requests.get());
        assertTrue(h3.errors().isEmpty(), h3.errors().toString());
    }

    @Test
    void fallsBackToTcpWhenQuicFailsAndRemembersIt() throws Exception {
        int deadPort;
        try (DatagramSocket nobody = new DatagramSocket(0, TestSupport.LOOPBACK)) {
            deadPort = nobody.getLocalPort();
            HttpsServer tcp = tcpOrigin(advertising("h3=\":" + deadPort + "\""));
            proxy = mitmProxy().withHttp3Options(Http3Options.builder()
                    .upstreamHandshakeTimeout(Duration.ofMillis(300)).build()).start();
            HttpClient client = client();
            String url = TestSupport.localhostUrl(tcp, "/");
            assertEquals("over tcp", TestSupport.get(client, url).body());
            // QUIC to the advertised port times out: TCP instead, and from then on without trying.
            long tried = System.nanoTime();
            assertEquals("over tcp", TestSupport.get(client, url).body());
            assertTrue(System.nanoTime() - tried >= Duration.ofMillis(250).toNanos(), "QUIC was tried first");
            long started = System.nanoTime();
            assertEquals("over tcp", TestSupport.get(client, url).body());
            assertTrue(System.nanoTime() - started < Duration.ofMillis(300).toNanos(),
                    "a server whose handshake failed is not tried again at once");
        }
    }

    @Test
    void forcedHostsGoOverHttp3WithoutAltSvc() throws Exception {
        HttpsServer tcp = tcpOrigin(TestSupport.fixed(200, "over tcp"));
        // The HTTP/3 origin on the UDP port with the HTTPS origin's number.
        H3TestOrigin h3 = h3Origin(tcp.getAddress().getPort());
        proxy = mitmProxy().withHttp3UpstreamHosts("^localhost:").start();
        HttpResponse<String> r = TestSupport.get(client(), TestSupport.localhostUrl(tcp, "/hello"));
        assertEquals("hello over h3", r.body());
        // Other hosts are not forced.
        assertEquals("over tcp", TestSupport.get(client(), TestSupport.url(tcp, "/hello")).body());
        assertEquals(1, h3.requests.get());
    }

    @Test
    void anHttp3ClientReachesAnHttp3ServerWithBodiesAndTrailers() throws Exception {
        HttpsServer tcp = tcpOrigin(TestSupport.fixed(200, "over tcp"));
        H3TestOrigin h3 = h3Origin(tcp.getAddress().getPort());
        SelfSignedSslContextSource listener = new SelfSignedSslContextSource();
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withReverseProxy("https://localhost:" + tcp.getAddress().getPort())
                .withSslContextSource(listener)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp3(true)
                .withHttp3Upstream(true)
                .withHttp3UpstreamHosts("localhost")
                .start();
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        byte[] body = new byte[1_000_000];
        new java.util.Random(7).nextBytes(body);
        String text = java.util.Base64.getEncoder().encodeToString(body);
        try (H3TestClient client = H3TestClient.connect(address, "localhost", listener.getCertificate())) {
            H3TestClient.Response r = client.request("POST", "/echo", List.of(new HeaderField("te", "trailers")),
                    text.getBytes(StandardCharsets.US_ASCII), List.of(new HeaderField("x-request-trailer", "t1")));
            assertEquals(200, r.status());
            assertEquals("h3", r.header("x-origin-protocol"));
            assertEquals(text, TestSupport.echoedBody(r.text()));
            assertEquals("t1", r.trailer("x-request-trailer"));

            H3TestClient.Response t = client.get("/trailers");
            assertEquals("with trailers", t.text());
            assertEquals("42", t.trailer("x-checksum"));

            H3TestClient.Response bytes = client.get("/bytes/3000000");
            assertEquals(3_000_000, bytes.body().length);
            byte[] expected = new byte[3_000_000];
            for (int i = 0; i < expected.length; i++) expected[i] = (byte) i;
            assertArrayEquals(expected, bytes.body());

            // Many streams at once from the client, over one QUIC connection to the server.
            List<Future<H3TestClient.Response>> many = new ArrayList<>();
            try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
                for (int i = 0; i < 40; i++) {
                    String path = i % 2 == 0 ? "/hello" : "/bytes/" + (10_000 + i);
                    many.add(pool.submit(() -> client.get(path)));
                }
                for (int i = 0; i < many.size(); i++) {
                    H3TestClient.Response r2 = many.get(i).get();
                    assertEquals(200, r2.status());
                    assertEquals(i % 2 == 0 ? H3TestOrigin.HELLO.length : 10_000 + i, r2.body().length);
                }
            }
        }
        assertEquals(1, h3.connections.get());
        assertTrue(h3.errors().isEmpty(), h3.errors().toString());
    }

    @Test
    void aGoAwayFromTheServerMovesLaterRequestsToANewConnection() throws Exception {
        HttpsServer tcp = tcpOrigin(TestSupport.fixed(200, "over tcp"));
        H3TestOrigin h3 = h3Origin(tcp.getAddress().getPort());
        proxy = mitmProxy().withHttp3UpstreamHosts("localhost").start();
        HttpClient client = client();
        assertEquals("ok", TestSupport.get(client, TestSupport.localhostUrl(tcp, "/goaway")).body());
        TestSupport.eventually("the proxy to drop the connection that sent GOAWAY", () -> {
            HttpResponse<String> r = TestSupport.get(client, TestSupport.localhostUrl(tcp, "/hello"));
            return r.body().equals("hello over h3") && h3.connections.get() == 2;
        });
        assertFalse(h3.requestLines().isEmpty());
    }
}
