package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.github.mahmoudimus.http2.HeaderField;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * The proxy's HTTP/3 against aioquic, an independent implementation, on either side: aioquic's
 * HTTP/3 client through a reverse proxy serving HTTP/3 to an origin over HTTP/1.1, HTTP/2 and
 * HTTP/3, and the proxy's HTTP/3 to aioquic's HTTP/3 server. Large bodies both ways, trailers,
 * many concurrent streams, and filters seeing the HTTP/3 requests.
 *
 * <p>Skipped unless Python 3 with aioquic is available ({@link AioquicPeers}).
 */
@Timeout(value = 180, unit = TimeUnit.SECONDS)
class AioquicHttp3Test {

    private static CertificateAuthority proxyCa;
    private static CertificateAuthority originCa;

    @TempDir
    Path dir;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<String> filtered = new CopyOnWriteArrayList<>();
    private HttpProxyServer proxy;
    private Path ca;

    @BeforeAll
    static void authorities() {
        proxyCa = CertificateAuthority.generate("aioquic H3 Proxy CA");
        originCa = CertificateAuthority.generate("aioquic H3 Origin CA");
    }

    @BeforeEach
    void setUp() throws Exception {
        AioquicPeers.assumeAvailable();
        ca = AioquicPeers.certificates(dir.resolve("proxy-ca.pem"), proxyCa.getCertificate());
    }

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    /**
     * A reverse proxy for {@code upstream} serving HTTP/3 with a certificate its CA issues, its
     * filters recording what they see and marking responses.
     */
    private void startProxy(String upstream, java.util.function.Consumer<HttpProxyServerBootstrap> configure) {
        HttpProxyServerBootstrap b = MicroProxy.bootstrap()
                .withPort(0)
                .withReverseProxy(upstream)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp3(true)
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                        filtered.add(originalRequest.method() + " " + originalRequest.uri() + " " + ctx.getHttpVersion());
                        if (originalRequest.uri().startsWith("/slow/")) {
                            // Holds the exchange back, past the stream's end, before it goes upstream
                            try {
                                Thread.sleep(500);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                            }
                        }
                        return new HttpFiltersAdapter(originalRequest, ctx) {
                            @Override
                            public HttpObject proxyToClientResponse(HttpObject o) {
                                if (o instanceof HttpResponse r) r.headers().set("x-filtered", ctx.getHttpVersion().text());
                                return o;
                            }
                        };
                    }
                });
        configure.accept(b);
        proxy = b.start();
    }

    private List<Map<String, Object>> send(List<Map<String, Object>> requests, boolean concurrent) throws Exception {
        return AioquicPeers.requests(dir, proxy.getListenAddress().getPort(), ca, requests, concurrent);
    }

    private static String sha256(byte[] data) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
    }

    private static byte[] counting(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) i;
        return b;
    }

    /**
     * The requests every origin gets: a GET, a 2 MB upload echoed, a 3 MB download, and a request
     * with a body and, unless the origin is the JDK's HTTP/1.1 server (which takes no request
     * trailers), trailers.
     */
    private static List<Map<String, Object>> standardRequests(boolean withTrailers) {
        Map<String, Object> hello = AioquicPeers.request("GET", "/echo/hello");
        Map<String, Object> upload = AioquicPeers.request("POST", "/echo/upload");
        upload.put("body_size", 2_000_000);
        upload.put("seed", 5);
        Map<String, Object> download = AioquicPeers.request("GET", "/bytes/3000000");
        Map<String, Object> trailers = AioquicPeers.request("POST", "/echo/trailers");
        trailers.put("body", "with trailers");
        trailers.put("headers", List.of(List.of("te", "trailers")));
        if (withTrailers) trailers.put("trailers", List.of(List.of("x-request-trailer", "t1")));
        return List.of(hello, upload, download, trailers);
    }

    private void checkStandard(List<Map<String, Object>> responses, String protocol, boolean trailersEchoed) throws Exception {
        Map<String, Object> hello = responses.get(0);
        assertEquals(200L, hello.get("status"));
        assertTrue(((String) hello.get("text")).startsWith("method: GET\nuri: /echo/hello\n"), (String) hello.get("text"));
        assertEquals("HTTP/3.0", AioquicPeers.field(hello, "headers", "x-filtered"));
        assertEquals(protocol, AioquicPeers.field(hello, "headers", "x-origin-protocol"));
        assertNull(AioquicPeers.field(hello, "headers", "alt-svc"));

        Map<String, Object> upload = responses.get(1);
        assertEquals(200L, upload.get("status"));
        assertTrue((Long) upload.get("length") > 2_000_000L);

        Map<String, Object> download = responses.get(2);
        assertEquals(3_000_000L, download.get("length"));
        assertEquals(sha256(counting(3_000_000)), download.get("sha256"));

        Map<String, Object> trailers = responses.get(3);
        assertEquals(200L, trailers.get("status"));
        assertTrue(((String) trailers.get("text")).endsWith("\n\nwith trailers"), (String) trailers.get("text"));
        if (trailersEchoed) assertEquals("t1", AioquicPeers.field(trailers, "trailers", "x-request-trailer"));
    }

    /** {@code n} GETs at once. */
    private void manyAtOnce(int n) throws Exception {
        List<Map<String, Object>> many = new ArrayList<>();
        for (int i = 0; i < n; i++) many.add(AioquicPeers.request("GET", "/bytes/" + (1000 + i)));
        List<Map<String, Object>> responses = send(many, true);
        for (int i = 0; i < n; i++) {
            assertEquals(200L, responses.get(i).get("status"));
            assertEquals(1000L + i, responses.get(i).get("length"));
        }
    }

    // ---------------------------------------------------------------------------------------

    @Test
    void anAioquicClientReachesAnHttp1Origin() throws Exception {
        HttpServer origin = TestSupport.origin(exchange -> {
            String path = exchange.getRequestURI().getPath();
            if (path.startsWith("/bytes/")) {
                byte[] out = counting(Integer.parseInt(path.substring(7)));
                exchange.getResponseHeaders().set("X-Origin-Protocol", "h1");
                exchange.sendResponseHeaders(200, out.length);
                exchange.getResponseBody().write(out);
                exchange.close();
            } else {
                exchange.getResponseHeaders().set("X-Origin-Protocol", "h1");
                TestSupport.echo().handle(exchange);
            }
        });
        closeables.add(() -> origin.stop(0));
        startProxy("http://127.0.0.1:" + origin.getAddress().getPort(), b -> {});
        List<Map<String, Object>> responses = send(standardRequests(false), true);
        checkStandard(responses, "h1", false);
        manyAtOnce(50);
        assertTrue(filtered.contains("GET /echo/hello HTTP/3.0"), filtered.toString());
    }

    @Test
    void aRequestWhoseStreamEndsLateGoesToAnHttp1OriginAsItsHeadIsFramed() throws Exception {
        // The stream's FIN comes after the proxy has framed the request's head for a body
        // (chunked, its end unknown) but before the exchange sends it, held back by a filter: the
        // body must still be sent, and ended, as the head is framed, or the origin waits for it
        HttpServer origin = TestSupport.origin(TestSupport.echo());
        closeables.add(() -> origin.stop(0));
        startProxy("http://127.0.0.1:" + origin.getAddress().getPort(), b -> {});
        Map<String, Object> get = AioquicPeers.request("GET", "/slow/late");
        get.put("end_delay", 0.2);
        Map<String, Object> post = AioquicPeers.request("POST", "/slow/late-post");
        post.put("body", "a body");
        post.put("end_delay", 0.2);
        List<Map<String, Object>> responses = send(List.of(get, post), true);
        assertEquals(200L, responses.get(0).get("status"));
        assertTrue(((String) responses.get(0).get("text")).startsWith("method: GET\nuri: /slow/late\n"),
                (String) responses.get(0).get("text"));
        assertEquals(200L, responses.get(1).get("status"));
        assertTrue(((String) responses.get(1).get("text")).endsWith("\n\na body"), (String) responses.get(1).get("text"));
    }

    @Test
    void anAioquicClientReachesAnHttp2Origin() throws Exception {
        H2TestOrigin origin = new H2TestOrigin(originCa.serverContext("localhost", "127.0.0.1"), s -> {
            String path = s.header(":path");
            if (path.startsWith("/bytes/")) {
                byte[] out = counting(Integer.parseInt(path.substring(7)));
                s.respond(200, false, "content-length", Integer.toString(out.length), "x-origin-protocol", "h2");
                s.data(out, true);
                return;
            }
            byte[] body = s.readBody();
            StringBuilder sb = new StringBuilder("method: " + s.header(":method") + "\nuri: " + path + "\n");
            for (HeaderField f : s.headers) {
                if (!f.name().startsWith(":")) sb.append("h:").append(f.name()).append(": ").append(f.value()).append('\n');
            }
            byte[] out = (sb + "\n" + new String(body, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
            s.respond(200, false, "x-origin-protocol", "h2");
            s.data(out, false);
            String trailer = s.trailer("x-request-trailer");
            if (trailer != null) {
                s.trailers("x-request-trailer", trailer);
            } else {
                s.data(new byte[0], true);
            }
        });
        closeables.add(origin);
        startProxy("https://localhost:" + origin.port(), b -> b.withHttp2Upstream(true));
        List<Map<String, Object>> responses = send(standardRequests(true), true);
        checkStandard(responses, "h2", true);
        manyAtOnce(50);
    }

    @Test
    void anAioquicClientReachesAnHttp3Origin() throws Exception {
        H3TestOrigin origin = new H3TestOrigin(originCa);
        closeables.add(origin);
        startProxy("https://localhost:" + origin.port(), b -> b.withHttp3Upstream(true).withHttp3UpstreamHosts("^localhost:"));
        List<Map<String, Object>> responses = send(standardRequests(true), true);
        checkStandard(responses, "h3", true);
        manyAtOnce(50);
        assertEquals(1, origin.connections.get(), "one QUIC connection to the origin for every exchange");
    }

    @Test
    void theProxySpeaksHttp3ToAnAioquicOrigin() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = g.generateKeyPair();
        X509Certificate leaf = originCa.issue(keys.getPublic(), List.of("localhost", "127.0.0.1"));
        Path cert = AioquicPeers.certificates(dir.resolve("origin.pem"), leaf, originCa.getCertificate());
        Path key = AioquicPeers.privateKey(dir.resolve("origin-key.pem"), keys.getPrivate());
        AioquicPeers.Origin origin = new AioquicPeers.Origin(dir, cert, key);
        closeables.add(origin);
        startProxy("https://localhost:" + origin.port, b -> b.withHttp3Upstream(true).withHttp3UpstreamHosts("^localhost:"));

        // aioquic on both sides of the proxy.
        List<Map<String, Object>> responses = send(standardRequests(true), true);
        checkStandard(responses, "h3", true);
        manyAtOnce(30);

        // The proxy's own HTTP/3 client side against aioquic, from a Java HTTP/3 client.
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        try (H3TestClient client = H3TestClient.connect(address, "localhost", proxyCa.getCertificate())) {
            H3TestClient.Response hello = client.get("/hello");
            assertEquals("hello from aioquic", hello.text());
            assertEquals("aioquic-origin", hello.header("server"));
            H3TestClient.Response t = client.get("/trailers");
            assertEquals("42", t.trailer("x-checksum"));
        }
        assertTrue(origin.requests().contains("GET /hello"), origin.requests().toString());
    }
}
