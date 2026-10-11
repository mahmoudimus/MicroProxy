package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsServer;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
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
import org.microproxy.http.HttpResponse;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * The transparent QUIC listener with aioquic's HTTP/3 client, as a firewall would send it there,
 * asking for {@code origin.test} (loopback, by the proxy's resolver): intercepted with a
 * certificate the proxy issues, to an aioquic HTTP/3 origin and to an HTTP/1.1 one over TCP; and,
 * for an ignored host, relayed untouched, so that aioquic's handshake completes with the aioquic
 * origin and its own certificate.
 *
 * <p>Skipped unless Python 3 with aioquic is available ({@link AioquicPeers}).
 */
@Timeout(value = 180, unit = TimeUnit.SECONDS)
class AioquicTransparentQuicTest {

    private static CertificateAuthority proxyCa;
    private static CertificateAuthority originCa;

    @TempDir
    Path dir;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<String> decisions = new CopyOnWriteArrayList<>();
    private final List<String> filtered = new CopyOnWriteArrayList<>();
    private HttpProxyServer proxy;
    private Path proxyCaPem;
    private Path originCaPem;

    @BeforeAll
    static void authorities() {
        proxyCa = CertificateAuthority.generate("aioquic Transparent Proxy CA");
        originCa = CertificateAuthority.generate("aioquic Transparent Origin CA");
    }

    @BeforeEach
    void setUp() throws Exception {
        AioquicPeers.assumeAvailable();
        proxyCaPem = AioquicPeers.certificates(dir.resolve("proxy-ca.pem"), proxyCa.getCertificate());
        originCaPem = AioquicPeers.certificates(dir.resolve("origin-ca.pem"), originCa.getCertificate());
    }

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    /** An aioquic HTTP/3 origin for {@code origin.test}, with a certificate from the origin CA. */
    private AioquicPeers.Origin aioquicOrigin() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = g.generateKeyPair();
        X509Certificate leaf = originCa.issue(keys.getPublic(), List.of(TransparentQuicTest.HOST, "localhost"));
        Path chain = AioquicPeers.certificates(dir.resolve("origin.pem"), leaf, originCa.getCertificate());
        Path key = AioquicPeers.privateKey(dir.resolve("origin-key.pem"), keys.getPrivate());
        AioquicPeers.Origin origin = new AioquicPeers.Origin(dir, chain, key);
        closeables.add(origin);
        return origin;
    }

    private void start(int port, java.util.function.Consumer<HttpProxyServerBootstrap> configure) {
        HttpProxyServerBootstrap b = MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(port)
                .withTransparentQuicPort(0)
                .withServerResolver(TransparentQuicTest.TEST_HOSTS)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .plusActivityTracker(new ActivityTracker() {
                    @Override
                    public void transparentQuicFlowDecided(FlowContext flow, ClientHello hello, boolean intercepted,
                            String reason) {
                        decisions.add(hello.sni() + " " + hello.alpnProtocols() + " " + intercepted);
                    }
                })
                .withFiltersSource((request, flow) -> {
                    filtered.add(request.method() + " " + request.uri() + " " + flow.getHttpVersion() + " "
                            + flow.isTransparentQuic());
                    return new HttpFiltersAdapter(request, flow) {
                        @Override
                        public HttpObject proxyToClientResponse(HttpObject o) {
                            if (o instanceof HttpResponse r) r.headers().set("x-filtered", "transparent-quic");
                            return o;
                        }
                    };
                });
        configure.accept(b);
        proxy = b.start();
    }

    private List<Map<String, Object>> send(Path ca, List<Map<String, Object>> requests) throws Exception {
        return AioquicPeers.requests(dir, proxy.getTransparentQuicAddress().getPort(), ca, TransparentQuicTest.HOST,
                requests, true);
    }

    private static List<Map<String, Object>> requests() {
        Map<String, Object> upload = AioquicPeers.request("POST", "/echo/upload");
        upload.put("body_size", 1_000_000);
        upload.put("seed", 3);
        return List.of(AioquicPeers.request("GET", "/hello"), upload, AioquicPeers.request("GET", "/bytes/2000000"));
    }

    @Test
    void interceptsAnAioquicClientToAnAioquicOrigin() throws Exception {
        AioquicPeers.Origin origin = aioquicOrigin();
        start(origin.port, b -> b.withHttp3Upstream(true));
        List<Map<String, Object>> responses = send(proxyCaPem, requests());
        assertEquals(200L, responses.get(0).get("status"));
        assertEquals("hello from aioquic", responses.get(0).get("text"));
        assertEquals("transparent-quic", AioquicPeers.field(responses.get(0), "headers", "x-filtered"));
        assertEquals("h3", AioquicPeers.field(responses.get(0), "headers", "x-origin-protocol"));
        assertEquals(200L, responses.get(1).get("status"));
        assertTrue((Long) responses.get(1).get("length") > 1_000_000L);
        assertEquals(2_000_000L, responses.get(2).get("length"));
        assertEquals(List.of(TransparentQuicTest.HOST + " [h3] true"), decisions);
        assertTrue(filtered.contains("GET /hello HTTP/3.0 true"), filtered.toString());
        assertEquals(3, origin.requests().size(), origin.requests().toString());
    }

    @Test
    void interceptsAnAioquicClientToAnHttp1OriginOverTcp() throws Exception {
        HttpsServer origin = TestSupport.httpsOrigin(originCa.serverContext(TransparentQuicTest.HOST), exchange -> {
            exchange.getResponseHeaders().set("X-Origin-Protocol", "h1");
            TestSupport.echo().handle(exchange);
        });
        closeables.add(() -> origin.stop(0));
        start(origin.getAddress().getPort(), b -> {});
        Map<String, Object> post = AioquicPeers.request("POST", "/form");
        post.put("body", "over tcp");
        List<Map<String, Object>> responses = send(proxyCaPem, List.of(post));
        Map<String, Object> r = responses.getFirst();
        assertEquals(200L, r.get("status"));
        assertEquals("h1", AioquicPeers.field(r, "headers", "x-origin-protocol"));
        assertEquals("over tcp", TestSupport.echoedBody((String) r.get("text")));
    }

    @Test
    void relaysAnIgnoredHostSoTheHandshakeIsTheOrigins() throws Exception {
        AioquicPeers.Origin origin = aioquicOrigin();
        start(origin.port, b -> b.withIgnoreHosts("^origin\\.test:"));
        // aioquic trusts only the origin's CA: the handshake, and every request, are the origin's.
        List<Map<String, Object>> responses = send(originCaPem, requests());
        assertEquals("hello from aioquic", responses.get(0).get("text"));
        assertFalse(responses.get(0).toString().contains("x-filtered"));
        assertEquals(2_000_000L, responses.get(2).get("length"));
        assertEquals(List.of(TransparentQuicTest.HOST + " [h3] false"), decisions);
        assertEquals(List.of("CONNECT " + TransparentQuicTest.HOST + ":" + origin.port + " HTTP/1.1 true"), filtered);
        assertEquals(3, origin.requests().size());
    }
}
