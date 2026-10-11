package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
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
import org.microproxy.dns.DnsMessage;
import org.microproxy.quic.QuicFraming;
import org.microproxy.quic.QuicInterceptor;
import org.microproxy.quic.QuicMessage;
import org.microproxy.quic.QuicStreamContext;
import org.microproxy.quic.QuicStreamMessage;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * DNS over QUIC with aioquic on either side of the proxy's transparent QUIC listener, a message
 * hook logging each query and rewriting the address of a blocked name: aioquic's client ({@code
 * interop/doq_client.py}) and server ({@code interop/doq_server.py}), each also against a Java
 * peer, with queries written in pieces and many streams at once.
 *
 * <p>Skipped unless Python 3 with aioquic is available ({@link AioquicPeers}).
 */
@Timeout(value = 180, unit = TimeUnit.SECONDS)
class AioquicDoqTest {

    static final String HOST = "origin.test";
    static final Map<String, String> ZONE = Map.of("www.example", "192.0.2.10", "ads.example", "192.0.2.66");

    private static CertificateAuthority proxyCa;
    private static CertificateAuthority originCa;

    @TempDir
    Path dir;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<String> queries = new CopyOnWriteArrayList<>();
    private HttpProxyServer proxy;
    private Path proxyCaPem;

    @BeforeAll
    static void authorities() {
        proxyCa = CertificateAuthority.generate("aioquic DoQ Proxy CA");
        originCa = CertificateAuthority.generate("aioquic DoQ Origin CA");
    }

    @BeforeEach
    void setUp() throws Exception {
        AioquicPeers.assumeAvailable();
        proxyCaPem = AioquicPeers.certificates(dir.resolve("proxy-ca.pem"), proxyCa.getCertificate());
    }

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    /** aioquic's DoQ server for {@code origin.test}, with a certificate from the origin CA. */
    private AioquicPeers.DoqServer aioquicServer() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = g.generateKeyPair();
        X509Certificate leaf = originCa.issue(keys.getPublic(), List.of(HOST, "localhost"));
        Path chain = AioquicPeers.certificates(dir.resolve("origin.pem"), leaf, originCa.getCertificate());
        Path key = AioquicPeers.privateKey(dir.resolve("origin-key.pem"), keys.getPrivate());
        AioquicPeers.DoqServer server = new AioquicPeers.DoqServer(dir, chain, key, ZONE);
        closeables.add(server);
        return server;
    }

    private DoqOrigin javaServer() throws Exception {
        DoqOrigin origin = new DoqOrigin(originCa, ZONE, "doq");
        closeables.add(origin);
        return origin;
    }

    /** Logs queries; answers ads.example with 0.0.0.0, rewriting the server's answer. */
    private QuicInterceptor blocker() {
        return new QuicInterceptor() {
            @Override
            public byte[] streamData(QuicStreamMessage message, QuicStreamContext stream) {
                return message.data();
            }

            @Override
            public List<QuicMessage> streamMessage(QuicMessage message, QuicStreamContext stream) {
                DnsMessage dns = message.dns();
                String name = dns.questions().getFirst().name();
                if (message.fromClient()) {
                    queries.add(name + " " + dns.questions().getFirst().typeName() + " on " + stream.streamId());
                    return List.of(message);
                }
                if (!name.equals("ads.example")) return List.of(message);
                return List.of(message.withDns(dns.withAnswers(dns.answers().stream()
                        .map(r -> r.withData(DnsMessage.Address.of("0.0.0.0"))).toList())));
            }
        };
    }

    private void proxyTo(int port) {
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(port)
                .withTransparentQuicPort(0)
                .withServerResolver(TransparentQuicTest.TEST_HOSTS)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withQuicInterceptor(blocker())
                .withQuicFraming(QuicFraming.defaults())
                .start();
    }

    @SuppressWarnings("unchecked")
    private static void checkAnswers(Map<String, Object> r) {
        assertEquals("doq", r.get("alpn"));
        Map<String, Object> answers = (Map<String, Object>) r.get("answers");
        assertEquals(Map.of("rcode", 0L, "addresses", List.of("192.0.2.10")), answers.get("www.example"));
        assertEquals(Map.of("rcode", 0L, "addresses", List.of("0.0.0.0")), answers.get("ads.example"));
        assertEquals(Map.of("rcode", 3L, "addresses", List.of()), answers.get("missing.example"));
    }

    @Test
    void aioquicClientAndServer() throws Exception {
        AioquicPeers.DoqServer server = aioquicServer();
        proxyTo(server.port);
        Map<String, Object> r = AioquicPeers.doq(dir, proxy.getTransparentQuicAddress().getPort(), proxyCaPem, HOST,
                List.of("www.example", "ads.example", "missing.example"), true);
        checkAnswers(r);
        assertTrue(queries.stream().anyMatch(q -> q.startsWith("ads.example A on ")), queries.toString());
        assertEquals(3, queries.size(), queries.toString());
        assertTrue(server.events().contains("QUERY ads.example 1"), server.events().toString());
    }

    @Test
    void aioquicClientAndJavaServer() throws Exception {
        DoqOrigin server = javaServer();
        proxyTo(server.port());
        Map<String, Object> r = AioquicPeers.doq(dir, proxy.getTransparentQuicAddress().getPort(), proxyCaPem, HOST,
                List.of("www.example", "ads.example", "missing.example"), false);
        checkAnswers(r);
        assertTrue(server.events.contains("ads.example A"), server.events.toString());
    }

    @Test
    void javaClientAndAioquicServer() throws Exception {
        AioquicPeers.DoqServer server = aioquicServer();
        proxyTo(server.port);
        QuicClient client = QuicClient.create(ClientConfig.builder(TlsConfig.builder()
                        .alpnProtocols("doq")
                        .serverName(HOST)
                        .trustManager(H3TestClient.trusting(proxyCa.getCertificate()))
                        .build())
                .build());
        closeables.add(client);
        QuicConnection c = client.connect(new InetSocketAddress(TestSupport.LOOPBACK,
                proxy.getTransparentQuicAddress().getPort()), HOST, Duration.ofSeconds(10));
        assertEquals("doq", c.alpn());
        for (int i = 0; i < 5; i++) {
            DnsMessage ads = DoqOrigin.query(c, DnsMessage.query(0, "ads.example", DnsMessage.A));
            assertEquals("0.0.0.0", ads.answers().getFirst().data().text());
            DnsMessage www = DoqOrigin.query(c, DnsMessage.query(0, "www.example", DnsMessage.A));
            assertEquals("192.0.2.10", www.answers().getFirst().data().text());
        }
        assertEquals(10, queries.size(), queries.toString());
    }
}
