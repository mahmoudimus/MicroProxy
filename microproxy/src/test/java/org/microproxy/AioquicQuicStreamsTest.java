package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.quic.QuicContext;
import org.microproxy.quic.QuicDatagram;
import org.microproxy.quic.QuicInterceptor;
import org.microproxy.quic.QuicStreamContext;
import org.microproxy.quic.QuicStreamMessage;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * QUIC that is not HTTP/3 between aioquic peers, intercepted stream by stream with the QUIC hooks:
 * aioquic's raw QUIC client ({@code interop/quic_echo_client.py}) and echo server ({@code
 * interop/quic_echo_server.py}) with an ALPN of their own, through the transparent QUIC listener,
 * and inside a CONNECT-UDP flow on the forward proxy's HTTP/3 listener, the client driving its inner
 * connection over HTTP Datagrams and capsules.
 *
 * <p>Skipped unless Python 3 with aioquic is available ({@link AioquicPeers}).
 */
@Timeout(value = 180, unit = TimeUnit.SECONDS)
class AioquicQuicStreamsTest {

    static final String HOST = "origin.test";
    static final String ALPN = "microproxy-echo";

    private static final SelfSignedSslContextSource TLS = new SelfSignedSslContextSource();
    private static CertificateAuthority proxyCa;
    private static CertificateAuthority originCa;

    @TempDir
    Path dir;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<String> hooks = new CopyOnWriteArrayList<>();
    private HttpProxyServer proxy;
    private Path proxyCaPem;

    @BeforeAll
    static void authorities() {
        proxyCa = CertificateAuthority.generate("aioquic QUIC Hooks Proxy CA");
        originCa = CertificateAuthority.generate("aioquic QUIC Hooks Origin CA");
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

    /** aioquic's echo server for {@code origin.test}, with a certificate from the origin CA. */
    private AioquicPeers.QuicEchoServer echoServer() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = g.generateKeyPair();
        X509Certificate leaf = originCa.issue(keys.getPublic(), List.of(HOST, "localhost"));
        Path chain = AioquicPeers.certificates(dir.resolve("origin.pem"), leaf, originCa.getCertificate());
        Path key = AioquicPeers.privateKey(dir.resolve("origin-key.pem"), keys.getPrivate());
        AioquicPeers.QuicEchoServer server = new AioquicPeers.QuicEchoServer(dir, chain, key, ALPN);
        closeables.add(server);
        return server;
    }

    /**
     * Upper-cases what the client sends on its first stream, prefixes its datagrams with {@code
     * c:}, and records the connection's start, resets and end.
     */
    private QuicInterceptor hooks() {
        return new QuicInterceptor() {
            @Override
            public void quicStart(QuicContext ctx) {
                hooks.add("start " + ctx.sni() + " " + ctx.alpn() + " masque=" + ctx.masque());
            }

            @Override
            public byte[] streamData(QuicStreamMessage m, QuicStreamContext s) {
                if (m.fromClient() && s.streamId() == 0) return m.text().toUpperCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);
                return m.data();
            }

            @Override
            public void streamReset(QuicStreamContext s, boolean fromClient, long code) {
                hooks.add("reset " + s.streamId() + " " + fromClient + " " + code);
            }

            @Override
            public byte[] datagram(QuicDatagram d, QuicContext ctx) {
                return d.fromClient() ? ("c:" + d.text()).getBytes(StandardCharsets.UTF_8) : d.data();
            }

            @Override
            public void quicEnd(QuicContext ctx) {
                hooks.add("end");
            }

            @Override
            public void quicError(QuicContext ctx, Throwable error) {
                hooks.add("error " + error.getMessage());
            }
        };
    }

    private void check(Map<String, Object> r, AioquicPeers.QuicEchoServer server, boolean masque) {
        assertEquals(ALPN, r.get("alpn"));
        assertEquals(List.of("HELLO 0", "hello 1", "hello 2"), r.get("echoes"));
        assertEquals(Boolean.TRUE, r.get("big_ok"), "a megabyte echoed, length " + r.get("big_length"));
        assertEquals("uni-echo:uni hello", r.get("uni_reply"));
        assertEquals("c:ping", r.get("datagram"));
        long reset = (Long) r.get("reset_stream");
        eventually("the server's reset and close", () -> server.events().contains("TERMINATED 7 done"));
        assertTrue(server.events().contains("RESET " + reset + " 42"), server.events().toString());
        assertTrue(server.events().contains("CONNECTED " + ALPN), server.events().toString());
        eventually("quicEnd", () -> hooks.contains("end"));
        assertEquals("start " + HOST + " " + ALPN + " masque=" + masque, hooks.getFirst());
        assertTrue(hooks.contains("reset " + reset + " true 42"), hooks.toString());
    }

    @Test
    void aioquicPeersThroughTheTransparentListener() throws Exception {
        AioquicPeers.QuicEchoServer server = echoServer();
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(server.port)
                .withTransparentQuicPort(0)
                .withServerResolver(TransparentQuicTest.TEST_HOSTS)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withQuicInterceptor(hooks())
                .start();
        Map<String, Object> r = AioquicPeers.quicEcho(dir, proxy.getTransparentQuicAddress().getPort(), proxyCaPem, HOST,
                ALPN, null, null);
        check(r, server, false);
    }

    @Test
    void aioquicPeersInsideAConnectUdpFlow() throws Exception {
        AioquicPeers.QuicEchoServer server = echoServer();
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withSslContextSource(TLS)
                .withHttp3(true)
                .withServerResolver(TransparentQuicTest.TEST_HOSTS)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp3Options(Http3Options.builder().connectUdpInterceptQuic(true).connectUdpQuicPorts().build())
                .withQuicInterceptor(hooks())
                .start();
        Path tlsPem = AioquicPeers.certificates(dir.resolve("listener.pem"), TLS.getCertificate());
        InetSocketAddress listener = proxy.getListenAddress();
        Map<String, Object> r = AioquicPeers.quicEcho(dir, listener.getPort(), proxyCaPem, HOST, ALPN,
                HOST + ":" + server.port, tlsPem);
        assertEquals(200L, r.get("masque_status"));
        check(r, server, true);
    }
}
