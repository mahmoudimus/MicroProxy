package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;

import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.quic.QuicContext;
import org.microproxy.quic.QuicInterceptor;
import org.microproxy.quic.QuicStreamMessage;
import org.microproxy.quic.QuicStreamContext;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * QUIC inside CONNECT-UDP flows over HTTP/2 ({@link Http3Options.Builder#connectUdpInterceptQuic}
 * with {@link HttpProxyServerBootstrap#withConnectUdp}, and no HTTP/3 listener): a MASQUE client
 * of the proxy's h2c listener runs a Java QUIC client through its flow ({@link H2MasqueBridge}),
 * whose packets travel in DATAGRAM capsules; the proxy decides on the inner QUIC as for a flow over
 * HTTP/3 ({@link MasqueQuicTest}): HTTP/3 is intercepted, an ignored host relayed, other QUIC goes
 * through the QUIC hooks, a connection follows its client to another flow, and UDP that is not
 * QUIC is relayed as before.
 */
@Timeout(value = 90, unit = TimeUnit.SECONDS)
class Http2MasqueQuicTest {

    static final String HOST = MasqueQuicTest.HOST;

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<String> decisions = new CopyOnWriteArrayList<>();
    private final List<String> filtered = new CopyOnWriteArrayList<>();
    private HttpProxyServer proxy;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("MASQUE h2 QUIC Origin CA");
        proxyCa = CertificateAuthority.generate("MASQUE h2 QUIC Proxy CA");
    }

    @AfterEach
    void tearDown() throws Exception {
        for (int i = closeables.size() - 1; i >= 0; i--) closeables.get(i).close();
        if (proxy != null) proxy.abort();
    }

    /** A forward proxy serving h2c and CONNECT-UDP, deciding on the QUIC of flows to any port. */
    private HttpProxyServerBootstrap forwardProxy() {
        return MicroProxy.bootstrap()
                .withPort(0)
                .withHttp2Cleartext(true)
                .withConnectUdp(true)
                .withHttp3Upstream(true)
                .withServerResolver((host, port) -> host.equals("127.0.0.1")
                        ? new InetSocketAddress(TestSupport.LOOPBACK, port) : TransparentQuicTest.TEST_HOSTS.resolve(host, port))
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp3Options(Http3Options.builder().connectUdpInterceptQuic(true).connectUdpQuicPorts().build())
                .plusActivityTracker(new ActivityTracker() {
                    @Override
                    public void transparentQuicFlowDecided(FlowContext flow, ClientHello hello, boolean intercepted,
                            String reason) {
                        decisions.add(hello.sni() + " " + intercepted + " " + reason);
                    }
                })
                .withFiltersSource((request, flow) -> new HttpFiltersAdapter(request, flow) {
                    @Override
                    public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject object) {
                        if (object instanceof HttpRequest r) filtered.add(r.method() + " " + r.uri() + " " + r.protocolVersion());
                        return null;
                    }
                });
    }

    /** A CONNECT-UDP flow to {@code host:port}, on an HTTP/2 connection of its own. */
    private H2StreamClient.Stream connectUdp(String host, int port) throws IOException {
        H2StreamClient masque = H2StreamClient.cleartext(proxy.getListenAddress(), "localhost:" + proxy.getListenAddress().getPort());
        closeables.add(masque);
        H2StreamClient.Stream flow = masque.open(masque.connectUdp("/.well-known/masque/udp/" + host + "/" + port + "/"), false);
        assertEquals(200, flow.status());
        return flow;
    }

    /** A MASQUE client's flow to {@code host:port}, bridged to a local UDP socket. */
    private H2MasqueBridge flowTo(String host, int port) throws IOException {
        H2MasqueBridge bridge = new H2MasqueBridge(connectUdp(host, port));
        closeables.add(bridge);
        return bridge;
    }

    private static String issuer(QuicConnection c) {
        return ((X509Certificate) c.peerCertificates().getFirst()).getIssuerX500Principal().getName();
    }

    private static String name(CertificateAuthority ca) {
        return ca.getCertificate().getSubjectX500Principal().getName();
    }

    private static ClientConfig streamsClient() {
        return ClientConfig.builder(TlsConfig.builder()
                .alpnProtocols(QuicStreamHooksTest.ALPN)
                .serverName(HOST)
                .trustManager(H3TestClient.trusting(proxyCa.getCertificate()))
                .build()).build();
    }

    @Test
    void http3InsideAFlowIsInterceptedAndFiltered() throws Exception {
        H3TestOrigin origin = new H3TestOrigin(originCa);
        closeables.add(origin);
        proxy = forwardProxy().start();
        H2MasqueBridge bridge = flowTo(HOST, origin.port());
        try (H3TestClient inner = H3TestClient.connect(bridge.address(), HOST, proxyCa.getCertificate())) {
            assertEquals(name(proxyCa), issuer(inner.quic), "a certificate the proxy issued for the SNI");
            for (int i = 0; i < 3; i++) {
                H3TestClient.Response r = inner.get("/hello");
                assertEquals(200, r.status());
                assertEquals("hello over h3", r.text());
            }
        }
        assertEquals(List.of(HOST + " true null"), decisions);
        assertTrue(filtered.contains("GET /hello HTTP/3.0"), filtered.toString());
        assertTrue(filtered.contains("CONNECT " + HOST + ":" + origin.port() + " HTTP/1.1"), filtered.toString());
        assertEquals(3, origin.requests.get());
    }

    @Test
    void anIgnoredHostIsRelayed() throws Exception {
        H3TestOrigin origin = new H3TestOrigin(originCa);
        closeables.add(origin);
        proxy = forwardProxy().withIgnoreHosts("^origin\\.test:").start();
        H2MasqueBridge bridge = flowTo(HOST, origin.port());
        try (H3TestClient inner = H3TestClient.connect(bridge.address(), HOST, originCa.getCertificate())) {
            assertEquals(name(originCa), issuer(inner.quic), "the real server's certificate");
            assertEquals("hello over h3", inner.get("/hello").text());
        }
        assertEquals(1, decisions.size());
        assertTrue(decisions.getFirst().startsWith(HOST + " false an ignored host"), decisions.toString());
        assertFalse(filtered.contains("GET /hello HTTP/3.0"), filtered.toString());
    }

    @Test
    void otherQuicInsideAFlowGoesThroughTheQuicHooks() throws Exception {
        QuicEchoOrigin origin = new QuicEchoOrigin(originCa, QuicStreamHooksTest.ALPN);
        closeables.add(origin);
        List<String> hooks = new CopyOnWriteArrayList<>();
        proxy = forwardProxy().withQuicInterceptor(new QuicInterceptor() {
            @Override
            public void quicStart(QuicContext ctx) {
                hooks.add("start " + ctx.sni() + " " + ctx.alpn() + " " + ctx.host() + ":" + ctx.port() + " masque="
                        + ctx.masque());
            }

            @Override
            public byte[] streamData(QuicStreamMessage m, QuicStreamContext s) {
                return m.fromClient() ? m.text().toUpperCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8) : m.data();
            }
        }).start();
        H2MasqueBridge bridge = flowTo(HOST, origin.port());
        try (QuicClient client = QuicClient.create(streamsClient());
                QuicConnection c = client.connect(bridge.address(), HOST, Duration.ofSeconds(10))) {
            QuicStream s = c.openBidirectionalStream();
            try (OutputStream out = s.getOutputStream()) {
                out.write("echo\ninside an h2 flow".getBytes(StandardCharsets.UTF_8));
            }
            assertEquals("INSIDE AN H2 FLOW", new String(s.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
            c.close(0, "done");
        }
        eventually("quicStart", () -> !hooks.isEmpty());
        assertEquals("start " + HOST + " " + QuicStreamHooksTest.ALPN + " " + HOST + ":" + origin.port() + " masque=true",
                hooks.getFirst());
        assertEquals(List.of(HOST + " true ALPN [" + QuicStreamHooksTest.ALPN + "]"), decisions);
    }

    /**
     * The MASQUE client carries an intercepted connection over to a new flow, on another HTTP/2
     * connection, in the middle of a transfer, and ends the old flow: the proxy's connection to the
     * client follows it there and stays open (see {@link
     * MasqueQuicTest#anInterceptedConnectionFollowsItsClientToAnotherFlow}).
     */
    @Test
    void anInterceptedConnectionFollowsItsClientToAnotherFlow() throws Exception {
        QuicEchoOrigin origin = new QuicEchoOrigin(originCa, QuicStreamHooksTest.ALPN);
        closeables.add(origin);
        proxy = forwardProxy().withQuicInterceptor((message, stream) -> message.data()).start();
        H2MasqueBridge bridge = flowTo(HOST, origin.port());
        H2StreamClient.Stream next = connectUdp(HOST, origin.port());
        try (QuicClient client = QuicClient.create(streamsClient());
                QuicConnection c = client.connect(bridge.address(), HOST, Duration.ofSeconds(10))) {
            byte[] data = QuicMigrationProxyTest.data(11, 1 << 20);
            AtomicLong received = new AtomicLong();
            CompletableFuture<byte[]> echoed = QuicMigrationProxyTest.echo(c, data, received);
            eventually("a quarter echoed", () -> received.get() > data.length / 4);
            H2StreamClient.Stream old = bridge.moveTo(next);
            assertArrayEquals(QuicMigrationProxyTest.sha256(data), echoed.get(60, TimeUnit.SECONDS));
            byte[] more = QuicMigrationProxyTest.data(12, 200_000);
            assertArrayEquals(QuicMigrationProxyTest.sha256(more),
                    QuicMigrationProxyTest.echo(c, more, new AtomicLong()).get(30, TimeUnit.SECONDS));
            assertTrue(bridge.receivedThrough(next) > 0, "the proxy answers through the new flow");
            old.end(); // the flow the connection left ends: the connection stays
            assertArrayEquals(QuicMigrationProxyTest.sha256(more),
                    QuicMigrationProxyTest.echo(c, more, new AtomicLong()).get(30, TimeUnit.SECONDS));
            assertTrue(c.isOpen());
            c.close(0, "done");
        }
        assertEquals(List.of(HOST + " true ALPN [" + QuicStreamHooksTest.ALPN + "]"), decisions);
    }

    /** UDP that is not QUIC goes to the target as before, through the UDP hooks. */
    @Test
    void udpThatIsNotQuicIsRelayed() throws Exception {
        Http3MasqueTest.UdpEcho udp = new Http3MasqueTest.UdpEcho();
        closeables.add(udp);
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = forwardProxy().withUdpInterceptor((m, ctx) -> {
            seen.add(m.text());
            return m.data();
        }).start();
        H2MasqueBridge bridge = flowTo("127.0.0.1", udp.port());
        try (java.net.DatagramSocket client = new java.net.DatagramSocket()) {
            client.setSoTimeout(5000);
            byte[] ping = "ping".getBytes(StandardCharsets.UTF_8);
            client.send(new java.net.DatagramPacket(ping, ping.length, bridge.address()));
            java.net.DatagramPacket p = new java.net.DatagramPacket(new byte[100], 100);
            client.receive(p);
            assertEquals("ping", new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8));
        }
        assertEquals(List.of("ping"), udp.received);
        assertTrue(seen.contains("ping"), seen.toString());
        assertTrue(decisions.isEmpty(), decisions.toString());
    }
}
