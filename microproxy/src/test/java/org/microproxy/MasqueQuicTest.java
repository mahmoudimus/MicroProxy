package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;

import io.github.mahmoudimus.http3.HeaderField;
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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.Http3Frame;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.quic.QuicContext;
import org.microproxy.quic.QuicInterceptor;
import org.microproxy.quic.QuicStreamContext;
import org.microproxy.quic.QuicStreamMessage;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * QUIC inside CONNECT-UDP flows ({@link Http3Options.Builder#connectUdpInterceptQuic}): a MASQUE
 * client of the forward proxy's HTTP/3 listener runs a Java QUIC client through its flow ({@link
 * MasqueBridge}); the proxy reads the inner ClientHello and decides as for transparent QUIC, with
 * the flow's target as the server: HTTP/3 is intercepted (filters and the frame interceptor see its
 * requests), an ignored host is relayed, other QUIC goes through the QUIC hooks, and UDP that is
 * not QUIC is relayed as before.
 */
@Timeout(value = 90, unit = TimeUnit.SECONDS)
class MasqueQuicTest {

    static final String HOST = "origin.test";

    private static final SelfSignedSslContextSource TLS = new SelfSignedSslContextSource();
    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<String> decisions = new CopyOnWriteArrayList<>();
    private final List<String> filtered = new CopyOnWriteArrayList<>();
    private HttpProxyServer proxy;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("MASQUE QUIC Origin CA");
        proxyCa = CertificateAuthority.generate("MASQUE QUIC Proxy CA");
    }

    @AfterEach
    void tearDown() throws Exception {
        for (int i = closeables.size() - 1; i >= 0; i--) closeables.get(i).close();
        if (proxy != null) proxy.abort();
    }

    /** A forward proxy serving HTTP/3, deciding on the QUIC of CONNECT-UDP flows to any port. */
    private HttpProxyServerBootstrap forwardProxy() {
        return MicroProxy.bootstrap()
                .withPort(0)
                .withSslContextSource(TLS)
                .withHttp3(true)
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

    /** A CONNECT-UDP flow to {@code host:port}, on a MASQUE client of its own. */
    private record Flow(H3TestClient masque, H3TestClient.Tunnel tunnel) {}

    private Flow connectUdp(String host, int port) throws IOException {
        H3TestClient masque = H3TestClient.connect(
                new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort()), "localhost",
                TLS.getCertificate());
        closeables.add(masque);
        List<HeaderField> request = H3TestClient.extendedConnect("connect-udp", "https",
                "localhost:" + proxy.getListenAddress().getPort(), "/.well-known/masque/udp/" + host + "/" + port + "/",
                new HeaderField("capsule-protocol", "?1"));
        H3TestClient.Tunnel tunnel = masque.open(request);
        assertEquals(200, tunnel.status);
        return new Flow(masque, tunnel);
    }

    /** A MASQUE client's flow to {@code host:port}, bridged to a local UDP socket. */
    private MasqueBridge flowTo(String host, int port) throws IOException {
        Flow flow = connectUdp(host, port);
        MasqueBridge bridge = new MasqueBridge(flow.masque(), flow.tunnel());
        closeables.add(bridge);
        return bridge;
    }

    private static String issuer(QuicConnection c) {
        return ((X509Certificate) c.peerCertificates().getFirst()).getIssuerX500Principal().getName();
    }

    private static String name(CertificateAuthority ca) {
        return ca.getCertificate().getSubjectX500Principal().getName();
    }

    @Test
    void http3InsideAFlowIsInterceptedAndFiltered() throws Exception {
        H3TestOrigin origin = new H3TestOrigin(originCa);
        closeables.add(origin);
        List<String> frames = new CopyOnWriteArrayList<>();
        proxy = forwardProxy().withFrameInterceptor((frame, direction, ctx) -> {
            if (frame instanceof Http3Frame.Headers h && h.get(":path") != null && direction == FrameDirection.FROM_CLIENT) {
                frames.add(h.get(":path") + " quic=" + ctx.flowContext().isTransparentQuic());
            }
            return frame;
        }).start();
        MasqueBridge bridge = flowTo(HOST, origin.port());
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
        assertTrue(frames.contains("/hello quic=true"), frames.toString());
        assertEquals(3, origin.requests.get());
    }

    /** A flow to an IP address reaches it by the SNI's name: the server's certificate names that. */
    @Test
    void http3ToAnIpAddressGoesThereByItsSni() throws Exception {
        H3TestOrigin origin = new H3TestOrigin(originCa);
        closeables.add(origin);
        // The name does not resolve: the flow's address is the server's.
        proxy = forwardProxy().withServerResolver((host, port) -> {
            if (host.equals("127.0.0.1")) return new InetSocketAddress(TestSupport.LOOPBACK, port);
            throw new java.net.UnknownHostException(host);
        }).start();
        MasqueBridge bridge = flowTo("127.0.0.1", origin.port());
        try (H3TestClient inner = H3TestClient.connect(bridge.address(), HOST, proxyCa.getCertificate())) {
            assertEquals("hello over h3", inner.get("/hello").text());
        }
        assertEquals(List.of(HOST + " true null"), decisions);
    }

    @Test
    void anIgnoredHostIsRelayed() throws Exception {
        H3TestOrigin origin = new H3TestOrigin(originCa);
        closeables.add(origin);
        proxy = forwardProxy().withIgnoreHosts("^origin\\.test:").start();
        MasqueBridge bridge = flowTo(HOST, origin.port());
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
        MasqueBridge bridge = flowTo(HOST, origin.port());
        ClientConfig config = ClientConfig.builder(TlsConfig.builder()
                .alpnProtocols(QuicStreamHooksTest.ALPN)
                .serverName(HOST)
                .trustManager(H3TestClient.trusting(proxyCa.getCertificate()))
                .build()).build();
        try (QuicClient client = QuicClient.create(config);
                QuicConnection c = client.connect(bridge.address(), HOST, Duration.ofSeconds(10))) {
            QuicStream s = c.openBidirectionalStream();
            try (OutputStream out = s.getOutputStream()) {
                out.write("echo\ninside a flow".getBytes(StandardCharsets.UTF_8));
            }
            assertEquals("INSIDE A FLOW", new String(s.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
            c.close(0, "done");
        }
        eventually("quicStart", () -> !hooks.isEmpty());
        assertEquals("start " + HOST + " " + QuicStreamHooksTest.ALPN + " " + HOST + ":" + origin.port() + " masque=true",
                hooks.getFirst());
        assertEquals(List.of(HOST + " true ALPN [" + QuicStreamHooksTest.ALPN + "]"), decisions);
    }

    /**
     * The MASQUE client carries an intercepted connection over to a new CONNECT-UDP flow in the
     * middle of a transfer, and ends the old flow: the proxy's connection to the client follows it
     * there (validating the path through the new flow) and stays open; the inner client then moves
     * to a new local port as well.
     *
     * <p>The proxy's connection is on the new flow once a packet the client sent through it arrived
     * (and closes with the flow it is on): the old flow ends only after a stream echoed through the
     * new one, since the transfer may be over before the move, the client then having nothing more
     * to send.
     */
    @Test
    void anInterceptedConnectionFollowsItsClientToAnotherFlow() throws Exception {
        QuicEchoOrigin origin = new QuicEchoOrigin(originCa, QuicStreamHooksTest.ALPN);
        closeables.add(origin);
        proxy = forwardProxy().withQuicInterceptor((message, stream) -> message.data()).start();
        MasqueBridge bridge = flowTo(HOST, origin.port());
        Flow next = connectUdp(HOST, origin.port()); // ready before the transfer, to move in its middle
        ClientConfig config = ClientConfig.builder(TlsConfig.builder()
                .alpnProtocols(QuicStreamHooksTest.ALPN)
                .serverName(HOST)
                .trustManager(H3TestClient.trusting(proxyCa.getCertificate()))
                .build()).build();
        try (QuicClient client = QuicClient.create(config);
                QuicConnection c = client.connect(bridge.address(), HOST, Duration.ofSeconds(10))) {
            byte[] data = QuicMigrationProxyTest.data(11, 2 << 20);
            java.util.concurrent.atomic.AtomicLong received = new java.util.concurrent.atomic.AtomicLong();
            java.util.concurrent.CompletableFuture<byte[]> echoed = QuicMigrationProxyTest.echo(c, data, received);
            eventually("a quarter echoed", () -> received.get() > data.length / 4);
            H3TestClient.Tunnel old = bridge.moveTo(next.masque(), next.tunnel());
            assertArrayEquals(QuicMigrationProxyTest.sha256(data), echoed.get(60, TimeUnit.SECONDS));
            byte[] more = QuicMigrationProxyTest.data(12, 200_000);
            assertArrayEquals(QuicMigrationProxyTest.sha256(more),
                    QuicMigrationProxyTest.echo(c, more, new java.util.concurrent.atomic.AtomicLong()).get(30, TimeUnit.SECONDS));
            assertTrue(bridge.receivedThrough(next.tunnel()) > 0, "the proxy answers through the new flow");
            old.end(); // the flow the connection left ends: the connection stays
            assertArrayEquals(QuicMigrationProxyTest.sha256(more),
                    QuicMigrationProxyTest.echo(c, more, new java.util.concurrent.atomic.AtomicLong()).get(30, TimeUnit.SECONDS));
            c.migrate(new InetSocketAddress(TestSupport.LOOPBACK, 0));
            assertArrayEquals(QuicMigrationProxyTest.sha256(more),
                    QuicMigrationProxyTest.echo(c, more, new java.util.concurrent.atomic.AtomicLong()).get(30, TimeUnit.SECONDS));
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
        MasqueBridge bridge = flowTo("127.0.0.1", udp.port());
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
        assertNotNull(proxy);
    }
}
