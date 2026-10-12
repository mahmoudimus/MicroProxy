package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicServer;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.tls.CertifiedKey;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.Http3Frame;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * The transparent QUIC listener with the Java QUIC and HTTP/3 clients, as a firewall would send
 * them to it: each client connects straight to the listener, asking for {@code origin.test}, which
 * the proxy's resolver maps to loopback. Intercepted HTTP/3 reaches HTTP/3, HTTP/2 and HTTP/1.1
 * origins, with filters, trackers and the frame interceptor seeing it; ignored and declined
 * hosts, and QUIC that is not HTTP/3, are relayed to the real server, whose certificate the
 * client sees.
 */
@Timeout(value = 90, unit = TimeUnit.SECONDS)
class TransparentQuicTest {

    static final String HOST = "origin.test";

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    /** A decision the listener reported. */
    record Decision(String sni, boolean intercepted, String reason, boolean transparentQuic) {}

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<Decision> decisions = new CopyOnWriteArrayList<>();
    private final List<String> filtered = new CopyOnWriteArrayList<>();
    private HttpProxyServer proxy;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("Transparent QUIC Origin CA");
        proxyCa = CertificateAuthority.generate("Transparent QUIC Proxy CA");
    }

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    /** Resolves {@code *.test} to loopback, as DNS would resolve the real origin. */
    static final HostResolver TEST_HOSTS = (host, port) -> {
        if (host.endsWith(".test")) return new InetSocketAddress(TestSupport.LOOPBACK, port);
        throw new UnknownHostException(host);
    };

    /**
     * A transparent proxy with a transparent QUIC listener, sending SNI-routed traffic to {@code
     * port} of {@code *.test} (loopback), intercepting with a CA the clients trust, recording
     * decisions and the requests its filters see.
     */
    private HttpProxyServerBootstrap transparent(int port) {
        return MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(port)
                .withTransparentQuicPort(0)
                .withServerResolver(TEST_HOSTS)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .plusActivityTracker(new ActivityTracker() {
                    @Override
                    public void transparentQuicFlowDecided(FlowContext flow, ClientHello hello, boolean intercepted,
                            String reason) {
                        decisions.add(new Decision(hello.sni(), intercepted, reason, flow.isTransparentQuic()));
                    }
                })
                .withFiltersSource((request, flow) -> new HttpFiltersAdapter(request, flow) {
                    @Override
                    public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject object) {
                        if (object instanceof HttpRequest r) {
                            filtered.add(r.method() + " " + r.uri() + " " + r.protocolVersion() + " quic="
                                    + flow.isTransparentQuic() + " sni=" + (flow.getClientHello() == null ? "-"
                                    : flow.getClientHello().sni()));
                        }
                        return null;
                    }
                });
    }

    private HttpProxyServer start(HttpProxyServerBootstrap b) {
        proxy = b.start();
        assertNotNull(proxy.getTransparentQuicAddress());
        return proxy;
    }

    private InetSocketAddress quicAddress() {
        return new InetSocketAddress(TestSupport.LOOPBACK, proxy.getTransparentQuicAddress().getPort());
    }

    private H3TestOrigin h3Origin() throws IOException {
        H3TestOrigin origin = new H3TestOrigin(originCa);
        closeables.add(origin);
        return origin;
    }

    private static String issuer(H3TestClient client) {
        return ((X509Certificate) client.quic.peerCertificates().getFirst()).getIssuerX500Principal().getName();
    }

    private static String name(CertificateAuthority ca) {
        return ca.getCertificate().getSubjectX500Principal().getName();
    }

    @Test
    void interceptsHttp3AndSpeaksHttp3ToTheOrigin() throws Exception {
        H3TestOrigin origin = h3Origin();
        start(transparent(origin.port()).withHttp3Upstream(true));
        try (H3TestClient client = H3TestClient.connect(quicAddress(), HOST, proxyCa.getCertificate())) {
            assertEquals(name(proxyCa), issuer(client), "a certificate the proxy issued for the SNI");
            for (int i = 0; i < 3; i++) {
                H3TestClient.Response r = client.get("/hello");
                assertEquals(200, r.status());
                assertEquals("hello over h3", r.text());
                assertEquals("h3", r.header("x-origin-protocol"));
            }
            H3TestClient.Response echo = client.post("/echo", "ping".getBytes(StandardCharsets.US_ASCII));
            assertEquals(200, echo.status());
            assertEquals("ping", TestSupport.echoedBody(echo.text()));
        }
        assertEquals(4, origin.requests.get());
        assertEquals(1, origin.connections.get(), "one QUIC connection to the origin");
        assertEquals(List.of(new Decision(HOST, true, null, true)), decisions);
        int port = origin.port();
        assertEquals("CONNECT " + HOST + ":" + port + " HTTP/1.1 quic=true sni=" + HOST, filtered.getFirst());
        assertEquals("GET /hello HTTP/3.0 quic=true sni=" + HOST, filtered.get(1));
        assertTrue(origin.errors().isEmpty(), origin.errors().toString());
    }

    /**
     * An intercepted connection reaches only the server its SNI named: a request for another host
     * (a client coalescing connections) gets 421, which makes the client open one of its own.
     */
    @Test
    void requestsForAnotherHostAre421() throws Exception {
        H3TestOrigin origin = h3Origin();
        start(transparent(origin.port()).withHttp3Upstream(true));
        try (H3TestClient client = H3TestClient.connect(quicAddress(), HOST, proxyCa.getCertificate())) {
            List<io.github.mahmoudimus.http3.HeaderField> other = List.of(
                    new io.github.mahmoudimus.http3.HeaderField(":method", "GET"),
                    new io.github.mahmoudimus.http3.HeaderField(":scheme", "https"),
                    new io.github.mahmoudimus.http3.HeaderField(":authority", "other.test"),
                    new io.github.mahmoudimus.http3.HeaderField(":path", "/hello"));
            assertEquals(421, client.readResponse(client.send(other, true)).status());
            // The same host on any port is the intercepted server: the port is the one redirected.
            assertEquals("hello over h3", client.get("/hello").text());
        }
        assertEquals(1, origin.requests.get(), "the misdirected request went nowhere");
    }

    /**
     * A CONNECT on an intercepted HTTP/3 connection goes to the intercepted server, which the client
     * takes for its HTTPS proxy, as one on an intercepted HTTP/2 connection does: here a proxy whose
     * TLS listener is origin.test's, which opens the tunnel to a raw TCP echo server. The CONNECT
     * reaches it as an HTTP/2 stream when it offers h2 (the default), else in HTTP/1.1.
     */
    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void aConnectOnAnInterceptedConnectionGoesToTheInterceptedProxy(boolean corpHttp2) throws Exception {
        TestSupport.RawServer echo = TestSupport.rawServer(socket -> socket.getInputStream().transferTo(socket.getOutputStream()));
        closeables.add(echo);
        List<String> corpRequests = new CopyOnWriteArrayList<>();
        HttpProxyServer corp = MicroProxy.bootstrap().withPort(0)
                .withSslContextSource(() -> originCa.serverContext(HOST, "localhost"))
                .withHttp2(corpHttp2)
                .withFiltersSource((request, flow) -> {
                    corpRequests.add(request.method() + " " + request.uri() + " " + request.protocolVersion());
                    return null;
                })
                .start();
        closeables.add(corp::abort);
        start(transparent(corp.getListenAddress().getPort()));
        try (H3TestClient client = H3TestClient.connect(quicAddress(), HOST, proxyCa.getCertificate())) {
            H3TestClient.Tunnel tunnel = client.open(H3TestClient.connect("127.0.0.1:" + echo.port()));
            assertEquals(200, tunnel.status);
            tunnel.out().write("through the corporate proxy".getBytes(StandardCharsets.UTF_8));
            tunnel.end();
            assertEquals("through the corporate proxy", tunnel.text());
        }
        assertEquals(List.of("CONNECT 127.0.0.1:" + echo.port() + (corpHttp2 ? " HTTP/2.0" : " HTTP/1.1")),
                corpRequests);
        assertTrue(filtered.contains("CONNECT 127.0.0.1:" + echo.port() + " HTTP/3.0 quic=true sni=" + HOST), filtered.toString());
    }

    /** With Retry, an intercepted client proves its address first; the proxy decides on it once. */
    @Test
    void interceptsAfterARetry() throws Exception {
        H3TestOrigin origin = h3Origin();
        start(transparent(origin.port()).withHttp3Upstream(true)
                .withHttp3Options(Http3Options.builder().retry(true).build()));
        try (H3TestClient client = H3TestClient.connect(quicAddress(), HOST, proxyCa.getCertificate())) {
            assertEquals(name(proxyCa), issuer(client));
            assertEquals("hello over h3", client.get("/hello").text());
        }
        assertEquals(List.of(new Decision(HOST, true, null, true)), decisions);
        assertEquals(1, filtered.stream().filter(f -> f.startsWith("CONNECT")).count());
    }

    @Test
    void interceptsHttp3ToAnHttp1OriginOverTcp() throws Exception {
        List<String> received = new CopyOnWriteArrayList<>();
        HttpsServer tcp = TestSupport.httpsOrigin(originCa.serverContext(HOST, "localhost"), exchange -> {
            received.add(exchange.getRequestMethod() + " " + exchange.getRequestURI() + " " + exchange.getProtocol());
            TestSupport.echo().handle(exchange);
        });
        closeables.add(() -> tcp.stop(0));
        // HTTP/3 upstream is on, but nothing answers QUIC on the origin's port: TCP it is.
        start(transparent(tcp.getAddress().getPort()).withHttp3Upstream(true));
        try (H3TestClient client = H3TestClient.connect(quicAddress(), HOST, proxyCa.getCertificate())) {
            H3TestClient.Response r = client.post("/over-tcp", "body".getBytes(StandardCharsets.US_ASCII));
            assertEquals(200, r.status());
            assertEquals("body", TestSupport.echoedBody(r.text()));
            assertEquals(List.of(HOST + ":" + client.quic.remoteAddress().getPort()),
                    TestSupport.echoedHeader(r.text(), "host"));
            assertEquals(200, client.get("/again").status());
        }
        assertEquals(List.of("POST /over-tcp HTTP/1.1", "GET /again HTTP/1.1"), received);
    }

    @Test
    void interceptsHttp3ToAnHttp2Origin() throws Exception {
        H2TestOrigin origin = new H2TestOrigin(originCa.serverContext(HOST, "localhost"), s -> {
            byte[] out = ("h2 says " + s.header(":path")).getBytes(StandardCharsets.UTF_8);
            s.respond(200, false, "x-origin-protocol", "h2");
            s.data(out, true);
        });
        closeables.add(origin);
        start(transparent(origin.port()).withHttp2Upstream(true));
        try (H3TestClient client = H3TestClient.connect(quicAddress(), HOST, proxyCa.getCertificate())) {
            H3TestClient.Response r = client.get("/two");
            assertEquals(200, r.status());
            assertEquals("h2 says /two", r.text());
            assertEquals("h2", r.header("x-origin-protocol"));
        }
    }

    @Test
    void theFrameInterceptorSeesTheInterceptedHttp3() throws Exception {
        record Seen(FrameDirection direction, String path, boolean transparentQuic) {}
        List<Seen> seen = new CopyOnWriteArrayList<>();
        H3TestOrigin origin = h3Origin();
        start(transparent(origin.port()).withHttp3Upstream(true).withFrameInterceptor((frame, direction, ctx) -> {
            if (frame instanceof Http3Frame.Headers h && h.get(":path") != null) {
                seen.add(new Seen(direction, h.get(":path"), ctx.flowContext() != null && ctx.flowContext().isTransparentQuic()));
                if (direction == FrameDirection.FROM_CLIENT) return h.withHeader("x-seen", "from-client");
            }
            return frame;
        }));
        try (H3TestClient client = H3TestClient.connect(quicAddress(), HOST, proxyCa.getCertificate())) {
            H3TestClient.Response r = client.get("/echo");
            assertEquals(200, r.status());
            assertEquals(List.of("from-client"), TestSupport.echoedHeader(r.text(), "x-seen"));
        }
        assertTrue(seen.contains(new Seen(FrameDirection.FROM_CLIENT, "/echo", true)), seen.toString());
        assertTrue(seen.contains(new Seen(FrameDirection.TO_SERVER, "/echo", true)), seen.toString());
    }

    @Test
    void ignoredHostsAreRelayedToTheRealServer() throws Exception {
        H3TestOrigin origin = h3Origin();
        start(transparent(origin.port()).withIgnoreHosts("^origin\\.test:"));
        // The client trusts only the origin's CA: its handshake completes with the real server.
        try (H3TestClient client = H3TestClient.connect(quicAddress(), HOST, originCa.getCertificate())) {
            assertEquals(name(originCa), issuer(client));
            for (int i = 0; i < 3; i++) assertEquals("hello over h3", client.get("/hello").text());
            byte[] big = new byte[300_000];
            new java.util.Random(3).nextBytes(big);
            H3TestClient.Response echo = client.post("/echo", big);
            assertEquals(200, echo.status());
        }
        assertEquals(1, decisions.size());
        Decision d = decisions.getFirst();
        assertFalse(d.intercepted());
        assertTrue(d.reason().startsWith("an ignored host"), d.reason());
        assertEquals(4, origin.requests.get());
        // The filters saw the made-up CONNECT, and nothing of the relayed requests.
        assertEquals(List.of("CONNECT " + HOST + ":" + origin.port() + " HTTP/1.1 quic=true sni=" + HOST), filtered);
    }

    @Test
    void aRelayedFlowIsOneRecordWhenItEnds() throws Exception {
        H3TestOrigin origin = h3Origin();
        RecordedFlows flows = new RecordedFlows();
        start(transparent(origin.port()).withIgnoreHosts("^origin\\.test:").plusActivityTracker(flows)
                // Long enough that no pause of a loaded machine ends the relay before the exchange is over.
                .withHttp3Options(Http3Options.builder().transparentRelayIdleTimeout(java.time.Duration.ofSeconds(3)).build()));
        try (H3TestClient client = H3TestClient.connect(quicAddress(), HOST, originCa.getCertificate())) {
            assertEquals("hello over h3", client.get("/hello").text());
        }
        // The record comes once the relay has been idle for its timeout, and the sweep after.
        FlowRecord r = flows.await(FlowRecord.Kind.QUIC_RELAY, java.time.Duration.ofSeconds(30));
        assertTrue(r.bytesReceived() > 1000 && r.bytesSent() > 1000, r.toString());
        assertEquals(r.bytesReceived(), r.upstreamBytesSent());
        assertEquals(r.bytesSent(), r.upstreamBytesReceived());
        assertEquals("quic_relayed", r.responseCodeDetails());
        assertEquals(origin.port(), r.upstreamAddress().getPort());
        assertTrue(r.context().isTransparentQuic());
        assertEquals("quic_relay " + HOST + " q", org.microproxy.extras.AccessLogFormat
                .envoy("%MP_FLOW% %REQUESTED_SERVER_NAME% %TLS_JA4_FINGERPRINT:1%").format(r));
    }

    @Test
    void hostsOutsideTheAllowRulesAreRelayed() throws Exception {
        H3TestOrigin origin = h3Origin();
        start(transparent(origin.port()).withAllowHosts("^allowed\\.test:"));
        try (H3TestClient client = H3TestClient.connect(quicAddress(), HOST, originCa.getCertificate())) {
            assertEquals("hello over h3", client.get("/hello").text());
        }
        assertFalse(decisions.getFirst().intercepted());
    }

    @Test
    void aFilterDecliningTheClientHelloRelaysIt() throws Exception {
        H3TestOrigin origin = h3Origin();
        List<String> hellos = new CopyOnWriteArrayList<>();
        start(transparent(origin.port()).withFiltersSource((request, flow) -> HttpFilters.builder()
                .allowMitmFor(hello -> {
                    hellos.add(hello.sni() + " " + hello.alpnProtocols());
                    return false;
                })
                .build()));
        try (H3TestClient client = H3TestClient.connect(quicAddress(), HOST, originCa.getCertificate())) {
            assertEquals(name(originCa), issuer(client));
            assertEquals("hello over h3", client.get("/hello").text());
        }
        assertEquals(List.of(HOST + " [h3]"), hellos);
        assertEquals("a filter declined", decisions.getFirst().reason());
    }

    @Test
    void withoutAMitmManagerEveryFlowIsRelayed() throws Exception {
        H3TestOrigin origin = h3Origin();
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(origin.port())
                .withTransparentQuicPort(0)
                .withServerResolver(TEST_HOSTS)
                .start();
        try (H3TestClient client = H3TestClient.connect(quicAddress(), HOST, originCa.getCertificate())) {
            assertEquals("hello over h3", client.get("/hello").text());
        }
    }

    /** QUIC that is not HTTP/3 (DNS over QUIC, say) is relayed untouched, as TLS without HTTP is over TCP. */
    @Test
    void otherQuicProtocolsAreRelayed() throws Exception {
        try (EchoQuic echo = new EchoQuic("doq")) {
            start(transparent(echo.port()));
            ClientConfig config = ClientConfig.builder(TlsConfig.builder()
                    .alpnProtocols("doq")
                    .serverName(HOST)
                    .trustManager(H3TestClient.trusting(originCa.getCertificate()))
                    .build()).build();
            try (QuicClient client = QuicClient.create(config);
                    QuicConnection c = client.connect(quicAddress(), HOST, Duration.ofSeconds(10))) {
                assertEquals("doq", c.alpn());
                for (int i = 0; i < 3; i++) {
                    QuicStream s = c.openBidirectionalStream();
                    byte[] data = ("query " + i).getBytes(StandardCharsets.US_ASCII);
                    try (OutputStream out = s.getOutputStream()) {
                        out.write(data);
                    }
                    assertArrayEquals(data, s.getInputStream().readAllBytes());
                }
            }
        }
        assertFalse(decisions.getFirst().intercepted());
        assertTrue(decisions.getFirst().reason().contains("no HTTP/3"), decisions.getFirst().reason());
    }

    @Test
    void anUnresolvableSniIsDropped() throws Exception {
        H3TestOrigin origin = h3Origin();
        // Ignored, so relayed: but the name does not resolve, so there is nowhere to relay it to.
        start(transparent(origin.port()).withIgnoreHosts("nowhere"));
        assertThrows(IOException.class, () -> connectQuickly("nowhere.invalid"));
        assertEquals(0, origin.connections.get());
        assertFalse(decisions.getFirst().intercepted());
    }

    /** Connects with a short handshake timeout, for clients that are expected to get nowhere. */
    private void connectQuickly(String sni) throws IOException {
        ClientConfig config = ClientConfig.builder(TlsConfig.builder()
                .alpnProtocols("h3")
                .serverName(sni)
                .trustAllCertificates(true)
                .build()).build();
        try (QuicClient client = QuicClient.create(config)) {
            client.connect(quicAddress(), sni, Duration.ofSeconds(2)).close();
        }
    }

    @Test
    void transparentQuicNeedsTransparentMode() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> MicroProxy.bootstrap().withPort(0).withTransparentQuicPort(0).start());
        assertTrue(e.getMessage().contains("transparent mode"), e.getMessage());
    }

    @Test
    void noListenerWithoutThePort() {
        proxy = MicroProxy.bootstrap().withPort(0).withTransparent(true).start();
        assertNull(proxy.getTransparentQuicAddress());
    }

    /** A QUIC server for {@code origin.test} speaking {@code alpn}, echoing each stream. */
    static final class EchoQuic implements AutoCloseable {
        final QuicServer server;

        EchoQuic(String alpn) throws Exception {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keys = g.generateKeyPair();
            X509Certificate leaf = originCa.issue(keys.getPublic(), List.of(HOST));
            ServerConfig config = ServerConfig.builder(TlsConfig.builder()
                    .certificate(new CertifiedKey(List.of(leaf, originCa.getCertificate()), keys.getPrivate()))
                    .alpnProtocols(alpn)
                    .build()).build();
            server = QuicServer.bind(new InetSocketAddress(TestSupport.LOOPBACK, 0), config);
            Thread.ofVirtual().start(() -> {
                while (true) {
                    QuicConnection c;
                    try {
                        c = server.accept();
                    } catch (IOException e) {
                        return;
                    }
                    Thread.ofVirtual().start(() -> {
                        try {
                            while (true) {
                                QuicStream s = c.acceptStream();
                                Thread.ofVirtual().start(() -> {
                                    try (InputStream in = s.getInputStream(); OutputStream out = s.getOutputStream()) {
                                        in.transferTo(out);
                                    } catch (IOException e) {
                                        // reset
                                    }
                                });
                            }
                        } catch (IOException e) {
                            // closed
                        }
                    });
                }
            });
        }

        int port() {
            return server.localAddress().getPort();
        }

        @Override
        public void close() {
            server.close();
        }
    }
}
