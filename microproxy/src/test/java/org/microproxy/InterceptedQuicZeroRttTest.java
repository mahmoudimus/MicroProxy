package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.SessionCache;
import io.github.mahmoudimus.quic.tls.ClientSessionStore;
import io.github.mahmoudimus.quic.tls.SessionTicket;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.quic.QuicInterceptor;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * Session resumption and 0-RTT on the QUIC servers that intercept: the transparent QUIC listener
 * and the server without a socket that intercepts HTTP/3 inside CONNECT-UDP flows serve HTTP/3
 * with the configuration of the proxy's HTTP/3 listener, so they issue tickets sealed with the
 * proxy's key, and with {@code --http3-0rtt} take early data, which reaches the origin marked
 * {@code Early-Data: 1}. A ticket's early data is accepted once across all of the proxy's QUIC
 * servers, not once by each. QUIC intercepted stream by stream gets no tickets: its streams are
 * opaque, so the proxy could not tell what is safe to replay.
 */
@Timeout(value = 90, unit = TimeUnit.SECONDS)
class InterceptedQuicZeroRttTest {

    static final String HOST = "origin.test";
    private static final long DELAY_MILLIS = 150;
    private static final SelfSignedSslContextSource TLS = new SelfSignedSslContextSource();

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private HttpProxyServer proxy;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("Intercepted 0-RTT Origin CA");
        proxyCa = CertificateAuthority.generate("Intercepted 0-RTT Proxy CA");
    }

    @AfterEach
    void tearDown() throws Exception {
        for (int i = closeables.size() - 1; i >= 0; i--) closeables.get(i).close();
        if (proxy != null) proxy.abort();
    }

    private <T extends AutoCloseable> T closing(T c) {
        closeables.add(c);
        return c;
    }

    /** A relay in front of {@code port} that delays every datagram, so that 0-RTT data surely goes before the handshake completes. */
    private InetSocketAddress delayed(InetSocketAddress target) throws IOException {
        return closing(new UdpDelayRelay(0, target, DELAY_MILLIS)).address();
    }

    private static H3TestClient.Options options(SessionCache sessions, boolean earlyData) {
        H3TestClient.Options options = new H3TestClient.Options();
        options.sessions = sessions;
        options.earlyData = earlyData;
        return options;
    }

    @Test
    void theTransparentListenerResumesAndTakesEarlyData() throws Exception {
        H3TestOrigin origin = closing(new H3TestOrigin(originCa));
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(origin.port())
                .withTransparentQuicPort(0)
                .withServerResolver(TransparentQuicTest.TEST_HOSTS)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp3Upstream(true)
                .withHttp3Options(Http3Options.builder().zeroRtt(true).build())
                .start();
        InetSocketAddress quic = delayed(new InetSocketAddress(TestSupport.LOOPBACK,
                proxy.getTransparentQuicAddress().getPort()));
        SessionCache sessions = SessionCache.memory();

        try (H3TestClient first = H3TestClient.connect(quic, HOST, proxyCa.getCertificate(), options(sessions, false))) {
            assertEquals(200, first.get("/hello").status());
            assertFalse(first.quic.isResumed());
        }
        try (H3TestClient early = H3TestClient.connect(quic, HOST, proxyCa.getCertificate(), options(sessions, true))) {
            assertTrue(early.quic.isZeroRtt(), "connected without waiting for the handshake");
            H3TestClient.Response r = early.get("/echo");
            assertEquals(200, r.status());
            assertEquals("h3", r.header("x-origin-protocol"));
            assertEquals(List.of("1"), TestSupport.echoedHeader(r.text(), "early-data"),
                    "the early request reached the origin marked");
            assertTrue(early.quic.earlyDataAccepted());
            assertTrue(early.quic.isResumed(), "the transparent listener resumed its own ticket");
        }
        try (H3TestClient unsafe = H3TestClient.connect(quic, HOST, proxyCa.getCertificate(), options(sessions, true))) {
            H3TestClient.Response r = unsafe.post("/echo", "not safe to replay".getBytes(StandardCharsets.UTF_8));
            assertEquals(425, r.status(), "a POST in 0-RTT data is too early");
        }
        assertTrue(origin.errors().isEmpty(), origin.errors().toString());
    }

    @Test
    void http3InsideConnectUdpFlowsResumesAndTakesEarlyDataOnceInAll() throws Exception {
        H3TestOrigin origin = closing(new H3TestOrigin(originCa));
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withSslContextSource(TLS)
                .withHttp3(true)
                .withHttp3Upstream(true)
                .withServerResolver(TransparentQuicTest.TEST_HOSTS)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp3Options(Http3Options.builder()
                        .zeroRtt(true)
                        .connectUdpInterceptQuic(true)
                        .connectUdpQuicPorts()
                        .build())
                .start();
        InetSocketAddress listener = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        Replaying tickets = new Replaying(SessionCache.memory().tickets());
        SessionCache sessions = new SessionCache(tickets, SessionCache.memory().tokens());

        try (H3TestClient first = H3TestClient.connect(delayed(flowTo(origin.port()).address()), HOST,
                proxyCa.getCertificate(), options(sessions, false))) {
            assertEquals(200, first.get("/hello").status());
            assertFalse(first.quic.isResumed());
        }

        tickets.pin = true; // from now on every connection presents the same ticket, as a replay would
        try (H3TestClient early = H3TestClient.connect(delayed(flowTo(origin.port()).address()), HOST,
                proxyCa.getCertificate(), options(sessions, true))) {
            assertTrue(early.quic.isZeroRtt(), "connected without waiting for the handshake");
            H3TestClient.Response r = early.get("/echo");
            assertEquals(200, r.status());
            assertEquals(List.of("1"), TestSupport.echoedHeader(r.text(), "early-data"),
                    "the early request reached the origin marked");
            assertTrue(early.quic.earlyDataAccepted());
            assertTrue(early.quic.isResumed(), "a flow's connection resumed another flow's ticket");
        }

        // The same ticket again, inside a flow and on the HTTP/3 listener: resumed, but no early data
        try (H3TestClient again = H3TestClient.connect(flowTo(origin.port()).address(), HOST, proxyCa.getCertificate(),
                options(sessions, true))) {
            assertTrue(again.quic.awaitHandshake(Duration.ofSeconds(10)));
            assertTrue(again.quic.isResumed());
            assertFalse(again.quic.earlyDataAccepted(), "a ticket's early data is accepted once");
        }
        try (H3TestClient elsewhere = H3TestClient.connect(listener, HOST, proxyCa.getCertificate(),
                options(sessions, true))) {
            assertTrue(elsewhere.quic.awaitHandshake(Duration.ofSeconds(10)));
            assertTrue(elsewhere.quic.isResumed(), "the HTTP/3 listener takes the flows' tickets");
            assertFalse(elsewhere.quic.earlyDataAccepted(), "and knows their early data was accepted");
        }
        assertTrue(origin.errors().isEmpty(), origin.errors().toString());
    }

    @Test
    void quicInterceptedStreamByStreamGetsNoTickets() throws Exception {
        QuicEchoOrigin origin = closing(new QuicEchoOrigin(originCa, "microproxy-echo"));
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(origin.port())
                .withTransparentQuicPort(0)
                .withServerResolver(TransparentQuicTest.TEST_HOSTS)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp3Options(Http3Options.builder().zeroRtt(true).build())
                .withQuicInterceptor((QuicInterceptor) (message, stream) -> message.data())
                .start();
        InetSocketAddress quic = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getTransparentQuicAddress().getPort());
        SessionCache sessions = SessionCache.memory();
        ClientConfig config = ClientConfig.builder(TlsConfig.builder()
                        .alpnProtocols("microproxy-echo")
                        .serverName(HOST)
                        .trustManager(H3TestClient.trusting(proxyCa.getCertificate()))
                        .earlyData(true)
                        .build())
                .sessionCache(sessions)
                .build();
        QuicClient client = closing(QuicClient.create(config));
        for (int i = 0; i < 2; i++) {
            QuicConnection c = client.connect(quic, HOST, Duration.ofSeconds(10));
            try {
                assertEquals("hello " + i, echo(c, "hello " + i));
                assertFalse(c.isResumed(), "no ticket to resume with");
                assertFalse(c.isZeroRtt());
            } finally {
                c.close(0, "");
            }
        }
    }

    /** Sends {@code text} on a new stream with the echo command, finishing it, and reads the answer. */
    private static String echo(QuicConnection c, String text) throws IOException {
        QuicStream s = c.openBidirectionalStream();
        try (OutputStream out = s.getOutputStream()) {
            out.write(("echo\n" + text).getBytes(StandardCharsets.UTF_8));
        }
        return new String(s.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    /** A MASQUE client's CONNECT-UDP flow to {@code HOST:port}, bridged to a local UDP socket. */
    private MasqueBridge flowTo(int port) throws IOException {
        H3TestClient masque = closing(H3TestClient.connect(
                new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort()), "localhost",
                TLS.getCertificate()));
        List<HeaderField> request = H3TestClient.extendedConnect("connect-udp", "https",
                "localhost:" + proxy.getListenAddress().getPort(), "/.well-known/masque/udp/" + HOST + "/" + port + "/",
                new HeaderField("capsule-protocol", "?1"));
        H3TestClient.Tunnel tunnel = masque.open(request);
        assertEquals(200, tunnel.status);
        return closing(new MasqueBridge(masque, tunnel));
    }

    /**
     * A client's tickets, which, once pinned, hand the next ticket taken to every later connection
     * too: the ticket of a captured first flight, sent again.
     */
    private static final class Replaying implements ClientSessionStore {
        private final ClientSessionStore tickets;
        volatile boolean pin;
        private volatile SessionTicket pinned;

        Replaying(ClientSessionStore tickets) {
            this.tickets = tickets;
        }

        @Override
        public void put(String key, SessionTicket ticket) {
            tickets.put(key, ticket);
        }

        @Override
        public SessionTicket take(String key) {
            SessionTicket p = pinned;
            if (p != null) return p;
            SessionTicket t = tickets.take(key);
            if (pin) pinned = t;
            return t;
        }
    }
}
