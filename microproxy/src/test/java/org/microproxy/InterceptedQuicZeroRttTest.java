package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.connection.SessionCache;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Session resumption and 0-RTT on the QUIC server that intercepts: the transparent QUIC listener
 * serves HTTP/3 with the configuration of the proxy's HTTP/3 listener, so it issues tickets sealed
 * with the proxy's key, and with {@code --http3-0rtt} takes early data, which reaches the origin
 * marked {@code Early-Data: 1}, though the listener hands the client's first datagrams to its QUIC
 * server from the thread that decided to intercept.
 */
@Timeout(value = 90, unit = TimeUnit.SECONDS)
class InterceptedQuicZeroRttTest {

    static final String HOST = "origin.test";
    private static final long DELAY_MILLIS = 150;

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
}
