package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.MetricsAssertions.awaitAtLeast;
import static org.microproxy.MetricsAssertions.awaitValue;
import static org.microproxy.MetricsAssertions.value;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * The transparent QUIC listener's stats: {@code quic_transparent.*} for its flows (intercepted,
 * relayed, dropped by reason, relayed bytes), {@code quic.transparent.*} for the connections it
 * intercepts, and {@code quic.upstream.*} for the proxy's connections to HTTP/3 servers.
 */
@Timeout(value = 90, unit = TimeUnit.SECONDS)
class TransparentQuicStatsTest {

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    private H3TestOrigin origin;
    private HttpProxyServer proxy;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("Transparent QUIC Stats Origin CA");
        proxyCa = CertificateAuthority.generate("Transparent QUIC Stats Proxy CA");
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.close();
    }

    private HttpProxyServer start(HttpProxyServerBootstrap b) throws Exception {
        origin = new H3TestOrigin(originCa);
        proxy = b.withPort(0)
                .withMetrics(true)
                .withTransparent(true)
                .withTransparentTlsPort(origin.port())
                .withTransparentQuicPort(0)
                .withServerResolver(TransparentQuicTest.TEST_HOSTS)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp3Options(Http3Options.builder().transparentRelayIdleTimeout(Duration.ofMillis(300)).build())
                .start();
        return proxy;
    }

    private InetSocketAddress quicAddress() {
        return new InetSocketAddress(TestSupport.LOOPBACK, proxy.getTransparentQuicAddress().getPort());
    }

    @Test
    void anInterceptedFlowCountsBothQuicConnections() throws Exception {
        start(MicroProxy.bootstrap().withHttp3Upstream(true));
        StatsRegistry r = proxy.getStats();
        try (H3TestClient client = H3TestClient.connect(quicAddress(), TransparentQuicTest.HOST, proxyCa.getCertificate())) {
            assertEquals(200, client.get("/hello").status());
            assertEquals(1, value(r, "quic_transparent.flows_active"));
            assertEquals(0, value(r, "quic_transparent.pending_initials"));
        }
        assertEquals(1, value(r, "quic_transparent.intercepted_total"));
        assertEquals(0, value(r, "quic_transparent.relayed_total"));
        awaitValue(r, "quic.transparent.connections_active", 0);
        assertEquals(1, value(r, "quic.transparent.connections_total"));
        assertTrue(value(r, "quic.transparent.bytes_received_total") > 0);
        // The proxy's own connection to the HTTP/3 server, as a client
        assertEquals(1, value(r, "quic.upstream.connections_total"));
        assertEquals(1, value(r, "quic.upstream.handshake_ms"));
        assertEquals(1, value(r, "cluster.direct.upstream_cx_http3_total"));
        proxy.abort();
        awaitValue(r, "quic.upstream.connections_active", 0);
        assertTrue(value(r, "quic.upstream.packets_sent_total") > 0);
        // QUIC counts its bytes as its connections close
        assertTrue(value(r, "cluster.direct.upstream_cx_rx_bytes_total") > 0);
        assertTrue(value(r, "cluster.direct.upstream_cx_tx_bytes_total") > 0);
        awaitValue(r, "http3.upstream.streams_active", 0);
    }

    @Test
    void aRelayedFlowCountsItsBytesWhenItEnds() throws Exception {
        start(MicroProxy.bootstrap().withIgnoreHosts("^origin\\.test:"));
        StatsRegistry r = proxy.getStats();
        try (H3TestClient client = H3TestClient.connect(quicAddress(), TransparentQuicTest.HOST, originCa.getCertificate())) {
            assertEquals(200, client.get("/hello").status());
        }
        assertEquals(1, value(r, "quic_transparent.relayed_total"));
        assertEquals(0, value(r, "quic_transparent.intercepted_total"));
        // The relay idles out, and its bytes are counted
        awaitValue(r, "quic_transparent.flows_active", 0);
        assertTrue(value(r, "quic_transparent.relay_rx_bytes_total") > 1000);
        assertTrue(value(r, "quic_transparent.relay_tx_bytes_total") > 1000);
        assertEquals(0, value(r, "quic.transparent.connections_total"), "nothing intercepted");
    }

    @Test
    void initialsTooSmallAreDroppedAsMalformed() throws Exception {
        start(MicroProxy.bootstrap());
        StatsRegistry r = proxy.getStats();
        // A long header Initial (version 1) in a datagram under the 1200 bytes a client's first must have
        byte[] initial = new byte[300];
        initial[0] = (byte) 0xc0;
        initial[4] = 1;
        initial[5] = 8; // an 8-byte Destination Connection ID (zeros), no Source Connection ID, no token
        initial[16] = 0x40; // the packet's length, a two-byte varint: 200
        initial[17] = (byte) 200;
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.send(new DatagramPacket(initial, initial.length, quicAddress()));
        }
        awaitAtLeast(r, "quic_transparent.dropped_initials.malformed", 1);
        assertEquals(0, value(r, "quic_transparent.flows_active"));
    }
}
