package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.microproxy.MetricsAssertions.awaitValue;
import static org.microproxy.MetricsAssertions.value;

import io.github.mahmoudimus.http3.HeaderField;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.udp.UdpContext;
import org.microproxy.udp.UdpInterceptor;
import org.microproxy.udp.UdpMessage;

/**
 * The CONNECT-UDP stats, {@code masque.*}: flows open and accepted, their datagrams and capsules
 * both ways and their bytes (counted when they end), refusals by reason; and the UDP hooks',
 * {@code hooks.udp.*}.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class MasqueStatsTest {

    private static final SelfSignedSslContextSource TLS = new SelfSignedSslContextSource();

    private HttpProxyServer proxy;
    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : closeables) c.close();
        if (proxy != null) proxy.abort();
    }

    private HttpProxyServerBootstrap forwardProxy() {
        return MicroProxy.bootstrap().withPort(0).withSslContextSource(TLS).withHttp3(true).withMetrics(true);
    }

    private H3TestClient client(boolean datagrams) throws IOException {
        H3TestClient.Options options = new H3TestClient.Options();
        options.datagrams = datagrams;
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        H3TestClient c = H3TestClient.connect(address, "localhost", TLS.getCertificate(), options);
        closeables.add(c);
        return c;
    }

    private H3TestClient.Tunnel open(H3TestClient client, int port) throws IOException {
        List<HeaderField> extra = new ArrayList<>(List.of(new HeaderField("capsule-protocol", "?1")));
        return client.open(H3TestClient.extendedConnect("connect-udp", "https", "localhost:" + proxy.getListenAddress().getPort(),
                "/.well-known/masque/udp/127.0.0.1/" + port + "/", extra.toArray(HeaderField[]::new)));
    }

    private Http3MasqueTest.UdpEcho echo() throws IOException {
        Http3MasqueTest.UdpEcho e = new Http3MasqueTest.UdpEcho();
        closeables.add(e);
        return e;
    }

    @Test
    void datagramsAndCapsulesAreCountedWhenTheFlowEnds() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        UdpInterceptor dropping = new UdpInterceptor() {
            @Override
            public byte[] udpMessage(UdpMessage message, UdpContext context) {
                String text = new String(message.data(), StandardCharsets.UTF_8);
                if (text.equals("drop")) return null;
                return text.equals("rewrite") ? "rewritten".getBytes(StandardCharsets.UTF_8) : message.data();
            }
        };
        proxy = forwardProxy().withUdpInterceptor(dropping).start();
        StatsRegistry r = proxy.getStats();

        // In QUIC DATAGRAM frames
        H3TestClient.Tunnel flow = open(client(true), udp.port());
        assertEquals(200, flow.status);
        for (int i = 0; i < 3; i++) {
            flow.sendDatagram(("ping " + i).getBytes(StandardCharsets.UTF_8));
            byte[] back = flow.receiveDatagram(Duration.ofSeconds(10));
            assertNotNull(back);
        }
        flow.sendDatagram("drop".getBytes(StandardCharsets.UTF_8));
        flow.sendDatagram("rewrite".getBytes(StandardCharsets.UTF_8));
        assertEquals("rewritten", new String(H3TestClient.udpPayload(flow.receiveDatagram(Duration.ofSeconds(10))),
                StandardCharsets.UTF_8));
        assertEquals(1, value(r, "masque.udp_flows_active"));
        flow.end();
        assertEquals(-1, flow.in().read());
        awaitValue(r, "masque.udp_flows_active", 0);
        assertEquals(1, value(r, "masque.udp_flows_total"));
        assertEquals(5, value(r, "masque.datagrams_rx"));
        assertEquals(0, value(r, "masque.capsules_rx"));
        // Back: three echoes and the rewritten one (the dropped one went nowhere)
        assertEquals(4, value(r, "masque.datagrams_tx"));
        assertEquals(0, value(r, "masque.capsules_tx"));
        assertEquals(6 * 3 + 4 + 7, value(r, "masque.rx_bytes_total"));
        assertEquals(6 * 3 + 9, value(r, "masque.tx_bytes_total"));
        assertEquals(0, value(r, "masque.datagrams_dropped"));
        // The hook saw each datagram both ways: dropped one, rewrote one
        assertEquals(1, value(r, "hooks.udp.drops"));
        assertEquals(1, value(r, "hooks.udp.rewrites"));
        assertEquals(9, value(r, "hooks.udp.invocations"));
        assertEquals(9, value(r, "hooks.udp.latency_us"));

        // In DATAGRAM capsules, for a client without QUIC datagrams
        H3TestClient.Tunnel capsules = open(client(false), udp.port());
        assertEquals(200, capsules.status);
        for (int i = 0; i < 2; i++) {
            capsules.sendDatagramCapsule(("capsule " + i).getBytes(StandardCharsets.UTF_8));
            assertNotNull(capsules.readCapsule());
        }
        capsules.end();
        awaitValue(r, "masque.udp_flows_total", 2);
        awaitValue(r, "masque.capsules_rx", 2);
        assertEquals(2, value(r, "masque.capsules_tx"));
        assertEquals(7, value(r, "masque.datagrams_rx"));
        assertEquals(6, value(r, "masque.datagrams_tx"));
        // The QUIC connections of the listener, counted as they close
        for (AutoCloseable c : closeables) c.close();
        awaitValue(r, "quic.downstream.connections_active", 0);
        assertEquals(2, value(r, "quic.downstream.connections_total"));
    }

    @Test
    void refusedFlowsAreCountedByReason() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = forwardProxy().withHttp3Options(Http3Options.builder().connectUdpMaxFlows(1, 1).build()).start();
        StatsRegistry r = proxy.getStats();
        H3TestClient client = client(true);
        H3TestClient.Tunnel first = open(client, udp.port());
        assertEquals(200, first.status);
        H3TestClient.Tunnel second = open(client, udp.port());
        assertEquals(503, second.status);
        assertEquals(1, value(r, "masque.flow_rejected.limit"));
        assertEquals(0, value(r, "masque.flow_rejected.policy"));
        assertEquals(1, value(r, "masque.udp_flows_active"));
        first.end();
        awaitValue(r, "masque.udp_flows_active", 0);
    }
}
