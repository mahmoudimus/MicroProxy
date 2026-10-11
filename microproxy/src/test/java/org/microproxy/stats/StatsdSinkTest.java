package org.microproxy.stats;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** The statsd sink, to a UDP socket of the test's. */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class StatsdSinkTest {

    private DatagramSocket statsd;

    @BeforeEach
    void listen() throws Exception {
        statsd = new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        statsd.setSoTimeout(5_000);
    }

    @AfterEach
    void close() {
        statsd.close();
    }

    private String target() {
        return "127.0.0.1:" + statsd.getLocalPort();
    }

    /** The lines of the next datagram. */
    private List<String> receive() throws Exception {
        DatagramPacket packet = new DatagramPacket(new byte[65536], 65536);
        statsd.receive(packet);
        return Arrays.asList(new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8).split("\n"));
    }

    /** Every line sent until the socket stays quiet for a moment. */
    private List<String> receiveAll() throws Exception {
        List<String> lines = new ArrayList<>();
        statsd.setSoTimeout(300);
        try {
            while (true) lines.addAll(receive());
        } catch (SocketTimeoutException e) {
            return lines;
        } finally {
            statsd.setSoTimeout(5_000);
        }
    }

    @Test
    void countersAreSentAsIncreasesGaugesAsValuesHistogramsAsSampledMeans() throws Exception {
        StatsRegistry r = StatsRegistry.create();
        Counter rq = r.counter("cluster.direct.upstream_rq_total");
        Gauge active = r.gauge("cluster.direct.upstream_rq_active");
        Histogram time = r.histogram("cluster.direct.upstream_rq_time");
        rq.add(3);
        active.set(2);
        time.record(10);
        time.record(30);
        try (StatsdSink sink = StatsdSink.builder(r, target()).build()) {
            assertEquals(1, sink.flush());
            assertEquals(List.of("envoy.cluster.direct.upstream_rq_active:2|g", "envoy.cluster.direct.upstream_rq_time:20|ms|@0.5",
                    "envoy.cluster.direct.upstream_rq_total:3|c"), receive());
            rq.inc();
            time.record(7);
            sink.flush();
            assertEquals(List.of("envoy.cluster.direct.upstream_rq_active:2|g", "envoy.cluster.direct.upstream_rq_time:7|ms",
                    "envoy.cluster.direct.upstream_rq_total:1|c"), receive(), "only the increase since the last flush");
            sink.flush();
            assertEquals(List.of("envoy.cluster.direct.upstream_rq_active:2|g"), receive(), "nothing new to count");
        }
    }

    @Test
    void dogStatsdSendsTheTagsWithTheTagExtractedName() throws Exception {
        StatsRegistry r = StatsRegistry.builder().prefix("microproxy").build();
        r.counter("http.ingress.downstream_rq_2xx").add(5);
        try (StatsdSink sink = StatsdSink.builder(r, target()).dogStatsd(true).build()) {
            sink.flush();
            assertEquals(List.of("microproxy.http.downstream_rq_xx:5|c|#envoy_http_conn_manager_prefix:ingress,"
                    + "envoy_response_code_class:2"), receive());
        }
    }

    @Test
    void linesArePackedIntoDatagramsOfAtMostTheMaximumSize() throws Exception {
        StatsRegistry r = StatsRegistry.create();
        for (int i = 0; i < 200; i++) r.counter("script.counter_number_" + i).inc();
        try (StatsdSink sink = StatsdSink.builder(r, target()).maxPacketSize(512).build()) {
            int datagrams = sink.flush();
            assertTrue(datagrams > 1, datagrams + " datagrams");
            List<String> lines = new ArrayList<>();
            for (int i = 0; i < datagrams; i++) {
                DatagramPacket packet = new DatagramPacket(new byte[65536], 65536);
                statsd.receive(packet);
                assertTrue(packet.getLength() <= 512, packet.getLength() + " bytes");
                lines.addAll(Arrays.asList(new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8)
                        .split("\n")));
            }
            assertEquals(200, lines.size());
            assertTrue(lines.contains("envoy.script.counter_number_199:1|c"));
        }
    }

    @Test
    void aStartedSinkFlushesEveryIntervalAndOnceMoreWhenClosed() throws Exception {
        StatsRegistry r = StatsRegistry.create();
        Counter c = r.counter("server.ticks");
        c.inc();
        StatsdSink sink = StatsdSink.builder(r, target()).interval(Duration.ofMillis(100)).build().start();
        try {
            assertEquals(List.of("envoy.server.ticks:1|c"), receive());
            c.add(2);
            assertEquals(List.of("envoy.server.ticks:2|c"), receive());
            assertThrows(IllegalStateException.class, sink::start);
        } finally {
            c.add(4);
            sink.close();
        }
        assertTrue(receiveAll().contains("envoy.server.ticks:4|c"), "the last flush on close");
    }

    @Test
    void addressesAreChecked() {
        StatsRegistry r = StatsRegistry.create();
        assertThrows(IllegalArgumentException.class, () -> StatsdSink.builder(r, "localhost"));
        assertThrows(IllegalArgumentException.class, () -> StatsdSink.builder(r, "localhost:"));
        assertThrows(IllegalArgumentException.class, () -> StatsdSink.builder(r, "localhost:x"));
        assertThrows(IllegalArgumentException.class, () -> StatsdSink.builder(r, "localhost:70000"));
        assertEquals(8125, StatsdSink.parse("[::1]:8125").getPort());
        assertTrue(StatsdSink.parse("[::1]:8125").getAddress().isLoopbackAddress());
        assertThrows(IllegalArgumentException.class, () -> StatsdSink.builder(r, target()).interval(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> StatsdSink.builder(r, target()).maxPacketSize(10));
    }
}
