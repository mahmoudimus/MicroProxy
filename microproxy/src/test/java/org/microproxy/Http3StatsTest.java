package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.MetricsAssertions.awaitAtLeast;
import static org.microproxy.MetricsAssertions.awaitValue;
import static org.microproxy.MetricsAssertions.value;

import com.sun.net.httpserver.HttpServer;
import io.github.mahmoudimus.quic.QuicStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.extras.JsonForTests;
import org.microproxy.stats.StatsFormatter;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * The HTTP/3 codec stats ({@code http3.downstream.*}), the QUIC connections' ({@code
 * quic.downstream.*}, counted when they close) and their qlog files, for a reverse proxy serving
 * HTTP/3.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class Http3StatsTest {

    @TempDir
    Path qlogDir;

    private HttpServer origin;
    private HttpProxyServer proxy;
    private SelfSignedSslContextSource tls;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.stop(0);
    }

    private HttpProxyServer start(boolean metrics, Path qlog) {
        origin = TestSupport.origin(TestSupport.echo());
        tls = new SelfSignedSslContextSource();
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withName("h3stats")
                .withMetrics(metrics)
                .withReverseProxy("http://127.0.0.1:" + origin.getAddress().getPort())
                .withSslContextSource(tls)
                .withHttp3(true)
                .withHttp3Options(Http3Options.builder().qlogDirectory(qlog).qlogMaxFiles(4).build())
                .start();
        return proxy;
    }

    private H3TestClient client() throws Exception {
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        return H3TestClient.connect(address, "localhost", tls.getCertificate());
    }

    @Test
    void streamsResetsGoAwayAndTheQuicConnectionAreCounted() throws Exception {
        start(true, null);
        StatsRegistry r = proxy.getStats();
        try (H3TestClient client = client()) {
            byte[] body = new byte[100_000];
            assertEquals(200, client.get("/a").status());
            assertEquals(200, client.post("/b", body).status());
            // A request stream the client resets before finishing it
            QuicStream s = client.send(client.head("POST", "/never", List.of()), false);
            s.reset(0x10c); // H3_REQUEST_CANCELLED
            awaitValue(r, "http3.downstream.rx_reset", 1);
            awaitValue(r, "http3.downstream.streams_active", 0);
            assertEquals(1, value(r, "quic.downstream.connections_active"));
            // A graceful stop sends GOAWAY, and waits for the connection
            Thread.ofVirtual().start(proxy::stop);
            assertTrue(client.awaitGoAway(Duration.ofSeconds(10)) >= 0, "GOAWAY from a stopping proxy");
        }
        awaitValue(r, "quic.downstream.connections_active", 0);
        assertEquals(1, value(r, "http3.downstream.goaway_sent"));
        assertEquals(1, value(r, "quic.downstream.connections_total"));
        assertEquals(1, value(r, "quic.downstream.handshake_ms"));
        assertEquals(1, value(r, "quic.downstream.rtt_ms"));
        assertEquals(1, value(r, "quic.downstream.congestion_controller.cubic"));
        assertTrue(value(r, "quic.downstream.packets_received_total") > 0);
        assertTrue(value(r, "quic.downstream.packets_sent_total") > 0);
        assertTrue(value(r, "quic.downstream.bytes_received_total") > 100_000);
        assertTrue(value(r, "quic.downstream.bytes_sent_total") > 0);
        assertEquals(0, value(r, "quic.downstream.migrations"));
        assertEquals(0, value(r, "quic.downstream.retry_sent"));
        assertTrue(r.metrics().stream().noneMatch(m -> m.name().startsWith("quic.downstream.handshake_failures")));
        // HTTP/3 clients' bytes count as the HTTP connection manager's, as TCP clients' do
        assertTrue(value(r, "http.h3stats.downstream_cx_rx_bytes_total") > 100_000);
        assertTrue(value(r, "http.h3stats.downstream_cx_tx_bytes_total") > 0);
        String scrape = StatsFormatter.prometheus(r);
        assertTrue(scrape.contains("envoy_quic_connections_total{microproxy_quic_scope=\"downstream\"} 1"), scrape);
        assertTrue(scrape.contains("envoy_http3_rx_reset{microproxy_direction=\"downstream\"} 1"), scrape);
    }

    @Test
    void qlogFilesAreJsonSeqTraces() throws Exception {
        start(false, qlogDir);
        try (H3TestClient client = client()) {
            assertEquals(200, client.get("/qlog").status());
        }
        // The file is complete once the proxy's side of the connection has ended
        Path file;
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (true) {
            try (Stream<Path> files = Files.list(qlogDir)) {
                List<Path> all = files.toList();
                if (!all.isEmpty() && endsWithClose(all.getFirst())) {
                    assertEquals(1, all.size(), all.toString());
                    file = all.getFirst();
                    break;
                }
            }
            if (System.nanoTime() > deadline) throw new AssertionError("no complete qlog file in " + qlogDir);
            Thread.sleep(50);
        }
        assertTrue(file.getFileName().toString().endsWith("_server.sqlog"), file.toString());
        String text = Files.readString(file, StandardCharsets.UTF_8);
        assertEquals('\u001e', text.charAt(0), "JSON-SEQ: each record starts with RS");
        String[] records = text.substring(1).split("\u001e");
        Map<?, ?> header = assertInstanceOf(Map.class, JsonForTests.parse(records[0].strip()));
        assertEquals("0.3", header.get("qlog_version"));
        assertEquals("JSON-SEQ", header.get("qlog_format"));
        Map<?, ?> trace = (Map<?, ?>) header.get("trace");
        assertEquals("server", ((Map<?, ?>) trace.get("vantage_point")).get("type"));
        Map<?, ?> common = (Map<?, ?>) trace.get("common_fields");
        String odcid = (String) common.get("ODCID");
        assertTrue(file.getFileName().toString().startsWith(odcid + "_"), file + " " + odcid);
        assertEquals("relative", common.get("time_format"));
        boolean sent = false;
        boolean received = false;
        double last = -1;
        for (int i = 1; i < records.length; i++) {
            assertTrue(records[i].endsWith("\n"), "a record ends with a newline");
            Map<?, ?> event = assertInstanceOf(Map.class, JsonForTests.parse(records[i].strip()), records[i]);
            double time = ((Number) event.get("time")).doubleValue();
            assertTrue(time >= last, "times never go back");
            last = time;
            assertInstanceOf(Map.class, event.get("data"));
            sent |= "transport:packet_sent".equals(event.get("name"));
            received |= "transport:packet_received".equals(event.get("name"));
        }
        assertTrue(sent && received, "packets sent and received");
    }

    /** Whether a qlog file has its connection's end. */
    private static boolean endsWithClose(Path file) throws IOException {
        String text = Files.readString(file, StandardCharsets.UTF_8);
        return text.contains("connectivity:connection_closed") && text.endsWith("\n");
    }

    @Test
    void qlogKeepsAtMostItsFiles() throws Exception {
        start(false, qlogDir);
        for (int i = 0; i < 6; i++) {
            try (H3TestClient client = client()) {
                assertEquals(200, client.get("/" + i).status());
            }
        }
        TestSupport.eventually("at most 4 qlog files", () -> {
            try (Stream<Path> files = Files.list(qlogDir)) {
                return files.count() == 4;
            } catch (IOException e) {
                return false;
            }
        });
        assertFalse(proxy.getStats().enabled(), "qlog without metrics");
    }
}
