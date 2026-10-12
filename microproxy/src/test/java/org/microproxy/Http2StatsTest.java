package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.http2.ErrorCode;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * The HTTP/2 codec stats, {@code http2.downstream.*} and {@code http2.upstream.*}, from frames
 * written one by one: resets, GOAWAY, trailers, header overflow, floods, streams open, and the
 * bytes counted to a cluster.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class Http2StatsTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("H2 Stats Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("H2 Stats Proxy CA");

    private HttpsServer origin;
    private H2TestOrigin h2Origin;
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.stop(0);
        if (h2Origin != null) H2TestOrigin.closeQuietly(h2Origin);
    }

    private String startOrigin() throws IOException {
        origin = HttpsServer.create(new InetSocketAddress(TestSupport.LOOPBACK, 0), 100);
        origin.setHttpsConfigurator(new HttpsConfigurator(originCa.serverContext("127.0.0.1")));
        origin.createContext("/", TestSupport.echo());
        origin.setExecutor(Executors.newCachedThreadPool());
        origin.start();
        return "127.0.0.1:" + origin.getAddress().getPort();
    }

    private HttpProxyServerBootstrap bootstrap(Http2Options options) {
        return MicroProxy.bootstrap().withPort(0).withName("h2stats").withMetrics(true)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp2(true)
                .withHttp2Options(options);
    }

    private static long value(StatsRegistry r, String name) {
        return MetricsAssertions.value(r, name);
    }

    @Test
    void clientFramesCountDownstream() throws Exception {
        String target = startOrigin();
        proxy = bootstrap(Http2Options.builder().maxPings(10).build()).start();
        StatsRegistry r = proxy.getStats();
        String p = "http2.downstream.";
        try (H2TestClient h2 = H2TestClient.connect(proxy.getListenAddress(), target, proxyCa.clientContext()).handshake()) {
            // A request with trailers
            h2.headers(1, h2.request("POST", "/with-trailers", "te", "trailers"), false);
            h2.data(1, "body".getBytes(StandardCharsets.UTF_8), false);
            h2.headers(1, java.util.List.of(new io.github.mahmoudimus.http2.HeaderField("x-sum", "1")), true);
            // (The JDK's test server takes no request trailers: what it answers does not matter here.)
            h2.response(1);
            MetricsAssertions.awaitValue(r, p + "trailers", 1);
            // A header list over the limit resets its stream
            h2.get(3, "/big", "x-big", "a".repeat(30_000));
            assertEquals(ErrorCode.PROTOCOL_ERROR, h2.awaitReset(3).error());
            MetricsAssertions.awaitValue(r, p + "header_overflow", 1);
            assertTrue(value(r, p + "tx_reset") >= 1, "tx_reset");
            // The client resets a stream it opened
            h2.headers(5, h2.request("POST", "/never-finished"), false);
            h2.rst(5, ErrorCode.CANCEL);
            MetricsAssertions.awaitValue(r, p + "rx_reset", 1);
            MetricsAssertions.awaitValue(r, p + "streams_active", 0);
            // A PING flood ends the connection: each PING needs an answer, as Envoy's control frames
            for (int i = 0; i < 20; i++) h2.ping(i);
            assertEquals(ErrorCode.ENHANCE_YOUR_CALM, h2.awaitGoAway().error());
        }
        MetricsAssertions.awaitValue(r, p + "outbound_control_flood", 1);
        assertTrue(value(r, p + "goaway_sent") >= 1);
        assertEquals(0, value(r, p + "inbound_window_update_frames_flood"));
        assertEquals(0, value(r, "http2.upstream.rx_reset"));
    }

    @Test
    void aClientsGoAwayIsCounted() throws Exception {
        String target = startOrigin();
        proxy = bootstrap(Http2Options.DEFAULT).start();
        StatsRegistry r = proxy.getStats();
        try (H2TestClient h2 = H2TestClient.connect(proxy.getListenAddress(), target, proxyCa.clientContext()).handshake()) {
            h2.get(1, "/x");
            h2.response(1);
            h2.writer.writeGoAway(1, ErrorCode.NO_ERROR, new byte[0]);
            h2.writer.flush();
            MetricsAssertions.awaitValue(r, "http2.downstream.goaway_received", 1);
            // An idle connection whose client is going away gets the proxy's GOAWAY too
            h2.awaitGoAway();
        }
        assertTrue(value(r, "http2.downstream.goaway_sent") >= 1);
    }

    @Test
    void serverFramesCountUpstreamAndBytesCountInTheCluster() throws Exception {
        h2Origin = new H2TestOrigin(originCa.serverContext("localhost", "127.0.0.1"), s -> {
            s.readBody();
            if (s.header(":path").equals("/reset")) {
                s.reset(ErrorCode.INTERNAL_ERROR);
                return;
            }
            s.respond(200, false, "content-type", "text/plain");
            s.data("payload".getBytes(StandardCharsets.UTF_8), false);
            s.trailers("x-checksum", "abc");
        });
        proxy = bootstrap(Http2Options.DEFAULT).withHttp2Upstream(true).start();
        StatsRegistry r = proxy.getStats();
        var client = TestSupport.client(proxy, proxyCa.clientContext());
        HttpRequest ok = HttpRequest.newBuilder(URI.create(h2Origin.url("/ok"))).timeout(Duration.ofSeconds(30)).build();
        assertEquals(200, TestSupport.send(client, ok).statusCode());
        HttpRequest reset = HttpRequest.newBuilder(URI.create(h2Origin.url("/reset"))).timeout(Duration.ofSeconds(30)).build();
        assertTrue(TestSupport.send(client, reset).statusCode() >= 500);

        String p = "http2.upstream.";
        MetricsAssertions.awaitValue(r, p + "trailers", 1);
        MetricsAssertions.awaitValue(r, p + "rx_reset", 1);
        MetricsAssertions.awaitValue(r, p + "streams_active", 0);
        assertEquals(0, value(r, "http2.downstream.rx_reset"));
        // The connection to the server counted its bytes, both ways
        assertTrue(value(r, "cluster.direct.upstream_cx_rx_bytes_total") > 0);
        assertTrue(value(r, "cluster.direct.upstream_cx_tx_bytes_total") > 0);
        assertEquals(1, value(r, "cluster.direct.upstream_cx_http2_total"));
    }
}
