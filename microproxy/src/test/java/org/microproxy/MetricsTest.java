package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.eventually;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.readUntil;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.cache.HttpCache;
import org.microproxy.cache.MemoryCacheStore;
import org.microproxy.extras.ConcurrencyLimiter;
import org.microproxy.stats.Counter;
import org.microproxy.stats.Gauge;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.Metric;
import org.microproxy.stats.StatsFormatter;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * Metrics end to end: requests through the proxy count by response class, response flag,
 * protocol and cluster, as do connection failures and timeouts, within the cardinality bounds.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class MetricsTest {

    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private final List<AutoCloseable> closing = new ArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        proxies.close();
        for (AutoCloseable c : closing) c.close();
    }

    private HttpServer origin(HttpServer server) {
        closing.add(() -> server.stop(0));
        return server;
    }

    /** A counter's or gauge's value, a histogram's count; 0 for a metric not registered. */
    private static long value(StatsRegistry r, String name) {
        Metric m = r.get(name);
        return switch (m) {
            case null -> 0;
            case Counter c -> c.value();
            case Gauge g -> g.value();
            case Histogram h -> h.snapshot().count();
            default -> throw new AssertionError(m);
        };
    }

    private static void awaitValue(StatsRegistry r, String name, long expected) {
        eventually(name + " = " + expected + " (is " + value(r, name) + ")", () -> value(r, name) == expected);
    }

    private static String listener(HttpProxyServer proxy) {
        InetSocketAddress a = proxy.getListenAddress();
        return "listener." + a.getAddress().getHostAddress() + "_" + a.getPort();
    }

    @Test
    void withoutMetricsTheRegistryIsTheNoopOne() {
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap());
        assertSame(StatsRegistry.NOOP, proxy.getStats());
        assertSame(StatsRegistry.NOOP, MicroProxy.bootstrap().withMetrics(true).withMetrics(false).getStats());
        StatsRegistry own = StatsRegistry.create();
        assertSame(own, MicroProxy.bootstrap().withStats(own).withMetrics(true).getStats(), "withMetrics keeps a registry");
    }

    @Test
    void http1RequestsCountByResponseClassProtocolAndCluster() throws Exception {
        HttpServer origin = origin(TestSupport.origin(exchange -> {
            String path = exchange.getRequestURI().getPath();
            int status = path.equals("/missing") ? 404 : path.equals("/broken") ? 503 : 200;
            TestSupport.fixed(status, "body").handle(exchange);
        }));
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withName("edge").withMetrics(true));
        StatsRegistry r = proxy.getStats();
        assertTrue(r.enabled());
        HttpClient client = client(proxy);
        assertEquals(200, get(client, TestSupport.url(origin, "/ok")).statusCode());
        assertEquals(404, get(client, TestSupport.url(origin, "/missing")).statusCode());
        assertEquals(503, get(client, TestSupport.url(origin, "/broken")).statusCode());

        awaitValue(r, "http.edge.downstream_rq_total", 3);
        awaitValue(r, "http.edge.downstream_rq_active", 0);
        assertEquals(1, value(r, "http.edge.downstream_rq_2xx"));
        assertEquals(1, value(r, "http.edge.downstream_rq_4xx"));
        assertEquals(1, value(r, "http.edge.downstream_rq_5xx"));
        assertEquals(0, value(r, "http.edge.downstream_rq_3xx"));
        assertEquals(3, value(r, "http.edge.downstream_rq_http1_total"));
        assertEquals(0, value(r, "http.edge.downstream_rq_http2_total"));
        assertEquals(3, value(r, "http.edge.downstream_rq_time"));
        // Server errors relayed as they are have no response flag.
        assertTrue(r.metrics().stream().noneMatch(m -> m.name().contains("response_flag")), r.metrics().toString());

        assertEquals(3, value(r, "cluster.direct.upstream_rq_total"));
        awaitValue(r, "cluster.direct.upstream_rq_active", 0);
        assertEquals(1, value(r, "cluster.direct.upstream_rq_2xx"));
        assertEquals(1, value(r, "cluster.direct.upstream_rq_4xx"));
        assertEquals(1, value(r, "cluster.direct.upstream_rq_5xx"));
        assertEquals(3, value(r, "cluster.direct.upstream_rq_time"));
        long upstreamConnections = value(r, "cluster.direct.upstream_cx_total");
        assertTrue(upstreamConnections >= 1, "connections: " + upstreamConnections);
        assertEquals(upstreamConnections, value(r, "cluster.direct.upstream_cx_connect_ms"));
        assertEquals(upstreamConnections, value(r, "cluster.direct.upstream_cx_http1_total"));
        assertEquals(0, value(r, "cluster.direct.upstream_cx_connect_fail"));

        long clientConnections = value(r, "http.edge.downstream_cx_total");
        assertTrue(clientConnections >= 1);
        assertEquals(clientConnections, value(r, "http.edge.downstream_cx_http1_total"));
        assertEquals(clientConnections, value(r, listener(proxy) + ".downstream_cx_total"));
        assertTrue(value(r, "http.edge.downstream_cx_rx_bytes_total") > 0);
        assertTrue(value(r, "http.edge.downstream_cx_tx_bytes_total") > 0);
        assertEquals(1, value(r, "server.live"));
        assertTrue(value(r, "server.memory_allocated") > 0);
        assertTrue(value(r, "server.concurrency") >= 1);
        assertNotNull(r.get("server.uptime"));

        // A test-only scrape: what the admin endpoint will serve.
        String scrape = StatsFormatter.prometheus(r);
        assertTrue(scrape.contains("# TYPE envoy_http_downstream_rq_xx counter\n"), scrape);
        assertTrue(scrape.contains("envoy_http_downstream_rq_xx{envoy_http_conn_manager_prefix=\"edge\","
                + "envoy_response_code_class=\"4\"} 1\n"), scrape);
        assertTrue(scrape.contains("envoy_cluster_upstream_rq_total{envoy_cluster_name=\"direct\"} 3\n"), scrape);
        assertTrue(scrape.contains("envoy_http_downstream_rq_time_bucket{envoy_http_conn_manager_prefix=\"edge\",le=\"+Inf\"} 3\n"),
                scrape);
        assertTrue(StatsFormatter.text(r).contains("http.edge.downstream_rq_total: 3\n"));

        proxy.stop();
        assertEquals(0, value(r, "http.edge.downstream_cx_active"));
        assertEquals(0, value(r, listener(proxy) + ".downstream_cx_active"));
        assertEquals(0, value(r, listener(proxy) + ".downstream_pre_cx_active"));
        assertEquals(clientConnections, value(r, "http.edge.downstream_cx_destroy"));
        assertEquals(clientConnections, value(r, "http.edge.downstream_cx_length_ms"));
        assertEquals(0, value(r, "server.live"));
        eventually("server connections closed", () -> value(r, "cluster.direct.upstream_cx_active") == 0);
        assertEquals(upstreamConnections, value(r, "cluster.direct.upstream_cx_destroy"));
    }

    @Test
    void aClientThatClosesItsConnectionIsARemoteDestroy() throws Exception {
        HttpServer origin = origin(TestSupport.origin(TestSupport.fixed(200, "ok")));
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withName("edge").withMetrics(true));
        StatsRegistry r = proxy.getStats();
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            write(s.getOutputStream(), "GET " + TestSupport.url(origin, "/") + " HTTP/1.1\r\nHost: x\r\n\r\n");
            assertTrue(readUntil(s.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
            awaitValue(r, "http.edge.downstream_cx_active", 1);
        }
        awaitValue(r, "http.edge.downstream_cx_destroy_remote", 1);
        assertEquals(0, value(r, "http.edge.downstream_cx_destroy_local"));
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            write(s.getOutputStream(), "GET " + TestSupport.url(origin, "/") + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            assertTrue(readUntil(s.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
            awaitValue(r, "http.edge.downstream_cx_destroy_local", 1);
        }
    }

    @Test
    void failuresCountByResponseFlagAndConnectFailures() throws Exception {
        try (Socket refusing = TestSupport.refusingPort()) {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withName("edge").withMetrics(true));
            StatsRegistry r = proxy.getStats();
            assertEquals(502, get(client(proxy), "http://127.0.0.1:" + refusing.getLocalPort() + "/").statusCode());
            awaitValue(r, "http.edge.downstream_rq_response_flag.UF", 1);
            assertEquals(1, value(r, "http.edge.downstream_rq_5xx"));
            assertEquals(1, value(r, "cluster.direct.upstream_cx_connect_fail"));
            assertEquals(0, value(r, "cluster.direct.upstream_cx_connect_timeout"));
            assertEquals(0, value(r, "cluster.direct.upstream_cx_total"));
            assertEquals(0, value(r, "cluster.direct.upstream_rq_total"), "no request went to a server");
            String scrape = StatsFormatter.prometheus(r);
            assertTrue(scrape.contains("envoy_http_downstream_rq_response_flag{envoy_http_conn_manager_prefix=\"edge\","
                    + "microproxy_response_flag=\"UF\"} 1\n"), scrape);
        }
        HttpProxyServer unresolving = proxies.start(MicroProxy.bootstrap().withName("dns").withMetrics(true)
                .withServerResolver((host, port) -> {
                    throw new UnknownHostException(host);
                }));
        StatsRegistry r = unresolving.getStats();
        assertEquals(502, get(client(unresolving), "http://nowhere.test/").statusCode());
        awaitValue(r, "http.dns.downstream_rq_response_flag.DF", 1);
        assertEquals(0, value(r, "cluster.direct.upstream_cx_connect_fail"), "a name that does not resolve is not a connection");
    }

    @Test
    void connectTimeoutsCount() throws Exception {
        // A listening socket whose accept queue is full leaves new connection attempts hanging.
        try (ServerSocket full = new ServerSocket(0, 1, TestSupport.LOOPBACK)) {
            List<Socket> fillers = new ArrayList<>();
            boolean saturated = false;
            try {
                for (int i = 0; i < 16 && !saturated; i++) {
                    Socket s = new Socket();
                    try {
                        s.connect(full.getLocalSocketAddress(), 200);
                        fillers.add(s);
                    } catch (SocketTimeoutException e) {
                        s.close();
                        saturated = true;
                    }
                }
                assumeTrue(saturated, "connections to a full backlog do not hang on this OS");
                HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withName("edge").withMetrics(true)
                        .withConnectTimeout(300));
                StatsRegistry r = proxy.getStats();
                assertEquals(502, get(client(proxy), "http://127.0.0.1:" + full.getLocalPort() + "/").statusCode());
                awaitValue(r, "cluster.direct.upstream_cx_connect_timeout", 1);
                assertEquals(1, value(r, "cluster.direct.upstream_cx_connect_fail"));
                // The exchange is counted once over, after the client has its answer.
                awaitValue(r, "http.edge.downstream_rq_response_flag.UF", 1);
            } finally {
                for (Socket s : fillers) s.close();
            }
        }
    }

    @Test
    void serverTimeoutsAndResetsCount() throws Exception {
        try (TestSupport.RawServer silent = TestSupport.rawServer(s -> {
            readUntil(s.getInputStream(), "\r\n\r\n");
            Thread.sleep(5_000);
        }); TestSupport.RawServer truncated = TestSupport.rawServer(s -> {
            readUntil(s.getInputStream(), "\r\n\r\n");
            write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial");
        })) {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withName("edge").withMetrics(true)
                    .withIdleConnectionTimeout(Duration.ofMillis(300)));
            StatsRegistry r = proxy.getStats();
            assertEquals(504, get(client(proxy), "http://127.0.0.1:" + silent.port() + "/").statusCode());
            awaitValue(r, "cluster.direct.upstream_rq_timeout", 1);
            awaitValue(r, "http.edge.downstream_rq_response_flag.UT", 1);
            String reply = TestSupport.rawExchange(proxy.getListenAddress(), "GET http://127.0.0.1:" + truncated.port()
                    + "/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            assertTrue(reply.startsWith("HTTP/1.1 200 OK\r\n"), reply);
            awaitValue(r, "cluster.direct.upstream_rq_rx_reset", 1);
            awaitValue(r, "http.edge.downstream_rq_tx_reset", 1);
            // A 200 whose body never came is not a 4xx or 5xx: its flag is not counted.
            assertEquals(0, value(r, "http.edge.downstream_rq_response_flag.UR"));
            assertEquals(2, value(r, "cluster.direct.upstream_rq_total"));
            awaitValue(r, "cluster.direct.upstream_rq_active", 0);
        }
    }

    @Test
    void aChainedProxyIsAClusterOfItsOwn() throws Exception {
        HttpServer origin = origin(TestSupport.origin(TestSupport.fixed(200, "ok")));
        InetSocketAddress upstream = proxies.start(MicroProxy.bootstrap()).getListenAddress();
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withName("edge").withMetrics(true)
                .withChainProxyManager(always(ChainTestSupport.http(upstream))));
        StatsRegistry r = proxy.getStats();
        assertEquals(200, get(client(proxy), TestSupport.url(origin, "/")).statusCode());
        String cluster = "cluster." + upstream.getHostString().replace('.', '_') + "_" + upstream.getPort();
        awaitValue(r, cluster + ".upstream_rq_2xx", 1);
        assertEquals(1, value(r, cluster + ".upstream_cx_total"));
        assertEquals(0, value(r, "cluster.direct.upstream_rq_total"));
        assertTrue(StatsFormatter.prometheus(r).contains("envoy_cluster_upstream_rq_total{envoy_cluster_name=\""
                + cluster.substring("cluster.".length()) + "\"} 1\n"));
    }

    @Test
    void http2AndTlsCountTheirProtocolAndHandshakes() throws Exception {
        HttpServer origin = origin(TestSupport.origin(TestSupport.echo()));
        HttpProxyServer h2c = proxies.start(MicroProxy.bootstrap().withName("h2c").withMetrics(true).withHttp2Cleartext(true));
        StatsRegistry r = h2c.getStats();
        try (H2TestClient c = H2TestClient.cleartext(h2c.getListenAddress(), "127.0.0.1:" + origin.getAddress().getPort())
                .handshake()) {
            c.get(1, "/a");
            c.get(3, "/b");
            assertEquals(200, c.response(1).status());
            assertEquals(200, c.response(3).status());
        }
        awaitValue(r, "http.h2c.downstream_rq_http2_total", 2);
        awaitValue(r, "http.h2c.downstream_rq_2xx", 2);
        assertEquals(0, value(r, "http.h2c.downstream_rq_http1_total"));
        awaitValue(r, "http.h2c.downstream_cx_http2_total", 1);
        assertEquals(0, value(r, "http.h2c.downstream_cx_http1_total"));
        assertTrue(value(r, "http.h2c.downstream_cx_rx_bytes_total") > 24, "the preface and frames");

        SelfSignedSslContextSource tls = new SelfSignedSslContextSource();
        HttpProxyServer reverse = proxies.start(MicroProxy.bootstrap().withName("tls").withMetrics(true)
                .withReverseProxy("http://127.0.0.1:" + origin.getAddress().getPort())
                .withSslContextSource(tls).withHttp2(true));
        StatsRegistry t = reverse.getStats();
        HttpClient client = HttpClient.newBuilder().sslContext(tls.getSslContext()).version(HttpClient.Version.HTTP_2).build();
        HttpResponse<String> response = TestSupport.send(client, HttpRequest.newBuilder(
                URI.create("https://localhost:" + reverse.getListenAddress().getPort() + "/x")).build());
        assertEquals(200, response.statusCode());
        assertEquals(HttpClient.Version.HTTP_2, response.version());
        awaitValue(t, "http.tls.downstream_rq_http2_total", 1);
        assertEquals(1, value(t, "http.tls.downstream_cx_ssl_total"));
        assertEquals(1, value(t, "http.tls.downstream_cx_http2_total"));
        assertEquals(1, value(t, listener(reverse) + ".ssl.handshake"));
        assertEquals(0, value(t, listener(reverse) + ".ssl.connection_error"));
        // A client that does not speak TLS to the TLS listener.
        TestSupport.rawExchange(reverse.getListenAddress(), "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        awaitValue(t, listener(reverse) + ".ssl.connection_error", 1);
    }

    @Test
    void http3CountsItsProtocol() throws Exception {
        HttpServer origin = origin(TestSupport.origin(TestSupport.echo()));
        SelfSignedSslContextSource tls = new SelfSignedSslContextSource();
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withName("h3").withMetrics(true)
                .withReverseProxy("http://127.0.0.1:" + origin.getAddress().getPort())
                .withSslContextSource(tls).withHttp3(true));
        StatsRegistry r = proxy.getStats();
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        try (H3TestClient client = H3TestClient.connect(address, "localhost", tls.getCertificate())) {
            assertEquals(200, client.get("/one").status());
            assertEquals(200, client.get("/two").status());
        }
        awaitValue(r, "http.h3.downstream_rq_http3_total", 2);
        awaitValue(r, "http.h3.downstream_rq_2xx", 2);
        assertEquals(1, value(r, "http.h3.downstream_cx_http3_total"));
        assertEquals(1, value(r, "http.h3.downstream_cx_total"));
        assertEquals(0, value(r, listener(proxy) + ".downstream_cx_total"), "the TCP listener's stats are its own");
        assertEquals(2, value(r, "cluster.direct.upstream_rq_2xx"));
    }

    @Test
    void perHostClustersBeyondTheLimitShareOther() throws Exception {
        List<HttpServer> origins = new ArrayList<>();
        for (int i = 0; i < 3; i++) origins.add(origin(TestSupport.origin(TestSupport.fixed(200, "ok"))));
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withName("edge")
                .withStats(StatsRegistry.builder().perHostClusters(true).maxClusters(2).build()));
        StatsRegistry r = proxy.getStats();
        HttpClient client = client(proxy);
        for (HttpServer o : origins) assertEquals(200, get(client, TestSupport.url(o, "/")).statusCode());
        awaitValue(r, "http.edge.downstream_rq_total", 3);
        for (int i = 0; i < 2; i++) {
            assertEquals(1, value(r, "cluster.127_0_0_1_" + origins.get(i).getAddress().getPort() + ".upstream_rq_total"));
        }
        assertNull(r.get("cluster.127_0_0_1_" + origins.get(2).getAddress().getPort() + ".upstream_rq_total"));
        assertEquals(1, value(r, "cluster.other.upstream_rq_total"));
        assertEquals(0, value(r, "cluster.direct.upstream_rq_total"));
        // Its later requests stay there, and the known ones keep theirs.
        assertEquals(200, get(client, TestSupport.url(origins.get(2), "/again")).statusCode());
        assertEquals(200, get(client, TestSupport.url(origins.get(0), "/again")).statusCode());
        awaitValue(r, "cluster.other.upstream_rq_total", 2);
        awaitValue(r, "cluster.127_0_0_1_" + origins.get(0).getAddress().getPort() + ".upstream_rq_total", 2);
    }

    @Test
    void lruEvictsTheClusterUsedLeastRecently() throws Exception {
        List<HttpServer> origins = new ArrayList<>();
        for (int i = 0; i < 3; i++) origins.add(origin(TestSupport.origin(TestSupport.fixed(200, "ok"))));
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withName("edge").withStats(StatsRegistry.builder()
                .perHostClusters(true).maxClusters(2).clusterOverflow(StatsRegistry.Overflow.LRU).build()));
        StatsRegistry r = proxy.getStats();
        for (HttpServer o : origins) {
            // A connection each: the cluster is looked up per connection.
            HttpClient fresh = client(proxy);
            assertEquals(200, get(fresh, TestSupport.url(o, "/")).statusCode());
            Thread.sleep(5);
        }
        awaitValue(r, "http.edge.downstream_rq_total", 3);
        String first = "cluster.127_0_0_1_" + origins.get(0).getAddress().getPort() + ".upstream_rq_total";
        assertNull(r.get(first), "evicted: " + r.metrics());
        for (int i = 1; i < 3; i++) {
            assertEquals(1, value(r, "cluster.127_0_0_1_" + origins.get(i).getAddress().getPort() + ".upstream_rq_total"));
        }
        assertNull(r.get("cluster.other.upstream_rq_total"));
    }

    @Test
    void cacheAndPoolAndLimiterStatsAreRegistered() throws Exception {
        HttpServer origin = origin(TestSupport.origin(exchange -> {
            exchange.getResponseHeaders().set("Cache-Control", "max-age=60");
            TestSupport.fixed(200, "cached").handle(exchange);
        }));
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withName("edge").withMetrics(true)
                .withHttpCache(HttpCache.builder().store(new MemoryCacheStore(1 << 20)).build())
                .withSharedServerConnectionPool(true)
                .withFiltersSource(ConcurrencyLimiter.builder().permits(10).build()));
        StatsRegistry r = proxy.getStats();
        HttpClient client = client(proxy);
        assertEquals("cached", get(client, TestSupport.url(origin, "/c")).body());
        assertEquals("cached", get(client, TestSupport.url(origin, "/c")).body());
        awaitValue(r, "cluster.cache.upstream_rq_2xx", 1);
        assertEquals(1, value(r, "cluster.direct.upstream_rq_total"), "the first went to the server");
        assertEquals(1, value(r, "cache.hits"));
        assertEquals(1, value(r, "cache.misses"));
        assertEquals(1, value(r, "cache.stores"));
        assertEquals(2, value(r, "concurrency_limit.acquired"));
        assertEquals(0, value(r, "concurrency_limit.rq_blocked"));
        assertNotNull(r.get("concurrency_limit.in_use"));
        assertTrue(value(r, "connection_pool.borrow") >= 1);
        assertNotNull(r.get("connection_pool.idle_connections"));
    }

    @Test
    void tlsInspectorCountsTheClientHellosItReads() throws Exception {
        try (Socket refusing = TestSupport.refusingPort()) {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withName("edge").withMetrics(true)
                    .withTransparent(true).withTransparentTlsPort(refusing.getLocalPort()));
            StatsRegistry r = proxy.getStats();
            // TLS without a CONNECT: the proxy reads its ClientHello for the server name.
            try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
                s.setSoTimeout(10_000);
                s.getOutputStream().write(TlsHellos.fromJdkClient("localhost", "h2"));
                s.getOutputStream().flush();
                s.getInputStream().readAllBytes();
            }
            awaitValue(r, "tls_inspector.tls_found", 1);
            assertEquals(1, value(r, "tls_inspector.sni_found"));
            assertEquals(1, value(r, "tls_inspector.alpn_found"));
            assertEquals(0, value(r, "tls_inspector.tls_not_found"));
            awaitValue(r, "cluster.direct.upstream_cx_connect_fail", 1);
        }
    }
}
