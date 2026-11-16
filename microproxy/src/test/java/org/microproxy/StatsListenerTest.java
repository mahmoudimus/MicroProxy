package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.stats.StatsFormatter;

/** The read-only stats listener: its paths, extra paths, readiness and liveness, and what it refuses. */
class StatsListenerTest {

    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private static final InetSocketAddress ANY_LOOPBACK_PORT = new InetSocketAddress(TestSupport.LOOPBACK, 0);
    private static final Map<String, String> ACTUATOR = Map.of("/metrics", "/stats/prometheus",
            "/health", "/ready", "/health/liveness", "/live", "/health/readiness", "/ready");

    private HttpServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void startOrigin() {
        origin = TestSupport.origin(TestSupport.fixed(200, "done"));
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private static HttpProxyServerBootstrap withStats() {
        return MicroProxy.bootstrap().withPort(0).withStatsListener(ANY_LOOPBACK_PORT);
    }

    private HttpResponse<String> stats(String method, String path) throws Exception {
        return send(proxy.getStatsListenerAddress(), method, path);
    }

    private static HttpResponse<String> send(InetSocketAddress a, String method, String path) throws Exception {
        return HTTP.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + a.getPort() + path))
                .timeout(Duration.ofSeconds(15)).method(method, HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path) throws Exception {
        return stats("GET", path);
    }

    @Test
    void servesOnlyTheStatsAndTheHealth() throws Exception {
        proxy = withStats().start();
        HttpResponse<String> index = get("/");
        assertEquals(200, index.statusCode());
        assertTrue(index.body().startsWith("stats listener paths are:\n"), index.body());
        for (String path : List.of("/stats", "/stats/prometheus", "/ready", "/live")) {
            assertTrue(index.body().contains("  " + path + ": "), path + " in " + index.body());
        }
        for (String path : List.of("/server_info", "/config_dump", "/listeners", "/clusters", "/logging",
                "/healthcheck/fail", "/drain_listeners", "/quitquitquit")) {
            assertEquals(404, get(path).statusCode(), path);
            assertEquals(404, stats("POST", path).statusCode(), path);
        }
        HttpResponse<String> post = stats("POST", "/stats");
        assertEquals(405, post.statusCode());
        assertEquals("GET, HEAD", post.headers().firstValue("allow").orElse(null));
        assertEquals(ServerState.LIVE, proxy.state(), "nothing it answers changes the proxy");
        assertEquals(200, stats("HEAD", "/stats/prometheus").statusCode());
    }

    @Test
    void needsNoTokenWhenTheAdminListenerHasOne() throws Exception {
        proxy = withStats().withAdmin(ANY_LOOPBACK_PORT).withAdminToken("secret").start();
        assertEquals(401, send(proxy.getAdminAddress(), "GET", "/stats/prometheus").statusCode());
        HttpResponse<String> metrics = get("/stats/prometheus");
        assertEquals(200, metrics.statusCode());
        assertEquals(StatsFormatter.PROMETHEUS_CONTENT_TYPE, metrics.headers().firstValue("content-type").orElse(null));
    }

    @Test
    void extraPathsAnswerAsTheirTargets() throws Exception {
        proxy = withStats().withStatsListenerPaths(ACTUATOR).start();
        TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/"));
        HttpResponse<String> metrics = get("/metrics");
        assertEquals(200, metrics.statusCode());
        assertEquals(StatsFormatter.PROMETHEUS_CONTENT_TYPE, metrics.headers().firstValue("content-type").orElse(null));
        assertTrue(metrics.body().contains("http_downstream_cx_total"), metrics.body());
        assertEquals(get("/stats/prometheus?filter=downstream_cx_total").body(),
                get("/metrics?filter=downstream_cx_total").body(), "the query carries over");
        assertEquals("LIVE\n", get("/health/readiness").body());
        assertEquals("LIVE\n", get("/health").body());
        assertEquals("ALIVE\n", get("/health/liveness").body());
        assertTrue(get("/").body().contains("  /metrics: as /stats/prometheus\n"));
    }

    @Test
    void extraPathsAreChecked() {
        HttpProxyServerBootstrap b = MicroProxy.bootstrap();
        assertThrows(IllegalArgumentException.class, () -> b.withStatsListenerPaths(Map.of("metrics", "/stats")));
        assertThrows(IllegalArgumentException.class, () -> b.withStatsListenerPaths(Map.of("/ready", "/live")));
        assertThrows(IllegalArgumentException.class, () -> b.withStatsListenerPaths(Map.of("/", "/live")));
        assertThrows(IllegalArgumentException.class, () -> b.withStatsListenerPaths(Map.of("/quit", "/quitquitquit")));
    }

    @Test
    void theReadinessCheckGatesReadyOnBothListenersButNotLive() throws Exception {
        AtomicBoolean ready = new AtomicBoolean();
        proxy = withStats().withAdmin(ANY_LOOPBACK_PORT).withReadinessCheck(ready::get).start();
        assertEquals(503, get("/ready").statusCode());
        assertEquals("NOT_READY\n", get("/ready").body());
        assertEquals("NOT_READY\n", send(proxy.getAdminAddress(), "GET", "/ready").body());
        assertEquals(200, get("/live").statusCode());
        assertEquals(ServerState.LIVE, proxy.state());

        ready.set(true);
        assertEquals("LIVE\n", get("/ready").body());
        assertEquals("LIVE\n", send(proxy.getAdminAddress(), "GET", "/ready").body());
    }

    @Test
    void aReadinessCheckThatThrowsIsNotReady() throws Exception {
        proxy = withStats().withReadinessCheck(() -> {
            throw new IllegalStateException("boom");
        }).start();
        assertEquals("NOT_READY\n", get("/ready").body());
        assertEquals(200, get("/live").statusCode());
    }

    @Test
    void aDrainingProxyIsAliveButNotReady() throws Exception {
        proxy = withStats().start();
        proxy.stopListeners();
        assertEquals("DRAINING\n", get("/ready").body());
        HttpResponse<String> live = get("/live");
        assertEquals(200, live.statusCode(), "a liveness probe must not restart a proxy finishing its exchanges");
        assertEquals("ALIVE\n", live.body());
    }

    @Test
    void probesOpenNoConnectionToTheProxy() throws Exception {
        proxy = withStats().start();
        for (int i = 0; i < 5; i++) {
            assertEquals(200, get("/live").statusCode());
            assertEquals(200, get("/ready").statusCode());
        }
        String counts = get("/stats?filter=downstream_cx_total").body();
        assertTrue(counts.contains("downstream_cx_total: "), counts);
        for (String line : counts.split("\n")) {
            assertTrue(line.endsWith(": 0"), "a probe counts no downstream connection: " + line);
        }
    }

    @Test
    void aRequestBodyIsNeverRead() throws Exception {
        proxy = withStats().start();
        try (Socket socket = new Socket(TestSupport.LOOPBACK, proxy.getStatsListenerAddress().getPort())) {
            socket.setSoTimeout(10_000);
            OutputStream out = socket.getOutputStream();
            // Announces a gigabyte, sends a kilobyte: the answer must not wait for the rest.
            out.write(("POST /stats HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1073741824\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.write(new byte[1024]);
            out.flush();
            String status = statusLine(socket.getInputStream());
            assertTrue(status.startsWith("HTTP/1.1 405"), status);
        }
        assertEquals(200, get("/ready").statusCode(), "it still answers");
    }

    @Test
    void aStatsListenerThatCannotBindStopsTheStartAndReleasesTheAdminListener() throws Exception {
        int adminPort;
        try (ServerSocket free = new ServerSocket(0, 50, TestSupport.LOOPBACK)) {
            adminPort = free.getLocalPort();
        }
        try (ServerSocket taken = new ServerSocket(0, 50, TestSupport.LOOPBACK)) {
            HttpProxyServerBootstrap b = MicroProxy.bootstrap().withPort(0)
                    .withAdmin(new InetSocketAddress(TestSupport.LOOPBACK, adminPort))
                    .withStatsListener(new InetSocketAddress(TestSupport.LOOPBACK, taken.getLocalPort()));
            UncheckedIOException e = assertThrows(UncheckedIOException.class, b::start);
            assertTrue(e.getMessage().contains("stats listener"), e.getMessage());
        }
        try (ServerSocket again = new ServerSocket()) {
            again.bind(new InetSocketAddress(TestSupport.LOOPBACK, adminPort));
        }
    }

    @Test
    void stoppingClosesIt() throws Exception {
        proxy = withStats().start();
        InetSocketAddress a = proxy.getStatsListenerAddress();
        proxy.stop();
        assertNull(proxy.getStatsListenerAddress());
        assertThrows(java.io.IOException.class, () -> send(a, "GET", "/ready"));
    }

    @Test
    void theFlagsAndPropertiesConfigureIt(@TempDir Path dir) throws Exception {
        Path props = dir.resolve("p.properties");
        Files.writeString(props, "port=0\nstats_address=127.0.0.1:0\n"
                + "stats_paths=/metrics=/stats/prometheus, /health/liveness=/live\n");
        proxy = MicroProxy.bootstrapFromFile(props).start();
        assertEquals(200, get("/metrics").statusCode());
        assertEquals("ALIVE\n", get("/health/liveness").body());
        assertEquals(Map.of("/metrics", "/stats/prometheus", "/health/liveness", "/live"),
                Launcher.statsPaths("/metrics=/stats/prometheus,/health/liveness=/live"));
        assertThrows(IllegalArgumentException.class, () -> Launcher.statsPaths("/metrics"));
    }

    private static String statusLine(InputStream in) throws Exception {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0 && c != '\n') line.write(c);
        return line.toString(StandardCharsets.US_ASCII).strip();
    }
}
