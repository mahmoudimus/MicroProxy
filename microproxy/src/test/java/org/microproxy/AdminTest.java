package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.stats.StatsFormatter;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.KeyStoreSslContextSource;

/** The admin listener: every endpoint, its methods, the token, redaction, logging levels and draining through it. */
class AdminTest {

    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private static final InetSocketAddress ANY_LOOPBACK_PORT = new InetSocketAddress(TestSupport.LOOPBACK, 0);

    private HttpServer origin;
    private final CountDownLatch release = new CountDownLatch(1);
    private final CountDownLatch slowArrived = new CountDownLatch(1);
    private HttpProxyServer proxy;

    @BeforeEach
    void startOrigin() {
        origin = TestSupport.origin(exchange -> {
            if (exchange.getRequestURI().getPath().equals("/slow")) {
                slowArrived.countDown();
                try {
                    release.await(20, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            TestSupport.fixed(200, "done " + exchange.getRequestURI().getPath()).handle(exchange);
        });
    }

    @AfterEach
    void tearDown() {
        release.countDown();
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private HttpProxyServerBootstrap withAdmin() {
        return MicroProxy.bootstrap().withPort(0).withAdmin(ANY_LOOPBACK_PORT);
    }

    private HttpResponse<String> admin(String method, String path, String... headers) throws Exception {
        InetSocketAddress a = proxy.getAdminAddress();
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + a.getPort() + path))
                .timeout(Duration.ofSeconds(15)).method(method, HttpRequest.BodyPublishers.noBody());
        if (headers.length > 0) b.headers(headers);
        return HTTP.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path) throws Exception {
        return admin("GET", path);
    }

    private HttpResponse<String> post(String path) throws Exception {
        return admin("POST", path);
    }

    private static String contentType(HttpResponse<?> r) {
        return r.headers().firstValue("content-type").orElse(null);
    }

    private String proxyGet(String path) throws Exception {
        return TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, path)).body();
    }

    // ---------------------------------------------------------------------------------------

    @Test
    void theIndexListsEveryEndpoint() throws Exception {
        proxy = withAdmin().start();
        assertEquals(TestSupport.LOOPBACK, proxy.getAdminAddress().getAddress());
        HttpResponse<String> index = get("/");
        assertEquals(200, index.statusCode());
        assertEquals("text/plain; charset=utf-8", contentType(index));
        for (String path : List.of("/stats", "/stats/prometheus", "/ready", "/server_info", "/listeners", "/clusters",
                "/config_dump", "/logging", "/healthcheck/fail", "/healthcheck/ok", "/drain_listeners", "/quitquitquit")) {
            assertTrue(index.body().contains("  " + path + ": "), path + " in " + index.body());
        }
        assertEquals(index.body(), get("/help").body());
        HttpResponse<String> head = admin("HEAD", "/");
        assertEquals(200, head.statusCode());
        assertEquals("", head.body());
        HttpResponse<String> missing = get("/certs");
        assertEquals(404, missing.statusCode());
        assertTrue(missing.body().contains("admin commands are:"));
    }

    @Test
    void readsAreGetAndChangesArePost() throws Exception {
        proxy = withAdmin().start();
        Map<String, String> types = new LinkedHashMap<>();
        types.put("/stats", "text/plain; charset=utf-8");
        types.put("/stats?format=json", "application/json");
        types.put("/stats/prometheus", "text/plain; version=0.0.4; charset=utf-8");
        types.put("/ready", "text/plain; charset=utf-8");
        types.put("/server_info", "application/json");
        types.put("/listeners", "text/plain; charset=utf-8");
        types.put("/listeners?format=json", "application/json");
        types.put("/clusters", "text/plain; charset=utf-8");
        types.put("/clusters?format=json", "application/json");
        types.put("/config_dump", "application/json");
        types.put("/logging", "text/plain; charset=utf-8");
        for (Map.Entry<String, String> e : types.entrySet()) {
            HttpResponse<String> r = get(e.getKey());
            assertEquals(200, r.statusCode(), e.getKey());
            assertEquals(e.getValue(), contentType(r), e.getKey());
            assertEquals("nosniff", r.headers().firstValue("x-content-type-options").orElseThrow());
            if (e.getValue().equals("application/json")) assertNotNull(Json.parse(r.body()), e.getKey());
            if (!e.getKey().equals("/logging")) {
                HttpResponse<String> wrong = post(e.getKey());
                assertEquals(405, wrong.statusCode(), "POST " + e.getKey());
                assertEquals("GET, HEAD", wrong.headers().firstValue("allow").orElseThrow());
            }
            assertEquals(405, admin("DELETE", e.getKey()).statusCode(), "DELETE " + e.getKey());
        }
        for (String path : List.of("/healthcheck/fail", "/healthcheck/ok", "/drain_listeners", "/quitquitquit")) {
            HttpResponse<String> r = get(path);
            assertEquals(405, r.statusCode(), "GET " + path);
            assertEquals("POST", r.headers().firstValue("allow").orElseThrow());
            assertTrue(r.body().contains("it changes the proxy"));
            assertEquals(405, admin("PUT", path).statusCode(), "PUT " + path);
        }
        assertEquals(ServerState.LIVE, proxy.state(), "nothing was changed by the refused requests");
        assertTrue(proxy.getListenAddress() != null && !proxy.isHealthCheckFailed());
    }

    @Test
    void theTokenGuardsEverythingButReady() throws Exception {
        proxy = withAdmin().withAdminToken("s3cret").start();
        HttpResponse<String> none = get("/stats");
        assertEquals(401, none.statusCode());
        assertTrue(none.headers().allValues("www-authenticate").containsAll(
                List.of("Bearer realm=\"MicroProxy admin\"", "Basic realm=\"MicroProxy admin\", charset=\"UTF-8\"")));
        assertEquals(401, admin("GET", "/stats", "Authorization", "Bearer wrong").statusCode());
        assertEquals(401, admin("GET", "/certs").statusCode(), "no hint of the paths without the token");
        assertEquals(401, admin("POST", "/quitquitquit", "Authorization", "Basic " + basic("admin:wrong")).statusCode());
        assertEquals(200, admin("GET", "/stats", "Authorization", "Bearer s3cret").statusCode());
        assertEquals(200, admin("GET", "/stats", "Authorization", "basic " + basic("anyone:s3cret")).statusCode());
        assertEquals(200, get("/ready").statusCode(), "/ready needs no token");
        assertEquals(ServerState.LIVE, proxy.state());
        proxy.stop();

        proxy = withAdmin().withAdminToken("ops:pa:ss").start();
        assertEquals(200, admin("GET", "/stats", "Authorization", "Basic " + basic("ops:pa:ss")).statusCode());
        assertEquals(401, admin("GET", "/stats", "Authorization", "Basic " + basic("other:pa:ss")).statusCode());
        assertThrows(IllegalArgumentException.class, () -> MicroProxy.bootstrap().withAdminToken(""));
    }

    private static String basic(String credentials) {
        return Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void onLoopbackOnlyLoopbackHostsAreAnsweredAndPagesCannotPost() throws Exception {
        proxy = withAdmin().start();
        InetSocketAddress a = proxy.getAdminAddress();
        assertTrue(raw(a, "GET /ready HTTP/1.1\r\nHost: localhost:" + a.getPort() + "\r\n\r\n").startsWith("HTTP/1.1 200"));
        assertTrue(raw(a, "GET /ready HTTP/1.1\r\nHost: [::1]\r\n\r\n").startsWith("HTTP/1.1 200"));
        assertTrue(raw(a, "GET /stats HTTP/1.1\r\nHost: attacker.example\r\n\r\n").startsWith("HTTP/1.1 403"),
                "a DNS-rebound name");
        assertTrue(raw(a, "POST /healthcheck/fail HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://attacker.example\r\n"
                + "Content-Length: 0\r\n\r\n").startsWith("HTTP/1.1 403"));
        assertFalse(proxy.isHealthCheckFailed());
    }

    private static String raw(InetSocketAddress address, String request) throws IOException {
        try (Socket s = new Socket(address.getAddress(), address.getPort())) {
            s.setSoTimeout(10_000);
            TestSupport.write(s.getOutputStream(), request);
            return TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
        }
    }

    @Test
    void statsFilterJsonAndUsedOnly() throws Exception {
        // The admin listener turns metrics on.
        proxy = withAdmin().start();
        assertTrue(proxy.getStats().enabled());
        assertEquals("done /a", proxyGet("/a"));
        eventually("the request counted", () -> {
            try {
                return get("/stats?filter=downstream_rq_total").body().contains("http.MicroProxy.downstream_rq_total: 1");
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        });
        String all = get("/stats").body();
        assertTrue(all.contains("server.state: 0\n") && all.contains("server.live: 1\n"), all);
        assertTrue(all.contains("cluster.direct.upstream_rq_total: 1\n"), all);

        assertEquals("server.live: 1\nserver.state: 0\n", get("/stats?filter=%5Eserver%5C.(live%7Cstate)%24").body());
        assertTrue(get("/stats?filter=%5Ecluster%5C.direct%5C.upstream_rq_%5B0-9%5D+xx%24").body()
                .contains("cluster.direct.upstream_rq_2xx: 1\n"), "a + is a regex's, not a space");
        String filtered = get("/stats?filter=%5Ecluster%5C.direct%5C.upstream_rq_%5B0-9%5Dxx%24").body();
        assertEquals("cluster.direct.upstream_rq_1xx: 0\ncluster.direct.upstream_rq_2xx: 1\ncluster.direct.upstream_rq_3xx: 0\n"
                + "cluster.direct.upstream_rq_4xx: 0\ncluster.direct.upstream_rq_5xx: 0\n", filtered);
        assertEquals("cluster.direct.upstream_rq_2xx: 1\n",
                get("/stats?usedonly&filter=%5Ecluster%5C.direct%5C.upstream_rq_%5B0-9%5Dxx%24").body());
        String used = get("/stats?usedonly").body();
        assertFalse(used.contains(": 0\n"), "no zero counter or gauge: " + used);
        assertTrue(used.contains("downstream_rq_time: P0"), used);
        assertFalse(used.contains("No recorded values"), used);

        HttpResponse<String> json = get("/stats?format=json&filter=server%5C.live");
        assertEquals("application/json", contentType(json));
        Map<?, ?> doc = (Map<?, ?>) Json.parse(json.body());
        List<?> stats = (List<?>) doc.get("stats");
        assertEquals(Map.of("name", "server.live", "value", 1L), stats.getFirst());
        assertEquals(2, stats.size(), "the stat, then the histograms");

        HttpResponse<String> prometheusForm = get("/stats?format=prometheus&filter=server%5C.state");
        assertEquals(StatsFormatter.PROMETHEUS_CONTENT_TYPE, contentType(prometheusForm));
        assertTrue(prometheusForm.body().contains("envoy_server_state 0\n"));

        assertEquals(400, get("/stats?filter=%5B").statusCode());
        assertEquals(400, get("/stats?format=xml").statusCode());
        assertTrue(raw(proxy.getAdminAddress(), "GET /stats?filter=%ZZ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .startsWith("HTTP/1.1 400"));
    }

    @Test
    void thePrometheusExpositionParses() throws Exception {
        proxy = withAdmin().withName("edge").start();
        proxyGet("/one");
        proxyGet("/two");
        HttpResponse<String> r = get("/stats/prometheus");
        assertEquals("text/plain; version=0.0.4; charset=utf-8", contentType(r));
        Map<String, String> types = PrometheusText.check(r.body());
        assertEquals("counter", types.get("envoy_http_downstream_rq_total"));
        assertEquals("gauge", types.get("envoy_server_state"));
        assertEquals("histogram", types.get("envoy_http_downstream_rq_time"));
        assertTrue(r.body().contains("envoy_http_downstream_rq_total{envoy_http_conn_manager_prefix=\"edge\"} 2\n"), r.body());
        eventually("a zero gauge left out by usedonly", () -> {
            try {
                String used = get("/stats/prometheus?usedonly&filter=downstream_rq").body();
                PrometheusText.check(used);
                return used.contains("downstream_rq_total") && !used.contains("downstream_rq_active");
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        });
    }

    @Test
    void readyFollowsTheStateAndTheHealthCheck() throws Exception {
        proxy = withAdmin().withHealthCheckPath("/healthz", false).start();
        HttpResponse<String> ready = get("/ready");
        assertEquals(200, ready.statusCode());
        assertEquals("LIVE\n", ready.body());

        HttpResponse<String> fail = post("/healthcheck/fail");
        assertEquals(200, fail.statusCode());
        assertEquals("OK\n", fail.body());
        assertTrue(proxy.isHealthCheckFailed());
        assertEquals(503, get("/ready").statusCode());
        assertEquals("HEALTH_CHECK_FAILED\n", get("/ready").body());
        HttpResponse<String> probe = HTTP.send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + proxy.getListenAddress().getPort() + "/healthz")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(503, probe.statusCode(), "the health-check path fails too");
        assertTrue(get("/server_info").body().contains("\"health_check_failed\": true"));

        assertEquals(200, post("/healthcheck/ok").statusCode());
        assertEquals("LIVE\n", get("/ready").body());

        assertEquals(200, post("/drain_listeners").statusCode());
        HttpResponse<String> draining = get("/ready");
        assertEquals(503, draining.statusCode());
        assertEquals("DRAINING\n", draining.body());
    }

    @Test
    void serverInfoSaysWhatRunsAndRedactsTheCommandLine() throws Exception {
        proxy = withAdmin().withHttp2Cleartext(true).withAdminToken("tok3n")
                .withCommandLineOptions(List.of("--port", "0", "--metrics", "--admin-token", "tok3n",
                        "--upstream-proxy", "http://user:pw0rd@proxy.example:3128", "--throttle", "1", "2",
                        "--ignore-hosts", "a", "--ignore-hosts", "b", "--script-var", "SECRET=hush",
                        "--mitm-ca-password", "capw"))
                .start();
        HttpResponse<String> r = admin("GET", "/server_info", "Authorization", "Bearer tok3n");
        assertEquals(200, r.statusCode());
        for (String secret : List.of("tok3n", "pw0rd", "hush", "capw")) {
            assertFalse(r.body().contains(secret), secret + " in " + r.body());
        }
        Map<?, ?> info = (Map<?, ?>) Json.parse(r.body());
        assertTrue(((String) info.get("version")).matches("[0-9]+\\.[0-9]+\\.[0-9]+.*"), "version " + info.get("version"));
        assertEquals("LIVE", info.get("state"));
        assertTrue(((String) info.get("uptime_current_epoch")).matches("[0-9]+s"));
        Map<?, ?> features = (Map<?, ?>) info.get("features");
        assertEquals(true, features.get("h2c"));
        assertEquals(false, features.get("h3"));
        assertEquals(true, features.get("metrics"));
        assertEquals(false, features.get("mitm"));
        Map<?, ?> jvm = (Map<?, ?>) info.get("jvm");
        assertEquals(Runtime.version().toString(), jvm.get("version"));
        assertEquals(ProcessHandle.current().pid(), jvm.get("pid"));
        List<?> listeners = (List<?>) info.get("listeners");
        assertEquals(1, listeners.size());
        Map<?, ?> options = (Map<?, ?>) info.get("command_line_options");
        assertEquals("0", options.get("--port"));
        assertEquals(true, options.get("--metrics"));
        assertEquals("[redacted]", options.get("--admin-token"));
        assertEquals("[redacted]", options.get("--mitm-ca-password"));
        assertEquals("http://[redacted]@proxy.example:3128", options.get("--upstream-proxy"));
        assertEquals(List.of("1", "2"), options.get("--throttle"));
        assertEquals(List.of("a", "b"), options.get("--ignore-hosts"));
        assertEquals("SECRET=[redacted]", options.get("--script-var"));
    }

    @Test
    void listenersShowAddressesAndProtocols() throws Exception {
        proxy = withAdmin().withName("edge").withHttp2Cleartext(true).withSocksDetection(true).start();
        String port = Integer.toString(proxy.getListenAddress().getPort());
        assertEquals("edge::127.0.0.1:" + port + "::tcp::http/1.1,h2c,socks5,socks4\n", get("/listeners").body());
        Map<?, ?> doc = (Map<?, ?>) Json.parse(get("/listeners?format=json").body());
        Map<?, ?> listener = (Map<?, ?>) ((List<?>) doc.get("listener_statuses")).getFirst();
        assertEquals("edge", listener.get("name"));
        assertEquals("127.0.0.1:" + port, listener.get("local_address"));
        assertEquals(List.of("http/1.1", "h2c", "socks5", "socks4"), listener.get("protocols"));
        assertEquals(true, listener.get("accepting"));
        post("/drain_listeners?inboundonly");
        assertTrue(get("/listeners").body().endsWith("::not_accepting\n"));
    }

    /** The HTTP/2 section of the bootstrap's config dump, without its options. */
    private Map<?, ?> http2ConfigDump() throws Exception {
        List<?> configs = (List<?>) ((Map<?, ?>) Json.parse(get("/config_dump").body())).get("configs");
        Map<Object, Object> http2 = new HashMap<>(
                (Map<?, ?>) ((Map<?, ?>) ((Map<?, ?>) configs.get(0)).get("bootstrap")).get("http2"));
        assertNotNull(http2.remove("options"));
        return http2;
    }

    private Map<?, ?> features() throws Exception {
        return (Map<?, ?>) ((Map<?, ?>) Json.parse(get("/server_info").body())).get("features");
    }

    /**
     * HTTP/2 to clients and servers is on by default, which the server info, the listeners and the
     * config dump show, and turned off they say so.
     */
    @Test
    void http2DefaultsShowInServerInfoListenersAndConfigDump() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("Admin H2 CA");
        proxy = withAdmin().withSslContextSource(() -> ca.serverContext("localhost")).start();
        String listeners = get("/listeners").body();
        assertTrue(listeners.endsWith("::tcp::tls,http/1.1,h2\n"), listeners);
        assertEquals(true, features().get("h2"));
        assertEquals(true, features().get("h2_upstream"));
        assertEquals(false, features().get("h2c"));
        assertEquals(Map.of("downstream", true, "upstream", true, "cleartext", false),
                http2ConfigDump());
        proxy.abort();

        proxy = withAdmin().withSslContextSource(() -> ca.serverContext("localhost")).withHttp2(false)
                .withHttp2Upstream(false).start();
        listeners = get("/listeners").body();
        assertTrue(listeners.endsWith("::tcp::tls,http/1.1\n"), listeners);
        assertEquals(false, features().get("h2"));
        assertEquals(false, features().get("h2_upstream"));
        assertEquals(Map.of("downstream", false, "upstream", false, "cleartext", false),
                http2ConfigDump());
        proxy.abort();

        // A plain forward proxy has nothing to serve h2 on (no TLS listener, no interception).
        proxy = withAdmin().start();
        assertEquals(false, features().get("h2"));
        assertEquals(true, features().get("h2_upstream"));
    }

    @Test
    void clustersShowTheirStatsPoolAndHealth() throws Exception {
        proxy = withAdmin().withSharedServerConnectionPool(true).start();
        proxyGet("/x");
        eventually("the request counted", () -> {
            try {
                return get("/clusters").body().contains("direct::upstream_rq_2xx::1\n");
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        });
        String text = get("/clusters").body();
        assertTrue(text.startsWith("direct::type::direct\ndirect::health_flags::healthy\n"), text);
        assertTrue(text.contains("direct::connection_pool::total_connections::"), text);
        assertFalse(text.contains("cache::"), "no cache configured, none used: " + text);
        Map<?, ?> doc = (Map<?, ?>) Json.parse(get("/clusters?format=json").body());
        List<?> clusters = (List<?>) doc.get("cluster_statuses");
        Map<?, ?> direct = (Map<?, ?>) clusters.getFirst();
        assertEquals("direct", direct.get("name"));
        Map<?, ?> stats = (Map<?, ?>) direct.get("stats");
        assertEquals(1L, stats.get("upstream_rq_total"));
        assertEquals(1L, ((Map<?, ?>) stats.get("upstream_rq_time")).get("count"));
        assertNotNull(direct.get("connection_pool"));
    }

    @Test
    void perHostAndChainedProxyClustersAreListedByKind() throws Exception {
        proxy = withAdmin().withStats(org.microproxy.stats.StatsRegistry.builder().perHostClusters(true).build()).start();
        proxyGet("/x");
        String host = "127_0_0_1_" + origin.getAddress().getPort();
        eventually("the host cluster", () -> {
            try {
                return get("/clusters").body().contains(host + "::type::host\n");
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        });
    }

    @Test
    void theConfigDumpRedactsSecrets(@TempDir Path dir) throws Exception {
        Path keyStore = dir.resolve("listener.p12");
        CertificateAuthority.generate("listener").save(keyStore, "ks-pa55".toCharArray());
        CertificateAuthority ca = CertificateAuthority.generate("Admin Test CA");
        proxy = withAdmin().withAdminToken("adm1n-t0ken")
                .withSslContextSource(new KeyStoreSslContextSource(keyStore, "ks-pa55".toCharArray()))
                .withProxyAuthenticator((user, password) -> "alice".equals(user) && "auth-pa55".equals(password))
                .withChainProxyManager(new UpstreamProxyManager("http://bob:chain-pa55@127.0.0.1:1", null, null))
                .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
                .withCommandLineOptions(List.of("--listener-keystore-password", "ks-pa55"))
                .start();
        HttpResponse<String> r = admin("GET", "/config_dump", "Authorization", "Bearer adm1n-t0ken");
        assertEquals(200, r.statusCode());
        String body = r.body();
        String key = Base64.getEncoder().encodeToString(ca.getPrivateKey().getEncoded());
        for (String secret : List.of("adm1n-t0ken", "ks-pa55", "auth-pa55", "chain-pa55", "bob", "PRIVATE KEY",
                key.substring(key.length() - 40))) {
            assertFalse(body.contains(secret), secret + " in " + body);
        }
        Map<?, ?> doc = (Map<?, ?>) Json.parse(body);
        List<?> configs = (List<?>) doc.get("configs");
        Map<?, ?> boot = (Map<?, ?>) ((Map<?, ?>) configs.get(0)).get("bootstrap");
        assertEquals("type.microproxy/BootstrapConfigDump", ((Map<?, ?>) configs.get(0)).get("@type"));
        assertEquals("[redacted]", ((Map<?, ?>) boot.get("listener_tls")).get("key_store_password"));
        assertEquals("[redacted]", ((Map<?, ?>) boot.get("proxy_authentication")).get("credentials"));
        Map<?, ?> mitm = (Map<?, ?>) boot.get("mitm");
        assertEquals("[redacted]", mitm.get("ca_private_key"));
        assertTrue(((String) mitm.get("ca_subject")).startsWith("CN=Admin Test CA"), (String) mitm.get("ca_subject"));
        String proxies = (String) ((Map<?, ?>) boot.get("chained_proxy")).get("proxies");
        assertTrue(proxies.contains("http://[redacted]@127.0.0.1:1"), proxies);
        Map<?, ?> admin = (Map<?, ?>) ((Map<?, ?>) configs.get(1)).get("admin");
        assertEquals("[redacted]", admin.get("token"));
        Map<?, ?> commandLine = (Map<?, ?>) ((Map<?, ?>) configs.get(2)).get("command_line_options");
        assertEquals("[redacted]", commandLine.get("--listener-keystore-password"));
        assertEquals(Map.of("time", "PT10S", "strategy", "gradual"), boot.get("drain"));
    }

    @Test
    void loggingListsAndSetsLevels() throws Exception {
        proxy = withAdmin().start();
        Logger impl = Logger.getLogger("org.microproxy.impl");
        Logger root = Logger.getLogger("org.microproxy");
        Level implBefore = impl.getLevel();
        Level rootBefore = root.getLevel();
        java.util.logging.Handler[] handlers = Logger.getLogger("").getHandlers();
        Level[] handlerLevels = new Level[handlers.length];
        for (int i = 0; i < handlers.length; i++) handlerLevels[i] = handlers[i].getLevel();
        try {
            String list = get("/logging").body();
            assertTrue(list.startsWith("active loggers:\n"), list);
            assertTrue(list.contains("  org.microproxy.impl.AdminServer: "), list);
            assertTrue(list.contains("  org.microproxy: "), list);

            HttpResponse<String> one = post("/logging?org.microproxy.impl=debug");
            assertEquals(200, one.statusCode());
            assertEquals(Level.FINE, impl.getLevel());
            assertTrue(one.body().contains("  org.microproxy.impl: debug\n"), one.body());
            assertTrue(one.body().contains("  org.microproxy.impl.AdminServer: debug\n"), "inherited: " + one.body());

            HttpResponse<String> all = post("/logging?level=warning");
            assertEquals(200, all.statusCode());
            assertEquals(Level.WARNING, impl.getLevel());
            assertEquals(Level.WARNING, root.getLevel());
            assertFalse(all.body().contains(": debug\n"), all.body());
            post("/logging?org.microproxy=TRACE");
            assertEquals(Level.FINEST, root.getLevel());

            assertEquals(400, post("/logging?level=loud").statusCode());
            assertEquals(400, post("/logging?com.example=debug").statusCode());
            assertEquals(Level.FINEST, root.getLevel(), "a bad request changes nothing");
            assertEquals(200, post("/logging").statusCode(), "without parameters it lists");
        } finally {
            for (int i = 0; i < handlers.length; i++) handlers[i].setLevel(handlerLevels[i]);
            impl.setLevel(implBefore);
            root.setLevel(rootBefore);
            for (String name : java.util.Collections.list(java.util.logging.LogManager.getLogManager().getLoggerNames())) {
                Logger l = Logger.getLogger(name);
                if (name.startsWith("org.microproxy.") && l.getLevel() == Level.WARNING) l.setLevel(null);
            }
        }
    }

    @Test
    void aGracefulDrainThroughTheAdminLetsTheRequestFinishAndThenStopsAccepting() throws Exception {
        proxy = withAdmin().withDrainTime(Duration.ofMillis(1500)).withDrainStrategy(DrainStrategy.IMMEDIATE).start();
        InetSocketAddress address = proxy.getListenAddress();
        try (DrainTest.Client inFlight = new DrainTest.Client(address)) {
            inFlight.send(TestSupport.url(origin, "/slow"));
            assertTrue(slowArrived.await(10, TimeUnit.SECONDS));
            long started = System.nanoTime();
            assertEquals(200, post("/drain_listeners?graceful&inboundonly").statusCode());
            assertEquals(503, get("/ready").statusCode());
            assertEquals("DRAINING\n", get("/ready").body());
            assertTrue(get("/stats?filter=%5Eserver%5C.state").body().contains("server.state: 1\n"));

            // Still accepting, each new request told to go elsewhere.
            try (DrainTest.Client late = new DrainTest.Client(address)) {
                DrainTest.Response r = late.get(TestSupport.url(origin, "/late"));
                assertEquals("done /late", r.body());
                assertEquals("close", r.headers().get("connection"));
            }
            release.countDown();
            assertEquals("done /slow", inFlight.read().body());

            eventually("the listener closed after the drain time", () -> {
                try {
                    new Socket(address.getAddress(), address.getPort()).close();
                    return false;
                } catch (IOException e) {
                    return e instanceof ConnectException;
                }
            });
            assertTrue(System.nanoTime() - started >= Duration.ofMillis(1400).toNanos());
        }
        assertEquals("DRAINING\n", get("/ready").body(), "the admin listener outlives the drain");

        assertEquals(200, post("/quitquitquit").statusCode());
        eventually("stopped", () -> proxy.state() == ServerState.STOPPED);
        eventually("the admin listener closed with the proxy", () -> proxy.getAdminAddress() == null);
    }

    @Test
    void theAdminListenerComesFromPropertiesAndCannotShareAPort(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("proxy.properties");
        Files.writeString(file, "port = 0\nadmin_port = 0\nadmin_token = from-file\ndrain_time = 2\n");
        proxy = MicroProxy.bootstrapFromFile(file).start();
        assertEquals(TestSupport.LOOPBACK, proxy.getAdminAddress().getAddress());
        assertEquals(401, get("/stats").statusCode());
        assertEquals(200, admin("GET", "/stats", "Authorization", "Bearer from-file").statusCode());
        assertEquals(Duration.ofSeconds(2), proxy.getDrainTime());
        InetSocketAddress taken = proxy.getAdminAddress();
        assertThrows(java.io.UncheckedIOException.class, () -> MicroProxy.bootstrap().withPort(0).withAdmin(taken).start());

        Properties p = new Properties();
        p.setProperty("admin_address", "127.0.0.1:0");
        Path second = dir.resolve("second.properties");
        try (var out = Files.newBufferedWriter(second)) {
            p.store(out, null);
        }
        HttpProxyServer other = MicroProxy.bootstrapFromFile(second).withPort(0).start();
        try {
            assertNotNull(other.getAdminAddress());
        } finally {
            other.stop();
        }
        assertNull(other.getAdminAddress());
    }

    @Test
    void aCloneKeepsAnAdminListenerOnlyOnAnyFreePort() throws Exception {
        proxy = withAdmin().start();
        HttpProxyServer clone = proxy.clone().withPort(0).start();
        try {
            assertNotNull(clone.getAdminAddress());
            assertTrue(clone.getAdminAddress().getPort() != proxy.getAdminAddress().getPort());
        } finally {
            clone.stop();
        }
        int fixed;
        try (java.net.ServerSocket s = new java.net.ServerSocket(0, 1, TestSupport.LOOPBACK)) {
            fixed = s.getLocalPort();
        }
        proxy.stop();
        proxy = MicroProxy.bootstrap().withPort(0).withAdmin(new InetSocketAddress(TestSupport.LOOPBACK, fixed)).start();
        assertEquals(fixed, proxy.getAdminAddress().getPort());
        HttpProxyServer second = proxy.clone().withPort(0).start();
        try {
            assertNull(second.getAdminAddress(), "the fixed port is the first server's");
        } finally {
            second.stop();
        }
    }

    // ---------------------------------------------------------------------------------------

    /**
     * A check of Prometheus's text format 0.0.4, as a scraper reads it: every line a comment
     * ({@code # HELP} or {@code # TYPE}) or a sample {@code name{labels} value}; a family's {@code
     * TYPE} before its samples, once; a histogram's buckets cumulative, ending at {@code +Inf} with
     * its {@code _count}.
     */
    static final class PrometheusText {
        private static final Pattern NAME = Pattern.compile("[a-zA-Z_:][a-zA-Z0-9_:]*");
        private static final Pattern SAMPLE = Pattern.compile(
                "(" + NAME + ")(?:\\{((?:[a-zA-Z_][a-zA-Z0-9_]*=\"(?:[^\"\\\\\\n]|\\\\[\\\\\"n])*\",?)*)\\})? "
                        + "(-?[0-9.eE+-]+|NaN|[+-]Inf)");
        private static final Pattern LABEL = Pattern.compile("([a-zA-Z_][a-zA-Z0-9_]*)=\"((?:[^\"\\\\]|\\\\.)*)\"");

        /** Checks {@code text}; returns the families' types by name. */
        static Map<String, String> check(String text) {
            Map<String, String> types = new HashMap<>();
            Map<String, Double> lastBucket = new HashMap<>();
            Map<String, Double> infBucket = new HashMap<>();
            assertTrue(text.isEmpty() || text.endsWith("\n"), "ends with a newline");
            for (String line : text.split("\n")) {
                if (line.startsWith("# HELP ")) {
                    assertTrue(NAME.matcher(line.substring(7).split(" ", 2)[0]).matches(), line);
                } else if (line.startsWith("# TYPE ")) {
                    String[] parts = line.substring(7).split(" ");
                    assertEquals(2, parts.length, line);
                    assertTrue(List.of("counter", "gauge", "histogram", "summary", "untyped").contains(parts[1]), line);
                    assertNull(types.put(parts[0], parts[1]), "one TYPE per family: " + line);
                } else {
                    Matcher m = SAMPLE.matcher(line);
                    assertTrue(m.matches(), "a sample: " + line);
                    String name = m.group(1);
                    double value = Double.parseDouble(m.group(3).replace("Inf", "Infinity"));
                    String family = types.containsKey(name) ? name : name.replaceFirst("_(bucket|sum|count)$", "");
                    String type = types.get(family);
                    assertNotNull(type, "TYPE before the samples of " + name);
                    if (type.equals("counter")) assertTrue(value >= 0, line);
                    Map<String, String> labels = new LinkedHashMap<>();
                    if (m.group(2) != null) {
                        Matcher l = LABEL.matcher(m.group(2));
                        while (l.find()) assertNull(labels.put(l.group(1), l.group(2)), "a label once: " + line);
                    }
                    if (type.equals("histogram") && name.endsWith("_bucket")) {
                        String le = labels.remove("le");
                        assertNotNull(le, line);
                        String series = family + labels;
                        Double previous = lastBucket.put(series, value);
                        assertTrue(previous == null || previous <= value, "cumulative buckets: " + line);
                        if (le.equals("+Inf")) infBucket.put(series, value);
                    } else if (type.equals("histogram") && name.endsWith("_count")) {
                        assertEquals(infBucket.get(family + labels), value, "+Inf bucket = count: " + line);
                    }
                }
            }
            return types;
        }
    }

    /** A small JSON reader for the admin's answers: objects (in order), arrays, strings, numbers (long or double), booleans, null. */
    static final class Json {
        private final String s;
        private int i;

        private Json(String s) {
            this.s = s;
        }

        static Object parse(String text) {
            Json p = new Json(text);
            Object v = p.value();
            p.space();
            if (p.i != text.length()) throw new IllegalArgumentException("trailing data at " + p.i);
            return v;
        }

        private void space() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        }

        private Object value() {
            space();
            char c = s.charAt(i);
            switch (c) {
                case '{' -> {
                    i++;
                    Map<String, Object> m = new LinkedHashMap<>();
                    space();
                    if (s.charAt(i) == '}') {
                        i++;
                        return m;
                    }
                    while (true) {
                        space();
                        String k = string();
                        space();
                        expect(':');
                        if (m.put(k, value()) != null) throw new IllegalArgumentException("duplicate key " + k);
                        space();
                        if (s.charAt(i) == ',') {
                            i++;
                        } else {
                            expect('}');
                            return m;
                        }
                    }
                }
                case '[' -> {
                    i++;
                    List<Object> l = new ArrayList<>();
                    space();
                    if (s.charAt(i) == ']') {
                        i++;
                        return l;
                    }
                    while (true) {
                        l.add(value());
                        space();
                        if (s.charAt(i) == ',') {
                            i++;
                        } else {
                            expect(']');
                            return l;
                        }
                    }
                }
                case '"' -> {
                    return string();
                }
                default -> {
                    if (s.startsWith("true", i)) {
                        i += 4;
                        return true;
                    }
                    if (s.startsWith("false", i)) {
                        i += 5;
                        return false;
                    }
                    if (s.startsWith("null", i)) {
                        i += 4;
                        return null;
                    }
                    int start = i;
                    while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
                    String n = s.substring(start, i);
                    if (n.isEmpty()) throw new IllegalArgumentException("unexpected " + c + " at " + start);
                    return n.matches("-?[0-9]+") ? (Object) Long.parseLong(n) : (Object) Double.parseDouble(n);
                }
            }
        }

        private String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') return sb.toString();
                if (c < 0x20) throw new IllegalArgumentException("control character in a string at " + i);
                if (c == '\\') {
                    char e = s.charAt(i++);
                    switch (e) {
                        case 'n' -> sb.append('\n');
                        case 't' -> sb.append('\t');
                        case 'r' -> sb.append('\r');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'u' -> {
                            sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            i += 4;
                        }
                        default -> sb.append(e);
                    }
                } else {
                    sb.append(c);
                }
            }
        }

        private void expect(char c) {
            if (s.charAt(i) != c) throw new IllegalArgumentException("expected " + c + " at " + i + ", got " + s.charAt(i));
            i++;
        }
    }
}
