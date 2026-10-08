package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.microproxy.cache.DiskCacheStore;
import org.microproxy.cache.MemoryCacheStore;
import org.microproxy.dns.DnssecHostResolver;
import org.microproxy.extras.ActivityLogger;
import org.microproxy.extras.LogFormat;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpVersion;
import org.microproxy.impl.BootstrapView;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.warc.WarcRecorder;

/**
 * The command line: every {@link Launcher} flag is parsed into the bootstrap it should configure
 * (without starting a server), and a few launches check the flags end to end.
 */
class LauncherTest {

    private final ByteArrayOutputStream console = new ByteArrayOutputStream();
    private final List<HttpProxyServer> servers = new ArrayList<>();
    private final List<AutoCloseable> closeables = new ArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        servers.forEach(HttpProxyServer::abort);
        for (AutoCloseable c : closeables) {
            c.close();
        }
    }

    private PrintStream out() {
        return new PrintStream(console, true, StandardCharsets.UTF_8);
    }

    private Launcher.Parsed parse(String... args) throws IOException {
        Launcher.Parsed parsed = Launcher.parse(args, out());
        if (parsed != null) closeables.addAll(parsed.resources());
        return parsed;
    }

    private BootstrapView view(String... args) throws IOException {
        return BootstrapView.of(parse(args).bootstrap());
    }

    private HttpProxyServer launch(String... args) throws IOException {
        HttpProxyServer server = Launcher.start(args, out());
        servers.add(server);
        return server;
    }

    private HttpServer origin(com.sun.net.httpserver.HttpHandler handler) {
        HttpServer origin = TestSupport.origin(handler);
        closeables.add(() -> origin.stop(0));
        return origin;
    }

    private static List<ChainedProxy> route(ChainedProxyManager manager, HttpMethod method, String uri) {
        Queue<ChainedProxy> queue = new ArrayDeque<>();
        manager.lookupChainedProxies(new DefaultHttpRequest(HttpVersion.HTTP_1_1, method, uri), queue, null);
        return List.copyOf(queue);
    }

    // --- help, defaults, unknown options ------------------------------------------------------

    @Test
    void helpListsEveryOptionAndStartsNothing() throws IOException {
        assertNull(Launcher.start(new String[] {"--help"}, out()));
        String usage = console.toString(StandardCharsets.UTF_8);
        for (String flag : List.of("--config", "--port", "--address", "--server", "--name", "--transparent",
                "--idle-timeout", "--connect-timeout", "--proxy-alias", "--throttle", "--accept-proxy-protocol",
                "--send-proxy-protocol", "--upstream-proxy", "--upstream-https-proxy", "--no-proxy", "--env-proxy",
                "--dnssec", "--dnssec-resolver", "--activity-log-format", "--shared-pool", "--cache-dir",
                "--cache-size", "--cache-memory", "--offline", "--warc-dir", "--mitm", "--mitm-ca",
                "--mitm-ca-password", "--mitm-trust-all", "--help")) {
            assertTrue(usage.contains(flag + " "), "usage lacks " + flag);
        }
        console.reset();
        assertNull(Launcher.parse(new String[] {"--port", "0", "-h"}, out()), "-h also only prints help");
        assertTrue(console.toString(StandardCharsets.UTF_8).startsWith("Usage:"));
    }

    @Test
    void noArgumentsGiveTheDefaults() throws IOException {
        BootstrapView v = view();
        assertEquals("MicroProxy", v.name());
        assertEquals(8080, v.address().getPort());
        assertTrue(v.address().getAddress().isLoopbackAddress(), "local only by default");
        assertTrue(v.allowLocalOnly());
        assertFalse(v.transparent());
        assertEquals(Duration.ofSeconds(70), v.idleConnectionTimeout());
        assertEquals(40_000, v.connectTimeoutMs());
        assertNull(v.proxyAlias());
        assertEquals(0, v.readThrottle());
        assertEquals(0, v.writeThrottle());
        assertFalse(v.acceptProxyProtocol());
        assertFalse(v.sendProxyProtocol());
        assertNull(v.chainProxyManager());
        assertNull(v.mitmManager());
        assertNull(v.httpCache());
        assertInstanceOf(DefaultHostResolver.class, v.serverResolver());
        assertTrue(v.activityTrackers().isEmpty());
        assertFalse(v.sharedServerConnectionPool());
    }

    @Test
    void unknownOptionsAndStrayArgumentsAreRejectedWithTheUsage() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> parse("--bogus"));
        assertTrue(e.getMessage().startsWith("unknown option: --bogus"), e.getMessage());
        assertTrue(e.getMessage().contains("Usage:"), "the error shows the usage");
        assertThrows(IllegalArgumentException.class, () -> parse("extra", "arguments"));
        // Underscored LittleProxy spellings are not accepted.
        assertThrows(IllegalArgumentException.class, () -> parse("--proxy_alias", "x"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"--config", "--port", "--address", "--name", "--idle-timeout", "--connect-timeout",
        "--proxy-alias", "--throttle", "--upstream-proxy", "--upstream-https-proxy", "--no-proxy",
        "--dnssec-resolver", "--activity-log-format", "--cache-dir", "--cache-size", "--cache-memory",
        "--warc-dir", "--mitm-ca", "--mitm-ca-password"})
    void optionsWithoutTheirValueAreRejected(String flag) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> parse("--port", "0", flag));
        assertEquals(flag + " needs a value", e.getMessage());
    }

    @Test
    void throttleNeedsBothRates() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> parse("--throttle", "1000"));
        assertEquals("--throttle needs a value", e.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"--port", "--idle-timeout", "--connect-timeout", "--cache-size", "--cache-memory"})
    void nonNumericValuesNameTheOption(String flag) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> parse(flag, "lots"));
        assertEquals(flag + " needs a number, got: lots", e.getMessage());
    }

    @Test
    void badThrottleAndLogFormatValuesAreExplained() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> parse("--throttle", "1k", "2k"));
        assertEquals("--throttle needs a number, got: 1k", e.getMessage());
        e = assertThrows(IllegalArgumentException.class, () -> parse("--activity-log-format", "fancy"));
        assertTrue(e.getMessage().startsWith("unknown --activity-log-format: fancy; expected one of [CLF, "),
                e.getMessage());
    }

    @Test
    void missingOrDirectoryConfigFilesAreUsageErrors(@TempDir Path dir) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> parse("--config", dir.resolve("absent.properties").toString()));
        assertTrue(e.getMessage().startsWith("--config file not found: "), e.getMessage());
        assertTrue(e.getMessage().endsWith("absent.properties"), e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> parse("--config", dir.toString()));
    }

    @Test
    void outOfRangePortsFailToStart() {
        assertThrows(IllegalArgumentException.class, () -> launch("--port", "-1"));
        assertThrows(IllegalArgumentException.class, () -> launch("--port", "999999"));
    }

    // --- listening -----------------------------------------------------------------------------

    @Test
    void portAddressServerAndName() throws IOException {
        assertEquals(0, view("--port", "0").address().getPort());
        assertEquals(new InetSocketAddress("127.0.0.1", 9999), view("--address", "127.0.0.1:9999").address());
        assertEquals(new InetSocketAddress("127.0.0.1", 8080), view("--address", "127.0.0.1").address(),
                "the port defaults to 8080");
        InetSocketAddress v6 = view("--address", "[::1]:0").address();
        assertTrue(v6.getAddress().isLoopbackAddress() && v6.getAddress().getAddress().length == 16, v6.toString());
        // The last of --port / --address wins.
        assertEquals(7000, view("--address", "127.0.0.1:9999", "--port", "7000").address().getPort());

        BootstrapView server = view("--server", "--port", "0");
        assertFalse(server.allowLocalOnly());
        assertTrue(server.address().getAddress().isAnyLocalAddress(), server.address().toString());

        assertEquals("edge-7", view("--name", "edge-7").name());
    }

    @Test
    void launchedServerListensWhereToldAndIsNamed() throws IOException {
        HttpProxyServer proxy = launch("--address", "127.0.0.1:0", "--name", "launched-by-test");
        assertEquals("127.0.0.1", proxy.getListenAddress().getAddress().getHostAddress());
        assertTrue(proxy.getListenAddress().getPort() > 0);
        assertTrue(Thread.getAllStackTraces().keySet().stream()
                .anyMatch(t -> t.getName().equals("launched-by-test-acceptor")), "threads carry the --name");
        assertTrue(console.toString(StandardCharsets.UTF_8).contains("MicroProxy listening on " + proxy.getListenAddress()));
        HttpServer origin = origin(echo());
        assertEquals(200, get(client(proxy), url(origin, "/")).statusCode());
    }

    @Test
    void serverFlagListensOnAllInterfaces() throws IOException {
        HttpProxyServer proxy = launch("--server", "--port", "0");
        assertTrue(proxy.getListenAddress().getAddress().isAnyLocalAddress(), proxy.getListenAddress().toString());
    }

    // --- message handling and timeouts ---------------------------------------------------------

    @Test
    void transparentAliasAndTimeoutsAreParsed() throws IOException {
        BootstrapView v = view("--transparent", "--proxy-alias", "gw", "--idle-timeout", "5",
                "--connect-timeout", "1234");
        assertTrue(v.transparent());
        assertEquals("gw", v.proxyAlias());
        assertEquals(Duration.ofSeconds(5), v.idleConnectionTimeout());
        assertEquals(1234, v.connectTimeoutMs());
        assertEquals(Duration.ZERO, view("--idle-timeout", "0").idleConnectionTimeout(), "0 disables the timeout");
    }

    @Test
    void proxyAliasAndTimeoutsReachTheRunningServer() throws IOException {
        HttpServer origin = origin(echo());
        HttpProxyServer proxy = launch("--port", "0", "--proxy-alias", "via-flag", "--idle-timeout", "9",
                "--connect-timeout", "4321");
        assertEquals(Duration.ofSeconds(9), proxy.getIdleConnectionTimeout());
        assertEquals(4321, proxy.getConnectTimeout());
        assertEquals(List.of("1.1 via-flag"), echoedHeader(get(client(proxy), url(origin, "/")).body(), "via"));
    }

    @Test
    void transparentProxyAddsNoVia() throws IOException {
        HttpServer origin = origin(echo());
        HttpProxyServer proxy = launch("--port", "0", "--transparent");
        String body = get(client(proxy), url(origin, "/")).body();
        assertTrue(echoedHeader(body, "via").isEmpty(), body);
    }

    @Test
    void throttleSetsBothRates() throws IOException {
        BootstrapView v = view("--throttle", "1000", "2000");
        assertEquals(1000, v.readThrottle());
        assertEquals(2000, v.writeThrottle());
        HttpProxyServer proxy = launch("--port", "0", "--throttle", "3000", "4000");
        assertEquals(List.of(3000L, 4000L), List.of(BootstrapView.currentThrottle(proxy)[0],
                BootstrapView.currentThrottle(proxy)[1]));
    }

    // --- PROXY protocol ------------------------------------------------------------------------

    @Test
    void proxyProtocolFlags() throws IOException {
        assertTrue(view("--accept-proxy-protocol").acceptProxyProtocol());
        assertTrue(view("--send-proxy-protocol").sendProxyProtocol());
    }

    @Test
    void acceptProxyProtocolRequiresTheHeader() throws IOException {
        HttpServer origin = origin(TestSupport.fixed(200, "ok"));
        HttpProxyServer proxy = launch("--port", "0", "--accept-proxy-protocol");
        String request = "GET " + url(origin, "/") + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        assertFalse(TestSupport.rawExchange(proxy.getListenAddress(), request).startsWith("HTTP/1.1 200"));
        String withHeader = TestSupport.rawExchange(proxy.getListenAddress(),
                "PROXY TCP4 192.0.2.1 127.0.0.1 5555 80\r\n" + request);
        assertTrue(withHeader.startsWith("HTTP/1.1 200"), withHeader);
    }

    @Test
    void sendProxyProtocolPrefixesServerConnections() throws Exception {
        AtomicReference<String> seen = new AtomicReference<>();
        try (TestSupport.RawServer raw = TestSupport.rawServer(s -> {
            seen.set(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n"));
            TestSupport.write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        })) {
            HttpProxyServer proxy = launch("--port", "0", "--send-proxy-protocol");
            assertEquals("ok", get(client(proxy), "http://127.0.0.1:" + raw.port() + "/").body());
            assertTrue(seen.get().startsWith("PROXY TCP4 127.0.0.1 127.0.0.1 "), seen.get());
        }
    }

    // --- upstream proxies ----------------------------------------------------------------------

    @Test
    void upstreamProxyFlagsBuildTheRoutes() throws IOException {
        BootstrapView v = view("--upstream-proxy", "http://alice:s3cret@127.0.0.1:3128",
                "--upstream-https-proxy", "socks5://127.0.0.1:1080", "--no-proxy", "internal.test,.corp");
        ChainedProxyManager manager = v.chainProxyManager();
        assertInstanceOf(UpstreamProxyManager.class, manager);

        ChainedProxy http = route(manager, HttpMethod.GET, "http://example.com/").get(0);
        assertEquals("127.0.0.1", http.getChainedProxyAddress().getHostString());
        assertEquals(3128, http.getChainedProxyAddress().getPort());
        assertEquals(ChainedProxyType.HTTP, http.getChainedProxyType());
        assertEquals("alice", http.getUsername());
        assertEquals("s3cret", http.getPassword());

        ChainedProxy https = route(manager, HttpMethod.CONNECT, "example.com:443").get(0);
        assertEquals(ChainedProxyType.SOCKS5, https.getChainedProxyType());
        assertEquals(1080, https.getChainedProxyAddress().getPort());

        assertEquals(List.of(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION),
                route(manager, HttpMethod.GET, "http://internal.test/"));
        assertEquals(List.of(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION),
                route(manager, HttpMethod.CONNECT, "www.corp:443"));
    }

    @Test
    void httpsUpstreamDefaultsToTheHttpOne() throws IOException {
        ChainedProxyManager manager = view("--upstream-https-proxy", "http://127.0.0.1:3129").chainProxyManager();
        assertEquals(3129, route(manager, HttpMethod.CONNECT, "example.com:443").get(0).getChainedProxyAddress().getPort());
        assertEquals(List.of(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION),
                route(manager, HttpMethod.GET, "http://example.com/"), "no plain-HTTP upstream was given");
        assertNull(view("--no-proxy", "example.com").chainProxyManager(), "--no-proxy alone configures nothing");
    }

    @Test
    void envProxyFollowsTheEnvironmentAndExplicitFlagsWin() throws IOException {
        boolean envHasProxy = UpstreamProxyManager.fromEnvironment(System.getenv()) != null;
        assertEquals(envHasProxy, view("--env-proxy").chainProxyManager() != null);
        ChainedProxyManager explicit = view("--env-proxy", "--upstream-proxy", "http://127.0.0.1:3130").chainProxyManager();
        assertEquals(3130, route(explicit, HttpMethod.GET, "http://example.com/").get(0).getChainedProxyAddress().getPort());
    }

    @Test
    void launchedProxyChainsThroughTheUpstreamExceptForNoProxyHosts() throws IOException {
        HttpServer origin = origin(echo());
        AtomicInteger upstreamRequests = new AtomicInteger();
        HttpProxyServer upstream = MicroProxy.bootstrap().withPort(0).withProxyAlias("upstream")
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void requestReceivedFromClient(FlowContext ctx, org.microproxy.http.HttpRequest req) {
                        upstreamRequests.incrementAndGet();
                    }
                }).start();
        servers.add(upstream);
        HttpProxyServer proxy = launch("--port", "0", "--upstream-proxy",
                "http://127.0.0.1:" + upstream.getListenAddress().getPort(), "--no-proxy", "localhost");
        HttpClient client = client(proxy);

        assertEquals(200, get(client, url(origin, "/chained")).statusCode());
        assertEquals(1, upstreamRequests.get());
        assertEquals(200, get(client, TestSupport.localhostUrl(origin, "/direct")).statusCode());
        assertEquals(1, upstreamRequests.get(), "localhost is reached directly");
    }

    // --- DNS, logging, pool --------------------------------------------------------------------

    @Test
    void dnssecLoggingAndPoolFlags() throws IOException {
        assertInstanceOf(DnssecHostResolver.class, view("--dnssec").serverResolver());
        assertInstanceOf(DnssecHostResolver.class, view("--dnssec-resolver", "9.9.9.9,1.1.1.1").serverResolver(),
                "--dnssec-resolver implies --dnssec");

        List<ActivityTracker> trackers = view("--activity-log-format", "json").activityTrackers();
        assertEquals(1, trackers.size());
        assertEquals(LogFormat.JSON, ((ActivityLogger) trackers.get(0)).getLogFormat(), "case-insensitive");
        assertEquals(2, view("--activity-log-format", "CLF", "--activity-log-format", "W3C").activityTrackers().size());

        assertTrue(view("--shared-pool").sharedServerConnectionPool());
    }

    @Test
    void sharedPoolFlagEnablesPoolMetrics() throws IOException {
        assertNull(launch("--port", "0").getServerConnectionPoolMetrics());
        assertNotNull(launch("--port", "0", "--shared-pool").getServerConnectionPoolMetrics());
    }

    // --- cache and WARC ------------------------------------------------------------------------

    @Test
    void cacheFlags(@TempDir Path dir) throws IOException {
        BootstrapView memory = view("--cache-memory", "2");
        assertInstanceOf(MemoryCacheStore.class, memory.httpCache().store());
        assertFalse(memory.httpCache().isOffline());

        BootstrapView disk = view("--cache-dir", dir.resolve("c").toString(), "--cache-size", "5", "--offline");
        assertInstanceOf(DiskCacheStore.class, disk.httpCache().store());
        assertTrue(disk.httpCache().isOffline());
        assertTrue(console.toString(StandardCharsets.UTF_8).contains("(offline: answering only from the cache)"));

        assertInstanceOf(DiskCacheStore.class,
                view("--cache-memory", "2", "--cache-dir", dir.resolve("d").toString()).httpCache().store(),
                "the disk cache wins when both are given");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> parse("--offline"));
        assertEquals("--offline needs --cache-dir or --cache-memory", e.getMessage());
    }

    @Test
    void memoryCacheAnswersRepeatRequests() throws IOException {
        AtomicInteger hits = new AtomicInteger();
        HttpServer origin = origin(exchange -> {
            byte[] body = ("hit " + hits.incrementAndGet()).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Cache-Control", "max-age=60");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        HttpProxyServer proxy = launch("--port", "0", "--cache-memory", "1");
        assertTrue(console.toString(StandardCharsets.UTF_8).contains("Caching in memory"));
        assertEquals("hit 1", get(client(proxy), url(origin, "/c")).body());
        assertEquals("hit 1", get(client(proxy), url(origin, "/c")).body());
        assertEquals(1, hits.get());
    }

    @Test
    void warcDirRecordsExchanges(@TempDir Path dir) throws Exception {
        Path warcDir = dir.resolve("warc");
        Launcher.Parsed parsed = parse("--port", "0", "--warc-dir", warcDir.toString());
        assertEquals(1, parsed.resources().size());
        WarcRecorder recorder = assertInstanceOf(WarcRecorder.class, parsed.resources().get(0));
        assertSame(recorder, parsed.bootstrap().getFiltersSource(), "the recorder runs as the (only) filter");
        assertTrue(console.toString(StandardCharsets.UTF_8).contains("Recording WARC files in"));

        HttpServer origin = origin(TestSupport.fixed(200, "archived"));
        HttpProxyServer proxy = parsed.bootstrap().start();
        servers.add(proxy);
        assertEquals("archived", get(client(proxy), url(origin, "/w")).body());
        for (int i = 0; i < 100 && recorder.recordedExchanges() == 0; i++) {
            Thread.sleep(20);
        }
        assertEquals(1, recorder.recordedExchanges());
        try (var files = Files.list(warcDir)) {
            assertTrue(files.anyMatch(f -> f.getFileName().toString().contains(".warc")), "a WARC file exists");
        }
    }

    // --- MITM ----------------------------------------------------------------------------------

    @Test
    void mitmFlagsLoadOrCreateTheCa(@TempDir Path dir) throws IOException {
        Path ca = dir.resolve("my-ca.p12");
        BootstrapView v = view("--mitm", "--mitm-ca", ca.toString(), "--mitm-ca-password", "pw1");
        CertificateAuthorityMitmManager mitm = assertInstanceOf(CertificateAuthorityMitmManager.class, v.mitmManager());
        assertTrue(Files.isRegularFile(dir.resolve("my-ca.pem")));
        assertTrue(console.toString(StandardCharsets.UTF_8).contains("trust the CA certificate in"));
        // The same CA comes back on the next start, under its password only.
        CertificateAuthority reloaded = CertificateAuthority.load(ca, "pw1".toCharArray());
        assertEquals(mitm.getCertificateAuthority().getCertificate(), reloaded.getCertificate());
        assertEquals(reloaded.getCertificate(),
                ((CertificateAuthorityMitmManager) view("--mitm", "--mitm-ca", ca.toString(), "--mitm-ca-password", "pw1")
                        .mitmManager()).getCertificateAuthority().getCertificate());
        assertThrows(IOException.class, () -> CertificateAuthority.load(ca, "wrong".toCharArray()));
        assertNull(view("--mitm-ca", ca.toString(), "--mitm-trust-all").mitmManager(), "the CA options need --mitm");
    }

    @Test
    void mitmTrustAllAcceptsUntrustedServers(@TempDir Path dir) throws IOException {
        CertificateAuthority unknownCa = CertificateAuthority.generate("Nobody Trusts Me");
        HttpsServer secure = TestSupport.httpsOrigin(unknownCa.serverContext("127.0.0.1"), TestSupport.fixed(200, "inside"));
        closeables.add(() -> secure.stop(0));
        Path ca = dir.resolve("ca.p12");

        HttpProxyServer strict = launch("--port", "0", "--mitm", "--mitm-ca", ca.toString());
        CertificateAuthority launcherCa = CertificateAuthority.load(ca, "microproxy".toCharArray());
        assertThrows(UncheckedIOException.class,
                () -> get(client(strict, launcherCa.clientContext()), url(secure, "/")),
                "the real server's certificate is validated by default");

        HttpProxyServer trusting = launch("--port", "0", "--mitm", "--mitm-ca", ca.toString(), "--mitm-trust-all");
        var response = get(client(trusting, launcherCa.clientContext()), url(secure, "/"));
        assertEquals(200, response.statusCode());
        assertEquals("inside", response.body());
    }

    // --- properties file -----------------------------------------------------------------------

    @Test
    void configFileIsReadAndFlagsOverrideIt(@TempDir Path dir) throws IOException {
        Path props = dir.resolve("p.properties");
        Files.writeString(props, """
                name=from-file
                port=0
                proxy_alias=file-alias
                idle_connection_timeout=12
                """);
        BootstrapView fromFile = view("--config", props.toString());
        assertEquals("from-file", fromFile.name());
        assertEquals("file-alias", fromFile.proxyAlias());
        assertEquals(Duration.ofSeconds(12), fromFile.idleConnectionTimeout());

        // Flags override the file, wherever --config appears.
        assertEquals("flag-alias", view("--config", props.toString(), "--proxy-alias", "flag-alias").proxyAlias());
        BootstrapView before = view("--proxy-alias", "flag-alias", "--idle-timeout", "3", "--config", props.toString());
        assertEquals("flag-alias", before.proxyAlias());
        assertEquals(Duration.ofSeconds(3), before.idleConnectionTimeout());
        assertEquals("from-file", before.name());
    }

    @Test
    void propertiesCoverTheCommandLineOptions(@TempDir Path dir) throws IOException {
        Path props = dir.resolve("all.properties");
        Files.writeString(props, """
                name=props
                address=127.0.0.1:9123
                transparent=true
                idle_connection_timeout=7
                connect_timeout=777
                proxy_alias=p-alias
                throttle_read_bytes_per_second=1111
                throttle_write_bytes_per_second=2222
                allow_proxy_protocol=true
                send_proxy_protocol=on
                upstream_proxy=http://127.0.0.1:3131
                upstream_https_proxy=socks4://127.0.0.1:1081
                no_proxy=skip.test
                upstream_fallback_to_direct=1
                dnssec=true
                activity_log_format=ltsv
                use_shared_server_connection_pool=true
                cache_dir=%s
                cache_max_mb=3
                offline=true
                max_initial_line_length=1000
                max_header_size=2000
                max_chunk_size=3000
                nic=127.0.0.1
                allow_requests_to_origin_server=true
                """.formatted(dir.resolve("cache").toString().replace("\\", "\\\\")));
        BootstrapView v = view("--config", props.toString());
        assertEquals("props", v.name());
        assertEquals(new InetSocketAddress("127.0.0.1", 9123), v.address());
        assertTrue(v.transparent());
        assertEquals(Duration.ofSeconds(7), v.idleConnectionTimeout());
        assertEquals(777, v.connectTimeoutMs());
        assertEquals("p-alias", v.proxyAlias());
        assertEquals(1111, v.readThrottle());
        assertEquals(2222, v.writeThrottle());
        assertTrue(v.acceptProxyProtocol());
        assertTrue(v.sendProxyProtocol());
        List<ChainedProxy> plain = route(v.chainProxyManager(), HttpMethod.GET, "http://example.com/");
        assertEquals(3131, plain.get(0).getChainedProxyAddress().getPort());
        assertEquals(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION, plain.get(1), "upstream_fallback_to_direct");
        assertEquals(ChainedProxyType.SOCKS4,
                route(v.chainProxyManager(), HttpMethod.CONNECT, "example.com:443").get(0).getChainedProxyType());
        assertEquals(List.of(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION),
                route(v.chainProxyManager(), HttpMethod.GET, "http://skip.test/"));
        assertInstanceOf(DnssecHostResolver.class, v.serverResolver());
        assertEquals(LogFormat.LTSV, ((ActivityLogger) v.activityTrackers().get(0)).getLogFormat());
        assertTrue(v.sharedServerConnectionPool());
        assertInstanceOf(DiskCacheStore.class, v.httpCache().store());
        assertTrue(v.httpCache().isOffline());
        assertEquals(1000, v.maxInitialLineLength());
        assertEquals(2000, v.maxHeaderSize());
        assertEquals(3000, v.maxChunkSize());
        assertEquals(new InetSocketAddress("127.0.0.1", 0), v.networkInterface());
        assertTrue(v.allowRequestToOriginServer());
    }

    @Test
    void addressPropertyMayAskForAnyFreePort(@TempDir Path dir) throws IOException {
        Path props = dir.resolve("ephemeral.properties");
        Files.writeString(props, "address=127.0.0.1:0\n");
        HttpProxyServer proxy = launch("--config", props.toString());
        assertEquals("127.0.0.1", proxy.getListenAddress().getAddress().getHostAddress());
        assertTrue(proxy.getListenAddress().getPort() > 0);

        Files.writeString(props, "address=[::1]:0\n");
        InetSocketAddress v6 = view("--config", props.toString()).address();
        assertEquals(0, v6.getPort());
        assertTrue(v6.getAddress().isLoopbackAddress() && v6.getAddress().getAddress().length == 16, v6.toString());

        Files.writeString(props, "address=127.0.0.1:70000\n");
        assertThrows(IllegalArgumentException.class, () -> parse("--config", props.toString()));
    }

    @Test
    void propertiesForServerModeEnvProxyAndMemoryCache(@TempDir Path dir) throws IOException {
        Path props = dir.resolve("more.properties");
        Files.writeString(props, """
                port=0
                allow_local_only=false
                use_env_proxy=true
                cache_memory_mb=2
                cache_max_entry_mb=1
                """);
        BootstrapView v = view("--config", props.toString());
        assertFalse(v.allowLocalOnly());
        assertTrue(v.address().getAddress().isAnyLocalAddress());
        assertEquals(UpstreamProxyManager.fromEnvironment(System.getenv()) != null, v.chainProxyManager() != null);
        assertInstanceOf(MemoryCacheStore.class, v.httpCache().store());
    }

    @Test
    void badPropertyValuesAreRejected(@TempDir Path dir) throws IOException {
        Path props = dir.resolve("bad.properties");
        Files.writeString(props, "connect_timeout=soon\n");
        assertThrows(IllegalArgumentException.class, () -> parse("--config", props.toString()));
        Files.writeString(props, "activity_log_format=fancy\n");
        assertThrows(IllegalArgumentException.class, () -> parse("--config", props.toString()));
        Files.writeString(props, "max_header_size=0\n");
        assertThrows(IllegalArgumentException.class, () -> parse("--config", props.toString()));
    }
}
