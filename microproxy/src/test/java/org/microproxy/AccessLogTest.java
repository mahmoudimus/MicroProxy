package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.ChainTestSupport.encrypted;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.readUntil;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.extras.ActivityLogger;
import org.microproxy.extras.AccessLogFilter;
import org.microproxy.extras.ConcurrencyLimiter;
import org.microproxy.extras.LogFormat;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * Access-log records end to end: each failure the proxy meets ends its exchange with the right
 * Envoy response flag and details, and tunnels get one record when they close.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class AccessLogTest {

    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private final RecordedFlows flows = new RecordedFlows();
    private final List<AutoCloseable> closing = new ArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        proxies.close();
        for (AutoCloseable c : closing) c.close();
    }

    private HttpProxyServerBootstrap bootstrap() {
        return MicroProxy.bootstrap().plusActivityTracker(flows);
    }

    private static Set<ResponseFlag> flags(ResponseFlag... flags) {
        EnumSet<ResponseFlag> set = EnumSet.noneOf(ResponseFlag.class);
        set.addAll(List.of(flags));
        return set;
    }

    private FlowRecord awaitStatus(int status) {
        return flows.await("a " + status + " record", r -> r.responseCode() == status);
    }

    @Test
    void aServedExchangeHasNoFlagsAndComesViaUpstream() throws Exception {
        HttpServer origin = TestSupport.origin(TestSupport.fixed(200, "hello"));
        closing.add(() -> origin.stop(0));
        HttpProxyServer proxy = proxies.start(bootstrap());
        assertEquals(200, get(client(proxy), TestSupport.url(origin, "/ok")).statusCode());
        FlowRecord r = awaitStatus(200);
        assertEquals(FlowRecord.Kind.HTTP1, r.kind());
        assertTrue(r.responseFlags().isEmpty());
        assertEquals("via_upstream", r.responseCodeDetails());
        assertEquals(ResponseSource.SERVER, r.source());
        assertTrue(r.failure().isEmpty());
        assertEquals(0, r.bytesReceived());
        assertEquals(5, r.bytesSent());
        assertTrue(r.upstreamBytesSent() > 0 && r.upstreamBytesReceived() > 5, r.toString());
        assertEquals(origin.getAddress().getPort(), r.upstreamAddress().getPort());
        assertNotNull(r.upstreamLocalAddress());
        assertEquals("127.0.0.1:" + origin.getAddress().getPort(), r.upstreamCluster());
        assertEquals(proxy.getListenAddress().getPort(), r.downstreamLocalAddress().getPort());
        assertTrue(r.duration().isPresent());
        assertEquals("GET", r.request().method().name());
    }

    @Test
    void anUnresolvableHostIsDf() {
        HttpProxyServer proxy = proxies.start(bootstrap().withServerResolver((host, port) -> {
            throw new UnknownHostException(host);
        }));
        assertEquals(502, get(client(proxy), "http://nowhere.test/x").statusCode());
        FlowRecord r = awaitStatus(502);
        assertEquals(flags(ResponseFlag.DNS_RESOLUTION_FAILED), r.responseFlags());
        assertEquals("proxy_failure:unresolved_host", r.responseCodeDetails());
        assertInstanceOf(ProxyFailure.UnresolvedHost.class, r.failure().orElseThrow());
        assertEquals(ResponseSource.PROXY, r.source());
    }

    @Test
    void aRefusedPortIsUf() throws Exception {
        try (Socket refusing = TestSupport.refusingPort()) {
            HttpProxyServer proxy = proxies.start(bootstrap());
            assertEquals(502, get(client(proxy), "http://127.0.0.1:" + refusing.getLocalPort() + "/").statusCode());
            FlowRecord r = awaitStatus(502);
            assertEquals(flags(ResponseFlag.UPSTREAM_CONNECTION_FAILURE), r.responseFlags());
            assertEquals("proxy_failure:connect_failed", r.responseCodeDetails());
            assertInstanceOf(ProxyFailure.ConnectFailed.class, r.failure().orElseThrow());
        }
    }

    @Test
    void retriesThroughEveryChainedProxyAddUrx() throws Exception {
        try (Socket first = TestSupport.refusingPort(); Socket second = TestSupport.refusingPort()) {
            ChainedProxy a = ChainTestSupport.http((InetSocketAddress) first.getLocalSocketAddress());
            ChainedProxy b = ChainTestSupport.http((InetSocketAddress) second.getLocalSocketAddress());
            HttpProxyServer proxy = proxies.start(bootstrap().withChainProxyManager(always(a, b)));
            assertEquals(502, get(client(proxy), "http://127.0.0.1:1/").statusCode());
            FlowRecord r = awaitStatus(502);
            assertEquals(flags(ResponseFlag.UPSTREAM_CONNECTION_FAILURE, ResponseFlag.UPSTREAM_RETRY_LIMIT_EXCEEDED),
                    r.responseFlags());
            assertEquals("UF,URX", ResponseFlag.render(r.responseFlags(), false));
        }
    }

    @Test
    void aFailedTlsHandshakeIsUfWithTheTransportFailureReason() {
        SelfSignedSslContextSource upstreamTls = new SelfSignedSslContextSource();
        SelfSignedSslContextSource otherTls = new SelfSignedSslContextSource();
        InetSocketAddress upstream = proxies.start(MicroProxy.bootstrap().withSslContextSource(upstreamTls))
                .getListenAddress();
        HttpProxyServer proxy = proxies.start(bootstrap()
                .withChainProxyManager(always(encrypted(upstream, otherTls.getSslContext()))));
        assertEquals(502, get(client(proxy), "http://127.0.0.1:1/").statusCode());
        FlowRecord r = awaitStatus(502);
        assertEquals(flags(ResponseFlag.UPSTREAM_CONNECTION_FAILURE), r.responseFlags());
        assertEquals("proxy_failure:tls_failed", r.responseCodeDetails());
        assertNotNull(r.upstreamTransportFailureReason());
        assertFalse(r.upstreamTransportFailureReason().isBlank());
    }

    @Test
    void aSilentServerIsUt() throws Exception {
        try (TestSupport.RawServer silent = TestSupport.rawServer(s -> {
            readUntil(s.getInputStream(), "\r\n\r\n");
            Thread.sleep(5_000);
        })) {
            HttpProxyServer proxy = proxies.start(bootstrap().withIdleConnectionTimeout(Duration.ofMillis(300)));
            assertEquals(504, get(client(proxy), "http://127.0.0.1:" + silent.port() + "/").statusCode());
            FlowRecord r = awaitStatus(504);
            assertEquals(flags(ResponseFlag.UPSTREAM_REQUEST_TIMEOUT), r.responseFlags());
            assertEquals("proxy_failure:server_timeout", r.responseCodeDetails());
        }
    }

    @Test
    void aMalformedResponseIsUpe() throws Exception {
        try (TestSupport.RawServer garbage = TestSupport.rawServer(s -> {
            readUntil(s.getInputStream(), "\r\n\r\n");
            write(s.getOutputStream(), "this is not HTTP\r\n\r\n");
        })) {
            HttpProxyServer proxy = proxies.start(bootstrap());
            assertEquals(502, get(client(proxy), "http://127.0.0.1:" + garbage.port() + "/").statusCode());
            FlowRecord r = awaitStatus(502);
            assertEquals(flags(ResponseFlag.UPSTREAM_PROTOCOL_ERROR), r.responseFlags());
            assertEquals("proxy_failure:bad_server_response", r.responseCodeDetails());
        }
    }

    @Test
    void aServerClosingBeforeItsResponseIsUc() throws Exception {
        try (TestSupport.RawServer closing = TestSupport.rawServer(s -> readUntil(s.getInputStream(), "\r\n\r\n"))) {
            HttpProxyServer proxy = proxies.start(bootstrap());
            assertEquals(502, get(client(proxy), "http://127.0.0.1:" + closing.port() + "/").statusCode());
            FlowRecord r = awaitStatus(502);
            assertEquals(flags(ResponseFlag.UPSTREAM_CONNECTION_TERMINATION), r.responseFlags());
        }
    }

    @Test
    void aServerResetAfterTheResponseStartedIsUr() throws Exception {
        try (TestSupport.RawServer truncated = TestSupport.rawServer(s -> {
            readUntil(s.getInputStream(), "\r\n\r\n");
            write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial");
        })) {
            HttpProxyServer proxy = proxies.start(bootstrap());
            String reply = TestSupport.rawExchange(proxy.getListenAddress(), "GET http://127.0.0.1:" + truncated.port()
                    + "/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            assertTrue(reply.startsWith("HTTP/1.1 200 OK\r\n"), reply);
            FlowRecord r = awaitStatus(200);
            assertEquals(flags(ResponseFlag.UPSTREAM_REMOTE_RESET), r.responseFlags());
            assertEquals("upstream_reset_after_response_started", r.responseCodeDetails());
            assertEquals(7, r.bytesSent());
        }
    }

    @Test
    void theConcurrencyLimiterIsRl() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        HttpServer slow = TestSupport.origin(exchange -> {
            started.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            TestSupport.fixed(200, "slow").handle(exchange);
        });
        closing.add(() -> slow.stop(0));
        closing.add(release::countDown);
        HttpProxyServer proxy = proxies.start(bootstrap()
                .withFiltersSource(ConcurrencyLimiter.builder().permits(1).build()));
        CompletableFuture<HttpResponse<String>> first = client(proxy).sendAsync(
                HttpRequest.newBuilder(URI.create(TestSupport.url(slow, "/1"))).build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(started.await(10, TimeUnit.SECONDS), "the first request holds the permit");
        assertEquals(429, get(client(proxy), TestSupport.url(slow, "/2")).statusCode());
        FlowRecord r = awaitStatus(429);
        assertEquals(flags(ResponseFlag.RATE_LIMITED), r.responseFlags());
        assertEquals("concurrency_limited", r.responseCodeDetails());
        assertEquals(ResponseSource.FILTER, r.source());
        release.countDown();
        assertEquals(200, first.get().statusCode());
    }

    @Test
    void aClientLeavingMidResponseIsDc() throws Exception {
        try (TestSupport.RawServer endless = TestSupport.rawServer(s -> {
            readUntil(s.getInputStream(), "\r\n\r\n");
            OutputStream out = s.getOutputStream();
            write(out, "HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n");
            byte[] chunk = new byte[16 * 1024];
            for (int i = 0; i < 5000; i++) {
                out.write(chunk);
                out.flush();
                Thread.sleep(2);
            }
        })) {
            HttpProxyServer proxy = proxies.start(bootstrap());
            try (Socket client = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
                write(client.getOutputStream(), "GET http://127.0.0.1:" + endless.port() + "/ HTTP/1.1\r\nHost: x\r\n\r\n");
                InputStream in = client.getInputStream();
                assertTrue(readUntil(in, "\r\n\r\n").startsWith("HTTP/1.1 200 OK"));
                in.readNBytes(1000);
                client.setSoLinger(true, 0);
            }
            FlowRecord r = awaitStatus(200);
            assertEquals(flags(ResponseFlag.DOWNSTREAM_CONNECTION_TERMINATION), r.responseFlags());
            assertEquals("downstream_remote_disconnect", r.responseCodeDetails());
            assertTrue(r.bytesSent() > 0, r.toString());
        }
    }

    @Test
    void aRejectedClientIsUaex() {
        HttpProxyServer proxy = proxies.start(bootstrap().withProxyAuthenticator((user, password) -> false));
        assertEquals(407, get(client(proxy), "http://127.0.0.1:1/").statusCode());
        FlowRecord r = awaitStatus(407);
        assertEquals(flags(ResponseFlag.UNAUTHORIZED_EXTERNAL_SERVICE), r.responseFlags());
        assertEquals("auth_rejected", r.responseCodeDetails());
        assertEquals(ResponseSource.PROXY, r.source());
    }

    @Test
    void aFilterShortCircuitHasNoFlagButFilterDetails() {
        HttpProxyServer proxy = proxies.start(bootstrap().withFiltersSource(HttpFilters.builder()
                .onRequest(req -> new org.microproxy.http.DefaultFullHttpResponse(org.microproxy.http.HttpVersion.HTTP_1_1,
                        org.microproxy.http.HttpResponseStatus.FORBIDDEN, "no"))
                .build()));
        assertEquals(403, get(client(proxy), "http://127.0.0.1:1/").statusCode());
        FlowRecord r = awaitStatus(403);
        assertTrue(r.responseFlags().isEmpty());
        assertEquals("filter", r.responseCodeDetails());
    }

    @Test
    void aMalformedRequestIsDpe() throws Exception {
        HttpProxyServer proxy = proxies.start(bootstrap());
        String reply = TestSupport.rawExchange(proxy.getListenAddress(), "GET http://x/ HTTP/1.1\r\nBad Header\r\n\r\n");
        assertTrue(reply.startsWith("HTTP/1.1 400"), reply);
        FlowRecord r = awaitStatus(400);
        assertEquals(flags(ResponseFlag.DOWNSTREAM_PROTOCOL_ERROR), r.responseFlags());
        assertEquals("downstream_protocol_error", r.responseCodeDetails());
        assertNull(r.request());
    }

    @Test
    void aConnectTunnelIsOneRecordWhenItCloses() throws Exception {
        try (TestSupport.RawServer echo = TestSupport.rawServer(s -> s.getInputStream().transferTo(s.getOutputStream()))) {
            HttpProxyServer proxy = proxies.start(bootstrap());
            try (Socket client = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
                String target = "127.0.0.1:" + echo.port();
                write(client.getOutputStream(), "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
                assertTrue(readUntil(client.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
                write(client.getOutputStream(), "hello tunnel");
                assertEquals("hello tunnel", new String(client.getInputStream().readNBytes(12), StandardCharsets.US_ASCII));
                assertTrue(flows.records.isEmpty(), "no record while the tunnel is open");
                client.shutdownOutput();
                assertEquals(-1, client.getInputStream().read());
            }
            FlowRecord r = flows.await(FlowRecord.Kind.TUNNEL);
            assertEquals(200, r.responseCode());
            assertEquals(12, r.bytesReceived());
            assertEquals(12, r.bytesSent());
            assertTrue(r.responseFlags().isEmpty(), r.toString());
            assertEquals("CONNECT", r.request().method().name());
            assertEquals(echo.port(), r.upstreamAddress().getPort());
            assertEquals(1, flows.records.size(), flows.records.toString());
        }
    }

    @Test
    void anIdleTunnelIsSi() throws Exception {
        try (TestSupport.RawServer silent = TestSupport.rawServer(s -> s.getInputStream().transferTo(OutputStream.nullOutputStream()))) {
            HttpProxyServer proxy = proxies.start(bootstrap().withIdleConnectionTimeout(Duration.ofMillis(300)));
            try (Socket client = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
                String target = "127.0.0.1:" + silent.port();
                write(client.getOutputStream(), "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
                assertTrue(readUntil(client.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
                FlowRecord r = flows.await(FlowRecord.Kind.TUNNEL);
                assertTrue(r.responseFlags().contains(ResponseFlag.STREAM_IDLE_TIMEOUT), r.toString());
                assertEquals("stream_idle_timeout", r.responseCodeDetails());
            }
        }
    }

    @Test
    void theLauncherWritesFilteredLinesToAFile(@TempDir Path dir) throws Exception {
        HttpServer origin = TestSupport.origin(TestSupport.fixed(200, "hello"));
        closing.add(() -> origin.stop(0));
        Path log = dir.resolve("access.log");
        HttpProxyServer proxy = Launcher.start(new String[] {"--port", "0", "--access-log", log.toString(),
            "--access-log-format", "%RESPONSE_CODE% %RESPONSE_FLAGS% %REQ(:PATH)% %MP_FLOW%",
            "--access-log-filter", "status>=400 || response_flag"}, new java.io.PrintStream(OutputStream.nullOutputStream()));
        closing.add(proxy::stop);
        assertEquals(200, get(client(proxy), TestSupport.url(origin, "/fine")).statusCode());
        assertEquals(502, get(client(proxy), "http://nowhere.invalid/broken").statusCode());
        TestSupport.eventually("the 502 line", () -> lines(log).contains("502 DF /broken h1"));
        assertEquals(List.of("502 DF /broken h1"), lines(log), "the 200 is filtered out");
    }

    @Test
    void theLauncherWritesJsonLines(@TempDir Path dir) throws Exception {
        Path log = dir.resolve("access.jsonl");
        HttpProxyServer proxy = Launcher.start(new String[] {"--port", "0", "--access-log", log.toString(),
            "--access-log-json", "{\"code\":\"%RESPONSE_CODE%\",\"flags\":\"%RESPONSE_FLAGS%\",\"host\":\"%REQ(:AUTHORITY)%\"}"},
                new java.io.PrintStream(OutputStream.nullOutputStream()));
        closing.add(proxy::stop);
        assertEquals(502, get(client(proxy), "http://nowhere.invalid/x").statusCode());
        TestSupport.eventually("a JSON line", () -> !lines(log).isEmpty());
        assertEquals("{\"code\":502,\"flags\":\"DF\",\"host\":\"nowhere.invalid\"}", lines(log).get(0));
    }

    @Test
    void anActivityLoggerFilterLeavesRecordsOut() {
        List<String> lines = new java.util.concurrent.CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(bootstrap().plusActivityTracker(ActivityLogger.builder()
                .format(LogFormat.envoy("%RESPONSE_CODE% %RESPONSE_FLAGS_LONG%"))
                .filter(AccessLogFilter.responseFlag(ResponseFlag.DNS_RESOLUTION_FAILED))
                .sink(lines::add)
                .build()).withServerResolver((host, port) -> {
                    if (host.equals("nowhere.test")) throw new UnknownHostException(host);
                    return new InetSocketAddress(TestSupport.LOOPBACK, 1);
                }));
        assertEquals(502, get(client(proxy), "http://nowhere.test/x").statusCode());
        assertEquals(502, get(client(proxy), "http://refused.test/x").statusCode());
        TestSupport.eventually("both records", () -> flows.records.size() == 2);
        assertEquals(List.of("502 DnsResolutionFailed"), lines);
    }

    private static List<String> lines(Path file) {
        try {
            return Files.exists(file) ? Files.readAllLines(file) : List.of();
        } catch (IOException e) {
            return List.of();
        }
    }
}
