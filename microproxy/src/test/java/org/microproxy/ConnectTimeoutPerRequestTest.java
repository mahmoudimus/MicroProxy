package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpVersion;

/** {@link HttpFilters#proxyToServerConnectTimeout()}: a connect timeout per request. */
class ConnectTimeoutPerRequestTest {

    /**
     * A listener whose accept queue is full: on Linux new connection attempts to it hang (the SYN
     * is dropped), which makes connect timeouts observable, as in {@link TimeoutTest}.
     */
    private static ServerSocket blackhole;
    private static final List<Socket> fillers = new ArrayList<>();
    private static boolean saturated;

    private HttpProxyServer proxy;

    @BeforeAll
    static void fillBacklog() throws Exception {
        blackhole = new ServerSocket(0, 1, TestSupport.LOOPBACK);
        for (int i = 0; i < 16 && !saturated; i++) {
            Socket s = new Socket();
            try {
                s.connect(blackhole.getLocalSocketAddress(), 200);
                fillers.add(s);
            } catch (SocketTimeoutException e) {
                s.close();
                saturated = true;
            }
        }
    }

    @AfterAll
    static void release() throws Exception {
        for (Socket s : fillers) s.close();
        blackhole.close();
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    private static String blackholeUrl() {
        return "http://127.0.0.1:" + blackhole.getLocalPort() + "/";
    }

    private static HttpFiltersSource timeout(Duration timeout) {
        return (request, flow) -> new HttpFilters() {
            @Override
            public Duration proxyToServerConnectTimeout() {
                return timeout;
            }
        };
    }

    /** Asserts that a request to the blackhole fails with 502 after roughly 300 ms. */
    private void assertGivesUpAfterAboutThreeHundredMillis() {
        long start = System.nanoTime();
        var response = get(client(proxy), blackholeUrl());
        long took = Duration.ofNanos(System.nanoTime() - start).toMillis();
        assertEquals(502, response.statusCode());
        assertTrue(took >= 250, "gave up after only " + took + " ms");
        assertTrue(took < 5000, "took " + took + " ms: the server's 30 s timeout applied");
    }

    @Test
    void aFilterShortensTheConnectTimeout() {
        assumeTrue(saturated, "connections to a full backlog do not hang on this OS");
        proxy = MicroProxy.bootstrap().withPort(0).withConnectTimeout(30_000)
                .withFiltersSource(timeout(Duration.ofMillis(300))).start();
        assertGivesUpAfterAboutThreeHundredMillis();
    }

    @Test
    void theShortestTimeoutInAChainWins() {
        assumeTrue(saturated, "connections to a full backlog do not hang on this OS");
        proxy = MicroProxy.bootstrap().withPort(0).withConnectTimeout(30_000)
                .withFiltersSource(timeout(Duration.ofSeconds(20)))
                .plusFiltersSource(timeout(null))
                .plusFiltersSource(timeout(Duration.ofMillis(300)))
                .plusFiltersSource(timeout(Duration.ZERO))
                .start();
        assertGivesUpAfterAboutThreeHundredMillis();
    }

    @Test
    void lambdaBuiltFiltersSetItWithConnectTimeout() {
        assumeTrue(saturated, "connections to a full backlog do not hang on this OS");
        proxy = MicroProxy.bootstrap().withPort(0).withConnectTimeout(30_000)
                .withFiltersSource(HttpFilters.builder().connectTimeout(Duration.ofMillis(300)).build()).start();
        assertGivesUpAfterAboutThreeHundredMillis();
        assertThrows(IllegalArgumentException.class, () -> HttpFilters.builder().connectTimeout(Duration.ZERO));
    }

    @Test
    void nonPositiveOrMissingTimeoutsKeepTheServers() {
        assumeTrue(saturated, "connections to a full backlog do not hang on this OS");
        proxy = MicroProxy.bootstrap().withPort(0).withConnectTimeout(300)
                .withFiltersSource(timeout(Duration.ofSeconds(-1))).start();
        assertGivesUpAfterAboutThreeHundredMillis();
    }

    @Test
    void itAppliesToEachChainedProxyTried() {
        assumeTrue(saturated, "connections to a full backlog do not hang on this OS");
        HttpServer origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
        try {
            InetSocketAddress hole = new InetSocketAddress(TestSupport.LOOPBACK, blackhole.getLocalPort());
            proxy = MicroProxy.bootstrap().withPort(0).withConnectTimeout(30_000)
                    .withChainProxyManager(ChainTestSupport.always(ChainTestSupport.http(hole), ChainTestSupport.http(hole),
                            ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION))
                    .withFiltersSource(timeout(Duration.ofMillis(300))).start();
            long start = System.nanoTime();
            assertEquals(200, get(client(proxy), TestSupport.url(origin, "/")).statusCode());
            long took = Duration.ofNanos(System.nanoTime() - start).toMillis();
            assertTrue(took >= 500, "gave up on the chained proxies after only " + took + " ms");
            assertTrue(took < 5000, "took " + took + " ms");
        } finally {
            origin.stop(0);
        }
    }

    @Test
    void chainsReportTheShortestPositiveTimeout() {
        var request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "http://example.com/");
        HttpFiltersSource chain = HttpFiltersChain.of(timeout(Duration.ofSeconds(5)), timeout(null),
                timeout(Duration.ofSeconds(2)), timeout(Duration.ofSeconds(-3)));
        assertEquals(Duration.ofSeconds(2), chain.filterRequest(request, null).proxyToServerConnectTimeout());
        assertNull(HttpFiltersChain.of(timeout(null), timeout(Duration.ZERO)).filterRequest(request, null)
                .proxyToServerConnectTimeout());
    }
}
