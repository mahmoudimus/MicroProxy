package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.ActivityTrackerAdapter;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyAdapter;
import org.microproxy.FlowContext;
import org.microproxy.FlowTimings;
import org.microproxy.FullFlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.http.HttpResponse;

/** {@link HttpProxyServerBootstrap#withChainedProxyRetryBackoff}: waits between chained proxy attempts. */
class ChainedProxyBackoffTest {

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private DefaultHttpProxyServer proxy;
    private final AtomicReference<FlowTimings> timings = new AtomicReference<>();

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    /** An address nothing listens on: connecting is refused at once. */
    private static ChainedProxy refused() throws Exception {
        InetSocketAddress address;
        try (ServerSocket s = new ServerSocket(0, 1, TestSupport.LOOPBACK)) {
            address = new InetSocketAddress(TestSupport.LOOPBACK, s.getLocalPort());
        }
        return () -> address;
    }

    private DefaultHttpProxyServer start(HttpProxyServerBootstrap bootstrap, ChainedProxy... route) {
        proxy = (DefaultHttpProxyServer) bootstrap.withPort(0)
                .withChainProxyManager((request, queue, details) -> queue.addAll(List.of(route)))
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void responseCompleted(FlowContext ctx, HttpResponse response) {
                        timings.set(ctx.timings());
                    }
                })
                .start();
        // The longest wait every time, so the timings are predictable.
        proxy.backoffJitter = () -> 1.0;
        return proxy;
    }

    private String origin() {
        HttpServer origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
        closeables.add(() -> origin.stop(0));
        return TestSupport.url(origin, "/");
    }

    /** Status of a GET for {@code url}, and how long it took in milliseconds. */
    private long[] timedGet(String url) {
        long start = System.nanoTime();
        int status = TestSupport.get(TestSupport.client(proxy), url).statusCode();
        return new long[] {status, Duration.ofNanos(System.nanoTime() - start).toMillis()};
    }

    @Test
    void backoffGrowsExponentiallyUpToTheMaximum() {
        assertEquals(100, ClientConnection.backoffNanos(1, 100, 1000, 1.0));
        assertEquals(200, ClientConnection.backoffNanos(2, 100, 1000, 1.0));
        assertEquals(400, ClientConnection.backoffNanos(3, 100, 1000, 1.0));
        assertEquals(1000, ClientConnection.backoffNanos(5, 100, 1000, 1.0));
        assertEquals(1000, ClientConnection.backoffNanos(64, 100, 1000, 1.0), "no overflow");
        long day = TimeUnit.DAYS.toNanos(1);
        assertEquals(day, ClientConnection.backoffNanos(40, TimeUnit.SECONDS.toNanos(1), day, 1.0));
        assertEquals(200, ClientConnection.backoffNanos(3, 100, 1000, 0.5), "full jitter scales the ceiling");
        assertEquals(0, ClientConnection.backoffNanos(3, 100, 1000, 0.0));
    }

    @Test
    void noWaitingUnlessConfigured() throws Exception {
        start(MicroProxy.bootstrap(), refused(), refused(), refused(), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        long[] result = timedGet(origin());
        assertEquals(200, result[0]);
        assertTrue(result[1] < 2000, "took " + result[1] + " ms");
    }

    @Test
    void waitsBetweenAttemptsAndCountsTowardsTheConnectPhase() throws Exception {
        start(MicroProxy.bootstrap().withChainedProxyRetryBackoff(Duration.ofMillis(100), Duration.ofMillis(150)),
                refused(), refused(), refused(), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        long[] result = timedGet(origin());
        assertEquals(200, result[0]);
        // 100 + 150 + 150 ms of waiting before the direct connection.
        assertTrue(result[1] >= 380, "took only " + result[1] + " ms");
        assertTrue(result[1] < 5000, "took " + result[1] + " ms");
        TestSupport.eventually("the exchange's timings", () -> timings.get() != null);
        long connect = timings.get().connect().orElseThrow().toMillis();
        assertTrue(connect >= 380, "the connect phase took only " + connect + " ms");
    }

    @Test
    void neverWaitsBeforeTheFirstAttemptOrAfterTheLast() throws Exception {
        start(MicroProxy.bootstrap().withChainedProxyRetryBackoff(Duration.ofSeconds(1), Duration.ofSeconds(1)),
                refused());
        long[] one = timedGet(origin());
        assertEquals(502, one[0]);
        assertTrue(one[1] < 800, "a single failed attempt took " + one[1] + " ms");
        proxy.abort();

        start(MicroProxy.bootstrap().withChainedProxyRetryBackoff(Duration.ofSeconds(1), Duration.ofSeconds(1)),
                refused(), refused());
        long[] two = timedGet(origin());
        assertEquals(502, two[0]);
        assertTrue(two[1] >= 950, "waited only " + two[1] + " ms between the attempts");
        assertTrue(two[1] < 1900, "took " + two[1] + " ms: waited after the last attempt too");
    }

    @Test
    void theWaitsOfOneRequestAreBoundedByTheConnectTimeout() throws Exception {
        start(MicroProxy.bootstrap().withConnectTimeout(600)
                        .withChainedProxyRetryBackoff(Duration.ofMillis(500), Duration.ofMillis(500)),
                refused(), refused(), refused(), refused(), refused(), refused());
        long[] result = timedGet(origin());
        assertEquals(502, result[0]);
        // Five waits of 500 ms would take 2.5 s; the budget is 600 ms.
        assertTrue(result[1] >= 550, "waited only " + result[1] + " ms");
        assertTrue(result[1] < 1800, "took " + result[1] + " ms");
    }

    @Test
    void aClientThatLeavesStopsTheRetries() throws Exception {
        AtomicInteger reached = new AtomicInteger();
        TestSupport.RawServer second = TestSupport.rawServer(s -> reached.incrementAndGet());
        closeables.add(second);
        CountDownLatch firstFailed = new CountDownLatch(1);
        CountDownLatch ended = new CountDownLatch(1);
        start(MicroProxy.bootstrap()
                        .withChainedProxyRetryBackoff(Duration.ofSeconds(5), Duration.ofSeconds(5))
                        .withFiltersSource((request, flow) -> new HttpFilters() {
                            @Override
                            public void exchangeEnded(boolean completed) {
                                ended.countDown();
                            }
                        })
                        .plusActivityTracker(new ActivityTrackerAdapter() {
                            @Override
                            public void serverConnectionExceptionCaught(FullFlowContext serverContext, Throwable cause) {
                                firstFailed.countDown();
                            }
                        }),
                refused(), second::address);
        try (Socket client = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            TestSupport.write(client.getOutputStream(), "GET " + origin() + " HTTP/1.1\r\nHost: x\r\n\r\n");
            assertTrue(firstFailed.await(10, TimeUnit.SECONDS));
        }
        long start = System.nanoTime();
        assertTrue(ended.await(10, TimeUnit.SECONDS));
        long took = Duration.ofNanos(System.nanoTime() - start).toMillis();
        assertTrue(took < 3000, "noticed the client leaving after " + took + " ms");
        assertEquals(0, reached.get(), "the next candidate was not tried for a client that left");
    }

    @Test
    void propertiesConfigureTheBackoff() {
        Properties p = new Properties();
        p.setProperty("chained_proxy_backoff_initial_ms", "100");
        p.setProperty("chained_proxy_backoff_max_ms", "2000");
        DefaultHttpProxyServerBootstrap b = DefaultHttpProxyServerBootstrap.fromProperties(p);
        assertEquals(Duration.ofMillis(100), b.chainedProxyBackoffInitial);
        assertEquals(Duration.ofMillis(2000), b.chainedProxyBackoffMax);
        assertEquals(Duration.ofMillis(2000), b.copy().chainedProxyBackoffMax);

        p.remove("chained_proxy_backoff_max_ms");
        assertEquals(Duration.ofMillis(800), DefaultHttpProxyServerBootstrap.fromProperties(p).chainedProxyBackoffMax,
                "the maximum defaults to eight times the initial wait");

        p.setProperty("chained_proxy_backoff_max_ms", "50");
        assertThrows(IllegalArgumentException.class, () -> DefaultHttpProxyServerBootstrap.fromProperties(p));
        Properties maxOnly = new Properties();
        maxOnly.setProperty("chained_proxy_backoff_max_ms", "50");
        assertThrows(IllegalArgumentException.class, () -> DefaultHttpProxyServerBootstrap.fromProperties(maxOnly));
        assertThrows(IllegalArgumentException.class,
                () -> MicroProxy.bootstrap().withChainedProxyRetryBackoff(Duration.ZERO, Duration.ofSeconds(1)));
        DefaultHttpProxyServerBootstrap off = (DefaultHttpProxyServerBootstrap) MicroProxy.bootstrap()
                .withChainedProxyRetryBackoff(Duration.ofMillis(1), Duration.ofMillis(2))
                .withChainedProxyRetryBackoff(null, null);
        assertEquals(null, off.chainedProxyBackoffInitial);
    }
}
