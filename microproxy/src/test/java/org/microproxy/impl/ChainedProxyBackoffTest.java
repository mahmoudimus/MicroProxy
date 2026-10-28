package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.random.RandomGenerator;
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
import org.microproxy.RetryBackoff;
import org.microproxy.TestSupport;
import org.microproxy.http.HttpResponse;

/**
 * {@link HttpProxyServerBootstrap#withChainedProxyRetryBackoff} and {@link
 * HttpFilters#chainedProxyRetryBackoff()}: waits between chained proxy attempts. Tests of which
 * waits are chosen record them ({@link DefaultHttpProxyServer#backoffSleeper}) instead of timing them.
 */
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
    private ChainedProxy refused() {
        Socket refusing = TestSupport.refusingPort();
        closeables.add(refusing);
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, refusing.getLocalPort());
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
        proxy.backoffRandom = LONGEST;
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

    /** Jitter that always draws {@code fraction}. */
    private static RandomGenerator jitter(double fraction) {
        return new RandomGenerator() {
            @Override
            public long nextLong() {
                throw new UnsupportedOperationException();
            }

            @Override
            public double nextDouble() {
                return fraction;
            }
        };
    }

    /** Jitter that always draws the longest wait. */
    private static final RandomGenerator LONGEST = jitter(1.0);

    private static long jitteredNanos(int failures, long initial, long max, double fraction) {
        return RetryBackoff.exponentialWithJitter(Duration.ofNanos(initial), Duration.ofNanos(max))
                .delay(failures, jitter(fraction)).toNanos();
    }

    @Test
    void backoffGrowsExponentiallyUpToTheMaximum() {
        assertEquals(100, jitteredNanos(1, 100, 1000, 1.0));
        assertEquals(200, jitteredNanos(2, 100, 1000, 1.0));
        assertEquals(400, jitteredNanos(3, 100, 1000, 1.0));
        assertEquals(1000, jitteredNanos(5, 100, 1000, 1.0));
        assertEquals(1000, jitteredNanos(64, 100, 1000, 1.0), "no overflow");
        long day = TimeUnit.DAYS.toNanos(1);
        assertEquals(day, jitteredNanos(40, TimeUnit.SECONDS.toNanos(1), day, 1.0));
        assertEquals(200, jitteredNanos(3, 100, 1000, 0.5), "full jitter scales the ceiling");
        assertEquals(0, jitteredNanos(3, 100, 1000, 0.0));
    }

    /** Starts the proxy with the waits recorded instead of waited out. */
    private List<Duration> recordWaits() {
        List<Duration> waits = new CopyOnWriteArrayList<>();
        proxy.backoffSleeper = nanos -> waits.add(Duration.ofNanos(nanos));
        return waits;
    }

    private static List<Duration> millis(long... values) {
        return java.util.Arrays.stream(values).mapToObj(Duration::ofMillis).toList();
    }

    @Test
    void deterministicBackoffWaitsExactlyDoublingTimes() throws Exception {
        start(MicroProxy.bootstrap().withChainedProxyRetryBackoff(
                        RetryBackoff.exponential(Duration.ofMillis(100), Duration.ofMillis(300))),
                refused(), refused(), refused(), refused(), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        proxy.backoffRandom = null;
        List<Duration> waits = recordWaits();
        assertEquals(200, timedGet(origin())[0]);
        assertEquals(millis(100, 200, 300, 300), waits);
    }

    @Test
    void aFilterBackoffWinsOverTheServers() throws Exception {
        start(MicroProxy.bootstrap()
                        .withChainedProxyRetryBackoff(RetryBackoff.fixed(Duration.ofSeconds(5)))
                        .withFiltersSource((request, flow) -> new HttpFilters() {
                            @Override
                            public RetryBackoff chainedProxyRetryBackoff() {
                                return RetryBackoff.exponential(Duration.ofMillis(10), Duration.ofMillis(25));
                            }
                        }),
                refused(), refused(), refused(), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        List<Duration> waits = recordWaits();
        assertEquals(200, timedGet(origin())[0]);
        assertEquals(millis(10, 20, 25), waits);
    }

    @Test
    void aFilterBackoffAppliesWhenTheServerHasNone() throws Exception {
        start(MicroProxy.bootstrap().withFiltersSource(
                        HttpFilters.builder().retryBackoff(RetryBackoff.fixed(Duration.ofMillis(7))).build()),
                refused(), refused(), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        List<Duration> waits = recordWaits();
        assertEquals(200, timedGet(origin())[0]);
        assertEquals(millis(7, 7), waits);
        assertThrows(NullPointerException.class, () -> HttpFilters.builder().retryBackoff(null));
    }

    @Test
    void aFilterCanTurnTheServersBackoffOff() throws Exception {
        start(MicroProxy.bootstrap().withMetrics(true)
                        .withChainedProxyRetryBackoff(RetryBackoff.fixed(Duration.ofSeconds(5)))
                        .withFiltersSource(HttpFilters.builder().retryBackoff(RetryBackoff.none()).build()),
                refused(), refused(), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        List<Duration> waits = recordWaits();
        assertEquals(200, timedGet(origin())[0]);
        assertEquals(List.of(), waits);
        assertEquals(0, ((org.microproxy.stats.Counter) proxy.getStats().get("cluster.direct.backoff_engaged")).value());
    }

    @Test
    void theFilterBackoffIsAskedOnlyAfterAFailure() throws Exception {
        AtomicInteger asked = new AtomicInteger();
        start(MicroProxy.bootstrap().withFiltersSource((request, flow) -> new HttpFilters() {
            @Override
            public RetryBackoff chainedProxyRetryBackoff() {
                asked.incrementAndGet();
                return RetryBackoff.fixed(Duration.ofMillis(1));
            }
        }), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        recordWaits();
        assertEquals(200, timedGet(origin())[0]);
        assertEquals(0, asked.get(), "a request that connects at once never asks");
    }

    @Test
    void aFilterThatThrowsGetsTheServersBackoff() throws Exception {
        start(MicroProxy.bootstrap()
                        .withChainedProxyRetryBackoff(RetryBackoff.fixed(Duration.ofMillis(3)))
                        .withFiltersSource((request, flow) -> new HttpFilters() {
                            @Override
                            public RetryBackoff chainedProxyRetryBackoff() {
                                throw new IllegalStateException("broken filter");
                            }
                        }),
                refused(), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        List<Duration> waits = recordWaits();
        assertEquals(200, timedGet(origin())[0]);
        assertEquals(millis(3), waits);
    }

    @Test
    void theWaitsAreCappedByTheBudgetExactly() throws Exception {
        start(MicroProxy.bootstrap().withConnectTimeout(600)
                        .withChainedProxyRetryBackoff(RetryBackoff.fixed(Duration.ofMillis(500))),
                refused(), refused(), refused(), refused(), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        List<Duration> waits = recordWaits();
        assertEquals(200, timedGet(origin())[0]);
        // 600 ms in all: one whole wait, what is left of the budget, then none.
        assertEquals(millis(500, 100), waits);
    }

    @Test
    void anUnbudgetedPolicyWaitsTheWholeDoublingSequence() throws Exception {
        // As LittleProxy forks that added a backoff: 3.1 s of waits with a 2 s connect timeout.
        start(MicroProxy.bootstrap().withConnectTimeout(2000)
                        .withChainedProxyRetryBackoff(
                                RetryBackoff.exponential(Duration.ofMillis(100), Duration.ofSeconds(5)).unbudgeted()),
                refused(), refused(), refused(), refused(), refused(), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        proxy.backoffRandom = null;
        List<Duration> waits = recordWaits();
        assertEquals(200, timedGet(origin())[0]);
        assertEquals(millis(100, 200, 400, 800, 1600), waits);
    }

    @Test
    void theSameWaitsAreCutAtTheDefaultBudget() throws Exception {
        start(MicroProxy.bootstrap().withConnectTimeout(2000)
                        .withChainedProxyRetryBackoff(RetryBackoff.exponential(Duration.ofMillis(100), Duration.ofSeconds(5))),
                refused(), refused(), refused(), refused(), refused(), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        List<Duration> waits = recordWaits();
        assertEquals(200, timedGet(origin())[0]);
        // 2 s in all: 100 + 200 + 400 + 800, then the 500 ms left.
        assertEquals(millis(100, 200, 400, 800, 500), waits);
    }

    @Test
    void aPolicysOwnBudgetReplacesTheDefault() throws Exception {
        start(MicroProxy.bootstrap().withConnectTimeout(60_000)
                        .withFiltersSource(HttpFilters.builder().retryBackoff(
                                RetryBackoff.fixed(Duration.ofMillis(400)).withBudget(Duration.ofMillis(1000))).build()),
                refused(), refused(), refused(), refused(), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        List<Duration> waits = recordWaits();
        assertEquals(200, timedGet(origin())[0]);
        assertEquals(millis(400, 400, 200), waits);
    }

    @Test
    void chainsUseTheFirstFilterThatNamesABackoff() {
        var request = new org.microproxy.http.DefaultHttpRequest(org.microproxy.http.HttpVersion.HTTP_1_1,
                org.microproxy.http.HttpMethod.GET, "http://example.com/");
        RetryBackoff first = RetryBackoff.fixed(Duration.ofSeconds(1));
        org.microproxy.HttpFiltersSource none = (r, f) -> new HttpFilters() {};
        org.microproxy.HttpFiltersSource chain = org.microproxy.HttpFiltersChain.of(none,
                HttpFilters.builder().retryBackoff(first).build(),
                HttpFilters.builder().retryBackoff(RetryBackoff.none()).build());
        assertEquals(first, chain.filterRequest(request, null).chainedProxyRetryBackoff());
        assertEquals(null, org.microproxy.HttpFiltersChain.of(none, none).filterRequest(request, null)
                .chainedProxyRetryBackoff());
    }

    /** The stat {@code name} of the cluster of chained proxy {@code proxy}. */
    private long clusterStat(ChainedProxy proxy, String name) {
        InetSocketAddress a = proxy.getChainedProxyAddress();
        org.microproxy.stats.Metric m = this.proxy.getStats().get("cluster."
                + org.microproxy.stats.TagExtractor.sanitize(a.getHostString() + "_" + a.getPort()) + "." + name);
        return m == null ? 0 : m instanceof org.microproxy.stats.Counter c ? c.value() : ((org.microproxy.stats.Gauge) m).value();
    }

    @Test
    void failoversAndBackoffsAreCountedPerCluster() throws Exception {
        ChainedProxy first = refused();
        ChainedProxy second = refused();
        start(MicroProxy.bootstrap().withMetrics(true)
                        .withChainedProxyRetryBackoff(Duration.ofMillis(400), Duration.ofMillis(400)),
                first, second, ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        // The first wait holds until the test has looked at the stats during it.
        CountDownLatch waiting = new CountDownLatch(1);
        CountDownLatch looked = new CountDownLatch(1);
        proxy.backoffSleeper = nanos -> {
            waiting.countDown();
            try {
                looked.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };
        String url = origin();
        AtomicReference<long[]> result = new AtomicReference<>();
        Thread request = Thread.ofVirtual().start(() -> result.set(timedGet(url)));
        assertTrue(waiting.await(10, TimeUnit.SECONDS));
        // While it waits before trying the second proxy, the second proxy's cluster is backing off.
        assertEquals(1, clusterStat(second, "backoff_active"));
        looked.countDown();
        request.join(10_000);
        assertEquals(200, result.get()[0]);
        org.microproxy.stats.StatsRegistry r = proxy.getStats();
        // a request is counted by its response class when it ends, which may be just after the
        // client has the response
        org.microproxy.TestSupport.eventually("the request counted",
                () -> ((org.microproxy.stats.Counter) r.get("cluster.direct.upstream_rq_2xx")).value() == 1);
        assertEquals(1, clusterStat(first, "upstream_cx_connect_fail"));
        assertEquals(1, clusterStat(first, "failover"));
        assertEquals(0, clusterStat(first, "backoff_engaged"), "the first attempt never waits");
        assertEquals(1, clusterStat(second, "upstream_cx_connect_fail"));
        assertEquals(1, clusterStat(second, "failover"));
        assertEquals(1, clusterStat(second, "backoff_engaged"));
        assertEquals(0, clusterStat(second, "backoff_active"));
        assertEquals(1, ((org.microproxy.stats.Counter) r.get("cluster.direct.backoff_engaged")).value());
        assertEquals(0, ((org.microproxy.stats.Counter) r.get("cluster.direct.failover")).value());
        assertEquals(0, ((org.microproxy.stats.Gauge) r.get("cluster.direct.backoff_active")).value());
        assertEquals(1, ((org.microproxy.stats.Counter) r.get("cluster.direct.upstream_rq_2xx")).value());
    }

    @Test
    void noWaitingUnlessConfigured() throws Exception {
        start(MicroProxy.bootstrap(), refused(), refused(), refused(), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        List<Duration> waits = recordWaits();
        assertEquals(200, timedGet(origin())[0]);
        assertEquals(List.of(), waits);
    }

    @Test
    void waitsBetweenAttemptsAndCountsTowardsTheConnectPhase() throws Exception {
        start(MicroProxy.bootstrap().withChainedProxyRetryBackoff(Duration.ofMillis(100), Duration.ofMillis(150)),
                refused(), refused(), refused(), ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        // The waits are recorded and really slept, so they show in the exchange's timings.
        List<Duration> waits = new CopyOnWriteArrayList<>();
        proxy.backoffSleeper = nanos -> {
            waits.add(Duration.ofNanos(nanos));
            java.util.concurrent.locks.LockSupport.parkNanos(nanos);
        };
        assertEquals(200, timedGet(origin())[0]);
        assertEquals(millis(100, 150, 150), waits);
        TestSupport.eventually("the exchange's timings", () -> timings.get() != null);
        long connect = timings.get().connect().orElseThrow().toMillis();
        assertTrue(connect >= 400, "the connect phase took only " + connect + " ms");
    }

    @Test
    void neverWaitsBeforeTheFirstAttemptOrAfterTheLast() throws Exception {
        start(MicroProxy.bootstrap().withChainedProxyRetryBackoff(Duration.ofSeconds(1), Duration.ofSeconds(1)),
                refused());
        List<Duration> one = recordWaits();
        assertEquals(502, timedGet(origin())[0]);
        assertEquals(List.of(), one, "a single failed attempt waits for nothing");
        proxy.abort();

        start(MicroProxy.bootstrap().withChainedProxyRetryBackoff(Duration.ofSeconds(1), Duration.ofSeconds(1)),
                refused(), refused());
        List<Duration> two = recordWaits();
        assertEquals(502, timedGet(origin())[0]);
        assertEquals(millis(1000), two, "one wait between the attempts, none after the last");
    }

    @Test
    void theWaitsOfOneRequestAreBoundedByTheConnectTimeout() throws Exception {
        start(MicroProxy.bootstrap().withConnectTimeout(600)
                        .withChainedProxyRetryBackoff(Duration.ofMillis(500), Duration.ofMillis(500)),
                refused(), refused(), refused(), refused(), refused(), refused());
        List<Duration> waits = recordWaits();
        assertEquals(502, timedGet(origin())[0]);
        // Five waits of 500 ms would be 2.5 s; the budget is 600 ms.
        assertEquals(millis(500, 100), waits);
    }

    @Test
    void aClientThatLeavesStopsTheRetries() throws Exception {
        AtomicInteger reached = new AtomicInteger();
        TestSupport.RawServer second = TestSupport.rawServer(s -> reached.incrementAndGet());
        closeables.add(second);
        CountDownLatch firstFailed = new CountDownLatch(1);
        CountDownLatch ended = new CountDownLatch(1);
        // A ten-minute wait, without a budget to shorten it: only the client leaving ends it in time.
        start(MicroProxy.bootstrap()
                        .withChainedProxyRetryBackoff(RetryBackoff.fixed(Duration.ofMinutes(10)).unbudgeted())
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
        assertTrue(ended.await(30, TimeUnit.SECONDS), "the client leaving ended the wait");
        assertEquals(0, reached.get(), "the next candidate was not tried for a client that left");
    }

    @Test
    void propertiesConfigureTheBackoff() {
        Properties p = new Properties();
        p.setProperty("chained_proxy_backoff_initial_ms", "100");
        p.setProperty("chained_proxy_backoff_max_ms", "2000");
        DefaultHttpProxyServerBootstrap b = DefaultHttpProxyServerBootstrap.fromProperties(p);
        assertEquals(RetryBackoff.exponentialWithJitter(Duration.ofMillis(100), Duration.ofMillis(2000)),
                b.chainedProxyBackoff, "jittered by default");
        assertEquals(b.chainedProxyBackoff, b.copy().chainedProxyBackoff);

        p.setProperty("chained_proxy_backoff_jitter", "false");
        assertEquals(RetryBackoff.exponential(Duration.ofMillis(100), Duration.ofMillis(2000)),
                DefaultHttpProxyServerBootstrap.fromProperties(p).chainedProxyBackoff);
        p.setProperty("chained_proxy_backoff_jitter", "true");
        assertEquals(RetryBackoff.exponentialWithJitter(Duration.ofMillis(100), Duration.ofMillis(2000)),
                DefaultHttpProxyServerBootstrap.fromProperties(p).chainedProxyBackoff);
        p.remove("chained_proxy_backoff_jitter");

        p.setProperty("chained_proxy_backoff_budget_ms", "unlimited");
        assertTrue(DefaultHttpProxyServerBootstrap.fromProperties(p).chainedProxyBackoff.isUnbudgeted());
        p.setProperty("chained_proxy_backoff_budget_ms", "5000");
        assertEquals(java.util.Optional.of(Duration.ofSeconds(5)),
                DefaultHttpProxyServerBootstrap.fromProperties(p).chainedProxyBackoff.budget());
        p.setProperty("chained_proxy_backoff_budget_ms", "0");
        assertThrows(IllegalArgumentException.class, () -> DefaultHttpProxyServerBootstrap.fromProperties(p));
        p.remove("chained_proxy_backoff_budget_ms");
        Properties budgetOnly = new Properties();
        budgetOnly.setProperty("chained_proxy_backoff_budget_ms", "unlimited");
        assertThrows(IllegalArgumentException.class, () -> DefaultHttpProxyServerBootstrap.fromProperties(budgetOnly));

        p.remove("chained_proxy_backoff_max_ms");
        assertEquals(Duration.ofMillis(800), DefaultHttpProxyServerBootstrap.fromProperties(p).chainedProxyBackoff.max(),
                "the maximum defaults to eight times the initial wait");

        p.setProperty("chained_proxy_backoff_max_ms", "50");
        assertThrows(IllegalArgumentException.class, () -> DefaultHttpProxyServerBootstrap.fromProperties(p));
        Properties maxOnly = new Properties();
        maxOnly.setProperty("chained_proxy_backoff_max_ms", "50");
        assertThrows(IllegalArgumentException.class, () -> DefaultHttpProxyServerBootstrap.fromProperties(maxOnly));
        Properties jitterOnly = new Properties();
        jitterOnly.setProperty("chained_proxy_backoff_jitter", "false");
        assertThrows(IllegalArgumentException.class, () -> DefaultHttpProxyServerBootstrap.fromProperties(jitterOnly));
        assertThrows(IllegalArgumentException.class,
                () -> MicroProxy.bootstrap().withChainedProxyRetryBackoff(Duration.ZERO, Duration.ofSeconds(1)));
        DefaultHttpProxyServerBootstrap off = (DefaultHttpProxyServerBootstrap) MicroProxy.bootstrap()
                .withChainedProxyRetryBackoff(Duration.ofMillis(1), Duration.ofMillis(2))
                .withChainedProxyRetryBackoff(null, null);
        assertEquals(RetryBackoff.none(), off.chainedProxyBackoff);
        assertEquals(RetryBackoff.none(), new DefaultHttpProxyServerBootstrap().chainedProxyBackoff, "off by default");
        assertEquals(RetryBackoff.none(), ((DefaultHttpProxyServerBootstrap) MicroProxy.bootstrap()
                .withChainedProxyRetryBackoff(RetryBackoff.fixed(Duration.ofMillis(1)))
                .withChainedProxyRetryBackoff((RetryBackoff) null)).chainedProxyBackoff);
        assertEquals(RetryBackoff.exponentialWithJitter(Duration.ofMillis(5), Duration.ofMillis(5)),
                ((DefaultHttpProxyServerBootstrap) MicroProxy.bootstrap()
                        .withChainedProxyRetryBackoff(Duration.ofMillis(5), null)).chainedProxyBackoff,
                "a missing maximum is the initial wait");
    }
}
