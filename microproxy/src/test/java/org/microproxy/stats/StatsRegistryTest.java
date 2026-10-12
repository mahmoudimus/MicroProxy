package org.microproxy.stats;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/** The registry's semantics: names and tags, kinds, the no-op registry, scopes, and many threads at once. */
class StatsRegistryTest {

    @Test
    void registeringANameAgainReturnsTheSameMetric() {
        StatsRegistry r = StatsRegistry.create();
        Counter c = r.counter("cluster.direct.upstream_rq_total");
        assertSame(c, r.counter("cluster.direct.upstream_rq_total"));
        c.inc();
        c.add(4);
        assertEquals(5, r.counter("cluster.direct.upstream_rq_total").value());
        Gauge g = r.gauge("cluster.direct.upstream_cx_active");
        g.inc();
        g.inc();
        g.dec();
        g.add(10);
        assertEquals(11, g.value());
        g.set(-3);
        assertEquals(-3, r.gauge("cluster.direct.upstream_cx_active").value());
        assertSame(r.histogram("x.time"), r.histogram("x.time"));
        assertEquals(3, r.size());
        assertEquals(List.of("cluster.direct.upstream_cx_active", "cluster.direct.upstream_rq_total", "x.time"),
                r.metrics().stream().map(Metric::name).toList());
    }

    @Test
    void aNameKeepsItsKind() {
        StatsRegistry r = StatsRegistry.create();
        r.counter("a.b");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> r.gauge("a.b"));
        assertEquals("a.b is a counter, not a gauge", e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> r.histogram("a.b"));
    }

    @Test
    void namesAreChecked() {
        StatsRegistry r = StatsRegistry.create();
        for (String bad : List.of("", ".a", "a.", "a..b", "a b", "a:b", "a\"b", "a{b}")) {
            assertThrows(IllegalArgumentException.class, () -> r.counter(bad), bad);
        }
        r.counter("listener.[__1]_8080.downstream_cx_total");
        r.counter("cluster.my-proxy_3128.upstream_rq_total");
    }

    @Test
    void tagsAreExtractedOnceAtRegistration() {
        StatsRegistry r = StatsRegistry.create();
        Counter c = r.counter("http.ingress.downstream_rq_2xx");
        assertEquals("http.downstream_rq_xx", c.tagExtractedName());
        assertEquals(List.of(new Tag("envoy_http_conn_manager_prefix", "ingress"), new Tag("envoy_response_code_class", "2")),
                c.tags());
        Metric cluster = r.counter("cluster.proxy_example_com_3128.upstream_rq_5xx");
        assertEquals("cluster.upstream_rq_xx", cluster.tagExtractedName());
        assertEquals(List.of(new Tag("envoy_cluster_name", "proxy_example_com_3128"), new Tag("envoy_response_code_class", "5")),
                cluster.tags());
        Metric listener = r.gauge("listener.127.0.0.1_8080.downstream_cx_active");
        assertEquals("listener.downstream_cx_active", listener.tagExtractedName());
        assertEquals(List.of(new Tag("envoy_listener_address", "127.0.0.1_8080")), listener.tags());
        Metric v6 = r.counter("listener.[__1]_8080.ssl.handshake");
        assertEquals("listener.ssl.handshake", v6.tagExtractedName());
        assertEquals(List.of(new Tag("envoy_listener_address", "[__1]_8080")), v6.tags());
        Metric flag = r.counter("http.ingress.downstream_rq_response_flag.UF");
        assertEquals("http.downstream_rq_response_flag", flag.tagExtractedName());
        assertEquals(List.of(new Tag("envoy_http_conn_manager_prefix", "ingress"), new Tag("microproxy_response_flag", "UF")),
                flag.tags());
        Metric plain = r.counter("server.total_connections");
        assertEquals("server.total_connections", plain.tagExtractedName());
        assertTrue(plain.tags().isEmpty());
        // Only a digit and "xx" end a response class.
        Metric total = r.counter("http.ingress.downstream_rq_total");
        assertEquals("http.downstream_rq_total", total.tagExtractedName());
        assertEquals(List.of(new Tag("envoy_http_conn_manager_prefix", "ingress")), total.tags());
    }

    @Test
    void customRulesRunAfterTheDefaults() {
        TagExtractor extractor = TagExtractor.envoyDefaults().with("script_area", "^script\\.(([a-z]+)\\.)");
        StatsRegistry r = StatsRegistry.builder().tagExtractor(extractor).build();
        Metric m = r.counter("script.auth.denied");
        assertEquals("script.denied", m.tagExtractedName());
        assertEquals(List.of(new Tag("script_area", "auth")), m.tags());
        assertThrows(IllegalArgumentException.class, () -> TagExtractor.none().with("t", "^a(b)"));
    }

    @Test
    void sanitizeLeavesNoDots() {
        assertEquals("proxy_example_com_3128", TagExtractor.sanitize("proxy.example.com:3128"));
        assertEquals("ok-name_1", TagExtractor.sanitize("ok-name_1"));
        assertEquals("_", TagExtractor.sanitize(""));
    }

    @Test
    void theNoopRegistryKeepsNothingAndItsMetricsDoNothing() {
        StatsRegistry r = StatsRegistry.NOOP;
        assertFalse(r.enabled());
        Counter c = r.counter("a.b");
        c.inc();
        c.add(10);
        assertEquals(0, c.value());
        Gauge g = r.gauge("a.c", "", () -> 42);
        g.set(5);
        assertEquals(0, g.value());
        Histogram h = r.histogram("a.d");
        h.record(3);
        assertEquals(0, h.snapshot().count());
        assertEquals(0, r.size());
        assertTrue(r.metrics().isEmpty());
        assertNull(r.get("a.b"));
        StatsScope scope = r.scope("script", 10);
        scope.counter("x").inc();
        assertEquals(0, scope.size());
        assertEquals("", StatsFormatter.prometheus(r));
    }

    @Test
    void supplierMetricsReadTheirValueWhenShown() {
        StatsRegistry r = StatsRegistry.create();
        AtomicLong hits = new AtomicLong();
        Counter c = r.counter("cache.hits", "hits", hits::get);
        Gauge g = r.gauge("server.total_connections", "open", () -> 7);
        hits.set(3);
        assertEquals(3, c.value());
        assertEquals(7, g.value());
        assertThrows(UnsupportedOperationException.class, c::inc);
        assertThrows(UnsupportedOperationException.class, () -> g.set(1));
        assertEquals("hits", c.help());
    }

    @Test
    void removedMetricsAreShownNoMore() {
        StatsRegistry r = StatsRegistry.create();
        Counter old = r.counter("cluster.a.upstream_rq_total");
        old.inc();
        assertTrue(r.remove("cluster.a.upstream_rq_total"));
        assertFalse(r.remove("cluster.a.upstream_rq_total"));
        assertNull(r.get("cluster.a.upstream_rq_total"));
        assertEquals(0, r.counter("cluster.a.upstream_rq_total").value(), "a new one starts from zero");
    }

    @Test
    void aScopeMakesAtMostItsLimit() {
        StatsRegistry r = StatsRegistry.create();
        StatsScope scope = r.scope("script", 2);
        assertSame(scope, r.scope("script", 50), "one scope per prefix");
        Counter a = scope.counter("a");
        Gauge b = scope.gauge("b");
        a.inc();
        b.set(4);
        Counter c = scope.counter("c");
        c.inc();
        assertEquals(0, c.value(), "past the limit, new names count nothing");
        assertNull(r.get("script.c"));
        assertSame(a, scope.counter("a"), "names already made keep working");
        assertEquals(1, r.counter("script.a").value());
        assertEquals(2, scope.size());
        assertThrows(IllegalArgumentException.class, () -> scope.gauge("a"));
        assertThrows(IllegalArgumentException.class, () -> scope.counter("bad name"));
    }

    @Test
    void theBuilderChecksItsSettings() {
        assertEquals("microproxy", StatsRegistry.builder().prefix("microproxy_").build().prefix());
        assertEquals("", StatsRegistry.builder().prefix("").build().prefix());
        assertThrows(IllegalArgumentException.class, () -> StatsRegistry.builder().prefix("a.b-c"));
        assertThrows(IllegalArgumentException.class, () -> StatsRegistry.builder().maxClusters(0));
        assertThrows(IllegalArgumentException.class, () -> StatsRegistry.builder().histogramBounds(1, 1));
        assertThrows(IllegalArgumentException.class, () -> StatsRegistry.builder().histogramBounds(2, Double.NaN));
        StatsRegistry r = StatsRegistry.builder().histogramBounds(1, 10).maxClusters(3)
                .clusterOverflow(StatsRegistry.Overflow.LRU).perHostClusters(true).maxScriptStats(5).build();
        assertArrayEquals(new double[] {1, 10}, r.histogramBounds());
        assertEquals(3, r.maxClusters());
        assertEquals(StatsRegistry.Overflow.LRU, r.clusterOverflow());
        assertTrue(r.perHostClusters());
        assertEquals(5, r.maxScriptStats());
        assertEquals(3, r.histogram("x").snapshot().buckets());
    }

    @Test
    void manyVirtualThreadsCountExactly() throws Exception {
        StatsRegistry r = StatsRegistry.create();
        int threads = 200;
        int perThread = 5_000;
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService exec = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int t = 0; t < threads; t++) {
                int id = t;
                exec.submit(() -> {
                    start.await();
                    // Every thread registers the same names, and holds its own references.
                    Counter c = r.counter("http.x.downstream_rq_total");
                    Gauge g = r.gauge("http.x.downstream_rq_active");
                    Histogram h = r.histogram("http.x.downstream_rq_time");
                    StatsScope scope = r.scope("script", 10);
                    for (int i = 0; i < perThread; i++) {
                        c.inc();
                        g.inc();
                        h.record(i % 2 == 0 ? 0.25 : 7);
                        scope.counter("n" + (i % 20)).inc();
                        g.dec();
                    }
                    r.counter("cluster.c" + (id % 7) + ".upstream_rq_total").inc();
                    return null;
                });
            }
            start.countDown();
        }
        long total = (long) threads * perThread;
        assertEquals(total, r.counter("http.x.downstream_rq_total").value());
        assertEquals(0, r.gauge("http.x.downstream_rq_active").value());
        Histogram.Snapshot s = r.histogram("http.x.downstream_rq_time").snapshot();
        assertEquals(total, s.count());
        assertEquals(total / 2, s.bucketCount(0));
        assertEquals(total / 2, s.bucketCount(3), "7 is in the (5, 10] bucket");
        assertEquals(total / 2 * 0.25 + total / 2 * 7, s.sum(), 1e-6);
        assertEquals(10, r.scope("script", 10).size(), "the scope stayed within its limit");
        long scripted = 0;
        for (int i = 0; i < 20; i++) {
            Metric m = r.get("script.n" + i);
            if (m instanceof Counter c) scripted += c.value();
        }
        assertEquals(total / 2, scripted, "the ten names made count every increment of theirs");
        long clusters = 0;
        for (int i = 0; i < 7; i++) clusters += r.counter("cluster.c" + i + ".upstream_rq_total").value();
        assertEquals(threads, clusters);
    }
}
