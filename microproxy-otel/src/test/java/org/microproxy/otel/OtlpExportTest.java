package org.microproxy.otel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.Socket;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.FlowContext;
import org.microproxy.FlowTracer;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersAdapter;
import org.microproxy.HttpFiltersSourceAdapter;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.stats.Counter;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.Metric;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.stats.Tag;

/**
 * The OTLP exporters against a test collector: metrics that match the registry, access-log records
 * as log records, retries with backoff and {@code Retry-After}, gzip and headers, the bounded queue
 * dropping (and counting) when the collector is down, span limits, and a disabled SDK doing
 * nothing.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class OtlpExportTest {

    private TestCollector collector;
    private HttpServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() throws Exception {
        collector = new TestCollector();
        origin = TestSupport.origin(TestSupport.echo());
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.stop();
        origin.stop(0);
        collector.close();
    }

    private Telemetry.Builder telemetry() {
        return Telemetry.builder().endpoint(collector.endpoint())
                .spanQueue(2048, 512, Duration.ofMillis(20)).logQueue(2048, 512, Duration.ofMillis(20))
                .metricInterval(Duration.ofHours(1)).retry(3, Duration.ofMillis(10), Duration.ofMillis(50));
    }

    private HttpProxyServer start(Telemetry telemetry, HttpProxyServerBootstrap bootstrap) {
        proxy = telemetry.install(bootstrap.withPort(0)).start();
        return proxy;
    }

    @Test
    void metricsMatchTheRegistry() {
        for (Telemetry.Protocol protocol : Telemetry.Protocol.values()) {
            collector.metricExports.clear();
            StatsRegistry registry = StatsRegistry.builder().prefix("envoy").build();
            registry.counter("script.blocked", "Blocked requests").add(5);
            registry.counter("cluster.api_example_com_443.upstream_rq_2xx").add(4);
            registry.counter("cluster.api_example_com_443.upstream_rq_5xx").add(1);
            registry.gauge("script.queue").set(-7);
            Histogram score = registry.histogram("script.score_ms");
            for (double v : new double[] {0.2, 3, 3, 70, 1e7}) score.record(v);
            Telemetry telemetry = telemetry().traces(false).logs(false).protocol(protocol).build();
            start(telemetry, MicroProxy.bootstrap().withName("edge").withStats(registry));
            // Before any traffic, every value is still: compare them all.
            assertTrue(telemetry.flush(Duration.ofSeconds(10)));
            List<TestCollector.Metric> exported = collector.metricExports.getLast();
            int compared = 0;
            for (Metric m : registry.metrics()) {
                if (m.name().startsWith("otel.") || m.name().startsWith("server.")) continue;
                TestCollector.Metric otlp = exported.stream().filter(e -> e.name().equals("envoy." + m.tagExtractedName()))
                        .findFirst().orElseThrow(() -> new AssertionError("no " + m.tagExtractedName()));
                Map<String, Object> tags = new HashMap<>();
                for (Tag t : m.tags()) tags.put(t.name(), t.value());
                TestCollector.Point point = otlp.points().stream().filter(p -> p.attributes().equals(tags)).findFirst()
                        .orElseThrow(() -> new AssertionError(m.name() + " " + tags + " in " + otlp));
                switch (m) {
                    case Counter c -> {
                        assertEquals("sum", otlp.type(), m.name());
                        assertTrue(otlp.monotonic());
                        assertEquals(2, otlp.temporality(), "cumulative");
                        assertEquals(c.value(), point.value(), m.name());
                    }
                    case org.microproxy.stats.Gauge g -> {
                        assertEquals("gauge", otlp.type(), m.name());
                        assertEquals(g.value(), point.value(), m.name());
                    }
                    case Histogram h -> {
                        Histogram.Snapshot snap = h.snapshot();
                        assertEquals("histogram", otlp.type());
                        assertEquals(2, otlp.temporality());
                        assertEquals(snap.count(), point.count(), m.name());
                        assertEquals(snap.bounds().length + 1, point.bucketCounts().size());
                        for (int i = 0; i < snap.buckets(); i++) {
                            assertEquals(snap.bucketCount(i), point.bucketCounts().get(i), m.name() + " bucket " + i);
                        }
                        for (int i = 0; i < snap.bounds().length; i++) assertEquals(snap.bounds()[i], point.bounds().get(i));
                        assertEquals(snap.sum(), point.sum(), 1e-6);
                    }
                    default -> { }
                }
                assertTrue(point.time() >= point.start() && point.start() > 0);
                compared++;
            }
            assertTrue(compared > 50, "compared " + compared);
            TestCollector.Metric blocked = metric(exported, "envoy.script.blocked");
            assertEquals("Blocked requests", blocked.description());
            assertEquals(5, blocked.points().getFirst().value());
            TestCollector.Metric rq = metric(exported, "envoy.cluster.upstream_rq_xx");
            assertTrue(rq.points().stream().anyMatch(p -> p.value() == 1
                    && p.attributes().equals(Map.of("envoy_cluster_name", "api_example_com_443",
                            "envoy_response_code_class", "5"))), rq.toString());
            assertTrue(rq.points().stream().anyMatch(p -> p.value() == 4
                    && p.attributes().equals(Map.of("envoy_cluster_name", "api_example_com_443",
                            "envoy_response_code_class", "2"))), rq.toString());
            assertEquals(-7, metric(exported, "envoy.script.queue").points().getFirst().value());
            TestCollector.Metric hist = metric(exported, "envoy.script.score_ms");
            assertEquals("ms", hist.unit());
            assertEquals(List.of(1L, 0L, 2L, 0L, 0L, 0L, 1L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 1L),
                    hist.points().getFirst().bucketCounts());

            // Traffic shows in the next export.
            for (int i = 0; i < 3; i++) {
                assertEquals(200, TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/m" + i)).statusCode());
            }
            TestSupport.eventually("the requests counted",
                    () -> ((Counter) registry.get("http.edge.downstream_rq_total")).value() == 3);
            assertTrue(telemetry.flush(Duration.ofSeconds(10)));
            exported = collector.metricExports.getLast();
            TestCollector.Metric total = metric(exported, "envoy.http.downstream_rq_total");
            assertEquals(3, total.points().getFirst().value());
            assertEquals("edge", total.points().getFirst().attributes().get("envoy_http_conn_manager_prefix"));
            TestCollector.Metric time = metric(exported, "envoy.http.downstream_rq_time");
            assertEquals("ms", time.unit());
            assertEquals(3, time.points().getFirst().count());
            assertEquals(2, ((Counter) registry.get("otel.metrics_exports")).value());
            proxy.stop();
            proxy = null;
        }
    }

    private static TestCollector.Metric metric(List<TestCollector.Metric> exported, String name) {
        return exported.stream().filter(e -> e.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError("no " + name));
    }

    @Test
    void accessLogRecordsAreLogRecords() {
        Telemetry telemetry = telemetry().metrics(false).build();
        start(telemetry, MicroProxy.bootstrap());
        assertEquals(200, TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/logged")).statusCode());
        TestCollector.Log log = collector.awaitLog("the access log record", l -> l.body().contains("/logged"));
        assertTrue(log.body().contains("\"GET /logged HTTP/1.1\" 200"), log.body());
        assertEquals(9, log.severity());
        assertEquals("INFO", log.severityText());
        assertEquals("GET", log.attributes().get("http.request.method"));
        assertEquals(200L, log.attributes().get("http.response.status_code"));
        assertEquals("/logged", log.attributes().get("url.path"));
        assertEquals("h1", log.attributes().get("microproxy.flow"));
        assertTrue(log.attributes().get("microproxy.duration_ms") instanceof Double);
        assertNotNull(log.attributes().get("guid:x-request-id"));
        TestCollector.Span server = collector.awaitSpan("the server span", s -> s.kind() == 2);
        assertEquals(server.traceId(), log.traceId());
        assertEquals(server.spanId(), log.spanId());
        assertEquals(1, log.flags());
        assertEquals(server.attr("guid:x-request-id"), log.attributes().get("guid:x-request-id"));
        assertTrue(log.observed() >= log.time());

        try (Socket refusing = TestSupport.refusingPort()) {
            assertEquals(502, TestSupport.get(TestSupport.client(proxy), "http://127.0.0.1:" + refusing.getLocalPort() + "/x")
                    .statusCode());
            TestCollector.Log failed = collector.awaitLog("the failure's record", l -> l.body().contains(" 502 "));
            assertEquals(17, failed.severity());
            assertEquals("UF", failed.attributes().get("response_flags"));
            assertTrue(failed.body().contains("UF"), failed.body());
        } catch (java.io.IOException e) {
            throw new AssertionError(e);
        }
    }

    @Test
    void exportsAreRetriedOn503AndWaitForRetryAfter() {
        collector.failNext(2, 503, null);
        Telemetry telemetry = telemetry().metrics(false).logs(false).build();
        start(telemetry, MicroProxy.bootstrap().withMetrics(true));
        TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/retried"));
        collector.awaitSpans("the spans, after two refusals", s -> s.size() >= 2);
        assertEquals(3, collector.requests.size());
        StatsRegistry stats = proxy.getStats();
        assertEquals(2, ((Counter) stats.get("otel.spans_export_retries")).value());
        TestSupport.eventually("the export counted", () -> ((Counter) stats.get("otel.spans_exported")).value() == 2);

        collector.requests.clear();
        collector.spans.clear();
        collector.failNext(1, 429, "1");
        TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/after"));
        collector.awaitSpans("the spans, after a Retry-After", s -> s.size() >= 2);
        long waited = collector.requests.get(1).nanos() - collector.requests.get(0).nanos();
        assertTrue(waited >= TimeUnit.MILLISECONDS.toNanos(900), "waited " + waited / 1_000_000 + " ms");
    }

    @Test
    void aBatchIsDroppedAfterItsRetries() {
        collector.failNext(100, 400, null);
        // The request's two spans (server and client) are queued one after the other, but a stall
        // between the two (a GC pause, a busy CPU) longer than a batch's delay would send them in
        // two batches: here a batch is sent when it holds both, and only then.
        Telemetry telemetry = telemetry().metrics(false).logs(false).spanQueue(2048, 2, Duration.ofHours(1)).build();
        start(telemetry, MicroProxy.bootstrap().withMetrics(true));
        TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/rejected"));
        StatsRegistry stats = proxy.getStats();
        TestSupport.eventually("the failure counted", () -> ((Counter) stats.get("otel.spans_failed")).value() == 2);
        // A 400 is not retried.
        assertEquals(1, collector.requests.size());
        assertEquals(0, ((Counter) stats.get("otel.spans_export_retries")).value());
    }

    @Test
    void exportsAreGzippedWithTheConfiguredHeaders() {
        Telemetry telemetry = telemetry().metrics(false).logs(false).compression(true)
                .header("Authorization", "Bearer secret-token").header("X-Tenant", "a b").build();
        start(telemetry, MicroProxy.bootstrap());
        TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/gzip"));
        collector.awaitSpans("the spans", s -> s.size() >= 2);
        TestCollector.Request request = collector.requests.getFirst();
        assertEquals("/v1/traces", request.path());
        assertEquals("gzip", request.contentEncoding());
        assertEquals("application/x-protobuf", request.contentType());
        assertEquals(List.of("Bearer secret-token"), request.headers().get("Authorization"));
        assertEquals(List.of("a b"), request.headers().get("X-tenant"));
        assertTrue(request.headers().get("User-agent").getFirst().startsWith("MicroProxy-OTLP-Exporter/"));
    }

    @Test
    void theQueueDropsWhenTheCollectorIsDown() throws Exception {
        // A collector that accepts connections and never answers: the exporter hangs on its first batch.
        CountDownLatch release = new CountDownLatch(1);
        try (TestSupport.RawServer hung = TestSupport.rawServer(s -> release.await(30, TimeUnit.SECONDS))) {
            Telemetry telemetry = Telemetry.builder().endpoint("http://127.0.0.1:" + hung.port()).metrics(false)
                    .logs(false).spanQueue(4, 2, Duration.ofMillis(1)).timeout(Duration.ofSeconds(2))
                    .retry(1, Duration.ofMillis(10), Duration.ofMillis(10)).build();
            start(telemetry, MicroProxy.bootstrap().withMetrics(true));
            long started = System.nanoTime();
            for (int i = 0; i < 20; i++) {
                assertEquals(200, TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/" + i)).statusCode());
            }
            // The proxy never waited for the collector.
            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(10));
            StatsRegistry stats = proxy.getStats();
            Counter dropped = (Counter) stats.get("otel.spans_dropped");
            // 40 spans: at most 2 in the hung export and 4 in the queue; the rest dropped, and counted.
            TestSupport.eventually("the drops counted", () -> dropped.value() >= 34);
            assertTrue(telemetry.spans.queued() <= 4);
            assertTrue(org.microproxy.stats.StatsFormatter.prometheus(stats).contains("envoy_otel_spans_dropped "));
            release.countDown();
        }
    }

    @Test
    void spanLimitsBoundWhatFiltersAdd() {
        Telemetry telemetry = telemetry().metrics(false).logs(false)
                .spanLimits(new SpanLimits(40, 8, 2, 1)).build();
        start(telemetry, MicroProxy.bootstrap().withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                return new HttpFiltersAdapter(originalRequest, ctx) {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                        for (int i = 0; i < 50; i++) flowContext.trace().setAttribute("custom." + i, "a long value " + i);
                        flowContext.trace().setAttribute("custom.list", List.of(1, 2.5, true, "xyz"));
                        flowContext.trace().addEvent("checked", Map.of("rule", "r1", "extra", "dropped"));
                        flowContext.trace().addEvent("second", Map.of());
                        flowContext.trace().addEvent("third", Map.of());
                        return null;
                    }
                };
            }
        }));
        TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/limits"));
        TestCollector.Span server = collector.awaitSpan("the server span", s -> s.kind() == 2);
        assertEquals(40, server.attributes().size());
        assertTrue(server.droppedAttributes() > 0);
        assertEquals("GET", server.attr("http.request.method"));
        server.attributes().values().forEach(v -> {
            if (v instanceof String s) assertTrue(s.length() <= 8, s);
        });
        assertEquals(2, server.events().size(), server.events().toString());
        assertTrue(server.droppedEvents() >= 1);
    }

    @Test
    void customAttributesAndEventsReachTheSpan() {
        Telemetry telemetry = telemetry().metrics(false).logs(false).build();
        start(telemetry, MicroProxy.bootstrap().withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                return new HttpFiltersAdapter(originalRequest, ctx) {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                        flowContext.trace().setAttribute("tenant", "acme");
                        flowContext.trace().setAttribute("weights", List.of(1, 2.5, true, "xyz"));
                        flowContext.trace().addEvent("rule.matched", Map.of("rule", "r1", "score", 7));
                        return null;
                    }
                };
            }
        }));
        TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/custom"));
        TestCollector.Span server = collector.awaitSpan("the server span", s -> s.kind() == 2);
        assertEquals("acme", server.attr("tenant"));
        assertEquals(List.of(1L, 2.5, true, "xyz"), server.attr("weights"));
        TestCollector.Event event = server.event("rule.matched");
        assertEquals("r1", event.attributes().get("rule"));
        assertEquals(7L, event.attributes().get("score"));
    }

    @Test
    void aDisabledSdkDoesNothing() {
        Telemetry telemetry = Telemetry.fromEnvironment(Map.of("OTEL_SDK_DISABLED", "true",
                "OTEL_EXPORTER_OTLP_ENDPOINT", collector.endpoint())).build();
        assertFalse(telemetry.isEnabled());
        HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap();
        telemetry.install(bootstrap);
        assertSame(FlowTracer.NOOP, bootstrap.getTracer());
        assertFalse(bootstrap.getStats().enabled());
        assertTrue(telemetry.spans == null && telemetry.logRecords == null);
        proxy = bootstrap.withPort(0).start();
        String body = TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/off")).body();
        assertEquals(List.of(), TestSupport.echoedHeader(body, "traceparent"));
        assertEquals(List.of(), TestSupport.echoedHeader(body, "x-request-id"));
    }
}
