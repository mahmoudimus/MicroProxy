package org.microproxy.stats;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Histogram bucketing, and the Prometheus, text and JSON forms against golden output. */
class StatsFormatterTest {

    @Test
    void theDefaultBoundsAreEnvoys() {
        assertArrayEquals(new double[] {0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000, 300000,
            600000, 1800000, 3600000}, Histogram.defaultBounds());
        assertEquals(20, StatsRegistry.create().histogram("t").snapshot().buckets());
    }

    @Test
    void aBucketIncludesItsUpperBound() {
        Histogram h = StatsRegistry.builder().histogramBounds(1, 5, 10).build().histogram("t");
        for (double v : new double[] {0, 1, 1.0001, 5, 9.9, 10, 10.5, 1e9, -3}) h.record(v);
        Histogram.Snapshot s = h.snapshot();
        assertEquals(3, s.bucketCount(0), "0, 1 and -3 are at most 1");
        assertEquals(2, s.bucketCount(1), "1.0001 and 5");
        assertEquals(2, s.bucketCount(2), "9.9 and 10");
        assertEquals(2, s.bucketCount(3), "10.5 and 1e9 are above every bound");
        assertEquals(9, s.count());
        assertEquals(9, s.cumulativeCount(3));
        assertEquals(5, s.cumulativeCount(1));
        assertEquals(0 + 1 + 1.0001 + 5 + 9.9 + 10 + 10.5 + 1e9 - 3, s.sum(), 1e-6);
    }

    @Test
    void recordNanosRecordsMilliseconds() {
        Histogram h = StatsRegistry.create().histogram("t");
        h.recordNanos(2_500_000);
        h.recordNanos(100_000);
        Histogram.Snapshot s = h.snapshot();
        assertEquals(1, s.bucketCount(0), "0.1 ms");
        assertEquals(1, s.bucketCount(2), "2.5 ms is in (1, 5]");
        assertEquals(2.6, s.sum(), 1e-9);
    }

    @Test
    void quantilesInterpolateInsideTheirBucket() {
        Histogram h = StatsRegistry.builder().histogramBounds(10, 20).build().histogram("t");
        for (int i = 0; i < 10; i++) h.record(5);
        for (int i = 0; i < 10; i++) h.record(15);
        Histogram.Snapshot s = h.snapshot();
        assertEquals(10, s.quantile(0.5), 1e-9);
        assertEquals(15, s.quantile(0.75), 1e-9);
        assertEquals(20, s.quantile(1), 1e-9);
        assertEquals(0, s.quantile(0), 1e-9);
        h.record(1000);
        assertEquals(20, h.snapshot().quantile(1), 1e-9, "the +Inf bucket reads as the last bound");
        assertTrue(Double.isNaN(StatsRegistry.create().histogram("empty").snapshot().quantile(0.5)));
        assertThrows(IllegalArgumentException.class, () -> s.quantile(1.5));
    }

    /** A small registry with every kind and tag the proxy uses. */
    private static StatsRegistry sample(StatsRegistry r) {
        r.counter("http.ingress.downstream_rq_total", "Requests from clients").add(3);
        r.counter("http.ingress.downstream_rq_2xx", "Responses to clients by status class").add(2);
        r.counter("http.ingress.downstream_rq_5xx", "Responses to clients by status class").inc();
        r.counter("http.ingress.downstream_rq_response_flag.UF", "By flag").inc();
        r.gauge("listener.127.0.0.1_8080.downstream_cx_active", "Connections open").set(1);
        r.gauge("server.live", "", () -> 1);
        Histogram h = r.histogram("cluster.direct.upstream_rq_time", "Request time", 1, 10);
        h.record(0.5);
        h.record(4);
        h.record(12.25);
        r.counter("script.say_hi");
        return r;
    }

    @Test
    void prometheusMatchesTheGoldenExposition() {
        String expected = """
                # HELP envoy_cluster_upstream_rq_time Request time
                # TYPE envoy_cluster_upstream_rq_time histogram
                envoy_cluster_upstream_rq_time_bucket{envoy_cluster_name="direct",le="1"} 1
                envoy_cluster_upstream_rq_time_bucket{envoy_cluster_name="direct",le="10"} 2
                envoy_cluster_upstream_rq_time_bucket{envoy_cluster_name="direct",le="+Inf"} 3
                envoy_cluster_upstream_rq_time_sum{envoy_cluster_name="direct"} 16.75
                envoy_cluster_upstream_rq_time_count{envoy_cluster_name="direct"} 3
                # HELP envoy_http_downstream_rq_response_flag By flag
                # TYPE envoy_http_downstream_rq_response_flag counter
                envoy_http_downstream_rq_response_flag{envoy_http_conn_manager_prefix="ingress",microproxy_response_flag="UF"} 1
                # HELP envoy_http_downstream_rq_total Requests from clients
                # TYPE envoy_http_downstream_rq_total counter
                envoy_http_downstream_rq_total{envoy_http_conn_manager_prefix="ingress"} 3
                # HELP envoy_http_downstream_rq_xx Responses to clients by status class
                # TYPE envoy_http_downstream_rq_xx counter
                envoy_http_downstream_rq_xx{envoy_http_conn_manager_prefix="ingress",envoy_response_code_class="2"} 2
                envoy_http_downstream_rq_xx{envoy_http_conn_manager_prefix="ingress",envoy_response_code_class="5"} 1
                # HELP envoy_listener_downstream_cx_active Connections open
                # TYPE envoy_listener_downstream_cx_active gauge
                envoy_listener_downstream_cx_active{envoy_listener_address="127.0.0.1_8080"} 1
                # TYPE envoy_script_say_hi counter
                envoy_script_say_hi 0
                # TYPE envoy_server_live gauge
                envoy_server_live 1
                """;
        assertEquals(expected, StatsFormatter.prometheus(sample(StatsRegistry.create())));
    }

    @Test
    void thePrefixIsConfigurable() {
        StatsRegistry r = StatsRegistry.builder().prefix("microproxy").build();
        r.counter("server.x").inc();
        assertEquals("# TYPE microproxy_server_x counter\nmicroproxy_server_x 1\n", StatsFormatter.prometheus(r));
        StatsRegistry bare = StatsRegistry.builder().prefix("").build();
        bare.counter("server.x").inc();
        assertEquals("# TYPE server_x counter\nserver_x 1\n", StatsFormatter.prometheus(bare));
    }

    @Test
    void labelValuesAndHelpAreEscaped() {
        StatsRegistry r = StatsRegistry.builder()
                .tagExtractor(TagExtractor.none().with("who", "^x\\.(([^.]+)\\.)")).build();
        r.counter("x.a-b.y", "two\nlines \\ here").inc();
        assertEquals("# HELP envoy_x_y two\\nlines \\\\ here\n# TYPE envoy_x_y counter\nenvoy_x_y{who=\"a-b\"} 1\n",
                StatsFormatter.prometheus(r));
        assertEquals("_9lives", StatsFormatter.metricName("9lives"));
    }

    @Test
    void theTextDumpMatchesTheGoldenOne() {
        String expected = """
                http.ingress.downstream_rq_2xx: 2
                http.ingress.downstream_rq_5xx: 1
                http.ingress.downstream_rq_response_flag.UF: 1
                http.ingress.downstream_rq_total: 3
                listener.127.0.0.1_8080.downstream_cx_active: 1
                script.say_hi: 0
                server.live: 1
                cluster.direct.upstream_rq_time: P0(nan,0) P25(nan,0.75) P50(nan,5.5) P75(nan,10) P90(nan,10) \
                P95(nan,10) P99(nan,10) P99.5(nan,10) P99.9(nan,10) P100(nan,10)
                """;
        StatsRegistry r = sample(StatsRegistry.create());
        assertEquals(expected, StatsFormatter.text(r));
        r.histogram("cluster.idle.upstream_rq_time");
        assertTrue(StatsFormatter.text(r).endsWith("cluster.idle.upstream_rq_time: No recorded values\n"));
    }

    @Test
    void theJsonFormMatchesTheGoldenOne() {
        String expected = "{\"stats\":["
                + "{\"name\":\"http.ingress.downstream_rq_2xx\",\"value\":2},"
                + "{\"name\":\"http.ingress.downstream_rq_5xx\",\"value\":1},"
                + "{\"name\":\"http.ingress.downstream_rq_response_flag.UF\",\"value\":1},"
                + "{\"name\":\"http.ingress.downstream_rq_total\",\"value\":3},"
                + "{\"name\":\"listener.127.0.0.1_8080.downstream_cx_active\",\"value\":1},"
                + "{\"name\":\"script.say_hi\",\"value\":0},"
                + "{\"name\":\"server.live\",\"value\":1},"
                + "{\"histograms\":{\"supported_quantiles\":[0,25,50,75,90,95,99,99.5,99.9,100],"
                + "\"computed_quantiles\":[{\"name\":\"cluster.direct.upstream_rq_time\",\"values\":["
                + "{\"interval\":null,\"cumulative\":0},{\"interval\":null,\"cumulative\":0.75},"
                + "{\"interval\":null,\"cumulative\":5.5},{\"interval\":null,\"cumulative\":10},"
                + "{\"interval\":null,\"cumulative\":10},{\"interval\":null,\"cumulative\":10},"
                + "{\"interval\":null,\"cumulative\":10},{\"interval\":null,\"cumulative\":10},"
                + "{\"interval\":null,\"cumulative\":10},{\"interval\":null,\"cumulative\":10}]}]}}]}";
        assertEquals(expected, StatsFormatter.json(sample(StatsRegistry.create())));
        assertEquals("{\"stats\":[{\"histograms\":{\"supported_quantiles\":[0,25,50,75,90,95,99,99.5,99.9,100],"
                + "\"computed_quantiles\":[]}}]}", StatsFormatter.json(StatsRegistry.NOOP));
    }

    @Test
    void everyFormShowsOnlyWhatThePredicateAccepts() {
        StatsRegistry r = sample(StatsRegistry.create());
        r.histogram("cluster.idle.upstream_rq_time");
        assertEquals("http.ingress.downstream_rq_2xx: 2\nhttp.ingress.downstream_rq_5xx: 1\n",
                StatsFormatter.text(r, m -> m.name().matches("http\\..*_[0-9]xx")));
        assertEquals("# TYPE envoy_server_live gauge\nenvoy_server_live 1\n",
                StatsFormatter.prometheus(r, m -> m.name().startsWith("server.")));
        assertEquals("{\"stats\":[{\"name\":\"server.live\",\"value\":1},{\"histograms\":{\"supported_quantiles\":"
                + "[0,25,50,75,90,95,99,99.5,99.9,100],\"computed_quantiles\":[]}}]}",
                StatsFormatter.json(r, m -> m.name().startsWith("server.")));

        String used = StatsFormatter.text(r, StatsFormatter::used);
        assertTrue(used.contains("server.live: 1\n"), used);
        assertTrue(used.contains("cluster.direct.upstream_rq_time: P0"), used);
        assertTrue(!used.contains("script.say_hi") && !used.contains("cluster.idle"), "unused counter and histogram: " + used);
    }
}
