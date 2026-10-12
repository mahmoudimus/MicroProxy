package org.microproxy.otel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.microproxy.FlowContext;
import org.microproxy.FlowTrace;
import org.microproxy.ClientDetails;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpVersion;

/** Configuration from OpenTelemetry's environment variables, and the tracer's decisions per request. */
class TelemetryConfigTest {

    private static final FlowContext FLOW = new FlowContext(1, () -> null, () -> null, new ClientDetails());

    private static HttpRequest request(String... headers) {
        HttpRequest r = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/");
        for (int i = 0; i < headers.length; i += 2) r.headers().add(headers[i], headers[i + 1]);
        return r;
    }

    @Test
    void theEnvironmentConfiguresEverything() {
        Map<String, String> env = Map.ofEntries(
                Map.entry("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318/"),
                Map.entry("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "https://logs.example/custom/path"),
                Map.entry("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json"),
                Map.entry("OTEL_EXPORTER_OTLP_HEADERS", "api-key=s%3Dcret, x-team = edge "),
                Map.entry("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip"),
                Map.entry("OTEL_EXPORTER_OTLP_TIMEOUT", "2500"),
                Map.entry("OTEL_SERVICE_NAME", "edge-proxy"),
                Map.entry("OTEL_RESOURCE_ATTRIBUTES", "service.name=ignored,deployment.environment=prod,team=a%2Cb"),
                Map.entry("OTEL_TRACES_SAMPLER", "parentbased_traceidratio"),
                Map.entry("OTEL_TRACES_SAMPLER_ARG", "0.25"),
                Map.entry("OTEL_PROPAGATORS", "b3multi,tracecontext,baggage"),
                Map.entry("OTEL_METRIC_EXPORT_INTERVAL", "15000"),
                Map.entry("OTEL_METRICS_EXPORTER", "none"),
                Map.entry("OTEL_BSP_MAX_QUEUE_SIZE", "64"),
                Map.entry("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "16"),
                Map.entry("OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT", "32"),
                Map.entry("OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT", "100"));
        Telemetry.Builder b = Telemetry.fromEnvironment(env);
        assertEquals("http://collector:4318/", b.endpoint);
        assertEquals("https://logs.example/custom/path", b.logsEndpoint);
        assertEquals(Telemetry.Protocol.HTTP_JSON, b.protocol);
        assertEquals(Map.of("api-key", "s=cret", "x-team", "edge"), b.headers);
        assertTrue(b.gzip);
        assertEquals(Duration.ofMillis(2500), b.timeout);
        assertEquals("ParentBased{root:TraceIdRatioBased{0.25}}", b.sampler.description());
        assertEquals(List.of(Propagators.B3_MULTI, Propagators.TRACE_CONTEXT), b.propagators);
        assertEquals(Duration.ofSeconds(15), b.metricInterval);
        assertFalse(b.metrics);
        assertTrue(b.traces && b.logs);
        assertEquals(64, b.spanQueue);
        assertEquals(16, b.spanBatch);
        assertEquals(new SpanLimits(32, 100, 128, 128), b.limits);
        Telemetry t = b.build();
        try {
            assertEquals("edge-proxy", t.resource.get("service.name"));
            assertEquals("prod", t.resource.get("deployment.environment"));
            assertEquals("a,b", t.resource.get("team"));
            assertEquals("java", t.resource.get("telemetry.sdk.language"));
            assertTrue(t.description().contains("traces to http://collector:4318/v1/traces"), t.description());
            assertTrue(t.description().contains("access logs to https://logs.example/custom/path"), t.description());
            assertFalse(t.description().contains("metrics to"), t.description());
        } finally {
            t.close();
        }
        assertEquals(URI.create("http://c:4318/v1/metrics"), Telemetry.signal(URI.create("http://c:4318"), "metrics"));
        assertTrue(Telemetry.configuredBy(env));
        assertFalse(Telemetry.configuredBy(Map.of("OTEL_SERVICE_NAME", "x")));
        assertFalse(Telemetry.configuredBy(Map.of("OTEL_EXPORTER_OTLP_ENDPOINT", "http://c", "OTEL_SDK_DISABLED", "true")));
    }

    @Test
    void badValuesAreRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> Telemetry.fromEnvironment(Map.of("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")));
        assertThrows(IllegalArgumentException.class,
                () -> Telemetry.fromEnvironment(Map.of("OTEL_TRACES_EXPORTER", "zipkin")));
        assertThrows(IllegalArgumentException.class,
                () -> Telemetry.fromEnvironment(Map.of("OTEL_EXPORTER_OTLP_ENDPOINT", "collector:4318")));
        assertThrows(IllegalArgumentException.class,
                () -> Telemetry.fromEnvironment(Map.of("OTEL_BSP_MAX_QUEUE_SIZE", "lots")));
        assertThrows(IllegalArgumentException.class,
                () -> Telemetry.fromEnvironment(Map.of("OTEL_EXPORTER_OTLP_HEADERS", "novalue")));
    }

    @Test
    void requestIdsAreKeptMadeOrLeftAlone() {
        Telemetry keep = Telemetry.builder().traces(false).metrics(false).logs(false).build();
        HttpRequest absent = request();
        FlowTrace made = keep.startExchange(FLOW, absent);
        assertEquals(made.requestId(), absent.headers().get("x-request-id"));
        assertEquals(4, java.util.UUID.fromString(made.requestId()).version());
        HttpRequest present = request("X-Request-Id", "abc");
        assertEquals("abc", keep.startExchange(FLOW, present).requestId());
        assertEquals("abc", present.headers().get("x-request-id"));

        Telemetry replace = Telemetry.builder().traces(false).metrics(false).logs(false)
                .requestId(Telemetry.RequestIdMode.REPLACE).build();
        present = request("X-Request-Id", "abc");
        String replaced = replace.startExchange(FLOW, present).requestId();
        assertFalse(replaced.equals("abc"));
        assertEquals(List.of(replaced), present.headers().getAll("x-request-id"));

        Telemetry off = Telemetry.builder().traces(false).metrics(false).logs(false).propagators(List.of())
                .requestId(Telemetry.RequestIdMode.OFF).build();
        absent = request();
        assertEquals(FlowTrace.NONE, off.startExchange(FLOW, absent));
        assertNull(absent.headers().get("x-request-id"));
    }

    @Test
    void theLastPropagatorWithAValidContextGivesTheParentAsTheCompositeOne() {
        String w3c = "0af7651916cd43dd8448eb211c80319c";
        String b3 = "80f198ee56343ba864fe8b2a57d3eff7";
        String[] both = {"traceparent", "00-" + w3c + "-b7ad6b7169203331-01",
            "X-B3-TraceId", b3, "X-B3-SpanId", "e457b5a2e4d86bd1", "X-B3-Sampled", "1"};
        Telemetry b3First = Telemetry.builder().traces(false).metrics(false).logs(false)
                .propagators(List.of(Propagators.B3_MULTI, Propagators.TRACE_CONTEXT)).build();
        assertEquals(w3c, b3First.startExchange(FLOW, request(both)).traceId());
        Telemetry w3cFirst = Telemetry.builder().traces(false).metrics(false).logs(false)
                .propagators(List.of(Propagators.TRACE_CONTEXT, Propagators.B3_MULTI)).build();
        assertEquals(b3, w3cFirst.startExchange(FLOW, request(both)).traceId());
        // A later propagator that finds nothing valid leaves what an earlier one found.
        assertEquals(w3c, w3cFirst.startExchange(FLOW, request("traceparent", "00-" + w3c + "-b7ad6b7169203331-01",
                "X-B3-TraceId", "not-hex", "X-B3-SpanId", "e457b5a2e4d86bd1")).traceId());
        assertEquals(b3, b3First.startExchange(FLOW, request("traceparent", "ff-" + w3c + "-b7ad6b7169203331-01",
                "X-B3-TraceId", b3, "X-B3-SpanId", "e457b5a2e4d86bd1")).traceId());
        // Injection writes every propagator's headers.
        FlowTrace trace = b3First.startExchange(FLOW, request(both));
        org.microproxy.http.HttpHeaders upstream = new org.microproxy.http.HttpHeaders();
        trace.injectUpstream(upstream, false);
        assertEquals(w3c, upstream.get("x-b3-traceid"));
        assertEquals("00-" + w3c + "-" + trace.spanId() + "-01", upstream.get("traceparent"));
    }

    @Test
    void unsampledExchangesOnlyPropagate() {
        Telemetry t = Telemetry.builder().sampler(Sampler.alwaysOff()).metrics(false).logs(false).build();
        try {
            FlowTrace trace = t.startExchange(FLOW, request("traceparent",
                    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"));
            // The parent was sampled and the sampler only decides for new traces... unless it is not parent-based.
            assertFalse(trace instanceof RecordingSpan);
            assertFalse(trace.isSampled());
            assertEquals("0af7651916cd43dd8448eb211c80319c", trace.traceId());
            assertEquals(16, trace.spanId().length());
            trace.setAttribute("ignored", "x");
            trace.addEvent("ignored", Map.of());
            org.microproxy.http.HttpHeaders upstream = new org.microproxy.http.HttpHeaders();
            trace.injectUpstream(upstream, false);
            assertEquals("00-0af7651916cd43dd8448eb211c80319c-" + trace.spanId() + "-00", upstream.get("traceparent"));

            Telemetry parentBased = Telemetry.builder().sampler(Sampler.parentBased(Sampler.alwaysOff()))
                    .metrics(false).logs(false).build();
            try {
                FlowTrace sampled = parentBased.startExchange(FLOW, request("traceparent",
                        "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"));
                assertTrue(sampled instanceof RecordingSpan);
                assertTrue(sampled.isSampled());
                assertFalse(parentBased.startExchange(FLOW, request()).isSampled());
            } finally {
                parentBased.close();
            }
        } finally {
            t.close();
        }
    }
}
