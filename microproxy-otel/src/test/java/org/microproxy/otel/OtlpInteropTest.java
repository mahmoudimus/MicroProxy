package org.microproxy.otel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.extras.JsonForTests;

/**
 * An independent decoder accepts the proxy's OTLP: opentelemetry-proto's generated Python classes
 * parse the protobuf payloads (with no field they do not know) and the JSON ones, and both
 * encodings decode to the same messages; for payloads made by the encoders directly and for those
 * a proxy exported. The interpreter is {@code -Dotel.interop.python}, else {@code
 * $OTEL_INTEROP_PYTHON}, else the QUIC interop tests' ({@code -Dquic.interop.python}, {@code
 * $QUIC_INTEROP_PYTHON}), else {@code python3}; the tests are skipped when it lacks {@code
 * opentelemetry-proto}, unless {@code -Dotel.interop.required=true}.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class OtlpInteropTest {

    private static volatile String python;
    private static volatile Boolean available;

    @TempDir
    Path dir;

    static void assumeAvailable() {
        Boolean known = available;
        if (known == null) {
            String quic = System.getProperty("quic.interop.python",
                    System.getenv().getOrDefault("QUIC_INTEROP_PYTHON", "python3"));
            python = System.getProperty("otel.interop.python", System.getenv().getOrDefault("OTEL_INTEROP_PYTHON", quic));
            known = run(List.of(python, "-c", "import opentelemetry.proto.collector.trace.v1.trace_service_pb2")) != null;
            available = known;
        }
        if (Boolean.getBoolean("otel.interop.required")) {
            assertTrue(known, python + " with opentelemetry-proto is required but not available");
        }
        Assumptions.assumeTrue(known, python + " with opentelemetry-proto is not available");
    }

    /** Runs {@code command}; its output, or null when it failed. */
    private static String run(List<String> command) {
        try {
            Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
            byte[] out = p.getInputStream().readAllBytes();
            if (!p.waitFor(60, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return null;
            }
            String text = new String(out, StandardCharsets.UTF_8);
            if (p.exitValue() != 0) {
                System.err.println(text);
                return null;
            }
            return text;
        } catch (IOException e) {
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    private Path script() throws IOException {
        Path target = dir.resolve("otlp_check.py");
        try (InputStream in = OtlpInteropTest.class.getResourceAsStream("/interop/otlp_check.py")) {
            assertNotNull(in, "no test resource interop/otlp_check.py");
            if (!Files.exists(target)) Files.copy(in, target);
        }
        return target;
    }

    /** Checks the payloads ({@code signal:encoding} to bytes); returns the decoded messages per signal. */
    private Map<?, ?> check(Map<String, byte[]> payloads) throws IOException {
        List<String> command = new ArrayList<>(List.of(python, "-I", script().toString()));
        for (Map.Entry<String, byte[]> p : payloads.entrySet()) {
            Path file = Files.write(dir.resolve(p.getKey().replace(':', '.')), p.getValue());
            command.add(p.getKey() + ":" + file);
        }
        String out = run(command);
        assertNotNull(out, "the decoder refused the payloads");
        String line = out.lines().filter(l -> l.startsWith("RESULT ")).findFirst().orElseThrow(() -> new AssertionError(out));
        return (Map<?, ?>) JsonForTests.parse(line.substring("RESULT ".length()));
    }

    private static Object path(Object root, Object... keys) {
        Object o = root;
        for (Object k : keys) o = k instanceof Integer i ? ((List<?>) o).get(i) : ((Map<?, ?>) o).get(k);
        return o;
    }

    private static String hex(Object base64) {
        return HexFormat.of().formatHex(Base64.getDecoder().decode((String) base64));
    }

    @Test
    void theEncodersPayloadsDecodeWithOpentelemetryProto() throws Exception {
        assumeAvailable();
        Attrs resource = OtlpEncodingTest.resource();
        Map<?, ?> result = check(new java.util.LinkedHashMap<>(Map.of(
                "traces:proto", OtlpProto.traces(resource, "org.microproxy", "1.0", OtlpEncodingTest.spans()),
                "traces:json", OtlpJson.traces(resource, "org.microproxy", "1.0", OtlpEncodingTest.spans()),
                "metrics:proto", OtlpProto.metrics(resource, "org.microproxy", "1.0", OtlpEncodingTest.metrics()),
                "metrics:json", OtlpJson.metrics(resource, "org.microproxy", "1.0", OtlpEncodingTest.metrics()),
                "logs:proto", OtlpProto.logs(resource, "org.microproxy", "1.0", OtlpEncodingTest.logs()),
                "logs:json", OtlpJson.logs(resource, "org.microproxy", "1.0", OtlpEncodingTest.logs()))));
        Object span = path(result, "traces", "resourceSpans", 0, "scopeSpans", 0, "spans", 0);
        assertEquals("0af7651916cd43dd8448eb211c80319c", hex(path(span, "traceId")));
        assertEquals("00f067aa0ba902b7", hex(path(span, "spanId")));
        assertEquals("b7ad6b7169203331", hex(path(span, "parentSpanId")));
        assertEquals("SPAN_KIND_SERVER", path(span, "kind"));
        assertEquals("1700000000000000000", path(span, "startTimeUnixNano"));
        assertEquals("STATUS_CODE_ERROR", path(span, "status", "code"));
        assertEquals(769L, path(span, "flags"));
        assertEquals(3L, path(span, "droppedAttributesCount"));
        assertEquals("org.microproxy", path(result, "traces", "resourceSpans", 0, "scopeSpans", 0, "scope", "name"));
        Object metric = path(result, "metrics", "resourceMetrics", 0, "scopeMetrics", 0, "metrics", 2);
        assertEquals("envoy.http.downstream_rq_time", path(metric, "name"));
        assertEquals("AGGREGATION_TEMPORALITY_CUMULATIVE", path(metric, "histogram", "aggregationTemporality"));
        assertEquals(List.of("1", "0", "4"), path(metric, "histogram", "dataPoints", 0, "bucketCounts"));
        assertEquals("-3", path(result, "metrics", "resourceMetrics", 0, "scopeMetrics", 0, "metrics", 1, "gauge",
                "dataPoints", 0, "asInt"));
        assertEquals("SEVERITY_NUMBER_WARN", path(result, "logs", "resourceLogs", 0, "scopeLogs", 0, "logRecords", 0,
                "severityNumber"));
    }

    @Test
    void aProxysExportsDecodeWithOpentelemetryProto() throws Exception {
        assumeAvailable();
        for (Telemetry.Protocol protocol : Telemetry.Protocol.values()) {
            try (TestCollector collector = new TestCollector()) {
                HttpServer origin = TestSupport.origin(TestSupport.echo());
                Telemetry telemetry = Telemetry.builder().endpoint(collector.endpoint()).protocol(protocol)
                        .spanQueue(2048, 512, Duration.ofMillis(20)).logQueue(2048, 512, Duration.ofMillis(20))
                        .metricInterval(Duration.ofHours(1)).build();
                HttpProxyServer proxy = telemetry.install(MicroProxy.bootstrap().withPort(0)).start();
                try {
                    TestSupport.send(TestSupport.client(proxy), java.net.http.HttpRequest.newBuilder(
                            java.net.URI.create(TestSupport.url(origin, "/interop?x=1")))
                            .header("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01").build());
                    collector.awaitSpans("spans", s -> s.size() >= 2);
                    collector.awaitLog("the log", l -> l.body().contains("/interop"));
                    telemetry.flush(Duration.ofSeconds(10));
                } finally {
                    proxy.stop();
                    origin.stop(0);
                }
                String encoding = protocol == Telemetry.Protocol.HTTP_JSON ? "json" : "proto";
                Map<String, byte[]> payloads = new java.util.LinkedHashMap<>();
                for (TestCollector.Request r : collector.requests) {
                    String signal = r.path().substring("/v1/".length());
                    payloads.putIfAbsent(signal + ":" + encoding, r.body());
                }
                assertEquals(3, payloads.size(), payloads.keySet().toString());
                Map<?, ?> result = check(payloads);
                Object spans = path(result, "traces", "resourceSpans", 0, "scopeSpans", 0, "spans");
                assertEquals("0af7651916cd43dd8448eb211c80319c", hex(path(spans, 0, "traceId")));
                List<?> kinds = ((List<?>) spans).stream().map(s -> path(s, "kind")).toList();
                assertTrue(kinds.contains("SPAN_KIND_SERVER") && kinds.contains("SPAN_KIND_CLIENT"), kinds.toString());
                List<?> resourceAttributes = (List<?>) path(result, "traces", "resourceSpans", 0, "resource", "attributes");
                assertTrue(resourceAttributes.stream().anyMatch(a -> "service.name".equals(path(a, "key"))));
                assertNotNull(path(result, "metrics", "resourceMetrics", 0, "scopeMetrics", 0, "metrics", 0, "name"));
                assertTrue(((String) path(result, "logs", "resourceLogs", 0, "scopeLogs", 0, "logRecords", 0, "body",
                        "stringValue")).contains("/interop"));
            }
        }
    }
}
