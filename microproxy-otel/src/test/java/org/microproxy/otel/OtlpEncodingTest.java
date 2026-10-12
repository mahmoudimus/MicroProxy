package org.microproxy.otel;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.microproxy.contentviews.ProtoMessage;
import org.microproxy.contentviews.Protobuf;
import org.microproxy.extras.JsonForTests;

/**
 * The OTLP encoders: protobuf by the opentelemetry-proto field numbers (read back with the core's
 * schema-less decoder) and the OTLP/JSON mapping (hex ids, 64-bit numbers as strings), carrying
 * the same values; and the protobuf writer's nested lengths.
 */
class OtlpEncodingTest {

    static final long HIGH = 0x0af7651916cd43ddL;
    static final long LOW = 0x8448eb211c80319cL;

    static Attrs attrs(Object... kv) {
        Attrs a = new Attrs(128, 4096);
        for (int i = 0; i < kv.length; i += 2) a.put((String) kv[i], kv[i + 1]);
        return a;
    }

    static Attrs resource() {
        return attrs("service.name", "edge", "process.pid", 42L);
    }

    static List<OtlpData.Span> spans() {
        Attrs a = attrs("http.request.method", "GET", "http.response.status_code", 503L, "ratio", 0.5, "ok", false,
                "list", List.of("a", 1L, 2.5, true), "unicode", "café ☃ \"quoted\"\n");
        a.addDropped(3);
        OtlpData.Span server = new OtlpData.Span(HIGH, LOW, 0x00f067aa0ba902b7L, 0xb7ad6b7169203331L, "rojo=1,congo=2",
                0x301, "GET", OtlpData.KIND_SERVER, 1_700_000_000_000_000_000L, 1_700_000_000_250_000_000L, a,
                List.of(new OtlpData.Event(1_700_000_000_100_000_000L, "connect", attrs("microproxy.duration_ms", 1.25)),
                        new OtlpData.Event(1_700_000_000_200_000_000L, "first_byte", Attrs.EMPTY)),
                2, OtlpData.STATUS_ERROR, "proxy_failure:connect_failed");
        OtlpData.Span client = new OtlpData.Span(HIGH, LOW, 0x1L, 0x00f067aa0ba902b7L, "", 0x101, "GET",
                OtlpData.KIND_CLIENT, 1_700_000_000_050_000_000L, 1_700_000_000_240_000_000L, attrs("server.port", 443L),
                List.of(), 0, OtlpData.STATUS_UNSET, null);
        return List.of(server, client);
    }

    static List<OtlpData.Metric> metrics() {
        return List.of(
                new OtlpData.Metric("envoy.http.downstream_rq_total", "Requests", "", OtlpData.MetricType.SUM,
                        1_000L, 2_000L, List.of(new OtlpData.Point(attrs("envoy_http_conn_manager_prefix", "edge"), 42, 0, 0,
                                null, null))),
                new OtlpData.Metric("envoy.server.state", "", "", OtlpData.MetricType.GAUGE, 1_000L, 2_000L,
                        List.of(new OtlpData.Point(Attrs.EMPTY, -3, 0, 0, null, null),
                                new OtlpData.Point(attrs("k", "v"), 0, 0, 0, null, null))),
                new OtlpData.Metric("envoy.http.downstream_rq_time", "", "ms", OtlpData.MetricType.HISTOGRAM, 1_000L,
                        2_000L, List.of(new OtlpData.Point(Attrs.EMPTY, 0, 5, 1234.5, new long[] {1, 0, 4},
                                new double[] {0.5, 10}),
                                new OtlpData.Point(attrs("empty", true), 0, 0, 0, new long[] {0, 0, 0},
                                        new double[] {0.5, 10}))));
    }

    static List<OtlpData.Log> logs() {
        return List.of(
                new OtlpData.Log(1_700_000_000_000_000_000L, 1_700_000_000_300_000_000L, OtlpData.SEVERITY_WARN, "WARN",
                        "[2026-10-12T00:00:00.000Z] \"GET / HTTP/1.1\" 404", attrs("http.response.status_code", 404L),
                        HIGH, LOW, 0x00f067aa0ba902b7L, 1),
                new OtlpData.Log(1_700_000_000_000_000_000L, 1_700_000_000_300_000_000L, OtlpData.SEVERITY_INFO, "INFO",
                        "untraced", Attrs.EMPTY, 0, 0, 0, 0),
                new OtlpData.Log(1_700_000_000_000_000_000L, 1_700_000_000_300_000_000L, OtlpData.SEVERITY_INFO, "INFO",
                        "unsampled", Attrs.EMPTY, HIGH, LOW, 7, 0));
    }

    @Test
    void spansDecodeToTheSameValuesFromProtobufAndJson() throws Exception {
        List<TestCollector.Span> fromProto = TestCollector.protoSpans(OtlpProto.traces(resource(), "org.microproxy", "1.0", spans()));
        List<TestCollector.Span> fromJson = TestCollector.jsonSpans(OtlpJson.traces(resource(), "org.microproxy", "1.0", spans()));
        assertEquals(fromProto, fromJson);
        TestCollector.Span s = fromProto.getFirst();
        assertEquals("0af7651916cd43dd8448eb211c80319c", s.traceId());
        assertEquals("00f067aa0ba902b7", s.spanId());
        assertEquals("b7ad6b7169203331", s.parentSpanId());
        assertEquals("rojo=1,congo=2", s.traceState());
        assertEquals(2, s.kind());
        assertEquals(1_700_000_000_000_000_000L, s.start());
        assertEquals(1_700_000_000_250_000_000L, s.end());
        assertEquals(Map.of("http.request.method", "GET", "http.response.status_code", 503L, "ratio", 0.5, "ok", false,
                "list", List.of("a", 1L, 2.5, true), "unicode", "café ☃ \"quoted\"\n"), s.attributes());
        assertEquals(3, s.droppedAttributes());
        assertEquals(2, s.droppedEvents());
        assertEquals(List.of("connect", "first_byte"), s.events().stream().map(TestCollector.Event::name).toList());
        assertEquals(1.25, s.event("connect").attributes().get("microproxy.duration_ms"));
        assertEquals(2, s.statusCode());
        assertEquals("proxy_failure:connect_failed", s.statusMessage());
        assertEquals(0x301, s.flags());
        assertEquals(Map.of("service.name", "edge", "process.pid", 42L), s.resource());
        TestCollector.Span c = fromProto.get(1);
        assertEquals("0000000000000001", c.spanId());
        assertEquals(0, c.statusCode());
        assertNull(c.statusMessage());
        assertEquals("", c.traceState());
    }

    @Test
    void metricsDecodeToTheSameValuesFromProtobufAndJson() throws Exception {
        List<TestCollector.Metric> fromProto = TestCollector.protoMetrics(OtlpProto.metrics(resource(), "org.microproxy", "1", metrics()));
        List<TestCollector.Metric> fromJson = TestCollector.jsonMetrics(OtlpJson.metrics(resource(), "org.microproxy", "1", metrics()));
        assertEquals(fromProto, fromJson);
        TestCollector.Metric sum = fromProto.getFirst();
        assertEquals("sum", sum.type());
        assertEquals(true, sum.monotonic());
        assertEquals(2, sum.temporality());
        assertEquals("Requests", sum.description());
        assertEquals(42, sum.points().getFirst().value());
        assertEquals(1_000L, sum.points().getFirst().start());
        assertEquals(2_000L, sum.points().getFirst().time());
        assertEquals(-3, fromProto.get(1).points().getFirst().value());
        TestCollector.Point h = fromProto.get(2).points().getFirst();
        assertEquals(5, h.count());
        assertEquals(1234.5, h.sum());
        assertEquals(List.of(1L, 0L, 4L), h.bucketCounts());
        assertEquals(List.of(0.5, 10.0), h.bounds());
        assertEquals("ms", fromProto.get(2).unit());
    }

    @Test
    void logsDecodeToTheSameValuesFromProtobufAndJson() throws Exception {
        List<TestCollector.Log> fromProto = TestCollector.protoLogs(OtlpProto.logs(resource(), "org.microproxy", "1", logs()));
        List<TestCollector.Log> fromJson = TestCollector.jsonLogs(OtlpJson.logs(resource(), "org.microproxy", "1", logs()));
        assertEquals(fromProto, fromJson);
        TestCollector.Log l = fromProto.getFirst();
        assertEquals(13, l.severity());
        assertEquals("WARN", l.severityText());
        assertEquals("[2026-10-12T00:00:00.000Z] \"GET / HTTP/1.1\" 404", l.body());
        assertEquals("0af7651916cd43dd8448eb211c80319c", l.traceId());
        assertEquals("00f067aa0ba902b7", l.spanId());
        assertEquals(1, l.flags());
        assertNull(fromProto.get(1).traceId());
    }

    @Test
    void theJsonMappingWritesIdsInHexAnd64BitNumbersAsStrings() {
        String json = new String(OtlpJson.traces(resource(), "org.microproxy", "1.0", spans()), StandardCharsets.UTF_8);
        Map<?, ?> root = (Map<?, ?>) JsonForTests.parse(json);
        Map<?, ?> span = (Map<?, ?>) ((List<?>) ((Map<?, ?>) ((List<?>) ((Map<?, ?>) ((List<?>) root.get("resourceSpans"))
                .getFirst()).get("scopeSpans")).getFirst()).get("spans")).getFirst();
        assertEquals("0af7651916cd43dd8448eb211c80319c", span.get("traceId"));
        assertEquals("b7ad6b7169203331", span.get("parentSpanId"));
        assertEquals("1700000000000000000", span.get("startTimeUnixNano"));
        assertEquals(2L, span.get("kind"));
        assertEquals(Map.of("intValue", "503"), ((Map<?, ?>) ((List<?>) span.get("attributes")).get(1)).get("value"));
    }

    @Test
    void nestedLengthsOfEverySizeAreWrittenInPlace() throws Exception {
        for (int size : new int[] {0, 1, 127, 128, 16_383, 16_384, 2_097_151, 2_097_152}) {
            ProtoWriter w = new ProtoWriter(16);
            int outer = w.begin(1);
            int inner = w.begin(2);
            w.stringField(3, "x".repeat(size));
            w.end(inner);
            w.varintField(4, 150);
            w.end(outer);
            byte[] bytes = w.toByteArray();
            byte[] expected = Protobuf.encode(Map.of(1, new java.util.LinkedHashMap<>(Map.of(2, Map.of(3, "x".repeat(size)),
                    4, 150))));
            ProtoMessage decoded = Protobuf.decode(bytes);
            ProtoMessage outerMessage = TestCollector.message(decoded.first(1).orElseThrow());
            ProtoMessage innerMessage = TestCollector.message(outerMessage.first(2).orElseThrow());
            assertEquals(size, TestCollector.text(innerMessage.first(3).orElseThrow()).length(), "size " + size);
            assertEquals(150, TestCollector.varint(outerMessage.first(4).orElseThrow()));
            assertEquals(expected.length, bytes.length, "size " + size);
        }
        ProtoWriter w = new ProtoWriter(1);
        w.idField(1, HIGH, LOW);
        w.fixed64Field(2, -1L);
        w.doubleField(3, 1.5);
        w.fixed32Field(4, 0x301);
        assertArrayEquals(new byte[] {0x0a, 16, 0x0a, (byte) 0xf7, 0x65, 0x19, 0x16, (byte) 0xcd, 0x43, (byte) 0xdd,
            (byte) 0x84, 0x48, (byte) 0xeb, 0x21, 0x1c, (byte) 0x80, 0x31, (byte) 0x9c,
            0x11, -1, -1, -1, -1, -1, -1, -1, -1,
            0x19, 0, 0, 0, 0, 0, 0, (byte) 0xf8, 0x3f,
            0x25, 0x01, 0x03, 0, 0}, w.toByteArray());
    }
}
