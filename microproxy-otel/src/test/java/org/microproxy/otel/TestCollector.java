package org.microproxy.otel;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.zip.GZIPInputStream;
import org.microproxy.TestSupport;
import org.microproxy.contentviews.DecodeException;
import org.microproxy.contentviews.ProtoMessage;
import org.microproxy.contentviews.ProtoValue;
import org.microproxy.contentviews.Protobuf;
import org.microproxy.extras.JsonForTests;

/**
 * An OTLP/HTTP collector for tests: it accepts {@code /v1/traces}, {@code /v1/metrics} and {@code
 * /v1/logs}, gzipped or not, and decodes protobuf bodies with the core's schema-less {@link
 * Protobuf} decoder (by the opentelemetry-proto field numbers) and JSON bodies with its JSON parser,
 * into the same plain records. It can answer the next requests with an error, to test retries.
 */
final class TestCollector implements AutoCloseable {

    private static final HexFormat HEX = HexFormat.of();

    record Span(String traceId, String spanId, String parentSpanId, String traceState, String name, int kind,
            long start, long end, Map<String, Object> attributes, List<Event> events, int statusCode,
            String statusMessage, int flags, Map<String, Object> resource, int droppedAttributes, int droppedEvents) {

        Object attr(String key) {
            return attributes.get(key);
        }

        Event event(String name) {
            return events.stream().filter(e -> e.name().equals(name)).findFirst().orElse(null);
        }
    }

    record Event(String name, long time, Map<String, Object> attributes) {}

    record Log(long time, long observed, int severity, String severityText, String body, Map<String, Object> attributes,
            String traceId, String spanId, int flags) {}

    record Point(Map<String, Object> attributes, long start, long time, long value, long count, double sum,
            List<Long> bucketCounts, List<Double> bounds) {}

    record Metric(String name, String description, String unit, String type, boolean monotonic, int temporality,
            List<Point> points) {}

    record Request(String path, String contentType, String contentEncoding, Map<String, List<String>> headers,
            byte[] body, long nanos) {}

    final HttpServer server;
    final List<Request> requests = new CopyOnWriteArrayList<>();
    final List<Span> spans = new CopyOnWriteArrayList<>();
    final List<Log> logs = new CopyOnWriteArrayList<>();
    final List<List<Metric>> metricExports = new CopyOnWriteArrayList<>();
    private final AtomicInteger failures = new AtomicInteger();
    private volatile int failStatus = 503;
    private volatile String retryAfter;

    TestCollector() throws IOException {
        server = HttpServer.create(new InetSocketAddress(TestSupport.LOOPBACK, 0), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.createContext("/", this::handle);
        server.start();
    }

    String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /** Answers the next {@code n} requests with {@code status} (and {@code Retry-After}, unless null). */
    void failNext(int n, int status, String retryAfter) {
        this.failStatus = status;
        this.retryAfter = retryAfter;
        failures.set(n);
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            byte[] raw = exchange.getRequestBody().readAllBytes();
            String encoding = exchange.getRequestHeaders().getFirst("Content-Encoding");
            byte[] body = "gzip".equals(encoding) ? gunzip(raw) : raw;
            String type = exchange.getRequestHeaders().getFirst("Content-Type");
            String path = exchange.getRequestURI().getPath();
            requests.add(new Request(path, type, encoding, Map.copyOf(exchange.getRequestHeaders()), body,
                    System.nanoTime()));
            if (failures.getAndUpdate(n -> Math.max(0, n - 1)) > 0) {
                if (retryAfter != null) exchange.getResponseHeaders().set("Retry-After", retryAfter);
                exchange.sendResponseHeaders(failStatus, -1);
                return;
            }
            boolean json = type != null && type.startsWith("application/json");
            try {
                switch (path) {
                    case "/v1/traces" -> spans.addAll(json ? jsonSpans(body) : protoSpans(body));
                    case "/v1/logs" -> logs.addAll(json ? jsonLogs(body) : protoLogs(body));
                    case "/v1/metrics" -> metricExports.add(json ? jsonMetrics(body) : protoMetrics(body));
                    default -> {
                        exchange.sendResponseHeaders(404, -1);
                        return;
                    }
                }
            } catch (DecodeException | RuntimeException e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(400, -1);
                return;
            }
            byte[] answer = json ? "{}".getBytes(StandardCharsets.UTF_8) : new byte[0];
            exchange.getResponseHeaders().set("Content-Type", json ? "application/json" : "application/x-protobuf");
            exchange.sendResponseHeaders(200, answer.length == 0 ? -1 : answer.length);
            if (answer.length > 0) exchange.getResponseBody().write(answer);
        }
    }

    static byte[] gunzip(byte[] raw) throws IOException {
        try (InputStream in = new GZIPInputStream(new ByteArrayInputStream(raw))) {
            return in.readAllBytes();
        }
    }

    // ---------------------------------------------------------------------------------------
    // Waiting

    List<Span> awaitSpans(String what, Predicate<List<Span>> done) {
        TestSupport.eventually(what + " in " + spans, () -> done.test(List.copyOf(spans)));
        return List.copyOf(spans);
    }

    Span awaitSpan(String what, Predicate<Span> matches) {
        TestSupport.eventually(what + " in " + spans, () -> spans.stream().anyMatch(matches));
        return spans.stream().filter(matches).findFirst().orElseThrow();
    }

    Log awaitLog(String what, Predicate<Log> matches) {
        TestSupport.eventually(what + " in " + logs, () -> logs.stream().anyMatch(matches));
        return logs.stream().filter(matches).findFirst().orElseThrow();
    }

    // ---------------------------------------------------------------------------------------
    // Protobuf, field by field (without a schema, whether a value is a message, text or bytes is
    // guessed; these read each one as the field is declared)

    static ProtoMessage message(ProtoValue v) throws DecodeException {
        return switch (v) {
            case ProtoValue.Message m -> m.message();
            case ProtoValue.Bytes b -> Protobuf.decode(b.data());
            case ProtoValue.Text t -> Protobuf.decode(t.utf8());
            default -> throw new DecodeException("not a message: " + v);
        };
    }

    static byte[] bytes(ProtoValue v) {
        return switch (v) {
            case ProtoValue.Bytes b -> b.data();
            case ProtoValue.Text t -> t.utf8();
            case ProtoValue.Message m -> Protobuf.encode(m.message());
            case ProtoValue.Packed p -> {
                ProtoMessage holder = new ProtoMessage(List.of(new org.microproxy.contentviews.ProtoField(1, p)));
                byte[] all = Protobuf.encode(holder);
                // Tag (1 byte) and length varint, then the payload.
                int i = 1;
                while ((all[i] & 0x80) != 0) i++;
                yield java.util.Arrays.copyOfRange(all, i + 1, all.length);
            }
            default -> throw new IllegalArgumentException("not length-delimited: " + v);
        };
    }

    static String text(ProtoValue v) {
        return new String(bytes(v), StandardCharsets.UTF_8);
    }

    static long fixed64(ProtoValue v) {
        return ((ProtoValue.Fixed64) v).bits();
    }

    static long varint(ProtoValue v) {
        return ((ProtoValue.Varint) v).value();
    }

    private static List<ProtoMessage> messages(ProtoMessage m, int field) throws DecodeException {
        List<ProtoMessage> out = new ArrayList<>();
        for (ProtoValue v : m.values(field)) out.add(message(v));
        return out;
    }

    private static ProtoMessage first(ProtoMessage m, int field) throws DecodeException {
        return message(m.first(field).orElseThrow(() -> new DecodeException("no field " + field)));
    }

    static String hex(ProtoValue v) {
        return HEX.formatHex(bytes(v));
    }

    /** Repeated {@code KeyValue}: key = 1, value = 2 ({@code AnyValue}). */
    static Map<String, Object> attributes(ProtoMessage m, int field) throws DecodeException {
        Map<String, Object> out = new LinkedHashMap<>();
        for (ProtoMessage kv : messages(m, field)) {
            out.put(text(kv.first(1).orElseThrow()), anyValue(first(kv, 2)));
        }
        return out;
    }

    /** {@code AnyValue}: string 1, bool 2, int 3, double 4, array 5. */
    static Object anyValue(ProtoMessage v) throws DecodeException {
        ProtoValue value = v.fields().getFirst().value();
        return switch (v.fields().getFirst().number()) {
            case 1 -> text(value);
            case 2 -> varint(value) != 0;
            case 3 -> varint(value);
            case 4 -> Double.longBitsToDouble(fixed64(value));
            case 5 -> {
                List<Object> list = new ArrayList<>();
                for (ProtoMessage e : messages(message(value), 1)) list.add(anyValue(e));
                yield list;
            }
            default -> throw new DecodeException("unexpected AnyValue " + v);
        };
    }

    static List<Span> protoSpans(byte[] body) throws DecodeException {
        List<Span> out = new ArrayList<>();
        for (ProtoMessage rs : messages(Protobuf.decode(body), 1)) {
            Map<String, Object> resource = attributes(first(rs, 1), 1);
            for (ProtoMessage ss : messages(rs, 2)) {
                ProtoMessage scope = first(ss, 1);
                if (!text(scope.first(1).orElseThrow()).equals("org.microproxy")) throw new DecodeException("scope");
                for (ProtoMessage s : messages(ss, 2)) {
                    List<Event> events = new ArrayList<>();
                    for (ProtoMessage e : messages(s, 11)) {
                        events.add(new Event(text(e.first(2).orElseThrow()), fixed64(e.first(1).orElseThrow()),
                                attributes(e, 3)));
                    }
                    int code = 0;
                    String message = null;
                    if (s.first(15).isPresent()) {
                        ProtoMessage status = first(s, 15);
                        code = (int) status.first(3).map(TestCollector::varint).orElse(0L).longValue();
                        message = status.first(2).map(TestCollector::text).orElse(null);
                    }
                    out.add(new Span(hex(s.first(1).orElseThrow()), hex(s.first(2).orElseThrow()),
                            s.first(4).map(TestCollector::hex).orElse(null),
                            s.first(3).map(TestCollector::text).orElse(""), text(s.first(5).orElseThrow()),
                            (int) varint(s.first(6).orElseThrow()), fixed64(s.first(7).orElseThrow()),
                            fixed64(s.first(8).orElseThrow()), attributes(s, 9), events, code, message,
                            ((ProtoValue.Fixed32) s.first(16).orElseThrow()).bits(), resource,
                            (int) s.first(10).map(TestCollector::varint).orElse(0L).longValue(),
                            (int) s.first(12).map(TestCollector::varint).orElse(0L).longValue()));
                }
            }
        }
        return out;
    }

    static List<Log> protoLogs(byte[] body) throws DecodeException {
        List<Log> out = new ArrayList<>();
        for (ProtoMessage rl : messages(Protobuf.decode(body), 1)) {
            for (ProtoMessage sl : messages(rl, 2)) {
                for (ProtoMessage l : messages(sl, 2)) {
                    out.add(new Log(fixed64(l.first(1).orElseThrow()), fixed64(l.first(11).orElseThrow()),
                            (int) varint(l.first(2).orElseThrow()), text(l.first(3).orElseThrow()),
                            text(first(l, 5).first(1).orElseThrow()), attributes(l, 6),
                            l.first(9).map(TestCollector::hex).orElse(null), l.first(10).map(TestCollector::hex).orElse(null),
                            l.first(8).map(v -> ((ProtoValue.Fixed32) v).bits()).orElse(0)));
                }
            }
        }
        return out;
    }

    static List<Metric> protoMetrics(byte[] body) throws DecodeException {
        List<Metric> out = new ArrayList<>();
        for (ProtoMessage rm : messages(Protobuf.decode(body), 1)) {
            for (ProtoMessage sm : messages(rm, 2)) {
                for (ProtoMessage m : messages(sm, 2)) {
                    String name = text(m.first(1).orElseThrow());
                    String description = m.first(2).map(TestCollector::text).orElse("");
                    String unit = m.first(3).map(TestCollector::text).orElse("");
                    List<Point> points = new ArrayList<>();
                    if (m.first(7).isPresent()) {
                        ProtoMessage sum = first(m, 7);
                        for (ProtoMessage p : messages(sum, 1)) points.add(numberPoint(p));
                        out.add(new Metric(name, description, unit, "sum", varint(sum.first(3).orElseThrow()) == 1,
                                (int) varint(sum.first(2).orElseThrow()), points));
                    } else if (m.first(5).isPresent()) {
                        for (ProtoMessage p : messages(first(m, 5), 1)) points.add(numberPoint(p));
                        out.add(new Metric(name, description, unit, "gauge", false, 0, points));
                    } else {
                        ProtoMessage histogram = first(m, 9);
                        for (ProtoMessage p : messages(histogram, 1)) {
                            List<Long> counts = new ArrayList<>();
                            ByteBuffer b = ByteBuffer.wrap(bytes(p.first(6).orElseThrow())).order(ByteOrder.LITTLE_ENDIAN);
                            while (b.hasRemaining()) counts.add(b.getLong());
                            List<Double> bounds = new ArrayList<>();
                            if (p.first(7).isPresent()) {
                                b = ByteBuffer.wrap(bytes(p.first(7).get())).order(ByteOrder.LITTLE_ENDIAN);
                                while (b.hasRemaining()) bounds.add(b.getDouble());
                            }
                            points.add(new Point(attributes(p, 9), fixed64(p.first(2).orElseThrow()),
                                    fixed64(p.first(3).orElseThrow()), 0, p.first(4).map(TestCollector::fixed64).orElse(0L),
                                    Double.longBitsToDouble(fixed64(p.first(5).orElseThrow())), counts, bounds));
                        }
                        out.add(new Metric(name, description, unit, "histogram", false,
                                (int) varint(histogram.first(2).orElseThrow()), points));
                    }
                }
            }
        }
        return out;
    }

    private static Point numberPoint(ProtoMessage p) throws DecodeException {
        return new Point(attributes(p, 7), fixed64(p.first(2).orElseThrow()), fixed64(p.first(3).orElseThrow()),
                fixed64(p.first(6).orElseThrow()), 0, 0, List.of(), List.of());
    }

    // ---------------------------------------------------------------------------------------
    // JSON

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) {
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> arr(Object o) {
        return o == null ? List.of() : (List<Object>) o;
    }

    private static long num(Object o) {
        if (o instanceof String s) return s.startsWith("-") ? Long.parseLong(s) : Long.parseUnsignedLong(s);
        return ((Number) o).longValue();
    }

    private static Map<String, Object> jsonAttributes(Object list) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Object kv : arr(list)) out.put((String) obj(kv).get("key"), jsonValue(obj(obj(kv).get("value"))));
        return out;
    }

    private static Object jsonValue(Map<String, Object> v) {
        Map.Entry<String, Object> e = v.entrySet().iterator().next();
        return switch (e.getKey()) {
            case "stringValue" -> e.getValue();
            case "boolValue" -> e.getValue();
            case "intValue" -> num(e.getValue());
            case "doubleValue" -> ((Number) e.getValue()).doubleValue();
            case "arrayValue" -> arr(obj(e.getValue()).get("values")).stream().map(x -> jsonValue(obj(x))).toList();
            default -> throw new IllegalArgumentException("unexpected AnyValue " + v);
        };
    }

    static List<Span> jsonSpans(byte[] body) {
        List<Span> out = new ArrayList<>();
        Map<String, Object> root = obj(JsonForTests.parse(new String(body, StandardCharsets.UTF_8)));
        for (Object rs : arr(root.get("resourceSpans"))) {
            Map<String, Object> resource = jsonAttributes(obj(obj(rs).get("resource")).get("attributes"));
            for (Object ss : arr(obj(rs).get("scopeSpans"))) {
                for (Object o : arr(obj(ss).get("spans"))) {
                    Map<String, Object> s = obj(o);
                    List<Event> events = new ArrayList<>();
                    for (Object e : arr(s.get("events"))) {
                        events.add(new Event((String) obj(e).get("name"), num(obj(e).get("timeUnixNano")),
                                jsonAttributes(obj(e).get("attributes"))));
                    }
                    Map<String, Object> status = obj(s.getOrDefault("status", Map.of()));
                    out.add(new Span((String) s.get("traceId"), (String) s.get("spanId"), (String) s.get("parentSpanId"),
                            (String) s.getOrDefault("traceState", ""), (String) s.get("name"), (int) num(s.get("kind")),
                            num(s.get("startTimeUnixNano")), num(s.get("endTimeUnixNano")),
                            jsonAttributes(s.get("attributes")), events,
                            status.containsKey("code") ? (int) num(status.get("code")) : 0, (String) status.get("message"),
                            (int) num(s.get("flags")), resource,
                            s.containsKey("droppedAttributesCount") ? (int) num(s.get("droppedAttributesCount")) : 0,
                            s.containsKey("droppedEventsCount") ? (int) num(s.get("droppedEventsCount")) : 0));
                }
            }
        }
        return out;
    }

    static List<Log> jsonLogs(byte[] body) {
        List<Log> out = new ArrayList<>();
        Map<String, Object> root = obj(JsonForTests.parse(new String(body, StandardCharsets.UTF_8)));
        for (Object rl : arr(root.get("resourceLogs"))) {
            for (Object sl : arr(obj(rl).get("scopeLogs"))) {
                for (Object o : arr(obj(sl).get("logRecords"))) {
                    Map<String, Object> l = obj(o);
                    out.add(new Log(num(l.get("timeUnixNano")), num(l.get("observedTimeUnixNano")),
                            (int) num(l.get("severityNumber")), (String) l.get("severityText"),
                            (String) obj(l.get("body")).get("stringValue"), jsonAttributes(l.get("attributes")),
                            (String) l.get("traceId"), (String) l.get("spanId"),
                            l.containsKey("flags") ? (int) num(l.get("flags")) : 0));
                }
            }
        }
        return out;
    }

    static List<Metric> jsonMetrics(byte[] body) {
        List<Metric> out = new ArrayList<>();
        Map<String, Object> root = obj(JsonForTests.parse(new String(body, StandardCharsets.UTF_8)));
        for (Object rm : arr(root.get("resourceMetrics"))) {
            for (Object sm : arr(obj(rm).get("scopeMetrics"))) {
                for (Object o : arr(obj(sm).get("metrics"))) {
                    Map<String, Object> m = obj(o);
                    String name = (String) m.get("name");
                    String description = (String) m.getOrDefault("description", "");
                    String unit = (String) m.getOrDefault("unit", "");
                    for (String type : List.of("sum", "gauge", "histogram")) {
                        if (!m.containsKey(type)) continue;
                        Map<String, Object> data = obj(m.get(type));
                        List<Point> points = new ArrayList<>();
                        for (Object p : arr(data.get("dataPoints"))) {
                            Map<String, Object> dp = obj(p);
                            points.add(new Point(jsonAttributes(dp.get("attributes")), num(dp.get("startTimeUnixNano")),
                                    num(dp.get("timeUnixNano")), dp.containsKey("asInt") ? num(dp.get("asInt")) : 0,
                                    dp.containsKey("count") ? num(dp.get("count")) : 0,
                                    dp.containsKey("sum") ? ((Number) dp.get("sum")).doubleValue() : 0,
                                    arr(dp.get("bucketCounts")).stream().map(TestCollector::num).toList(),
                                    arr(dp.get("explicitBounds")).stream().map(x -> ((Number) x).doubleValue()).toList()));
                        }
                        out.add(new Metric(name, description, unit, type, Boolean.TRUE.equals(data.get("isMonotonic")),
                                data.containsKey("aggregationTemporality") ? (int) num(data.get("aggregationTemporality")) : 0,
                                points));
                    }
                }
            }
        }
        return out;
    }
}
