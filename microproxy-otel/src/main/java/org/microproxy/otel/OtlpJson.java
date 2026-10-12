package org.microproxy.otel;

import java.util.HexFormat;
import java.util.List;

/**
 * Encodes OTLP's export requests as JSON ({@code application/json}), in the OTLP/JSON mapping:
 * protobuf's JSON mapping with lowerCamelCase names, enums as numbers and 64-bit integers as
 * decimal strings, except that trace and span ids are hex strings rather than base64.
 */
final class OtlpJson {

    private static final HexFormat HEX = HexFormat.of();

    private OtlpJson() {}

    static byte[] traces(Attrs resource, String scopeName, String scopeVersion, List<OtlpData.Span> spans) {
        StringBuilder sb = new StringBuilder(256 + spans.size() * 768);
        sb.append("{\"resourceSpans\":[{");
        resource(sb, resource);
        sb.append(",\"scopeSpans\":[{");
        scope(sb, scopeName, scopeVersion);
        sb.append(",\"spans\":[");
        for (int i = 0; i < spans.size(); i++) {
            if (i > 0) sb.append(',');
            span(sb, spans.get(i));
        }
        sb.append("]}]}]}");
        return utf8(sb);
    }

    static byte[] metrics(Attrs resource, String scopeName, String scopeVersion, List<OtlpData.Metric> metrics) {
        StringBuilder sb = new StringBuilder(256 + metrics.size() * 256);
        sb.append("{\"resourceMetrics\":[{");
        resource(sb, resource);
        sb.append(",\"scopeMetrics\":[{");
        scope(sb, scopeName, scopeVersion);
        sb.append(",\"metrics\":[");
        for (int i = 0; i < metrics.size(); i++) {
            if (i > 0) sb.append(',');
            metric(sb, metrics.get(i));
        }
        sb.append("]}]}]}");
        return utf8(sb);
    }

    static byte[] logs(Attrs resource, String scopeName, String scopeVersion, List<OtlpData.Log> logs) {
        StringBuilder sb = new StringBuilder(256 + logs.size() * 512);
        sb.append("{\"resourceLogs\":[{");
        resource(sb, resource);
        sb.append(",\"scopeLogs\":[{");
        scope(sb, scopeName, scopeVersion);
        sb.append(",\"logRecords\":[");
        for (int i = 0; i < logs.size(); i++) {
            if (i > 0) sb.append(',');
            log(sb, logs.get(i));
        }
        sb.append("]}]}]}");
        return utf8(sb);
    }

    private static byte[] utf8(StringBuilder sb) {
        return sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static void resource(StringBuilder sb, Attrs attributes) {
        sb.append("\"resource\":{");
        attributes(sb, attributes);
        if (attributes.dropped() > 0) sb.append(",\"droppedAttributesCount\":").append(attributes.dropped());
        sb.append('}');
    }

    private static void scope(StringBuilder sb, String name, String version) {
        sb.append("\"scope\":{\"name\":");
        string(sb, name);
        if (version != null && !version.isEmpty()) {
            sb.append(",\"version\":");
            string(sb, version);
        }
        sb.append('}');
    }

    private static void span(StringBuilder sb, OtlpData.Span s) {
        sb.append("{\"traceId\":\"").append(SpanContext.traceIdHex(s.traceIdHigh(), s.traceIdLow()))
                .append("\",\"spanId\":\"").append(HEX.toHexDigits(s.spanId())).append('"');
        if (!s.traceState().isEmpty()) {
            sb.append(",\"traceState\":");
            string(sb, s.traceState());
        }
        if (s.parentSpanId() != 0) sb.append(",\"parentSpanId\":\"").append(HEX.toHexDigits(s.parentSpanId())).append('"');
        sb.append(",\"flags\":").append(Integer.toUnsignedString(s.flags()));
        sb.append(",\"name\":");
        string(sb, s.name());
        sb.append(",\"kind\":").append(s.kind());
        sb.append(",\"startTimeUnixNano\":\"").append(Long.toUnsignedString(s.startNanos()))
                .append("\",\"endTimeUnixNano\":\"").append(Long.toUnsignedString(s.endNanos())).append("\",");
        attributes(sb, s.attributes());
        if (s.attributes().dropped() > 0) sb.append(",\"droppedAttributesCount\":").append(s.attributes().dropped());
        if (!s.events().isEmpty()) {
            sb.append(",\"events\":[");
            for (int i = 0; i < s.events().size(); i++) {
                OtlpData.Event e = s.events().get(i);
                if (i > 0) sb.append(',');
                sb.append("{\"timeUnixNano\":\"").append(Long.toUnsignedString(e.timeNanos())).append("\",\"name\":");
                string(sb, e.name());
                sb.append(',');
                attributes(sb, e.attributes());
                if (e.attributes().dropped() > 0) sb.append(",\"droppedAttributesCount\":").append(e.attributes().dropped());
                sb.append('}');
            }
            sb.append(']');
        }
        if (s.droppedEvents() > 0) sb.append(",\"droppedEventsCount\":").append(s.droppedEvents());
        if (s.statusCode() != OtlpData.STATUS_UNSET) {
            // As in protobuf, an unset status is no status.
            sb.append(",\"status\":{");
            if (s.statusMessage() != null && !s.statusMessage().isEmpty()) {
                sb.append("\"message\":");
                string(sb, s.statusMessage());
                sb.append(',');
            }
            sb.append("\"code\":").append(s.statusCode()).append('}');
        }
        sb.append('}');
    }

    private static void metric(StringBuilder sb, OtlpData.Metric m) {
        sb.append("{\"name\":");
        string(sb, m.name());
        if (!m.description().isEmpty()) {
            sb.append(",\"description\":");
            string(sb, m.description());
        }
        if (!m.unit().isEmpty()) {
            sb.append(",\"unit\":");
            string(sb, m.unit());
        }
        switch (m.type()) {
            case SUM -> {
                sb.append(",\"sum\":{\"dataPoints\":[");
                numberPoints(sb, m);
                sb.append("],\"aggregationTemporality\":2,\"isMonotonic\":true}");
            }
            case GAUGE -> {
                sb.append(",\"gauge\":{\"dataPoints\":[");
                numberPoints(sb, m);
                sb.append("]}");
            }
            case HISTOGRAM -> {
                sb.append(",\"histogram\":{\"dataPoints\":[");
                for (int i = 0; i < m.points().size(); i++) {
                    OtlpData.Point p = m.points().get(i);
                    if (i > 0) sb.append(',');
                    sb.append('{');
                    attributes(sb, p.attributes());
                    times(sb, m);
                    sb.append(",\"count\":\"").append(p.count()).append("\",\"sum\":");
                    number(sb, p.sum());
                    sb.append(",\"bucketCounts\":[");
                    for (int b = 0; b < p.bucketCounts().length; b++) {
                        if (b > 0) sb.append(',');
                        sb.append('"').append(p.bucketCounts()[b]).append('"');
                    }
                    sb.append("],\"explicitBounds\":[");
                    for (int b = 0; b < p.bounds().length; b++) {
                        if (b > 0) sb.append(',');
                        number(sb, p.bounds()[b]);
                    }
                    sb.append("]}");
                }
                sb.append("],\"aggregationTemporality\":2}");
            }
        }
        sb.append('}');
    }

    private static void numberPoints(StringBuilder sb, OtlpData.Metric m) {
        for (int i = 0; i < m.points().size(); i++) {
            OtlpData.Point p = m.points().get(i);
            if (i > 0) sb.append(',');
            sb.append('{');
            attributes(sb, p.attributes());
            times(sb, m);
            sb.append(",\"asInt\":\"").append(p.value()).append("\"}");
        }
    }

    private static void times(StringBuilder sb, OtlpData.Metric m) {
        sb.append(",\"startTimeUnixNano\":\"").append(Long.toUnsignedString(m.startNanos()))
                .append("\",\"timeUnixNano\":\"").append(Long.toUnsignedString(m.timeNanos())).append('"');
    }

    private static void log(StringBuilder sb, OtlpData.Log l) {
        sb.append("{\"timeUnixNano\":\"").append(Long.toUnsignedString(l.timeNanos()))
                .append("\",\"observedTimeUnixNano\":\"").append(Long.toUnsignedString(l.observedNanos()))
                .append("\",\"severityNumber\":").append(l.severityNumber()).append(",\"severityText\":");
        string(sb, l.severityText());
        sb.append(",\"body\":{\"stringValue\":");
        string(sb, l.body());
        sb.append("},");
        attributes(sb, l.attributes());
        if (l.attributes().dropped() > 0) sb.append(",\"droppedAttributesCount\":").append(l.attributes().dropped());
        if (l.spanId() != 0) {
            sb.append(",\"flags\":").append(Integer.toUnsignedString(l.flags()))
                    .append(",\"traceId\":\"").append(SpanContext.traceIdHex(l.traceIdHigh(), l.traceIdLow()))
                    .append("\",\"spanId\":\"").append(HEX.toHexDigits(l.spanId())).append('"');
        }
        sb.append('}');
    }

    private static void attributes(StringBuilder sb, Attrs attributes) {
        sb.append("\"attributes\":[");
        for (int i = 0; i < attributes.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append("{\"key\":");
            string(sb, attributes.key(i));
            sb.append(",\"value\":");
            anyValue(sb, attributes.value(i));
            sb.append('}');
        }
        sb.append(']');
    }

    private static void anyValue(StringBuilder sb, Object value) {
        switch (value) {
            case String s -> {
                sb.append("{\"stringValue\":");
                string(sb, s);
                sb.append('}');
            }
            case Boolean b -> sb.append("{\"boolValue\":").append(b).append('}');
            case Long l -> sb.append("{\"intValue\":\"").append(l).append("\"}");
            case Double d -> {
                sb.append("{\"doubleValue\":");
                number(sb, d);
                sb.append('}');
            }
            case List<?> list -> {
                sb.append("{\"arrayValue\":{\"values\":[");
                for (int i = 0; i < list.size(); i++) {
                    if (i > 0) sb.append(',');
                    anyValue(sb, list.get(i));
                }
                sb.append("]}}");
            }
            default -> {
                sb.append("{\"stringValue\":");
                string(sb, String.valueOf(value));
                sb.append('}');
            }
        }
    }

    /** A double as protobuf's JSON mapping writes it: a number, or a string for NaN and the infinities. */
    private static void number(StringBuilder sb, double d) {
        if (Double.isNaN(d)) {
            sb.append("\"NaN\"");
        } else if (Double.isInfinite(d)) {
            sb.append(d > 0 ? "\"Infinity\"" : "\"-Infinity\"");
        } else if (d == Math.rint(d) && Math.abs(d) < 1e15) {
            sb.append((long) d);
        } else {
            sb.append(d);
        }
    }

    static void string(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x2028 || c == 0x2029
                            || Character.isSurrogate(c) && !validSurrogate(s, i)) {
                        sb.append("\\u").append(HEX.toHexDigits(c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private static boolean validSurrogate(String s, int i) {
        char c = s.charAt(i);
        if (Character.isHighSurrogate(c)) return i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1));
        return i > 0 && Character.isHighSurrogate(s.charAt(i - 1));
    }
}
