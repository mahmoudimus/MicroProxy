package org.microproxy.otel;

import java.util.List;

/**
 * Encodes OTLP's export requests as protobuf ({@code application/x-protobuf}), with the field
 * numbers of opentelemetry-proto's {@code collector/{trace,metrics,logs}/v1} services and the
 * {@code trace}, {@code metrics}, {@code logs}, {@code common} and {@code resource} messages they
 * carry. One request holds one resource and one instrumentation scope.
 */
final class OtlpProto {

    private OtlpProto() {}

    /** {@code ExportTraceServiceRequest}. */
    static byte[] traces(Attrs resource, String scopeName, String scopeVersion, List<OtlpData.Span> spans) {
        ProtoWriter w = new ProtoWriter(256 + spans.size() * 512);
        int resourceSpans = w.begin(1);
        resource(w, 1, resource);
        int scopeSpans = w.begin(2);
        scope(w, 1, scopeName, scopeVersion);
        for (OtlpData.Span s : spans) span(w, 2, s);
        w.end(scopeSpans);
        w.end(resourceSpans);
        return w.toByteArray();
    }

    /** {@code ExportMetricsServiceRequest}. */
    static byte[] metrics(Attrs resource, String scopeName, String scopeVersion, List<OtlpData.Metric> metrics) {
        ProtoWriter w = new ProtoWriter(256 + metrics.size() * 128);
        int resourceMetrics = w.begin(1);
        resource(w, 1, resource);
        int scopeMetrics = w.begin(2);
        scope(w, 1, scopeName, scopeVersion);
        for (OtlpData.Metric m : metrics) metric(w, 2, m);
        w.end(scopeMetrics);
        w.end(resourceMetrics);
        return w.toByteArray();
    }

    /** {@code ExportLogsServiceRequest}. */
    static byte[] logs(Attrs resource, String scopeName, String scopeVersion, List<OtlpData.Log> logs) {
        ProtoWriter w = new ProtoWriter(256 + logs.size() * 384);
        int resourceLogs = w.begin(1);
        resource(w, 1, resource);
        int scopeLogs = w.begin(2);
        scope(w, 1, scopeName, scopeVersion);
        for (OtlpData.Log l : logs) log(w, 2, l);
        w.end(scopeLogs);
        w.end(resourceLogs);
        return w.toByteArray();
    }

    /** {@code Resource}: attributes = 1, dropped_attributes_count = 2. */
    private static void resource(ProtoWriter w, int field, Attrs attributes) {
        int m = w.begin(field);
        attributes(w, 1, attributes);
        if (attributes.dropped() > 0) w.varintField(2, attributes.dropped());
        w.end(m);
    }

    /** {@code InstrumentationScope}: name = 1, version = 2. */
    private static void scope(ProtoWriter w, int field, String name, String version) {
        int m = w.begin(field);
        w.stringField(1, name);
        if (version != null && !version.isEmpty()) w.stringField(2, version);
        w.end(m);
    }

    /**
     * {@code Span}: trace_id = 1, span_id = 2, trace_state = 3, parent_span_id = 4, name = 5, kind
     * = 6, start_time_unix_nano = 7, end_time_unix_nano = 8, attributes = 9,
     * dropped_attributes_count = 10, events = 11, dropped_events_count = 12, status = 15, flags = 16.
     */
    private static void span(ProtoWriter w, int field, OtlpData.Span s) {
        int m = w.begin(field);
        w.idField(1, s.traceIdHigh(), s.traceIdLow());
        w.idField(2, s.spanId());
        if (!s.traceState().isEmpty()) w.stringField(3, s.traceState());
        if (s.parentSpanId() != 0) w.idField(4, s.parentSpanId());
        w.stringField(5, s.name());
        w.varintField(6, s.kind());
        w.fixed64Field(7, s.startNanos());
        w.fixed64Field(8, s.endNanos());
        attributes(w, 9, s.attributes());
        if (s.attributes().dropped() > 0) w.varintField(10, s.attributes().dropped());
        for (OtlpData.Event e : s.events()) {
            // Span.Event: time_unix_nano = 1, name = 2, attributes = 3, dropped_attributes_count = 4.
            int em = w.begin(11);
            w.fixed64Field(1, e.timeNanos());
            w.stringField(2, e.name());
            attributes(w, 3, e.attributes());
            if (e.attributes().dropped() > 0) w.varintField(4, e.attributes().dropped());
            w.end(em);
        }
        if (s.droppedEvents() > 0) w.varintField(12, s.droppedEvents());
        if (s.statusCode() != OtlpData.STATUS_UNSET) {
            // Status: message = 2, code = 3.
            int sm = w.begin(15);
            if (s.statusMessage() != null && !s.statusMessage().isEmpty()) w.stringField(2, s.statusMessage());
            w.varintField(3, s.statusCode());
            w.end(sm);
        }
        w.fixed32Field(16, s.flags());
        w.end(m);
    }

    /**
     * {@code Metric}: name = 1, description = 2, unit = 3, gauge = 5, sum = 7, histogram = 9; {@code
     * Sum}: data_points = 1, aggregation_temporality = 2 (2, cumulative), is_monotonic = 3; {@code
     * Gauge}: data_points = 1; {@code Histogram}: data_points = 1, aggregation_temporality = 2.
     */
    private static void metric(ProtoWriter w, int field, OtlpData.Metric metric) {
        int m = w.begin(field);
        w.stringField(1, metric.name());
        if (!metric.description().isEmpty()) w.stringField(2, metric.description());
        if (!metric.unit().isEmpty()) w.stringField(3, metric.unit());
        switch (metric.type()) {
            case SUM -> {
                int sum = w.begin(7);
                for (OtlpData.Point p : metric.points()) numberPoint(w, metric, p);
                w.varintField(2, 2);
                w.varintField(3, 1);
                w.end(sum);
            }
            case GAUGE -> {
                int gauge = w.begin(5);
                for (OtlpData.Point p : metric.points()) numberPoint(w, metric, p);
                w.end(gauge);
            }
            case HISTOGRAM -> {
                int histogram = w.begin(9);
                for (OtlpData.Point p : metric.points()) histogramPoint(w, metric, p);
                w.varintField(2, 2);
                w.end(histogram);
            }
        }
        w.end(m);
    }

    /**
     * {@code NumberDataPoint} as data_points = 1: attributes = 7, start_time_unix_nano = 2,
     * time_unix_nano = 3, as_int = 6 ({@code sfixed64}).
     */
    private static void numberPoint(ProtoWriter w, OtlpData.Metric metric, OtlpData.Point p) {
        int m = w.begin(1);
        attributes(w, 7, p.attributes());
        w.fixed64Field(2, metric.startNanos());
        w.fixed64Field(3, metric.timeNanos());
        w.fixed64Field(6, p.value());
        w.end(m);
    }

    /**
     * {@code HistogramDataPoint} as data_points = 1: attributes = 9, start_time_unix_nano = 2,
     * time_unix_nano = 3, count = 4, sum = 5, bucket_counts = 6 (packed {@code fixed64}),
     * explicit_bounds = 7 (packed {@code double}).
     */
    private static void histogramPoint(ProtoWriter w, OtlpData.Metric metric, OtlpData.Point p) {
        int m = w.begin(1);
        attributes(w, 9, p.attributes());
        w.fixed64Field(2, metric.startNanos());
        w.fixed64Field(3, metric.timeNanos());
        // Fields at their default (a zero count, zero flags) are left out, as protobuf leaves them out.
        if (p.count() != 0) w.fixed64Field(4, p.count());
        w.doubleField(5, p.sum());
        int counts = w.begin(6);
        for (long c : p.bucketCounts()) w.rawFixed64(c);
        w.end(counts);
        if (p.bounds().length > 0) {
            int bounds = w.begin(7);
            for (double b : p.bounds()) w.rawFixed64(Double.doubleToRawLongBits(b));
            w.end(bounds);
        }
        w.end(m);
    }

    /**
     * {@code LogRecord}: time_unix_nano = 1, severity_number = 2, severity_text = 3, body = 5,
     * attributes = 6, dropped_attributes_count = 7, flags = 8, trace_id = 9, span_id = 10,
     * observed_time_unix_nano = 11.
     */
    private static void log(ProtoWriter w, int field, OtlpData.Log l) {
        int m = w.begin(field);
        w.fixed64Field(1, l.timeNanos());
        w.varintField(2, l.severityNumber());
        w.stringField(3, l.severityText());
        int body = w.begin(5);
        w.stringField(1, l.body());
        w.end(body);
        attributes(w, 6, l.attributes());
        if (l.attributes().dropped() > 0) w.varintField(7, l.attributes().dropped());
        if (l.spanId() != 0) {
            if (l.flags() != 0) w.fixed32Field(8, l.flags());
            w.idField(9, l.traceIdHigh(), l.traceIdLow());
            w.idField(10, l.spanId());
        }
        w.fixed64Field(11, l.observedNanos());
        w.end(m);
    }

    /** Repeated {@code KeyValue} as {@code field}: key = 1, value = 2. */
    private static void attributes(ProtoWriter w, int field, Attrs attributes) {
        for (int i = 0; i < attributes.size(); i++) {
            int m = w.begin(field);
            w.stringField(1, attributes.key(i));
            anyValue(w, 2, attributes.value(i));
            w.end(m);
        }
    }

    /**
     * {@code AnyValue}: string_value = 1, bool_value = 2, int_value = 3, double_value = 4,
     * array_value = 5 ({@code ArrayValue}: values = 1).
     */
    private static void anyValue(ProtoWriter w, int field, Object value) {
        int m = w.begin(field);
        switch (value) {
            case String s -> w.stringField(1, s);
            case Boolean b -> w.varintField(2, b ? 1 : 0);
            case Long l -> w.varintField(3, l);
            case Double d -> w.doubleField(4, d);
            case List<?> list -> {
                int array = w.begin(5);
                for (Object o : list) anyValue(w, 1, o);
                w.end(array);
            }
            default -> w.stringField(1, String.valueOf(value));
        }
        w.end(m);
    }
}
