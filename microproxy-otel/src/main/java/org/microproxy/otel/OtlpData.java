package org.microproxy.otel;

import java.util.List;

/**
 * What is exported, as OTLP models it: finished spans, log records and metrics, each kept as plain
 * values until the encoders ({@link OtlpProto}, {@link OtlpJson}) write them.
 */
final class OtlpData {

    private OtlpData() {}

    /** {@code Span.SpanKind}. */
    static final int KIND_INTERNAL = 1;
    static final int KIND_SERVER = 2;
    static final int KIND_CLIENT = 3;

    /** {@code Status.StatusCode}. */
    static final int STATUS_UNSET = 0;
    static final int STATUS_ERROR = 2;

    /** {@code SeverityNumber}. */
    static final int SEVERITY_INFO = 9;
    static final int SEVERITY_WARN = 13;
    static final int SEVERITY_ERROR = 17;

    /** {@code SpanFlags}: the trace flags, and whether the parent's being remote is known, and is. */
    static final int FLAG_HAS_IS_REMOTE = 0x100;
    static final int FLAG_IS_REMOTE = 0x200;

    /** A finished span; {@code parentSpanId} is 0 for a root span. Times are epoch nanoseconds. */
    record Span(long traceIdHigh, long traceIdLow, long spanId, long parentSpanId, String traceState, int flags,
            String name, int kind, long startNanos, long endNanos, Attrs attributes, List<Event> events,
            int droppedEvents, int statusCode, String statusMessage) {}

    /** An event of a span. */
    record Event(long timeNanos, String name, Attrs attributes) {}

    /** A log record; {@code spanId} is 0 when it belongs to no span. */
    record Log(long timeNanos, long observedNanos, int severityNumber, String severityText, String body,
            Attrs attributes, long traceIdHigh, long traceIdLow, long spanId, int flags) {}

    /** The kind of a {@link Metric}. */
    enum MetricType { SUM, GAUGE, HISTOGRAM }

    /**
     * A metric with its data points, all cumulative from {@code startNanos} to {@code timeNanos};
     * sums are monotonic.
     */
    record Metric(String name, String description, String unit, MetricType type, long startNanos, long timeNanos,
            List<Point> points) {}

    /**
     * A data point: {@code value} for a sum or a gauge; {@code count}, {@code sum}, the count of
     * each bucket and the buckets' upper bounds for a histogram.
     */
    record Point(Attrs attributes, long value, long count, double sum, long[] bucketCounts, double[] bounds) {}
}
