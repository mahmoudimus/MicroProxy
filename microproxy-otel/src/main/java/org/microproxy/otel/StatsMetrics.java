package org.microproxy.otel;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.microproxy.stats.Counter;
import org.microproxy.stats.Gauge;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.Metric;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.stats.Tag;

/**
 * Reads a {@link StatsRegistry} as OTLP metrics, the way Prometheus sees it: metrics with the same
 * tag-extracted name are one OTLP metric, named {@code <prefix>.<tag-extracted name>} ({@code
 * envoy.cluster.upstream_rq_total}), whose data points carry the tags as attributes. Counters are
 * monotonic cumulative sums, gauges are gauges, and histograms are cumulative histograms with the
 * registry's explicit bounds, all integers. Times run from when the proxy started.
 */
final class StatsMetrics {

    private StatsMetrics() {}

    static List<OtlpData.Metric> collect(StatsRegistry registry, String prefix, long startNanos, long nowNanos,
            SpanLimits limits) {
        Map<String, List<Metric>> families = new TreeMap<>();
        for (Metric m : registry.metrics()) {
            families.computeIfAbsent(m.tagExtractedName(), k -> new ArrayList<>()).add(m);
        }
        List<OtlpData.Metric> out = new ArrayList<>(families.size());
        String p = prefix == null || prefix.isEmpty() ? "" : prefix + ".";
        for (Map.Entry<String, List<Metric>> family : families.entrySet()) {
            List<Metric> members = family.getValue();
            Metric first = members.getFirst();
            Metric.Type type = first.type();
            Map<String, OtlpData.Point> points = new LinkedHashMap<>();
            String help = "";
            for (Metric m : members) {
                // A metric whose name clashes with a family of another kind is left out, as Prometheus's is.
                if (m.type() != type) continue;
                if (help.isEmpty()) help = m.help();
                Attrs attributes = new Attrs(limits.maxAttributes(), limits.maxAttributeValueLength());
                for (Tag t : m.tags()) attributes.put(t.name(), t.value());
                OtlpData.Point point = switch (m) {
                    case Counter c -> new OtlpData.Point(attributes, c.value(), 0, 0, null, null);
                    case Gauge g -> new OtlpData.Point(attributes, g.value(), 0, 0, null, null);
                    case Histogram h -> {
                        Histogram.Snapshot s = h.snapshot();
                        long[] counts = new long[s.buckets()];
                        for (int i = 0; i < counts.length; i++) counts[i] = s.bucketCount(i);
                        yield new OtlpData.Point(attributes, 0, s.count(), s.sum(), counts, s.bounds());
                    }
                    default -> null;
                };
                if (point != null) points.put(m.name(), point);
            }
            if (points.isEmpty()) continue;
            String name = p + family.getKey();
            OtlpData.MetricType otlpType = switch (type) {
                case COUNTER -> OtlpData.MetricType.SUM;
                case GAUGE -> OtlpData.MetricType.GAUGE;
                case HISTOGRAM -> OtlpData.MetricType.HISTOGRAM;
            };
            out.add(new OtlpData.Metric(name, help, unit(family.getKey(), type), otlpType, startNanos, nowNanos,
                    List.copyOf(points.values())));
        }
        return out;
    }

    /** The unit, by the name's suffix: {@code ms} and {@code us} for histograms, {@code By} for bytes. */
    static String unit(String name, Metric.Type type) {
        if (name.endsWith("_us")) return "us";
        if (name.endsWith("_ms") || type == Metric.Type.HISTOGRAM && name.endsWith("_time")) return "ms";
        if (name.contains("bytes")) return "By";
        if (type == Metric.Type.HISTOGRAM) return "ms";
        return "";
    }
}
