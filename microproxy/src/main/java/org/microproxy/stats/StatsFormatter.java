package org.microproxy.stats;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Predicate;

/**
 * Renders a registry's metrics as Envoy's admin endpoint does: Prometheus's text exposition
 * format, the plain {@code /stats} dump and its JSON form.
 *
 * <p>Prometheus names are the registry's {@linkplain StatsRegistry#prefix() prefix}, {@code _},
 * and the {@linkplain Metric#tagExtractedName() tag-extracted name} with its dots made {@code _};
 * the tags are labels: {@code envoy_cluster_upstream_rq_xx{envoy_response_code_class="2",
 * envoy_cluster_name="direct"} 7}. The other forms use the flat names.
 */
public final class StatsFormatter {

    /** The quantiles the text and JSON forms show of a histogram, in percent, as Envoy's do. */
    private static final double[] QUANTILES = {0, 25, 50, 75, 90, 95, 99, 99.5, 99.9, 100};

    private StatsFormatter() {}

    /** The content type of {@link #prometheus}'s output. */
    public static final String PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";

    /**
     * The metrics in Prometheus's text exposition format, version 0.0.4: per family (metrics with
     * the same tag-extracted name), a {@code # HELP} line when the metric has a description, a
     * {@code # TYPE} line, and a sample per tag set; a histogram has a cumulative {@code _bucket}
     * sample per bound ({@code le}, the last {@code +Inf}), then {@code _sum} and {@code _count}.
     * Families are sorted by name, samples by labels.
     *
     * @param registry the metrics
     * @return the exposition
     */
    public static String prometheus(StatsRegistry registry) {
        return prometheus(registry, m -> true);
    }

    /**
     * The metrics {@code include} accepts, in Prometheus's text exposition format (see {@link
     * #prometheus(StatsRegistry)}).
     *
     * @param registry the metrics
     * @param include which metrics to show
     * @return the exposition
     */
    public static String prometheus(StatsRegistry registry, Predicate<? super Metric> include) {
        StringBuilder out = new StringBuilder(4096);
        String prefix = registry.prefix().isEmpty() ? "" : registry.prefix() + "_";
        Map<String, List<Metric>> families = new TreeMap<>();
        for (Metric m : registry.metrics()) {
            if (!include.test(m)) continue;
            families.computeIfAbsent(prefix + metricName(m.tagExtractedName()), k -> new ArrayList<>()).add(m);
        }
        for (Map.Entry<String, List<Metric>> family : families.entrySet()) {
            String name = family.getKey();
            List<Metric> members = family.getValue();
            members.sort(Comparator.comparing(m -> labels(m.tags(), null, null)));
            Metric first = members.getFirst();
            String help = members.stream().map(Metric::help).filter(h -> !h.isEmpty()).findFirst().orElse("");
            if (!help.isEmpty()) out.append("# HELP ").append(name).append(' ').append(escapeHelp(help)).append('\n');
            out.append("# TYPE ").append(name).append(' ').append(first.type().prometheusName()).append('\n');
            for (Metric m : members) {
                // A metric whose name clashes with a family of another kind is left out.
                if (m.type() != first.type()) continue;
                switch (m) {
                    case Counter c -> sample(out, name, labels(m.tags(), null, null), Long.toString(c.value()));
                    case Gauge g -> sample(out, name, labels(m.tags(), null, null), Long.toString(g.value()));
                    case Histogram h -> histogram(out, name, m.tags(), h.snapshot());
                    default -> { }
                }
            }
        }
        return out.toString();
    }

    private static void histogram(StringBuilder out, String name, List<Tag> tags, Histogram.Snapshot s) {
        double[] bounds = s.bounds();
        long cumulative = 0;
        for (int i = 0; i < s.buckets(); i++) {
            cumulative += s.bucketCount(i);
            String le = i < bounds.length ? number(bounds[i]) : "+Inf";
            sample(out, name + "_bucket", labels(tags, "le", le), Long.toString(cumulative));
        }
        String labels = labels(tags, null, null);
        sample(out, name + "_sum", labels, number(s.sum()));
        sample(out, name + "_count", labels, Long.toString(s.count()));
    }

    private static void sample(StringBuilder out, String name, String labels, String value) {
        out.append(name).append(labels).append(' ').append(value).append('\n');
    }

    /** The label set {@code {a="1",b="2"}} of {@code tags}, plus {@code extra} if not null; empty for none. */
    private static String labels(List<Tag> tags, String extra, String extraValue) {
        if (tags.isEmpty() && extra == null) return "";
        StringBuilder sb = new StringBuilder().append('{');
        for (Tag t : tags) {
            if (sb.length() > 1) sb.append(',');
            sb.append(labelName(t.name())).append("=\"").append(escapeLabel(t.value())).append('"');
        }
        if (extra != null) {
            if (sb.length() > 1) sb.append(',');
            sb.append(extra).append("=\"").append(extraValue).append('"');
        }
        return sb.append('}').toString();
    }

    /**
     * {@code name} as a Prometheus metric name: every character other than a letter, digit, {@code
     * _} or {@code :} becomes {@code _}, and a leading digit gets a {@code _} before it.
     *
     * @param name a tag-extracted stat name
     * @return the Prometheus name, without the prefix
     */
    public static String metricName(String name) {
        StringBuilder sb = new StringBuilder(name.length() + 1);
        if (!name.isEmpty() && Character.isDigit(name.charAt(0))) sb.append('_');
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            sb.append((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == ':'
                    ? c : '_');
        }
        return sb.toString();
    }

    private static String labelName(String name) {
        return metricName(name).replace(':', '_');
    }

    private static String escapeLabel(String value) {
        if (value.indexOf('\\') < 0 && value.indexOf('"') < 0 && value.indexOf('\n') < 0) return value;
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private static String escapeHelp(String help) {
        return help.replace("\\", "\\\\").replace("\n", "\\n");
    }

    /** A number as Prometheus reads it: integers without a fraction, others as Java writes doubles. */
    static String number(double v) {
        if (Double.isNaN(v)) return "NaN";
        if (Double.isInfinite(v)) return v > 0 ? "+Inf" : "-Inf";
        if (v == Math.rint(v) && Math.abs(v) < 1e15) return Long.toString((long) v);
        return Double.toString(v);
    }

    /**
     * The metrics as Envoy's {@code /stats} text: a line {@code name: value} per counter and gauge,
     * sorted by flat name, then a line per histogram with its estimated quantiles, {@code name:
     * P0(nan,0.5) P25(nan,1.2) ...} (Envoy's interval values are not kept: {@code nan}), or {@code
     * name: No recorded values}.
     *
     * @param registry the metrics
     * @return the dump, a line per metric
     */
    public static String text(StatsRegistry registry) {
        return text(registry, m -> true);
    }

    /**
     * The metrics {@code include} accepts, as Envoy's {@code /stats} text (see {@link
     * #text(StatsRegistry)}).
     *
     * @param registry the metrics
     * @param include which metrics to show
     * @return the dump, a line per metric
     */
    public static String text(StatsRegistry registry, Predicate<? super Metric> include) {
        StringBuilder out = new StringBuilder(4096);
        List<Metric> metrics = registry.metrics().stream().filter(include).toList();
        for (Metric m : metrics) {
            switch (m) {
                case Counter c -> out.append(m.name()).append(": ").append(c.value()).append('\n');
                case Gauge g -> out.append(m.name()).append(": ").append(g.value()).append('\n');
                default -> { }
            }
        }
        for (Metric m : metrics) {
            if (!(m instanceof Histogram h)) continue;
            Histogram.Snapshot s = h.snapshot();
            out.append(m.name()).append(':');
            if (s.count() == 0) {
                out.append(" No recorded values");
            } else {
                for (double q : QUANTILES) {
                    out.append(" P").append(number(q)).append("(nan,").append(number(round(s.quantile(q / 100)))).append(')');
                }
            }
            out.append('\n');
        }
        return out.toString();
    }

    /**
     * The metrics as Envoy's {@code /stats?format=json}: {@code {"stats": [...]}} with an object
     * {@code {"name": ..., "value": ...}} per counter and gauge, sorted by flat name, and last an
     * object {@code {"histograms": {"supported_quantiles": [...], "computed_quantiles": [...]}}}
     * whose entries give each histogram's estimated quantiles as {@code {"interval": null,
     * "cumulative": ...}} ({@code null} when nothing was recorded).
     *
     * @param registry the metrics
     * @return the JSON document
     */
    public static String json(StatsRegistry registry) {
        return json(registry, m -> true);
    }

    /**
     * The metrics {@code include} accepts, as Envoy's {@code /stats?format=json} (see {@link
     * #json(StatsRegistry)}).
     *
     * @param registry the metrics
     * @param include which metrics to show
     * @return the JSON document
     */
    public static String json(StatsRegistry registry, Predicate<? super Metric> include) {
        StringBuilder out = new StringBuilder(4096).append("{\"stats\":[");
        List<Metric> metrics = registry.metrics().stream().filter(include).toList();
        boolean firstStat = true;
        for (Metric m : metrics) {
            long value;
            if (m instanceof Counter c) {
                value = c.value();
            } else if (m instanceof Gauge g) {
                value = g.value();
            } else {
                continue;
            }
            if (!firstStat) out.append(',');
            firstStat = false;
            out.append("{\"name\":");
            jsonString(out, m.name());
            out.append(",\"value\":").append(value).append('}');
        }
        if (!firstStat) out.append(',');
        out.append("{\"histograms\":{\"supported_quantiles\":[");
        for (int i = 0; i < QUANTILES.length; i++) {
            if (i > 0) out.append(',');
            out.append(number(QUANTILES[i]));
        }
        out.append("],\"computed_quantiles\":[");
        boolean firstHistogram = true;
        for (Metric m : metrics) {
            if (!(m instanceof Histogram h)) continue;
            if (!firstHistogram) out.append(',');
            firstHistogram = false;
            Histogram.Snapshot s = h.snapshot();
            out.append("{\"name\":");
            jsonString(out, m.name());
            out.append(",\"values\":[");
            for (int i = 0; i < QUANTILES.length; i++) {
                if (i > 0) out.append(',');
                out.append("{\"interval\":null,\"cumulative\":")
                        .append(s.count() == 0 ? "null" : number(round(s.quantile(QUANTILES[i] / 100)))).append('}');
            }
            out.append("]}");
        }
        return out.append("]}}]}").toString();
    }

    /**
     * Whether {@code metric} has been used, as Envoy's {@code usedonly} asks: a counter or gauge
     * that is not zero, a histogram with values. (Envoy remembers whether a stat was ever written,
     * so it also shows a gauge set back to zero; this registry keeps no such mark.)
     *
     * @param metric the metric
     * @return whether it has a value worth showing
     */
    public static boolean used(Metric metric) {
        return switch (metric) {
            case Counter c -> c.value() != 0;
            case Gauge g -> g.value() != 0;
            case Histogram h -> h.snapshot().count() != 0;
            default -> true;
        };
    }

    /** {@code v} to three decimals, so estimates read cleanly. */
    private static double round(double v) {
        return Double.isFinite(v) ? Math.round(v * 1000) / 1000.0 : v;
    }

    private static void jsonString(StringBuilder out, String s) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
