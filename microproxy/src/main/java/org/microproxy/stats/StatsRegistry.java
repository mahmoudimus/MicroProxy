package org.microproxy.stats;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * The proxy's metrics, by Envoy's flat stat names ({@code http.<prefix>.downstream_rq_total},
 * {@code cluster.<name>.upstream_cx_connect_ms}, ...), each with the tags its name carries ({@link
 * TagExtractor}), for {@link StatsFormatter} to show.
 *
 * <p>Metrics are made once and then kept: the proxy resolves its own when it starts, per
 * listener, per cluster and per connection, and keeps them in fields, so counting a request is an
 * add to a {@link java.util.concurrent.atomic.LongAdder}, never a lookup by name. Registering a
 * name again returns the metric already there (of the same kind, or an {@link
 * IllegalArgumentException} is thrown). Nothing here takes a lock of its own.
 *
 * <p>{@link #NOOP} is the registry of a proxy without metrics (the default): its metrics do
 * nothing and it keeps none, so the proxy counts unconditionally at no cost.
 *
 * <p>The registry also bounds how many metrics the proxy makes for things whose number is not
 * fixed: the clusters requests go to ({@link Builder#maxClusters}, {@link Builder#clusterOverflow},
 * {@link Builder#perHostClusters}) and the stats scripts make ({@link Builder#maxScriptStats}).
 */
public final class StatsRegistry {

    /** What happens to a new cluster once {@link Builder#maxClusters} clusters have stats. */
    public enum Overflow {
        /** Its stats go to the cluster named {@code other} (the default). */
        OTHER,
        /** The cluster used least recently loses its stats, which start again from zero if it comes back. */
        LRU
    }

    /** A registry whose metrics do nothing and that keeps none; the default of every proxy. */
    public static final StatsRegistry NOOP = new StatsRegistry(null);

    /** The name of the cluster that clusters over {@link Builder#maxClusters} share. */
    public static final String OTHER_CLUSTER = "other";

    private final boolean enabled;
    private final String prefix;
    private final TagExtractor tagExtractor;
    private final int maxClusters;
    private final Overflow clusterOverflow;
    private final boolean perHostClusters;
    private final int maxScriptStats;
    private final double[] histogramBounds;
    private final Map<String, Metric> metrics = new ConcurrentHashMap<>();
    private final Map<String, StatsScope> scopes = new ConcurrentHashMap<>();
    private final StatsScope noopScope;

    private StatsRegistry(Builder b) {
        this.enabled = b != null;
        Builder o = b != null ? b : new Builder();
        this.prefix = o.prefix;
        this.tagExtractor = o.tagExtractor;
        this.maxClusters = o.maxClusters;
        this.clusterOverflow = o.clusterOverflow;
        this.perHostClusters = o.perHostClusters;
        this.maxScriptStats = o.maxScriptStats;
        this.histogramBounds = o.histogramBounds.clone();
        this.noopScope = new StatsScope(this, "", 0);
    }

    /** {@return a registry with the default settings} */
    public static StatsRegistry create() {
        return builder().build();
    }

    /** {@return a builder with the default settings} */
    public static Builder builder() {
        return new Builder();
    }

    /** {@return whether this registry keeps metrics; false only for {@link #NOOP}} */
    public boolean enabled() {
        return enabled;
    }

    /**
     * {@return the prefix of exported names, without separator: {@code envoy} by default, as in
     * {@code envoy_cluster_upstream_rq_total} (Prometheus) and {@code envoy.cluster.direct...} (statsd)}
     */
    public String prefix() {
        return prefix;
    }

    /** {@return what takes the tags out of flat names} */
    public TagExtractor tagExtractor() {
        return tagExtractor;
    }

    /** {@return how many clusters may have stats of their own} */
    public int maxClusters() {
        return maxClusters;
    }

    /** {@return what happens to clusters beyond {@link #maxClusters()}} */
    public Overflow clusterOverflow() {
        return clusterOverflow;
    }

    /** {@return whether a direct connection's cluster is its server ({@code host_port}) rather than {@code direct}} */
    public boolean perHostClusters() {
        return perHostClusters;
    }

    /** {@return how many stats scripts may make} */
    public int maxScriptStats() {
        return maxScriptStats;
    }

    /** {@return a copy of the bucket bounds of histograms registered without bounds of their own} */
    public double[] histogramBounds() {
        return histogramBounds.clone();
    }

    /**
     * The counter named {@code name}, made the first time.
     *
     * @param name the flat name
     * @return the counter
     * @throws IllegalArgumentException if the name is not valid, or names a metric of another kind
     */
    public Counter counter(String name) {
        return counter(name, "");
    }

    /**
     * The counter named {@code name}, made the first time with {@code help}.
     *
     * @param name the flat name
     * @param help a one-line description for Prometheus's {@code # HELP}
     * @return the counter
     * @throws IllegalArgumentException if the name is not valid, or names a metric of another kind
     */
    public Counter counter(String name, String help) {
        if (!enabled) return Instruments.NOOP_COUNTER;
        return register(name, Counter.class, () -> new Instruments.AdderCounter(name, extract(name), help));
    }

    /**
     * A counter named {@code name} whose count is read from {@code value}, for counts kept
     * elsewhere (such as {@link org.microproxy.cache.HttpCache#stats()}); it cannot be added to.
     *
     * @param name the flat name
     * @param help a one-line description for Prometheus's {@code # HELP}
     * @param value reads the count; called whenever the metrics are shown
     * @return the counter (the one already registered under {@code name}, if any)
     * @throws IllegalArgumentException if the name is not valid, or names a metric of another kind
     */
    public Counter counter(String name, String help, LongSupplier value) {
        Objects.requireNonNull(value, "value");
        if (!enabled) return Instruments.NOOP_COUNTER;
        return register(name, Counter.class, () -> new Instruments.SupplierCounter(name, extract(name), help, value));
    }

    /**
     * The gauge named {@code name}, made the first time.
     *
     * @param name the flat name
     * @return the gauge
     * @throws IllegalArgumentException if the name is not valid, or names a metric of another kind
     */
    public Gauge gauge(String name) {
        return gauge(name, "");
    }

    /**
     * The gauge named {@code name}, made the first time with {@code help}.
     *
     * @param name the flat name
     * @param help a one-line description for Prometheus's {@code # HELP}
     * @return the gauge
     * @throws IllegalArgumentException if the name is not valid, or names a metric of another kind
     */
    public Gauge gauge(String name, String help) {
        if (!enabled) return Instruments.NOOP_GAUGE;
        return register(name, Gauge.class, () -> new Instruments.AtomicGauge(name, extract(name), help));
    }

    /**
     * A gauge named {@code name} whose value is read from {@code value}, for values kept elsewhere
     * (a pool's size, the heap's); it cannot be changed through the gauge.
     *
     * @param name the flat name
     * @param help a one-line description for Prometheus's {@code # HELP}
     * @param value reads the value; called whenever the metrics are shown
     * @return the gauge (the one already registered under {@code name}, if any)
     * @throws IllegalArgumentException if the name is not valid, or names a metric of another kind
     */
    public Gauge gauge(String name, String help, LongSupplier value) {
        Objects.requireNonNull(value, "value");
        if (!enabled) return Instruments.NOOP_GAUGE;
        return register(name, Gauge.class, () -> new Instruments.SupplierGauge(name, extract(name), help, value));
    }

    /**
     * The histogram named {@code name}, made the first time with the registry's bounds ({@link
     * Builder#histogramBounds}, Envoy's by default).
     *
     * @param name the flat name
     * @return the histogram
     * @throws IllegalArgumentException if the name is not valid, or names a metric of another kind
     */
    public Histogram histogram(String name) {
        return histogram(name, "");
    }

    /**
     * The histogram named {@code name}, made the first time with {@code help} and the registry's
     * bounds.
     *
     * @param name the flat name
     * @param help a one-line description for Prometheus's {@code # HELP}
     * @return the histogram
     * @throws IllegalArgumentException if the name is not valid, or names a metric of another kind
     */
    public Histogram histogram(String name, String help) {
        return histogram(name, help, histogramBounds);
    }

    /**
     * The histogram named {@code name}, made the first time with {@code help} and {@code bounds}.
     *
     * @param name the flat name
     * @param help a one-line description for Prometheus's {@code # HELP}
     * @param bounds the buckets' upper bounds, ascending and finite
     * @return the histogram (the one already registered under {@code name}, with its bounds, if any)
     * @throws IllegalArgumentException if the name is not valid, names a metric of another kind,
     *     or the bounds are not ascending and finite
     */
    public Histogram histogram(String name, String help, double... bounds) {
        checkBounds(bounds);
        if (!enabled) return Instruments.NOOP_HISTOGRAM;
        return register(name, Histogram.class, () -> new Instruments.BucketHistogram(name, extract(name), help, bounds));
    }

    /**
     * The scope of metrics named {@code prefix.<name>}, which makes at most {@code maxStats} of
     * them: for metrics whose names come from outside, such as scripts'. The same prefix gives the
     * same scope (with the limit it was first asked with).
     *
     * @param prefix the names' prefix, without the dot
     * @param maxStats how many metrics the scope may make
     * @return the scope
     * @throws IllegalArgumentException if the prefix is not a valid name or the limit is negative
     */
    public StatsScope scope(String prefix, int maxStats) {
        checkName(prefix);
        if (maxStats < 0) throw new IllegalArgumentException("maxStats must not be negative: " + maxStats);
        if (!enabled) return noopScope;
        return scopes.computeIfAbsent(prefix, p -> new StatsScope(this, p, maxStats));
    }

    /**
     * The metric named {@code name}, if registered.
     *
     * @param name the flat name
     * @return the metric, or null
     */
    public Metric get(String name) {
        return metrics.get(name);
    }

    /**
     * Forgets the metric named {@code name}: it is shown no more, and registering the name again
     * makes a new one. Whoever holds the old one may still use it, to no effect.
     *
     * @param name the flat name
     * @return whether there was such a metric
     */
    public boolean remove(String name) {
        return metrics.remove(name) != null;
    }

    /** {@return the metrics, sorted by flat name} */
    public List<Metric> metrics() {
        List<Metric> all = new ArrayList<>(metrics.values());
        all.sort(Comparator.comparing(Metric::name));
        return all;
    }

    /** {@return how many metrics there are} */
    public int size() {
        return metrics.size();
    }

    @Override
    public String toString() {
        return enabled ? "StatsRegistry[" + metrics.size() + " metrics, prefix " + prefix + "]" : "StatsRegistry.NOOP";
    }

    private TagExtractor.Result extract(String name) {
        return tagExtractor.extract(name);
    }

    private <T extends Metric> T register(String name, Class<T> type, java.util.function.Supplier<T> make) {
        checkName(name);
        Metric m = metrics.get(name);
        if (m == null) m = metrics.computeIfAbsent(name, n -> make.get());
        if (!type.isInstance(m)) {
            throw new IllegalArgumentException(name + " is a " + m.type().prometheusName() + ", not a "
                    + type.getSimpleName().toLowerCase(Locale.ROOT));
        }
        return type.cast(m);
    }

    /**
     * Checks that {@code name} is a valid flat name: letters, digits, {@code _}, {@code -}, {@code
     * [}, {@code ]} and dots between non-empty parts.
     */
    static void checkName(String name) {
        Objects.requireNonNull(name, "name");
        if (name.isEmpty() || name.startsWith(".") || name.endsWith(".") || name.contains("..")) {
            throw new IllegalArgumentException("not a stat name: '" + name + "'");
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '_' || c == '-' || c == '.' || c == '[' || c == ']';
            if (!ok) throw new IllegalArgumentException("not a stat name (character '" + c + "'): '" + name + "'");
        }
    }

    private static void checkBounds(double[] bounds) {
        for (int i = 0; i < bounds.length; i++) {
            if (!Double.isFinite(bounds[i]) || (i > 0 && bounds[i] <= bounds[i - 1])) {
                throw new IllegalArgumentException("histogram bounds must be finite and ascending: "
                        + java.util.Arrays.toString(bounds));
            }
        }
    }

    /** Settings for a {@link StatsRegistry}. */
    public static final class Builder {
        private String prefix = "envoy";
        private TagExtractor tagExtractor = TagExtractor.envoyDefaults();
        private int maxClusters = 100;
        private Overflow clusterOverflow = Overflow.OTHER;
        private boolean perHostClusters;
        private int maxScriptStats = 100;
        private double[] histogramBounds = Histogram.Snapshot.DEFAULT_BOUNDS;

        private Builder() {}

        /**
         * The prefix of exported names (default {@code envoy}): Prometheus names start with it and
         * {@code _}, statsd names with it and a dot. A trailing {@code _} or dot is dropped; an
         * empty prefix exports names as they are.
         *
         * @param prefix the prefix, such as {@code microproxy}
         * @return this builder
         * @throws IllegalArgumentException if it has characters other than letters, digits and {@code _}
         */
        public Builder prefix(String prefix) {
            String p = Objects.requireNonNull(prefix, "prefix").strip();
            while (p.endsWith("_") || p.endsWith(".")) p = p.substring(0, p.length() - 1);
            for (int i = 0; i < p.length(); i++) {
                char c = p.charAt(i);
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9' && i > 0) || c == '_')) {
                    throw new IllegalArgumentException("not a stats prefix: '" + prefix + "'");
                }
            }
            this.prefix = p;
            return this;
        }

        /**
         * What takes the tags out of flat names (default {@link TagExtractor#envoyDefaults()}).
         *
         * @param extractor the extractor
         * @return this builder
         */
        public Builder tagExtractor(TagExtractor extractor) {
            this.tagExtractor = Objects.requireNonNull(extractor, "extractor");
            return this;
        }

        /**
         * How many clusters (chained proxies, and servers with {@link #perHostClusters}) may have
         * stats of their own (default 100), besides {@code direct}, {@code cache}, {@code replay}
         * and {@code other}, which always may.
         *
         * @param max the most clusters, at least 1
         * @return this builder
         * @throws IllegalArgumentException if it is less than 1
         */
        public Builder maxClusters(int max) {
            if (max < 1) throw new IllegalArgumentException("maxClusters must be at least 1: " + max);
            this.maxClusters = max;
            return this;
        }

        /**
         * What happens to clusters beyond {@link #maxClusters} (default {@link Overflow#OTHER}).
         *
         * @param overflow where their stats go
         * @return this builder
         */
        public Builder clusterOverflow(Overflow overflow) {
            this.clusterOverflow = Objects.requireNonNull(overflow, "overflow");
            return this;
        }

        /**
         * Whether each server a direct connection goes to is a cluster of its own, named {@code
         * host_port} (default false: they all are {@code direct}). A forward proxy's servers are
         * any number: {@link #maxClusters} bounds them.
         *
         * @param perHost whether servers are clusters of their own
         * @return this builder
         */
        public Builder perHostClusters(boolean perHost) {
            this.perHostClusters = perHost;
            return this;
        }

        /**
         * How many stats scripts may make (default 100); past that, a script's new stats do nothing.
         *
         * @param max the most script stats
         * @return this builder
         * @throws IllegalArgumentException if it is negative
         */
        public Builder maxScriptStats(int max) {
            if (max < 0) throw new IllegalArgumentException("maxScriptStats must not be negative: " + max);
            this.maxScriptStats = max;
            return this;
        }

        /**
         * The bucket bounds of histograms registered without bounds of their own (default Envoy's,
         * {@link Histogram#defaultBounds()}).
         *
         * @param bounds the upper bounds, ascending and finite
         * @return this builder
         * @throws IllegalArgumentException if they are not ascending and finite
         */
        public Builder histogramBounds(double... bounds) {
            checkBounds(bounds);
            this.histogramBounds = bounds.clone();
            return this;
        }

        /** {@return a new registry with these settings} */
        public StatsRegistry build() {
            return new StatsRegistry(this);
        }
    }
}
