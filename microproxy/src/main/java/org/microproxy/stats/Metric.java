package org.microproxy.stats;

import java.util.List;

/**
 * A named statistic of a {@link StatsRegistry}: a {@link Counter}, a {@link Gauge} or a {@link
 * Histogram}.
 *
 * <p>Every metric has two names. Its {@linkplain #name() flat name} is Envoy's, with every value
 * in it ({@code http.ingress.downstream_rq_2xx}), as the {@code /stats} text dump and statsd show
 * it. Its {@linkplain #tagExtractedName() tag-extracted name} has those values taken out as
 * {@linkplain #tags() tags} by the registry's {@link TagExtractor} when the metric is registered
 * ({@code http.downstream_rq_xx} with {@code envoy_http_conn_manager_prefix="ingress"} and {@code
 * envoy_response_code_class="2"}), as Prometheus shows it.
 */
public interface Metric {

    /** What kind of metric a {@link Metric} is. */
    enum Type {
        /** A count that only goes up ({@link Counter}). */
        COUNTER("counter"),
        /** A value that goes up and down ({@link Gauge}). */
        GAUGE("gauge"),
        /** A distribution of recorded values in fixed buckets ({@link Histogram}). */
        HISTOGRAM("histogram");

        private final String prometheusName;

        Type(String prometheusName) {
            this.prometheusName = prometheusName;
        }

        /** {@return the name Prometheus's {@code # TYPE} line gives this kind} */
        public String prometheusName() {
            return prometheusName;
        }
    }

    /** {@return the flat name, such as {@code cluster.direct.upstream_rq_total}} */
    String name();

    /** {@return the name with its tag values taken out, such as {@code cluster.upstream_rq_total}} */
    String tagExtractedName();

    /** {@return the tags taken out of the flat name, in the order they were found} */
    List<Tag> tags();

    /** {@return what kind of metric this is} */
    Type type();

    /** {@return a one-line description for Prometheus's {@code # HELP} line, or an empty string} */
    String help();
}
