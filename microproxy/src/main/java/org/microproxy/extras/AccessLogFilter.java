package org.microproxy.extras;

import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Pattern;
import org.microproxy.FlowRecord;
import org.microproxy.ResponseFlag;

/**
 * Decides which finished exchanges and flows an access log writes, with the semantics of Envoy's
 * access-log filters: {@link #statusCode}, {@link #duration}, {@link #notHealthCheck}, {@link
 * #responseFlag}, {@link #header}, {@link #runtime} sampling, and the {@link #allOf} and {@link
 * #anyOf} combinators. Build one in Java,
 *
 * <pre>{@code
 * AccessLogFilter errors = AccessLogFilter.statusCode(Comparison.GE, 500)
 *         .or(AccessLogFilter.responseFlag())
 *         .and(AccessLogFilter.notHealthCheck());
 * }</pre>
 *
 * <p>or {@link #parse} the compact syntax the command line and properties use: {@code status>=500
 * || response_flag && not_health_check}. See {@link #parse} for the grammar.
 */
@FunctionalInterface
public interface AccessLogFilter {

    /** Logs everything. */
    AccessLogFilter ALL = record -> true;

    /** The health-check path {@link #notHealthCheck()} looks for. */
    String DEFAULT_HEALTH_CHECK_PATH = "/healthz";

    /**
     * Whether {@code record} is to be logged.
     *
     * @param record the finished exchange or flow
     * @return whether to log it
     */
    boolean test(FlowRecord record);

    /**
     * Both this filter and {@code other}.
     *
     * @param other the other filter
     * @return a filter that passes what both pass
     */
    default AccessLogFilter and(AccessLogFilter other) {
        return allOf(this, other);
    }

    /**
     * This filter or {@code other}.
     *
     * @param other the other filter
     * @return a filter that passes what either passes
     */
    default AccessLogFilter or(AccessLogFilter other) {
        return anyOf(this, other);
    }

    /** {@return a filter that passes what this one does not} */
    default AccessLogFilter negate() {
        AccessLogFilter self = this;
        return record -> !self.test(record);
    }

    /** How {@link #statusCode} and {@link #duration} compare. */
    enum Comparison {
        /** Equal. */
        EQ,
        /** Not equal. */
        NE,
        /** Greater than or equal. */
        GE,
        /** Less than or equal. */
        LE,
        /** Greater than. */
        GT,
        /** Less than. */
        LT;

        /**
         * Compares {@code actual} with {@code value}.
         *
         * @param actual the record's value
         * @param value the filter's value
         * @return whether the comparison holds
         */
        public boolean test(long actual, long value) {
            return switch (this) {
                case EQ -> actual == value;
                case NE -> actual != value;
                case GE -> actual >= value;
                case LE -> actual <= value;
                case GT -> actual > value;
                case LT -> actual < value;
            };
        }
    }

    /**
     * Compares the status of the response the client got (0 for none) with {@code value}.
     *
     * @param comparison how to compare
     * @param value the status to compare with
     * @return the filter
     */
    static AccessLogFilter statusCode(Comparison comparison, int value) {
        Objects.requireNonNull(comparison);
        return record -> comparison.test(record.responseCode(), value);
    }

    /**
     * Compares the duration of the exchange or flow, in milliseconds, with {@code millis}. A
     * record whose duration is unknown never passes.
     *
     * @param comparison how to compare
     * @param millis the duration to compare with
     * @return the filter
     */
    static AccessLogFilter duration(Comparison comparison, long millis) {
        Objects.requireNonNull(comparison);
        return record -> record.durationNanos() >= 0 && comparison.test(record.durationNanos() / 1_000_000, millis);
    }

    /**
     * Leaves out health checks: requests for {@link #DEFAULT_HEALTH_CHECK_PATH}, and requests
     * from Envoy's health checker ({@code User-Agent: Envoy/HC}).
     *
     * @return the filter
     */
    static AccessLogFilter notHealthCheck() {
        return notHealthCheckPath(DEFAULT_HEALTH_CHECK_PATH);
    }

    /**
     * Leaves out health checks: requests for {@code path} (its query aside), and requests from
     * Envoy's health checker ({@code User-Agent: Envoy/HC}).
     *
     * @param path the health-check path
     * @return the filter
     */
    static AccessLogFilter notHealthCheckPath(String path) {
        Objects.requireNonNull(path);
        return record -> {
            if ("Envoy/HC".equals(AccessLogFormat.requestHeader(record, "user-agent"))) return false;
            String p = AccessLogFormat.requestHeader(record, ":path");
            if (p == null) return true;
            int query = p.indexOf('?');
            return !(query < 0 ? p : p.substring(0, query)).equals(path);
        };
    }

    /**
     * Leaves out health checks: requests that carry the field {@code header}.
     *
     * @param header the field that marks a health check
     * @return the filter
     */
    static AccessLogFilter notHealthCheckHeader(String header) {
        Objects.requireNonNull(header);
        return record -> AccessLogFormat.requestHeader(record, header) == null;
    }

    /**
     * Passes records with any of {@code flags}, or with any flag at all when none is given.
     *
     * @param flags the flags to look for
     * @return the filter
     */
    static AccessLogFilter responseFlag(ResponseFlag... flags) {
        if (flags.length == 0) return record -> !record.responseFlags().isEmpty();
        Set<ResponseFlag> wanted = EnumSet.noneOf(ResponseFlag.class);
        for (ResponseFlag f : flags) wanted.add(Objects.requireNonNull(f));
        return record -> {
            for (ResponseFlag f : record.responseFlags()) {
                if (wanted.contains(f)) return true;
            }
            return false;
        };
    }

    /**
     * Passes requests that carry the field {@code name} (or the pseudo-header, such as {@code
     * :path}).
     *
     * @param name the field name
     * @return the filter
     */
    static AccessLogFilter header(String name) {
        Objects.requireNonNull(name);
        return record -> AccessLogFormat.requestHeader(record, name) != null;
    }

    /**
     * Passes requests whose field {@code name} matches {@code regex} as a whole.
     *
     * @param name the field name
     * @param regex the regular expression
     * @return the filter
     */
    static AccessLogFilter header(String name, String regex) {
        Objects.requireNonNull(name);
        Pattern pattern = Pattern.compile(regex);
        return record -> {
            String value = AccessLogFormat.requestHeader(record, name);
            return value != null && pattern.matcher(value).matches();
        };
    }

    /**
     * Passes requests whose field {@code name} is exactly {@code value}.
     *
     * @param name the field name
     * @param value the value
     * @return the filter
     */
    static AccessLogFilter headerEquals(String name, String value) {
        Objects.requireNonNull(name);
        Objects.requireNonNull(value);
        return record -> value.equals(AccessLogFormat.requestHeader(record, name));
    }

    /**
     * Passes {@code percent} percent of records, as Envoy's runtime filter does: chosen by the
     * request's {@code X-Request-ID} when it has one (so every log samples the same requests),
     * else at random.
     *
     * @param percent from 0 to 100
     * @return the filter
     */
    static AccessLogFilter runtime(double percent) {
        if (!(percent >= 0 && percent <= 100)) throw new IllegalArgumentException("not a percentage: " + percent);
        long threshold = Math.round(percent * 10_000);
        return record -> {
            String id = AccessLogFormat.requestHeader(record, "x-request-id");
            long draw = id != null ? Math.floorMod((long) id.hashCode(), 1_000_000L)
                    : ThreadLocalRandom.current().nextLong(1_000_000L);
            return draw < threshold;
        };
    }

    /**
     * Passes what all of {@code filters} pass.
     *
     * @param filters the filters
     * @return the filter
     */
    static AccessLogFilter allOf(AccessLogFilter... filters) {
        AccessLogFilter[] all = filters.clone();
        for (AccessLogFilter f : all) Objects.requireNonNull(f);
        return record -> {
            for (AccessLogFilter f : all) {
                if (!f.test(record)) return false;
            }
            return true;
        };
    }

    /**
     * Passes what any of {@code filters} passes.
     *
     * @param filters the filters
     * @return the filter
     */
    static AccessLogFilter anyOf(AccessLogFilter... filters) {
        AccessLogFilter[] all = filters.clone();
        for (AccessLogFilter f : all) Objects.requireNonNull(f);
        return record -> {
            for (AccessLogFilter f : all) {
                if (f.test(record)) return true;
            }
            return false;
        };
    }

    /**
     * Parses the compact syntax:
     *
     * <pre>
     * expr   := term (('||' | 'or') term)*
     * term   := factor (('&amp;&amp;' | 'and') factor)*
     * factor := ('!' | 'not') factor | '(' expr ')' | filter
     * filter := ('status' | 'status_code') op INT
     *         | 'duration' op INT ['ms' | 's']
     *         | 'not_health_check' ['(' (path | 'header=' name) ')']
     *         | 'response_flag' ['(' flag (',' flag)* ')']
     *         | 'header' '(' name [('~' regex) | ('=' value)] ')'
     *         | ('runtime' | 'sample') '(' percent ['%'] ')'
     * op     := '=' | '==' | '!=' | '&gt;=' | '&lt;=' | '&gt;' | '&lt;'
     * </pre>
     *
     * <p>For example {@code status>=500 || response_flag(UF,UO)}, {@code not_health_check(/ready)
     * && sample(10%)}, {@code header(user-agent~curl/.*)}. Flags are short codes or long names.
     *
     * @param expression the filter expression
     * @return the filter
     * @throws IllegalArgumentException if the expression is malformed
     */
    static AccessLogFilter parse(String expression) {
        return new AccessLogFilterParser(expression).parse();
    }
}
