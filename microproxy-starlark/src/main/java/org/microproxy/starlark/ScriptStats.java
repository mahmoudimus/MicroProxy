package org.microproxy.starlark;

import org.microproxy.stats.Counter;
import org.microproxy.stats.Gauge;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.stats.StatsScope;
import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkFloat;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;

/**
 * The {@code stats} module: a script's own metrics, kept in the proxy's {@link StatsRegistry} as
 * {@code script.<name>} next to the proxy's (and shown wherever they are: Prometheus, statsd).
 * {@code stats.counter("blocked").inc()} counts; {@code stats.gauge("queue").set(n)} and {@code
 * stats.histogram("score").record(x)} keep a value and a distribution.
 *
 * <p>A script may make at most {@link StatsRegistry#maxScriptStats()} of them (100 by default):
 * further names get metrics that count nothing, and a warning is logged, so that names made from
 * request data cannot grow the registry without bound. Without metrics ({@code --metrics}) every
 * metric counts nothing. A metric found once may be kept in a global, as in {@code BLOCKED =
 * stats.counter("blocked")} at the top level, so a hook does not look it up by name per request.
 */
@StarlarkBuiltin(name = "stats", doc = "The script's own metrics, as script.<name> in the proxy's stats.")
public final class ScriptStats implements StarlarkValue {

    /** The module of a script without metrics: every metric counts nothing. */
    static final ScriptStats NOOP = new ScriptStats(StatsRegistry.NOOP);

    private final StatsScope scope;

    ScriptStats(StatsRegistry registry) {
        this.scope = registry.scope("script", registry.maxScriptStats());
    }

    /** {@return the module for {@code registry}: {@link #NOOP} for no registry or the no-op one} */
    static ScriptStats of(StatsRegistry registry) {
        return registry == null || !registry.enabled() ? NOOP : new ScriptStats(registry);
    }

    /**
     * {@code stats.counter(name)}: the counter {@code script.<name>}.
     *
     * @param name the name within {@code script}
     * @return the counter (one that counts nothing once the script stats are full)
     * @throws EvalException if the name is not valid, or names a metric of another kind
     */
    @StarlarkMethod(name = "counter", doc = "The counter script.<name>, which only goes up.",
            parameters = {@Param(name = "name", doc = "letters, digits, _, - and dots")})
    public ScriptCounter counter(String name) throws EvalException {
        try {
            return new ScriptCounter(scope.counter(name));
        } catch (IllegalArgumentException e) {
            throw Starlark.errorf("%s", e.getMessage());
        }
    }

    /**
     * {@code stats.gauge(name)}: the gauge {@code script.<name>}.
     *
     * @param name the name within {@code script}
     * @return the gauge (one that keeps nothing once the script stats are full)
     * @throws EvalException if the name is not valid, or names a metric of another kind
     */
    @StarlarkMethod(name = "gauge", doc = "The gauge script.<name>, a value that goes up and down.",
            parameters = {@Param(name = "name", doc = "letters, digits, _, - and dots")})
    public ScriptGauge gauge(String name) throws EvalException {
        try {
            return new ScriptGauge(scope.gauge(name));
        } catch (IllegalArgumentException e) {
            throw Starlark.errorf("%s", e.getMessage());
        }
    }

    /**
     * {@code stats.histogram(name)}: the histogram {@code script.<name>}.
     *
     * @param name the name within {@code script}
     * @return the histogram (one that records nothing once the script stats are full)
     * @throws EvalException if the name is not valid, or names a metric of another kind
     */
    @StarlarkMethod(name = "histogram", doc = "The histogram script.<name>, with Envoy's buckets (milliseconds).",
            parameters = {@Param(name = "name", doc = "letters, digits, _, - and dots")})
    public ScriptHistogram histogram(String name) throws EvalException {
        try {
            return new ScriptHistogram(scope.histogram(name));
        } catch (IllegalArgumentException e) {
            throw Starlark.errorf("%s", e.getMessage());
        }
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<stats module>");
    }

    /** A counter of a script. */
    @StarlarkBuiltin(name = "Counter", doc = "A script counter.")
    public static final class ScriptCounter implements StarlarkValue {
        private final Counter counter;

        ScriptCounter(Counter counter) {
            this.counter = counter;
        }

        /**
         * {@code counter.inc(n=1)}.
         *
         * @param n how much to add
         * @throws EvalException if {@code n} is negative or too large
         */
        @StarlarkMethod(name = "inc", doc = "Adds n (default 1), not negative.",
                parameters = {@Param(name = "n", defaultValue = "1")})
        public void inc(StarlarkInt n) throws EvalException {
            long v = n.toLong("n");
            if (v < 0) throw Starlark.errorf("a counter only goes up: inc(%d)", v);
            counter.add(v);
        }

        /**
         * {@code counter.value}.
         *
         * @return the count so far
         */
        @StarlarkMethod(name = "value", doc = "The count so far.", structField = true)
        public StarlarkInt value() {
            return StarlarkInt.of(counter.value());
        }

        @Override
        public void repr(Printer printer, StarlarkSemantics semantics) {
            printer.append("<counter ").append(counter.name()).append(">");
        }
    }

    /** A gauge of a script. */
    @StarlarkBuiltin(name = "Gauge", doc = "A script gauge.")
    public static final class ScriptGauge implements StarlarkValue {
        private final Gauge gauge;

        ScriptGauge(Gauge gauge) {
            this.gauge = gauge;
        }

        /**
         * {@code gauge.set(value)}.
         *
         * @param value the new value
         * @throws EvalException if it is too large
         */
        @StarlarkMethod(name = "set", doc = "Sets the value.", parameters = {@Param(name = "value")})
        public void set(StarlarkInt value) throws EvalException {
            gauge.set(value.toLong("value"));
        }

        /**
         * {@code gauge.inc(n=1)}.
         *
         * @param n how much to add
         * @throws EvalException if it is too large
         */
        @StarlarkMethod(name = "inc", doc = "Adds n (default 1).", parameters = {@Param(name = "n", defaultValue = "1")})
        public void inc(StarlarkInt n) throws EvalException {
            gauge.add(n.toLong("n"));
        }

        /**
         * {@code gauge.dec(n=1)}.
         *
         * @param n how much to subtract
         * @throws EvalException if it is too large
         */
        @StarlarkMethod(name = "dec", doc = "Subtracts n (default 1).", parameters = {@Param(name = "n", defaultValue = "1")})
        public void dec(StarlarkInt n) throws EvalException {
            gauge.add(-n.toLong("n"));
        }

        /**
         * {@code gauge.value}.
         *
         * @return the current value
         */
        @StarlarkMethod(name = "value", doc = "The current value.", structField = true)
        public StarlarkInt value() {
            return StarlarkInt.of(gauge.value());
        }

        @Override
        public void repr(Printer printer, StarlarkSemantics semantics) {
            printer.append("<gauge ").append(gauge.name()).append(">");
        }
    }

    /** A histogram of a script. */
    @StarlarkBuiltin(name = "Histogram", doc = "A script histogram.")
    public static final class ScriptHistogram implements StarlarkValue {
        private final Histogram histogram;

        ScriptHistogram(Histogram histogram) {
            this.histogram = histogram;
        }

        /**
         * {@code histogram.record(value)}.
         *
         * @param value an int or a float
         * @throws EvalException if it is not a finite number
         */
        @StarlarkMethod(name = "record", doc = "Records a value (an int or a float; milliseconds for times).",
                parameters = {@Param(name = "value")})
        public void record(Object value) throws EvalException {
            double v;
            if (value instanceof StarlarkInt i) {
                v = i.toDouble();
            } else if (value instanceof StarlarkFloat f) {
                v = f.toDouble();
            } else {
                throw Starlark.errorf("record needs an int or a float, not %s", Starlark.type(value));
            }
            if (!Double.isFinite(v)) throw Starlark.errorf("record needs a finite value, not %s", v);
            histogram.record(v);
        }

        /**
         * {@code histogram.count}.
         *
         * @return how many values were recorded
         */
        @StarlarkMethod(name = "count", doc = "How many values were recorded.", structField = true)
        public StarlarkInt count() {
            return StarlarkInt.of(histogram.snapshot().count());
        }

        @Override
        public void repr(Printer printer, StarlarkSemantics semantics) {
            printer.append("<histogram ").append(histogram.name()).append(">");
        }
    }
}
