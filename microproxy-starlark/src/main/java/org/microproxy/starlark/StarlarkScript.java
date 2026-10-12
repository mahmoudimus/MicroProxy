package org.microproxy.starlark;

import com.google.common.collect.ImmutableMap;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.microproxy.FlowContext;
import org.microproxy.ScriptCallObserver;
import org.microproxy.contentviews.ProtoSchema;
import org.microproxy.stats.Counter;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.stats.TagExtractor;
import org.microproxy.starlark.stdlib.Stdlib;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Module;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkCallable;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.syntax.FileOptions;
import org.microproxy.thirdparty.starlark.syntax.LoadStatement;
import org.microproxy.thirdparty.starlark.syntax.ParserInput;
import org.microproxy.thirdparty.starlark.syntax.Program;
import org.microproxy.thirdparty.starlark.syntax.StarlarkFile;
import org.microproxy.thirdparty.starlark.syntax.Statement;
import org.microproxy.thirdparty.starlark.syntax.SyntaxError;

/**
 * A compiled Starlark file whose top-level statements have run. Its globals are frozen, so one
 * script is safely shared by every connection: each call gets its own {@link StarlarkThread}, and
 * functions cannot change global state. Calls are bounded by a step count, a wall-clock timeout
 * and an allocation budget ({@link Limits}).
 *
 * <p>Each call is measured: its interpreter steps, about how many bytes of values it created
 * ({@link StarlarkThread#getAllocatedBytes()}, an estimate of what was made rather than of what
 * stayed in memory) and its time. With metrics they go to {@code
 * hooks.starlark.<script>.<hook>.*}, tagged with the script's {@linkplain #statsName() name} and
 * the hook; they add up per exchange in {@link FlowContext#scriptStats()}; and a {@link
 * ScriptCallObserver} sees each call.
 *
 * <p>A script may {@code load()} modules of the standard library ported from starlarky ({@link
 * Stdlib}), e.g. {@code load("@stdlib//urllib/parse", "parse")}. Such a script runs with Python's
 * string semantics ({@link Stdlib#withPythonStrings}), which the library relies on; a script without
 * {@code load} statements runs exactly as before.
 */
public final class StarlarkScript {

    private static final System.Logger LOG = System.getLogger("org.microproxy.starlark.script");

    /** Type annotations are allowed and resolved; unannotated code is unaffected. */
    static final FileOptions FILE_OPTIONS =
            FileOptions.DEFAULT.toBuilder().allowTypeSyntax(true).resolveTypeSyntax(true).build();

    /** Annotations are checked when the script loads and again on every call. */
    static final StarlarkSemantics SEMANTICS = StarlarkSemantics.builder()
            .setBool(StarlarkSemantics.EXPERIMENTAL_STARLARK_STATIC_TYPE_CHECKING, true)
            .setBool(StarlarkSemantics.EXPERIMENTAL_STARLARK_DYNAMIC_TYPE_CHECKING, true)
            .build();

    /**
     * {@link #SEMANTICS} for scripts that load standard library modules (in a holder, so that the
     * library initializes only when a script loads from it).
     */
    private static final class StdlibSemantics {
        static final StarlarkSemantics VALUE = Stdlib.withPythonStrings(SEMANTICS);
    }

    /**
     * Bounds on each call into a script (and on running its top level). A call that goes past one
     * fails with an {@link EvalException}, as any failing call does; the thread running it is not
     * stopped otherwise.
     *
     * @param maxSteps the positive maximum number of interpreter steps
     * @param timeout the wall-clock limit, checked every few steps and by long-running builtins
     *     (regular expressions); non-positive millisecond values disable the deadline
     * @param maxAllocBytes the most bytes of values a call may create, as {@link
     *     StarlarkThread#getAllocatedBytes()} estimates them; {@code Long.MAX_VALUE} for no limit
     */
    public record Limits(long maxSteps, Duration timeout, long maxAllocBytes) {

        /**
         * The default allocation budget, 64 MiB a call: a buffered body of the default 10 MiB counts
         * about 20 MiB as a string (two bytes a character), so a call can still copy it a few times.
         */
        public static final long DEFAULT_MAX_ALLOC_BYTES = 64L << 20;

        /** Ten million steps, five seconds and 64 MiB per call. */
        public static final Limits DEFAULT = new Limits(10_000_000, Duration.ofSeconds(5));

        /**
         * Creates execution bounds.
         *
         * @param maxSteps the positive maximum number of interpreter steps
         * @param timeout the non-null wall-clock limit
         * @param maxAllocBytes the positive allocation budget, or {@code Long.MAX_VALUE} for none
         * @throws IllegalArgumentException if {@code maxSteps} or {@code maxAllocBytes} is not
         *     positive
         * @throws NullPointerException if {@code timeout} is null
         */
        public Limits {
            if (maxSteps <= 0) throw new IllegalArgumentException("maxSteps must be positive");
            Objects.requireNonNull(timeout, "timeout");
            if (maxAllocBytes <= 0) throw new IllegalArgumentException("maxAllocBytes must be positive");
        }

        /**
         * Creates execution bounds with the {@linkplain #DEFAULT_MAX_ALLOC_BYTES default allocation
         * budget}.
         *
         * @param maxSteps the positive maximum number of interpreter steps
         * @param timeout the non-null wall-clock limit
         */
        public Limits(long maxSteps, Duration timeout) {
            this(maxSteps, timeout, DEFAULT_MAX_ALLOC_BYTES);
        }

        /**
         * These bounds with another step limit.
         *
         * @param maxSteps the positive maximum number of interpreter steps
         * @return the new bounds
         */
        public Limits withMaxSteps(long maxSteps) {
            return new Limits(maxSteps, timeout, maxAllocBytes);
        }

        /**
         * These bounds with another wall-clock limit.
         *
         * @param timeout the limit; zero for none
         * @return the new bounds
         */
        public Limits withTimeout(Duration timeout) {
            return new Limits(maxSteps, timeout, maxAllocBytes);
        }

        /**
         * These bounds with another allocation budget.
         *
         * @param maxAllocBytes the positive budget, or {@code Long.MAX_VALUE} for none
         * @return the new bounds
         */
        public Limits withMaxAllocBytes(long maxAllocBytes) {
            return new Limits(maxSteps, timeout, maxAllocBytes);
        }
    }

    private final String name;
    private final Module module;
    private final Limits limits;
    private final StarlarkSemantics semantics;
    private final ProtoSchema protoSchema;
    /** The registry for {@code hooks.starlark.*}; null without metrics. */
    private final StatsRegistry stats;
    /** The name the stats are tagged with ({@code microproxy_script}). */
    private final String statsName;
    /** Sees every call; null for none. */
    private final ScriptCallObserver observer;
    /** The deadline of a call, in nanoseconds after it starts; 0 for none. */
    private final long timeoutNanos;
    /** The hooks called so far, each resolved (with its stats) once. */
    private final Map<String, Hook> hooks = new ConcurrentHashMap<>();

    /** A function of the script that is called as a hook, and its stats (null without metrics). */
    private record Hook(StarlarkCallable function, HookStats stats) {}

    /**
     * {@code hooks.starlark.<script>.<hook>.*}: one hook's calls into one script. Scripts are few and
     * hooks a fixed set, so there are few of these; a reloaded script shares its predecessor's.
     */
    private record HookStats(Counter invocations, Counter errors, Histogram latencyUs, Histogram steps,
            Histogram allocBytes, Counter stepsExceeded, Counter memoryExceeded, Counter timeExceeded) {

        static HookStats of(StatsRegistry stats, String script, String hook, Limits limits) {
            String p = "hooks.starlark." + script + "." + TagExtractor.sanitize(hook) + ".";
            String budget = p + "budget_exceeded.";
            return new HookStats(stats.counter(p + "invocations", "Hook calls"),
                    stats.counter(p + "errors", "Hook calls that threw"),
                    stats.histogram(p + "latency_us", "Microseconds hook calls took", Histogram.microsecondBounds()),
                    stats.histogram(p + "steps", "Interpreter steps hook calls ran", powers(10, 10, limits.maxSteps())),
                    stats.histogram(p + "alloc_bytes", "Bytes of values hook calls created (an estimate)",
                            powers(1024, 4, Math.min(limits.maxAllocBytes(), 1L << 30))),
                    stats.counter(budget + "steps", "Hook calls stopped at the step limit"),
                    stats.counter(budget + "memory", "Hook calls stopped at the allocation budget"),
                    stats.counter(budget + "time", "Hook calls stopped at the deadline"));
        }

        /** Bucket bounds {@code first, first * factor, ...}, up to the first at or past {@code max}. */
        static double[] powers(long first, long factor, long max) {
            List<Double> bounds = new ArrayList<>();
            for (long b = first; ; b *= factor) {
                bounds.add((double) b);
                if (b >= max || b > Long.MAX_VALUE / factor) break;
            }
            return bounds.stream().mapToDouble(Double::doubleValue).toArray();
        }

        void record(long nanos, long steps, long allocBytes, boolean failed, StarlarkThread.Budget exceeded) {
            invocations.inc();
            if (failed) errors.inc();
            latencyUs.record(nanos / 1_000.0);
            this.steps.record(steps);
            this.allocBytes.record(allocBytes);
            if (exceeded != null) {
                switch (exceeded) {
                    case STEPS -> stepsExceeded.inc();
                    case MEMORY -> memoryExceeded.inc();
                    case TIME -> timeExceeded.inc();
                }
            }
        }
    }

    private StarlarkScript(String name, Module module, Limits limits, StarlarkSemantics semantics,
            ProtoSchema protoSchema, StatsRegistry stats, String statsName, ScriptCallObserver observer) {
        this.name = name;
        this.module = module;
        this.limits = limits;
        this.semantics = semantics;
        this.protoSchema = protoSchema;
        this.stats = stats == null || !stats.enabled() ? null : stats;
        this.statsName = statsName;
        this.observer = observer == ScriptCallObserver.NOOP ? null : observer;
        long millis = limits.timeout().toMillis();
        this.timeoutNanos = millis > 0 ? limits.timeout().toNanos() : 0;
    }

    /**
     * The name the stats of a script called {@code name} are tagged with: its file name without
     * {@code .star}, with only letters, digits, {@code _} and {@code -}.
     *
     * @param name a file path or script name
     * @return the stats name
     */
    static String statsName(String name) {
        String file = name.substring(Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\')) + 1);
        if (file.endsWith(".star") && file.length() > ".star".length()) {
            file = file.substring(0, file.length() - ".star".length());
        }
        return TagExtractor.sanitize(file);
    }

    /**
     * The name this script's stats are tagged with ({@code microproxy_script}): its file name
     * without {@code .star}, or the one given to {@link #withStatsName}.
     *
     * @return the stats name
     */
    public String statsName() {
        return statsName;
    }

    /**
     * This script with its stats tagged {@code name} rather than after its file. The script itself
     * is shared, not run again.
     *
     * @param name the name, made fit for a stat name as {@link TagExtractor#sanitize} does
     * @return the script with the name
     */
    public StarlarkScript withStatsName(String name) {
        return new StarlarkScript(this.name, module, limits, semantics, protoSchema, stats,
                TagExtractor.sanitize(Objects.requireNonNull(name)), observer);
    }

    /**
     * This script with {@code observer} seeing every call into it. The script itself is shared,
     * not run again.
     *
     * @param observer the observer, or null for none
     * @return the script with the observer
     */
    public StarlarkScript withObserver(ScriptCallObserver observer) {
        return new StarlarkScript(name, module, limits, semantics, protoSchema, stats, statsName, observer);
    }

    /**
     * This script with a protobuf schema for its {@code protobuf} and {@code grpc} modules, so that
     * {@code protobuf.decode(data, type="pkg.Message")} decodes with field names (and {@code
     * encode} takes them). The script itself is shared, not run again.
     *
     * @param schema the schema, or {@code null} for none (the well-known types only)
     * @return the script with the schema
     */
    public StarlarkScript withProtoSchema(ProtoSchema schema) {
        return new StarlarkScript(name, module, limits, semantics, schema, stats, statsName, observer);
    }

    /** {@return the protobuf schema the script decodes with, or {@code null}} */
    public ProtoSchema protoSchema() {
        return protoSchema;
    }

    /**
     * Loads and runs the script in {@code file}.
     *
     * @param file the UTF-8 script file
     * @param limits the bounds for top-level execution and later calls
     * @return the compiled script with frozen globals
     * @throws IOException if the file cannot be read
     * @throws ScriptException if parsing, compilation or top-level execution fails
     */
    public static StarlarkScript load(Path file, Limits limits) throws IOException, ScriptException {
        return load(file, limits, Map.of());
    }

    /**
     * Loads and runs the script in {@code file}, with {@code constants} as read-only globals
     * (see {@link ScriptedProxy.Builder#constants}).
     *
     * @param file the UTF-8 script file
     * @param limits the bounds for top-level execution and later calls
     * @param constants the globals to copy and freeze before compilation
     * @return the compiled script with frozen globals
     * @throws IOException if the file cannot be read
     * @throws ScriptException if parsing, compilation or top-level execution fails
     * @throws IllegalArgumentException if a constant name or value is invalid
     */
    public static StarlarkScript load(Path file, Limits limits, Map<String, ?> constants)
            throws IOException, ScriptException {
        return load(file, limits, constants, null);
    }

    /**
     * Loads and runs the script in {@code file}, with {@code constants} as read-only globals and
     * its {@code stats} module counting into {@code stats}.
     *
     * @param file the UTF-8 script file
     * @param limits the bounds for top-level execution and later calls
     * @param constants the globals to copy and freeze before compilation
     * @param stats the registry of the script's {@code stats}, or {@code null} for metrics that count nothing
     * @return the compiled script with frozen globals
     * @throws IOException if the file cannot be read
     * @throws ScriptException if parsing, compilation or top-level execution fails
     * @throws IllegalArgumentException if a constant name or value is invalid
     */
    public static StarlarkScript load(Path file, Limits limits, Map<String, ?> constants, StatsRegistry stats)
            throws IOException, ScriptException {
        return compile(Files.readString(file, StandardCharsets.UTF_8), file.toString(), limits, constants, stats);
    }

    /**
     * Compiles and runs {@code source}; {@code name} appears in error messages.
     *
     * @param source the Starlark source to compile
     * @param name the script name used in diagnostics
     * @param limits the bounds for top-level execution and later calls
     * @return the compiled script with frozen globals
     * @throws ScriptException if parsing, compilation or top-level execution fails
     */
    public static StarlarkScript compile(String source, String name, Limits limits) throws ScriptException {
        return compile(source, name, limits, Map.of());
    }

    /**
     * Compiles and runs {@code source} with {@code constants} as read-only globals (see {@link
     * ScriptedProxy.Builder#constants}); {@code name} appears in error messages.
     *
     * @param source the Starlark source to compile
     * @param name the script name used in diagnostics
     * @param limits the bounds for top-level execution and later calls
     * @param constants the globals to copy and freeze before compilation
     * @return the compiled script with frozen globals
     * @throws ScriptException if parsing, compilation or top-level execution fails
     * @throws IllegalArgumentException for constants that are not valid (see {@link
     *     ScriptedProxy.Builder#constants})
     */
    public static StarlarkScript compile(String source, String name, Limits limits, Map<String, ?> constants)
            throws ScriptException {
        return compile(source, name, limits, constants, null);
    }

    /**
     * Compiles and runs {@code source} with {@code constants} as read-only globals, its {@code
     * stats} module counting into {@code stats} ({@link ScriptStats}); {@code name} appears in error
     * messages.
     *
     * @param source the Starlark source to compile
     * @param name the script name used in diagnostics
     * @param limits the bounds for top-level execution and later calls
     * @param constants the globals to copy and freeze before compilation
     * @param stats the registry of the script's {@code stats}, or {@code null} for metrics that count nothing
     * @return the compiled script with frozen globals
     * @throws ScriptException if parsing, compilation or top-level execution fails
     * @throws IllegalArgumentException for constants that are not valid (see {@link
     *     ScriptedProxy.Builder#constants})
     */
    public static StarlarkScript compile(String source, String name, Limits limits, Map<String, ?> constants,
            StatsRegistry stats) throws ScriptException {
        ImmutableMap<String, Object> values = ScriptConstants.convert(constants);
        StarlarkFile file = StarlarkFile.parse(ParserInput.fromString(source, name), FILE_OPTIONS);
        if (!file.ok()) {
            throw new ScriptException(file.errors().stream().map(Object::toString).collect(Collectors.joining("\n")));
        }
        List<String> loads = loads(file);
        StarlarkSemantics semantics = loads.isEmpty() ? SEMANTICS : StdlibSemantics.VALUE;
        ScriptStats scriptStats = ScriptStats.of(stats);
        Module module = Module.withPredeclared(semantics, values.isEmpty() && scriptStats == ScriptStats.NOOP
                ? Builtins.PREDECLARED
                : ImmutableMap.<String, Object>builder().putAll(Builtins.PREDECLARED).putAll(values)
                        .put("stats", scriptStats).buildKeepingLast());
        Map<String, Module> loaded;
        try {
            loaded = loads.isEmpty() ? Map.of() : Stdlib.loadAll(loads);
        } catch (EvalException e) {
            throw new ScriptException(name + ": " + e.getMessage(), e);
        }
        try (Mutability mu = Mutability.create(name)) {
            Program program = Starlark.maybeWithTypeInfo(Program.compileFile(file, module), module, semantics, loaded::get);
            StarlarkThread thread = newThread(mu, limits, semantics);
            long timeout = limits.timeout().toMillis();
            if (timeout > 0) thread.setDeadlineNanos(System.nanoTime() + limits.timeout().toNanos());
            thread.setLoader(loaded::get);
            Starlark.execFileProgram(program, module, thread);
        } catch (SyntaxError.Exception e) {
            throw new ScriptException(e.errors().stream().map(Object::toString).collect(Collectors.joining("\n")), e);
        } catch (EvalException e) {
            throw new ScriptException(e.getMessageWithStack(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScriptException("interrupted while loading " + name, e);
        }
        for (String constant : values.keySet()) {
            if (module.getGlobal(constant) != null) {
                throw new ScriptException(name + ": " + constant + " is a script constant; the script cannot assign it");
            }
        }
        // Closing the mutability froze the globals.
        return new StarlarkScript(name, module, limits, semantics, null, stats, statsName(name), null);
    }

    /** The labels of the file's load statements. */
    private static List<String> loads(StarlarkFile file) {
        List<String> loads = new ArrayList<>();
        for (Statement st : file.getStatements()) {
            if (st instanceof LoadStatement load) {
                loads.add(load.getImport().getValue());
            }
        }
        return loads;
    }

    /**
     * The name given at compile time (the file path for loaded scripts).
     *
     * @return the diagnostic name of this script
     */
    public String name() {
        return name;
    }

    /**
     * Whether the script defines a function {@code function}.
     *
     * @param function the global name to inspect
     * @return whether that global is callable
     */
    public boolean defines(String function) {
        return module.getGlobal(function) instanceof StarlarkCallable;
    }

    /**
     * The value of the global {@code name} (frozen), or {@code null} when the script sets none.
     *
     * @param name the global name to look up
     * @return the frozen global value, or null if absent
     */
    public Object global(String name) {
        return module.getGlobal(name);
    }

    /**
     * Calls {@code function} with {@code args}, for no exchange (see {@link #call(FlowContext,
     * String, Mutability, Object...)}).
     *
     * @param function the global function name
     * @param mu the owner of values created by this call
     * @param args the positional Starlark arguments
     * @return the function's Starlark result
     * @throws EvalException if the function is absent, evaluation fails or an execution limit is reached
     * @throws InterruptedException if the calling thread is interrupted
     */
    public Object call(String function, Mutability mu, Object... args) throws EvalException, InterruptedException {
        return call(null, function, mu, args);
    }

    /**
     * Calls {@code function} with {@code args} for the exchange {@code flow}. Values the call
     * creates belong to {@code mu}, so several calls for one request can share state through it.
     * The call is measured (steps, bytes of values created, time): with metrics, in {@code
     * hooks.starlark.<script>.<function>.*}; in {@code flow}'s {@linkplain FlowContext#scriptStats()
     * totals}; and by the {@linkplain #withObserver observer}. Without any of them, and without a
     * timeout, no clock is read.
     *
     * @param flow the exchange the call is for, or null
     * @param function the global function name
     * @param mu the owner of values created by this call
     * @param args the positional Starlark arguments
     * @return the function's Starlark result
     * @throws EvalException if the function is absent, evaluation fails or an execution limit is reached
     * @throws InterruptedException if the calling thread is interrupted
     */
    public Object call(FlowContext flow, String function, Mutability mu, Object... args)
            throws EvalException, InterruptedException {
        Hook hook = hooks.get(function);
        if (hook == null) hook = hooks.computeIfAbsent(function, this::hook);
        if (hook.function() == null) {
            throw Starlark.errorf("%s does not define %s()", name, function);
        }
        StarlarkThread thread = newThread(mu, limits, semantics);
        if (protoSchema != null) thread.setThreadLocal(ProtoSchema.class, protoSchema);
        HookStats hookStats = hook.stats();
        ScriptCallObserver observer = this.observer;
        if (hookStats == null && flow == null && observer == null) {
            if (timeoutNanos > 0) thread.setDeadlineNanos(System.nanoTime() + timeoutNanos);
            return Starlark.call(thread, hook.function(), List.of(args), Map.of());
        }
        long start = System.nanoTime();
        if (timeoutNanos > 0) thread.setDeadlineNanos(start + timeoutNanos);
        Object token = observer == null ? null : observer.onCallStart(function, statsName, flow);
        Throwable error = null;
        try {
            return Starlark.call(thread, hook.function(), List.of(args), Map.of());
        } catch (Throwable t) {
            error = t;
            throw t;
        } finally {
            long nanos = System.nanoTime() - start;
            long steps = thread.getExecutedSteps();
            long allocBytes = thread.getAllocatedBytes();
            StarlarkThread.Budget exceeded = error == null ? null : thread.exceededBudget();
            if (hookStats != null) hookStats.record(nanos, steps, allocBytes, error != null, exceeded);
            if (flow != null) flow.recordScriptCall(nanos, steps, allocBytes);
            if (observer != null) {
                observer.onCallEnd(token, function, statsName, flow, steps, allocBytes, nanos, budgetName(exceeded),
                        error);
            }
        }
    }

    /** Resolves a hook, once: the function, and its stats. */
    private Hook hook(String function) {
        Object fn = module.getGlobal(function);
        if (!(fn instanceof StarlarkCallable callable)) return new Hook(null, null);
        return new Hook(callable, stats == null ? null : HookStats.of(stats, statsName, function, limits));
    }

    /** {@code steps}, {@code memory}, {@code time}, or null: the tag value of a budget. */
    static String budgetName(StarlarkThread.Budget budget) {
        if (budget == null) return null;
        return switch (budget) {
            case STEPS -> "steps";
            case MEMORY -> "memory";
            case TIME -> "time";
        };
    }

    private static final StarlarkThread.PrintHandler PRINT =
            (t, msg) -> LOG.log(Level.INFO, "{0}: {1}", t.getCallerLocation(), msg);

    /** A thread with the step and allocation limits; the caller sets the deadline. */
    private static StarlarkThread newThread(Mutability mu, Limits limits, StarlarkSemantics semantics) {
        StarlarkThread thread = StarlarkThread.createTransient(mu, semantics);
        thread.setMaxExecutionSteps(limits.maxSteps());
        if (limits.maxAllocBytes() != Long.MAX_VALUE) thread.setMaxAllocatedBytes(limits.maxAllocBytes());
        thread.setPrintHandler(PRINT);
        return thread;
    }

    @Override
    public String toString() {
        return "StarlarkScript[" + name + "]";
    }
}
