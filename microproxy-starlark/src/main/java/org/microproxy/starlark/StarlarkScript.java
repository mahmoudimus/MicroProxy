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
import java.util.stream.Collectors;
import org.microproxy.contentviews.ProtoSchema;
import org.microproxy.stats.Counter;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.StatsRegistry;
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
 * functions cannot change global state. Calls are bounded by a step count and a wall-clock
 * timeout ({@link Limits}).
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
     * Bounds on each call into a script (and on running its top level).
     *
     * @param maxSteps the positive maximum number of interpreter steps
     * @param timeout the wall-clock limit; non-positive millisecond values disable the deadline
     */
    public record Limits(long maxSteps, Duration timeout) {
        /** Ten million steps and five seconds per call. */
        public static final Limits DEFAULT = new Limits(10_000_000, Duration.ofSeconds(5));

        /**
         * Creates execution bounds.
         *
         * @param maxSteps the positive maximum number of interpreter steps
         * @param timeout the non-null wall-clock limit
         * @throws IllegalArgumentException if {@code maxSteps} is not positive
         * @throws NullPointerException if {@code timeout} is null
         */
        public Limits {
            if (maxSteps <= 0) throw new IllegalArgumentException("maxSteps must be positive");
            Objects.requireNonNull(timeout, "timeout");
        }
    }

    private final String name;
    private final Module module;
    private final Limits limits;
    private final StarlarkSemantics semantics;
    private final ProtoSchema protoSchema;
    /** {@code hooks.starlark.*}: the calls into scripts, resolved once; null without metrics, when no clock is read. */
    private final HookStats hookStats;

    /** The counts of calls into scripts, which every script of a registry shares. */
    private record HookStats(Counter invocations, Counter errors, Histogram latencyUs) {

        static HookStats of(StatsRegistry stats) {
            if (stats == null || !stats.enabled()) return null;
            return new HookStats(stats.counter("hooks.starlark.invocations", "Hook calls"),
                    stats.counter("hooks.starlark.errors", "Hook calls that threw"),
                    stats.histogram("hooks.starlark.latency_us", "Microseconds hook calls took",
                            Histogram.microsecondBounds()));
        }
    }

    private StarlarkScript(String name, Module module, Limits limits, StarlarkSemantics semantics,
            ProtoSchema protoSchema, HookStats hookStats) {
        this.name = name;
        this.module = module;
        this.limits = limits;
        this.semantics = semantics;
        this.protoSchema = protoSchema;
        this.hookStats = hookStats;
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
        return new StarlarkScript(name, module, limits, semantics, schema, hookStats);
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
        return new StarlarkScript(name, module, limits, semantics, null, HookStats.of(stats));
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
     * Calls {@code function} with {@code args}. Values the call creates belong to {@code mu}, so
     * several calls for one request can share state through it. With metrics, the call is counted
     * in {@code hooks.starlark.*}: its time, and whether it failed.
     *
     * @param function the global function name
     * @param mu the owner of values created by this call
     * @param args the positional Starlark arguments
     * @return the function's Starlark result
     * @throws EvalException if the function is absent, evaluation fails or an execution limit is reached
     * @throws InterruptedException if the calling thread is interrupted
     */
    public Object call(String function, Mutability mu, Object... args) throws EvalException, InterruptedException {
        Object fn = module.getGlobal(function);
        if (!(fn instanceof StarlarkCallable)) {
            throw Starlark.errorf("%s does not define %s()", name, function);
        }
        StarlarkThread thread = newThread(mu, limits, semantics);
        if (protoSchema != null) thread.setThreadLocal(ProtoSchema.class, protoSchema);
        HookStats stats = hookStats;
        if (stats == null) return Starlark.call(thread, fn, List.of(args), Map.of());
        long start = System.nanoTime();
        boolean failed = true;
        try {
            Object result = Starlark.call(thread, fn, List.of(args), Map.of());
            failed = false;
            return result;
        } finally {
            stats.invocations().inc();
            if (failed) stats.errors().inc();
            stats.latencyUs().record((System.nanoTime() - start) / 1_000.0);
        }
    }

    private static StarlarkThread newThread(Mutability mu, Limits limits, StarlarkSemantics semantics) {
        StarlarkThread thread = StarlarkThread.createTransient(mu, semantics);
        thread.setMaxExecutionSteps(limits.maxSteps());
        long timeout = limits.timeout().toMillis();
        if (timeout > 0) {
            thread.setExpirationMs(System.currentTimeMillis() + timeout);
        }
        thread.setPrintHandler((t, msg) -> LOG.log(Level.INFO, "{0}: {1}", t.getCallerLocation(), msg));
        return thread;
    }

    @Override
    public String toString() {
        return "StarlarkScript[" + name + "]";
    }
}
