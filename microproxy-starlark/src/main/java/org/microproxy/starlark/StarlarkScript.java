package org.microproxy.starlark;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Module;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkCallable;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.syntax.FileOptions;
import org.microproxy.thirdparty.starlark.syntax.ParserInput;
import org.microproxy.thirdparty.starlark.syntax.Program;
import org.microproxy.thirdparty.starlark.syntax.StarlarkFile;
import org.microproxy.thirdparty.starlark.syntax.SyntaxError;

/**
 * A compiled Starlark file whose top-level statements have run. Its globals are frozen, so one
 * script is safely shared by every connection: each call gets its own {@link StarlarkThread}, and
 * functions cannot change global state. Calls are bounded by a step count and a wall-clock
 * timeout ({@link Limits}).
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

    /** Bounds on each call into a script (and on running its top level). */
    public record Limits(long maxSteps, Duration timeout) {
        /** Ten million steps and five seconds per call. */
        public static final Limits DEFAULT = new Limits(10_000_000, Duration.ofSeconds(5));

        public Limits {
            if (maxSteps <= 0) throw new IllegalArgumentException("maxSteps must be positive");
            Objects.requireNonNull(timeout, "timeout");
        }
    }

    private final String name;
    private final Module module;
    private final Limits limits;

    private StarlarkScript(String name, Module module, Limits limits) {
        this.name = name;
        this.module = module;
        this.limits = limits;
    }

    /** Loads and runs the script in {@code file}. */
    public static StarlarkScript load(Path file, Limits limits) throws IOException, ScriptException {
        return compile(Files.readString(file, StandardCharsets.UTF_8), file.toString(), limits);
    }

    /** Compiles and runs {@code source}; {@code name} appears in error messages. */
    public static StarlarkScript compile(String source, String name, Limits limits) throws ScriptException {
        StarlarkFile file = StarlarkFile.parse(ParserInput.fromString(source, name), FILE_OPTIONS);
        if (!file.ok()) {
            throw new ScriptException(file.errors().stream().map(Object::toString).collect(Collectors.joining("\n")));
        }
        Module module = Module.withPredeclared(SEMANTICS, Builtins.PREDECLARED);
        try (Mutability mu = Mutability.create(name)) {
            Program program = Starlark.maybeWithTypeInfo(Program.compileFile(file, module), module, SEMANTICS, null);
            Starlark.execFileProgram(program, module, newThread(mu, limits));
        } catch (SyntaxError.Exception e) {
            throw new ScriptException(e.errors().stream().map(Object::toString).collect(Collectors.joining("\n")), e);
        } catch (EvalException e) {
            throw new ScriptException(e.getMessageWithStack(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScriptException("interrupted while loading " + name, e);
        }
        // Closing the mutability froze the globals.
        return new StarlarkScript(name, module, limits);
    }

    /** The name given at compile time (the file path for loaded scripts). */
    public String name() {
        return name;
    }

    /** Whether the script defines a function {@code function}. */
    public boolean defines(String function) {
        return module.getGlobal(function) instanceof StarlarkCallable;
    }

    /**
     * Calls {@code function} with {@code args}. Values the call creates belong to {@code mu}, so
     * several calls for one request can share state through it.
     */
    public Object call(String function, Mutability mu, Object... args) throws EvalException, InterruptedException {
        Object fn = module.getGlobal(function);
        if (!(fn instanceof StarlarkCallable)) {
            throw Starlark.errorf("%s does not define %s()", name, function);
        }
        return Starlark.call(newThread(mu, limits), fn, List.of(args), Map.of());
    }

    private static StarlarkThread newThread(Mutability mu, Limits limits) {
        StarlarkThread thread = StarlarkThread.createTransient(mu, SEMANTICS);
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
