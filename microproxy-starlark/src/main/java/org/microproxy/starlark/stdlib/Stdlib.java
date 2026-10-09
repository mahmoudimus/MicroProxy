package org.microproxy.starlark.stdlib;

import com.google.common.collect.ImmutableMap;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger.Level;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import org.microproxy.thirdparty.larky.LarkySemantics;
import org.microproxy.thirdparty.larky.modules.BinasciiModule;
import org.microproxy.thirdparty.larky.modules.C99MathModule;
import org.microproxy.thirdparty.larky.modules.CodecsModule;
import org.microproxy.thirdparty.larky.modules.CollectionsModule;
import org.microproxy.thirdparty.larky.modules.RegexModule;
import org.microproxy.thirdparty.larky.modules.ResultModule;
import org.microproxy.thirdparty.larky.modules.StructModule;
import org.microproxy.thirdparty.larky.modules.SysModule;
import org.microproxy.thirdparty.larky.modules.XMLModule;
import org.microproxy.thirdparty.larky.modules.ZLibModule;
import org.microproxy.thirdparty.larky.modules.codecs.TextUtil;
import org.microproxy.thirdparty.larky.modules.globals.LarkyGlobals;
import org.microproxy.thirdparty.larky.modules.globals.PythonBuiltins;
import org.microproxy.thirdparty.larky.modules.testing.AssertionsModule;
import org.microproxy.thirdparty.larky.objects.LarkyClassMethod;
import org.microproxy.thirdparty.larky.objects.LarkyStaticMethod;
import org.microproxy.thirdparty.larky.objects.LarkySuper;
import org.microproxy.thirdparty.larky.objects.type.LarkyBaseObjectType;
import org.microproxy.thirdparty.larky.objects.type.LarkyTypeObject;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Module;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.PercentFormat;
import org.microproxy.thirdparty.starlark.eval.PythonStrings;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.syntax.FileOptions;
import org.microproxy.thirdparty.starlark.syntax.ParserInput;
import org.microproxy.thirdparty.starlark.syntax.Program;
import org.microproxy.thirdparty.starlark.syntax.StarlarkFile;
import org.microproxy.thirdparty.starlark.syntax.SyntaxError;

/**
 * The Python-compatible standard library ported from starlarky, for {@code load()} in scripts:
 * {@code load("@stdlib//urllib/parse", "parse")}, {@code load("@vendor//option/result", "Ok")}.
 *
 * <p>A label names a {@code .star} file under {@code org/microproxy/starlark/<namespace>/} on the
 * class path ({@code @stdlib//io} may also be {@code io/__init__.star}), or for {@code @stdlib} one
 * of the native (Java) modules the files are built on, such as {@code @stdlib//jzlib}. Inside the
 * library, a label without a namespace ({@code load("types", ...)}) means {@code @stdlib}.
 *
 * <p>Each module is compiled and run once per process, in its own thread under {@link
 * #MODULE_LIMITS}, with starlarky's predeclared environment ({@link #ENVIRONMENT}: Python's
 * {@code bytes}, {@code iter}, {@code type}, {@code object}, ... and Larky's {@code _struct}
 * helpers). Its globals are then frozen, and the frozen module is shared by every script that
 * loads it (and by every connection running those scripts): functions from it run in the calling
 * script's thread, within its step and time limits, and so does the code of values the module
 * made (Larky structs' dunder methods and properties run in {@link StarlarkThread#current()}, not
 * in the thread that loaded the module). Loading the same label again returns the same module; a
 * cycle of loads, a missing module, or a module that fails while loading is an error naming the
 * chain of loads (a failed module is not cached, so the next load reports it again).
 */
public final class Stdlib {

    private static final System.Logger LOG = System.getLogger("org.microproxy.starlark.stdlib");

    /** Where {@code @<namespace>//path} files live on the class path. */
    static final String RESOURCE_ROOT = "org/microproxy/starlark/";

    /** Namespaces a label may name. */
    static final List<String> NAMESPACES = List.of("stdlib", "vendor");

    /** Bounds on running one module's top level (each module separately). */
    public static final Limits MODULE_LIMITS = new Limits(200_000_000, Duration.ofSeconds(60));

    /** Bounds on running a module's top-level statements. */
    public record Limits(long maxSteps, Duration timeout) {}

    /**
     * Python's string behaviour, which the library's code relies on: {@code str % args} with
     * printf flags and widths, Unicode-aware case mapping and classification, Python's bounds for
     * {@code find}/{@code count}/..., and CPython's codec names and error handlers for
     * {@code bytes.decode}. Applied to the modules and to every script that loads one.
     */
    public static StarlarkSemantics withPythonStrings(StarlarkSemantics semantics) {
        return semantics.toBuilder()
                .setBool(PythonStrings.PYTHON_STRING_BOUNDS, true)
                .setBool(PythonStrings.PYTHON_UNICODE_STRINGS, true)
                .setBool(PercentFormat.PYTHON_PERCENT_FORMAT, true)
                .setBool(StarlarkBytes.PYTHON_CODECS, true)
                .setBool(LarkySemantics.PYCOMPAT_TYPE_BUILTIN_FUNCTION, false)
                .build();
    }

    /** The semantics modules run their top level with. */
    static final StarlarkSemantics MODULE_SEMANTICS = withPythonStrings(StarlarkSemantics.DEFAULT);

    /** As starlarky's strict mode: top-level rebinding, and loads bind globals. */
    static final FileOptions MODULE_FILE_OPTIONS = FileOptions.DEFAULT.toBuilder()
            .allowToplevelRebinding(true)
            .loadBindsGlobally(true)
            .build();

    /**
     * The predeclared environment of library modules (and of starlarky's tests): Larky's globals
     * ({@code _struct}, {@code _mutablestruct}, {@code _partial}, ...), Python builtins that replace
     * Starlark's ({@code bytes}, {@code int}, {@code iter}, {@code next}, {@code getattr}, ...), and
     * the class model ({@code object}, {@code type}, {@code super}, {@code classmethod},
     * {@code staticmethod}). Scripts do not see these; they load what they need.
     */
    public static final ImmutableMap<String, Object> ENVIRONMENT;

    /** The native modules, by their {@code @stdlib//} name. */
    static final ImmutableMap<String, Object> NATIVES;

    static {
        // bytes.decode uses the codecs module's codecs (under PYTHON_CODECS only).
        StarlarkBytes.setDecoder(TextUtil.PyCodecs::decode);
        ImmutableMap.Builder<String, Object> env = ImmutableMap.builder();
        Starlark.addMethods(env, new LarkyGlobals());
        Starlark.addMethods(env, new PythonBuiltins());
        env.put("object", LarkyBaseObjectType.getInstance());
        env.put("type", LarkyTypeObject.getInstance());
        env.put("super", LarkySuper.getInstance());
        env.put("classmethod", LarkyClassMethod.getInstance());
        env.put("staticmethod", LarkyStaticMethod.getInstance());
        ENVIRONMENT = env.buildKeepingLast();

        NATIVES = ImmutableMap.<String, Object>builder()
                .put("assertions", AssertionsModule.INSTANCE)
                .put("c99math", C99MathModule.INSTANCE)
                .put("codecs", CodecsModule.INSTANCE)
                .put("jbinascii", BinasciiModule.INSTANCE)
                .put("jcollections", CollectionsModule.INSTANCE)
                .put("jhashlib", HashlibModule.INSTANCE)
                .put("jrandom", RandomModule.INSTANCE)
                .put("jregex", RegexModule.INSTANCE)
                .put("jresult", ResultModule.INSTANCE)
                .put("jstruct", StructModule.INSTANCE)
                .put("json", JsonModule.INSTANCE)
                .put("jxml", XMLModule.INSTANCE)
                .put("jzlib", ZLibModule.INSTANCE)
                .put("sys", SysModule.INSTANCE)
                .buildOrThrow();
    }

    private static final Loader DEFAULT = new Loader(NATIVES);

    private Stdlib() {}

    /**
     * Loads the modules a script's {@code load} statements name, by label (in order); see {@link
     * Loader#loadAll}.
     */
    public static Map<String, Module> loadAll(List<String> labels) throws EvalException {
        return DEFAULT.loadAll(labels);
    }

    /** A label resolved to its namespace and path (without {@code .star}). */
    record Label(String namespace, String path) {
        String key() {
            return "@" + namespace + "//" + path;
        }

        @Override
        public String toString() {
            return key();
        }
    }

    /**
     * Resolves {@code label}: {@code @namespace//path}, {@code @namespace/path} (as starlarky
     * accepts), or (only inside the library, {@code inLibrary}) a bare path meaning {@code @stdlib}.
     */
    static Label parse(String label, boolean inLibrary) throws EvalException {
        String namespace;
        String path;
        if (label.startsWith("@")) {
            int slash = label.indexOf('/');
            if (slash < 0) {
                throw Starlark.errorf("cannot load '%s': a label is @stdlib//<module> or @vendor//<module>", label);
            }
            namespace = label.substring(1, slash);
            path = label.substring(label.startsWith("//", slash) ? slash + 2 : slash + 1);
        } else if (inLibrary) {
            namespace = "stdlib";
            path = label;
        } else {
            throw Starlark.errorf(
                    "cannot load '%s': scripts load only the standard library (@stdlib//<module> or"
                            + " @vendor//<module>); they cannot read files",
                    label);
        }
        if (path.endsWith(".star")) {
            path = path.substring(0, path.length() - ".star".length());
        }
        if (!NAMESPACES.contains(namespace)) {
            throw Starlark.errorf("cannot load '%s': unknown namespace @%s (there are @stdlib and @vendor)",
                    label, namespace);
        }
        if (path.isEmpty() || path.startsWith("/") || path.endsWith("/")
                || List.of(path.split("/")).stream().anyMatch(p -> p.isEmpty() || p.equals(".") || p.equals(".."))) {
            throw Starlark.errorf("cannot load '%s': bad module path '%s'", label, path);
        }
        return new Label(namespace, path);
    }

    /**
     * Loads and caches modules. One instance serves the whole process; tests make their own with
     * extra native modules (such as {@code unittest}).
     */
    static final class Loader {

        private final ImmutableMap<String, Object> natives;
        private final Limits limits;
        private final Map<String, Module> cache = new ConcurrentHashMap<>();
        // Held while a module (and what it loads) is being initialized, so each runs once.
        private final ReentrantLock lock = new ReentrantLock();

        Loader(Map<String, Object> natives) {
            this(natives, MODULE_LIMITS);
        }

        Loader(Map<String, Object> natives, Limits limits) {
            this.natives = ImmutableMap.copyOf(natives);
            this.limits = limits;
        }

        /**
         * Loads the modules {@code labels} name, as a map from each label (as written) to its
         * module, for a script's {@link StarlarkThread#setLoader loader} and for type checking.
         */
        Map<String, Module> loadAll(List<String> labels) throws EvalException {
            return loadAll(labels, false, new ArrayDeque<>());
        }

        Map<String, Module> loadAll(List<String> labels, boolean inLibrary, Deque<String> pending)
                throws EvalException {
            Map<String, Module> modules = new LinkedHashMap<>();
            for (String label : labels) {
                if (!modules.containsKey(label)) {
                    modules.put(label, load(parse(label, inLibrary), pending));
                }
            }
            return modules;
        }

        Module load(Label label, Deque<String> pending) throws EvalException {
            Module cached = cache.get(label.key());
            if (cached != null) {
                return cached;
            }
            lock.lock();
            try {
                cached = cache.get(label.key());
                if (cached != null) {
                    return cached;
                }
                if (pending.contains(label.key())) {
                    throw Starlark.errorf("cycle in loads: %s -> %s", String.join(" -> ", pending), label);
                }
                pending.addLast(label.key());
                try {
                    Module module = initialize(label, pending);
                    cache.put(label.key(), module);
                    return module;
                } finally {
                    pending.removeLast();
                }
            } finally {
                lock.unlock();
            }
        }

        private Module initialize(Label label, Deque<String> pending) throws EvalException {
            if (label.namespace().equals("stdlib") && natives.containsKey(label.path())) {
                // A native module: one global, named after it (load("@stdlib//jzlib", "jzlib")).
                Module module = Module.create();
                module.setGlobal(label.path(), natives.get(label.path()));
                return module;
            }
            String resource = RESOURCE_ROOT + label.namespace() + "/" + label.path() + ".star";
            byte[] source = read(resource);
            if (source == null) {
                resource = RESOURCE_ROOT + label.namespace() + "/" + label.path() + "/__init__.star";
                source = read(resource);
            }
            if (source == null) {
                throw Starlark.errorf("cannot load '%s': no such module (available: %s)", label, available(label.namespace()));
            }
            Module module = Module.withPredeclared(MODULE_SEMANTICS, ENVIRONMENT);
            Program program;
            try {
                StarlarkFile file = StarlarkFile.parse(ParserInput.fromUTF8(source, label.key()), MODULE_FILE_OPTIONS);
                program = Program.compileFile(file, module);
            } catch (SyntaxError.Exception e) {
                throw Starlark.errorf("cannot load '%s': %s", label,
                        e.errors().stream().map(Object::toString).collect(Collectors.joining("\n")));
            }
            Map<String, Module> loads;
            try {
                loads = loadAll(program.getLoads(), true, pending);
            } catch (EvalException e) {
                throw Starlark.errorf("cannot load '%s': %s", label, e.getMessage());
            }
            long started = System.nanoTime();
            try (Mutability mu = Mutability.create(label.key())) {
                StarlarkThread thread = StarlarkThread.createTransient(mu, MODULE_SEMANTICS);
                thread.setLoader(loads::get);
                thread.setMaxExecutionSteps(limits.maxSteps());
                thread.setExpirationMs(System.currentTimeMillis() + limits.timeout().toMillis());
                thread.setPrintHandler((t, msg) -> LOG.log(Level.INFO, "{0}: {1}", t.getCallerLocation(), msg));
                Starlark.execFileProgram(program, module, thread);
                // Values the module made may hold on to this thread; they run their code in the
                // caller's thread (StarlarkThread.current()), but where there is none (Java code
                // calling repr, say), the load's deadline must not linger.
                thread.setExpirationMs(Long.MAX_VALUE);
            } catch (EvalException e) {
                throw Starlark.errorf("cannot load '%s': %s", label, e.getMessageWithStack());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw Starlark.errorf("interrupted while loading '%s'", label);
            }
            LOG.log(Level.DEBUG, () -> String.format("loaded %s in %d ms", label, (System.nanoTime() - started) / 1_000_000));
            return module;
        }

        private String available(String namespace) {
            TreeSet<String> names = new TreeSet<>();
            if (namespace.equals("stdlib")) {
                for (String name : Modules.STDLIB) names.add(name);
            } else {
                for (String name : Modules.VENDOR) names.add(name);
            }
            return String.join(", ", names);
        }

        @Nullable
        private static byte[] read(String resource) throws EvalException {
            ClassLoader cl = Stdlib.class.getClassLoader();
            try (InputStream in = cl.getResourceAsStream(resource)) {
                return in == null ? null : in.readAllBytes();
            } catch (IOException e) {
                throw Starlark.errorf("cannot read %s: %s", resource, e.getMessage());
            }
        }
    }

    /** The modules meant for scripts (the README's list), for error messages. */
    static final class Modules {
        static final List<String> STDLIB = List.of(
                "base64", "binascii", "builtins", "bz2", "codecs", "collections", "csv", "dicts", "enum",
                "functools", "hashlib", "hmac", "io", "itertools", "json", "larky", "math", "operator",
                "random", "re", "reprlib", "sets", "string", "struct", "sys", "textwrap", "types",
                "urllib/parse", "urllib/request", "uuid", "xml/etree/ElementTree", "zipfile", "zlib");
        static final List<String> VENDOR = List.of(
                "asserts", "escapes", "luhn", "multidict", "option/result", "six");

        private Modules() {}
    }
}
