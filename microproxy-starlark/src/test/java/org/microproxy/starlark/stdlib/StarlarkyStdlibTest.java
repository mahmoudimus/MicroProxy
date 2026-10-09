package org.microproxy.starlark.stdlib;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.google.common.collect.ImmutableMap;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.microproxy.starlark.stdlib.UnittestModule.Outcome;
import org.microproxy.starlark.stdlib.UnittestModule.Results;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Module;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.syntax.ParserInput;
import org.microproxy.thirdparty.starlark.syntax.Program;
import org.microproxy.thirdparty.starlark.syntax.StarlarkFile;
import org.microproxy.thirdparty.starlark.syntax.SyntaxError;

/**
 * Runs starlarky's tests of the ported standard library ({@code stdlib_tests/} and the
 * {@code vendor_tests/} of the ported vendor modules, under {@code org/microproxy/starlark/} in the
 * test resources), each file as starlarky's {@code StdLibTests} did: in the library's environment,
 * with {@code @stdlib//unittest} and {@code @vendor//asserts}. Every test function is reported
 * separately (a file that fails outside its tests is one failure, "&lt;file&gt;").
 *
 * <p>{@code microproxy_tests/} holds MicroProxy's own tests of what it changed (hashlib and hmac on
 * the JDK, re on java.util.regex).
 *
 * <p>Tests that fail because of a known difference from starlarky are listed in {@link
 * #EXPECTED_FAILURES} with the reason; they must fail (an entry that passes, or names no test, fails
 * the build), and nothing else may.
 */
class StarlarkyStdlibTest {

    private static final String ROOT = "org/microproxy/starlark/";
    private static final List<String> DIRS = List.of("stdlib_tests", "vendor_tests", "microproxy_tests");
    private static final String FILE_LEVEL = "<file>";

    /** "file::test" (or "file::<file>") -> why it fails here. */
    static final Map<String, String> EXPECTED_FAILURES = ImmutableMap.<String, String>builder()
            .put("stdlib_tests/test_hashlib.star::_test_new_blake2_shake",
                    "BLAKE2 and SHAKE are not in the JDK (starlarky's came from BouncyCastle)")
            .put("stdlib_tests/test_re_cpython.star::_test_unsupported_constructs_fail_cleanly",
                    "engine difference: java.util.regex runs look-around, backreferences and a{1001},"
                            + " which RE2 rejects (only conditional groups still fail)")
            .put("stdlib_tests/test_larky.star::_test_while_true_exception_stack_trace_is_correct",
                    "stack traces do not quote source lines (starlarky's evaluator adds them)")
            .buildOrThrow();

    private static final Stdlib.Loader LOADER = new Stdlib.Loader(ImmutableMap.<String, Object>builder()
            .putAll(Stdlib.NATIVES)
            .put("unittest", UnittestModule.INSTANCE)
            .buildOrThrow());

    /** Outcomes by file, then by test name. */
    private static Map<String, Map<String, String>> results;

    static synchronized Map<String, Map<String, String>> results() throws IOException, URISyntaxException {
        if (results == null) {
            Map<String, Map<String, String>> all = new LinkedHashMap<>();
            for (Path file : testFiles()) {
                Path root = Path.of(StarlarkyStdlibTest.class.getClassLoader().getResource(ROOT).toURI());
                String name = root.relativize(file).toString().replace('\\', '/');
                all.put(name, run(name, Files.readAllBytes(file)));
            }
            results = all;
        }
        return results;
    }

    private static List<Path> testFiles() throws IOException, URISyntaxException {
        List<Path> files = new ArrayList<>();
        for (String dir : DIRS) {
            Path root = Path.of(StarlarkyStdlibTest.class.getClassLoader().getResource(ROOT + dir).toURI());
            try (Stream<Path> walk = Files.walk(root)) {
                walk.filter(p -> p.getFileName().toString().startsWith("test_") && p.toString().endsWith(".star"))
                        .sorted()
                        .forEach(files::add);
            }
        }
        return files;
    }

    /** Runs one test file; returns each test's error (null when it passed). */
    private static Map<String, String> run(String name, byte[] source) {
        Map<String, String> outcomes = new LinkedHashMap<>();
        Results results = new Results();
        String fileError = null;
        try {
            Module module = Module.withPredeclared(Stdlib.MODULE_SEMANTICS, Stdlib.ENVIRONMENT);
            StarlarkFile file = StarlarkFile.parse(ParserInput.fromUTF8(source, name), Stdlib.MODULE_FILE_OPTIONS);
            Program program = Program.compileFile(file, module);
            Map<String, Module> loads = LOADER.loadAll(program.getLoads(), true, new ArrayDeque<>());
            try (Mutability mu = Mutability.create(name)) {
                StarlarkThread thread = StarlarkThread.createTransient(mu, Stdlib.MODULE_SEMANTICS);
                thread.setLoader(loads::get);
                thread.setThreadLocal(Results.class, results);
                thread.setMaxExecutionSteps(2_000_000_000L);
                thread.setExpirationMs(System.currentTimeMillis() + 300_000);
                thread.setPrintHandler((t, msg) -> {});
                Starlark.execFileProgram(program, module, thread);
            }
        } catch (SyntaxError.Exception e) {
            fileError = e.errors().stream().map(Object::toString).collect(Collectors.joining("\n"));
        } catch (EvalException e) {
            fileError = e.getMessageWithStack();
        } catch (Exception e) {
            fileError = e.toString();
        }
        for (Outcome o : results.outcomes) {
            String key = o.name();
            for (int i = 2; outcomes.containsKey(key); i++) {
                key = o.name() + "#" + i;
            }
            outcomes.put(key, o.error());
        }
        if (fileError != null || results.outcomes.isEmpty()) {
            outcomes.put(FILE_LEVEL, fileError);
        }
        return outcomes;
    }

    @TestFactory
    Stream<DynamicNode> starlarkyTests() throws Exception {
        Map<String, Map<String, String>> all = results();
        printSummary(all);
        return all.entrySet().stream().map(file -> DynamicContainer.dynamicContainer(file.getKey(),
                file.getValue().entrySet().stream().map(test -> DynamicTest.dynamicTest(test.getKey(), () -> {
                    String key = file.getKey() + "::" + test.getKey();
                    String error = test.getValue();
                    String expected = EXPECTED_FAILURES.get(key);
                    if (expected == null && error != null) {
                        fail(key + " failed:\n" + error);
                    }
                    if (expected != null && error == null) {
                        fail(key + " passed, but is listed in EXPECTED_FAILURES (" + expected + "); remove it");
                    }
                }))));
    }

    @Test
    void expectedFailuresNameTests() throws Exception {
        Map<String, Map<String, String>> all = results();
        Set<String> keys = new HashSet<>();
        all.forEach((file, tests) -> tests.keySet().forEach(t -> keys.add(file + "::" + t)));
        for (String key : EXPECTED_FAILURES.keySet()) {
            assertTrue(keys.contains(key), "EXPECTED_FAILURES names no test: " + key);
        }
    }

    private static void printSummary(Map<String, Map<String, String>> all) {
        StringBuilder sb = new StringBuilder("starlarky stdlib tests (passed / expected failures / failed):\n");
        int[] total = new int[3];
        all.forEach((file, tests) -> {
            int[] n = new int[3];
            tests.forEach((test, error) -> {
                boolean expected = EXPECTED_FAILURES.containsKey(file + "::" + test);
                n[error == null ? 0 : expected ? 1 : 2]++;
            });
            for (int i = 0; i < 3; i++) total[i] += n[i];
            sb.append(String.format("  %-45s %4d / %3d / %3d%n", file, n[0], n[1], n[2]));
            tests.forEach((test, error) -> {
                if (error != null && !EXPECTED_FAILURES.containsKey(file + "::" + test)) {
                    sb.append("      FAIL ").append(test).append(": ")
                            .append(error.lines().filter(l -> l.startsWith("Error")).findFirst()
                                    .orElse(error.lines().findFirst().orElse("")))
                            .append('\n');
                }
            });
        });
        sb.append(String.format("  %-45s %4d / %3d / %3d%n", "TOTAL", total[0], total[1], total[2]));
        System.out.println(sb);
    }
}
