package org.microproxy.starlark.stdlib;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkCallable;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;
import org.microproxy.thirdparty.starlark.eval.Tuple;

/**
 * {@code @stdlib//unittest} for the ported starlarky tests: the subset of Python's unittest they
 * use ({@code TestSuite}, {@code FunctionTestCase}, {@code TextTestRunner}, {@code expectedFailure}).
 * Unlike starlarky's (built on JUnit 3), the runner runs every test and records each outcome in the
 * thread's {@link Results}, for {@link StarlarkyStdlibTest} to report.
 */
@StarlarkBuiltin(name = "unittest", doc = "Python's unittest, for the stdlib tests.")
public final class UnittestModule implements StarlarkValue {

    static final UnittestModule INSTANCE = new UnittestModule();

    /** One test's outcome: {@code error} is null when it passed. */
    record Outcome(String name, String error) {}

    /** The outcomes of the tests a thread ran, in order. */
    static final class Results {
        final List<Outcome> outcomes = new ArrayList<>();
    }

    @StarlarkMethod(name = "TestSuite", doc = "An empty test suite.")
    public Suite testSuite() {
        return new Suite();
    }

    @StarlarkMethod(name = "FunctionTestCase", doc = "A test case calling function.",
            parameters = {@Param(name = "function")})
    public TestCase functionTestCase(StarlarkCallable function) {
        return new TestCase(function, false);
    }

    @StarlarkMethod(name = "expectedFailure", doc = "Marks a test case as expected to fail.",
            parameters = {@Param(name = "testCase")})
    public TestCase expectedFailure(TestCase testCase) {
        return new TestCase(testCase.function, true);
    }

    @StarlarkMethod(name = "TextTestRunner", doc = "A runner that records outcomes.")
    public Runner textTestRunner() {
        return new Runner();
    }

    /** A test suite. */
    @StarlarkBuiltin(name = "TestSuite", doc = "A test suite.")
    public static final class Suite implements StarlarkValue {
        final List<TestCase> tests = new ArrayList<>();

        @StarlarkMethod(name = "addTest", doc = "Adds a test case.", parameters = {@Param(name = "test")})
        public void addTest(TestCase test) {
            tests.add(test);
        }

        @StarlarkMethod(name = "countTestCases", doc = "The number of test cases.")
        public int countTestCases() {
            return tests.size();
        }
    }

    /** A test case (a function, possibly expected to fail). */
    @StarlarkBuiltin(name = "FunctionTestCase", doc = "A test case.")
    public static final class TestCase implements StarlarkValue {
        final StarlarkCallable function;
        final boolean expectFailure;

        TestCase(StarlarkCallable function, boolean expectFailure) {
            this.function = function;
            this.expectFailure = expectFailure;
        }
    }

    /** Runs suites. */
    @StarlarkBuiltin(name = "TextTestRunner", doc = "A test runner.")
    public static final class Runner implements StarlarkValue {
        @StarlarkMethod(name = "run", doc = "Runs every test of suite, recording each outcome.",
                parameters = {@Param(name = "suite")}, useStarlarkThread = true)
        public void run(Suite suite, StarlarkThread thread) throws InterruptedException {
            Results results = thread.getThreadLocal(Results.class);
            for (TestCase test : suite.tests) {
                String error = null;
                try {
                    Starlark.call(thread, test.function, Tuple.empty(), Map.of());
                } catch (EvalException e) {
                    error = e.getMessageWithStack();
                } catch (RuntimeException e) {
                    java.io.StringWriter w = new java.io.StringWriter();
                    e.printStackTrace(new java.io.PrintWriter(w));
                    error = w.toString();
                }
                if (test.expectFailure) {
                    // as unittest.expectedFailure: a failure passes, a success fails
                    error = error != null ? null : "expected to fail (unittest.expectedFailure), but passed";
                }
                if (results != null) {
                    results.outcomes.add(new Outcome(test.function.getName(), error));
                }
            }
        }
    }
}
