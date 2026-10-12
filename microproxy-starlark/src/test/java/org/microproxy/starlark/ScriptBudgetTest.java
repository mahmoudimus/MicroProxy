package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;
import org.microproxy.ClientDetails;
import org.microproxy.FlowContext;
import org.microproxy.ScriptCallObserver;
import org.microproxy.dns.DnsMessage;
import org.microproxy.stats.Counter;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.StatsFormatter;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.thirdparty.starlark.eval.Allocations;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;

/**
 * What a hook call is measured by (steps, the bytes of values it creates, time), the budgets on
 * them, the per-script and per-hook stats, an exchange's totals and the observer.
 */
class ScriptBudgetTest {

    /** A call as an observer saw it end. */
    record Call(String hook, String script, FlowContext flow, long steps, long allocBytes, long nanos, String budget,
            Throwable error) {}

    /** Records every call, checking that each end gets its start's token. */
    static final class Recorder implements ScriptCallObserver {
        final List<String> starts = new CopyOnWriteArrayList<>();
        final List<Call> calls = new CopyOnWriteArrayList<>();

        @Override
        public Object onCallStart(String hook, String script, FlowContext flow) {
            starts.add(hook + "@" + script);
            return List.of(hook, script);
        }

        @Override
        public void onCallEnd(Object token, String hook, String script, FlowContext flow, long steps, long allocBytes,
                long nanos, String budgetExceeded, Throwable error) {
            assertEquals(List.of(hook, script), token, "the token onCallStart returned");
            calls.add(new Call(hook, script, flow, steps, allocBytes, nanos, budgetExceeded, error));
        }

        Call last() {
            return calls.getLast();
        }
    }

    private static final String X1000 = "x".repeat(1000);

    private static FlowContext flow() {
        return new FlowContext(9, () -> new InetSocketAddress("127.0.0.1", 9), () -> null, new ClientDetails());
    }

    /** Calls {@code f} of {@code source} with {@code args}, and returns how the call ended. */
    private static Call run(String source, StarlarkScript.Limits limits, Object... args) throws Exception {
        Recorder recorder = new Recorder();
        StarlarkScript script = StarlarkScript.compile(source, "measure.star", limits).withObserver(recorder);
        try (Mutability mu = Mutability.create("test")) {
            script.call("f", mu, args);
        } catch (EvalException e) {
            // the recorder has it
        }
        assertEquals(1, recorder.calls.size());
        return recorder.last();
    }

    /** The bytes {@code expression} counts, beyond what calling a function that returns None does. */
    private static long bytesOf(String expression, Object... args) throws Exception {
        String params = args.length == 0 ? "" : args.length == 1 ? "a" : "a, b";
        String prelude = "load(\"@stdlib//larky\", \"larky\")\n";
        boolean stdlib = expression.contains("larky.");
        Call base = run((stdlib ? prelude : "") + "def f(" + params + "):\n    return None\n",
                StarlarkScript.Limits.DEFAULT, args);
        Call call = run((stdlib ? prelude : "") + "def f(" + params + "):\n    return " + expression + "\n",
                StarlarkScript.Limits.DEFAULT, args);
        assertNull(call.error(), () -> expression + ": " + call.error());
        return call.allocBytes() - base.allocBytes();
    }

    private static void assertBetween(long low, long high, long actual, String what) {
        assertTrue(actual >= low && actual <= high, what + ": " + actual + " not in [" + low + ", " + high + "]");
    }

    // ---- what is counted -------------------------------------------------------------------

    @Test
    void stringsCountTwoBytesACharacterAndTheirObjects() throws Exception {
        long one = Allocations.string(1000);
        assertBetween(Allocations.string(2000), Allocations.string(2000) + 64, bytesOf("a + a", X1000), "concat");
        assertBetween(Allocations.string(10_000), Allocations.string(10_000) + 64, bytesOf("a * 10", X1000), "repeat");
        assertBetween(Allocations.string(1001), Allocations.string(1001) + 64, bytesOf("'%s!' % a", X1000), "percent");
        assertBetween(Allocations.string(999), Allocations.string(999) + 64, bytesOf("a[1:]", X1000), "slice");
        assertBetween(one, one + 64, bytesOf("a.upper()", X1000), "upper");
        assertBetween(Allocations.string(2000), Allocations.string(2000) + 64, bytesOf("a.replace('x', 'yy')", X1000),
                "replace");
        assertTrue(bytesOf("'-'.join([a, a])", X1000) >= Allocations.string(2001), "join");
        assertTrue(bytesOf("a.split('x')", X1000) >= 1001 * Allocations.string(0), "split: 1001 empty strings");
        assertTrue(bytesOf("'{}{}'.format(a, a)", X1000) >= Allocations.string(2000), "format");
        assertTrue(bytesOf("str([a])", X1000) >= Allocations.string(1004), "str");
        assertEquals(0, bytesOf("a.strip()", X1000), "an unchanged string is not a new one");
    }

    @Test
    void bytesCountTheirLength() throws Exception {
        StarlarkBytes b = StarlarkBytes.immutableOf(new byte[1000]);
        assertBetween(Allocations.bytes(2000), Allocations.bytes(2000) + 64, bytesOf("a + a", b), "concat");
        assertBetween(Allocations.bytes(10_000), Allocations.bytes(10_000) + 64, bytesOf("a * 10", b), "repeat");
        assertTrue(bytesOf("a[1:]", b) >= Allocations.bytes(999), "slice");
        assertTrue(bytesOf("a.hex()", b) >= Allocations.string(2000), "hex");
        assertTrue(bytesOf("a.decode('utf-8')", b) >= Allocations.string(1000), "decode");
    }

    @Test
    void listsCountTheirGrowth() throws Exception {
        StarlarkInt n = StarlarkInt.of(10_000);
        long slots = Allocations.REFERENCE * 10_000L;
        // An appended list's array grows by half each time: about three times its final size, all told.
        assertBetween(slots, 5 * slots, run("""
                def f(n):
                    l = []
                    for i in range(n):
                        l.append(i)
                    return l
                """, StarlarkScript.Limits.DEFAULT, n).allocBytes(), "append");
        assertTrue(bytesOf("[i for i in range(a)]", n) >= 2 * slots, "comprehension");
        assertTrue(bytesOf("list(range(a))", n) >= slots, "list()");
        assertTrue(bytesOf("[a, a, a]", n) >= Allocations.sequence(3), "literal");
        assertTrue(bytesOf("[0] * a", n) >= slots, "repeat");
        assertTrue(bytesOf("[0] * a + [1] * a", n) >= 4 * slots, "concat");
    }

    @Test
    void dictsCountTheirEntries() throws Exception {
        long bytes = run("""
                def f(n):
                    d = {}
                    for i in range(n):
                        d[i] = i
                    return d
                """, StarlarkScript.Limits.DEFAULT, StarlarkInt.of(10_000)).allocBytes();
        // Counted when the size reaches a power of two: 8192 of the 10000 entries.
        assertTrue(bytes >= 8192L * Allocations.DICT_ENTRY, "dict: " + bytes);
        assertTrue(bytesOf("{i: i for i in range(a)}", StarlarkInt.of(1000)) >= Allocations.dict(1000), "comprehension");
        assertTrue(bytesOf("dict(x=1, y=2)") >= Allocations.dict(2), "dict()");
    }

    @Test
    void tuplesAndStructsCount() throws Exception {
        assertTrue(bytesOf("tuple(range(a))", StarlarkInt.of(1000)) >= Allocations.sequence(1000), "tuple()");
        assertTrue(bytesOf("(a, a)", StarlarkInt.of(1)) >= Allocations.sequence(2), "tuple literal");
        assertTrue(bytesOf("larky.struct(x=1, y=2)") >= Allocations.struct(2), "struct");
        assertTrue(bytesOf("response(200, 'x' * 100)") >= Allocations.bytes(100), "response()");
    }

    @Test
    void builtinsCountWhatTheyReturn() throws Exception {
        String json = "[\"" + X1000 + "\"]";
        assertTrue(bytesOf("json.decode(a)", json) >= Allocations.string(1000), "json.decode");
        assertTrue(bytesOf("json.encode([a])", X1000) >= Allocations.string(1004), "json.encode");
        assertTrue(bytesOf("re.findall('x', a)", X1000) >= 1000 * Allocations.string(1), "re.findall");
        assertTrue(bytesOf("re.sub('x', 'yy', a)", X1000) >= Allocations.string(2000), "re.sub");
        assertTrue(bytesOf("base64.encode(a)", X1000) >= Allocations.string(1336), "base64.encode");
        assertTrue(bytesOf("base64.decode(a)", "eHh4".repeat(250)) >= Allocations.bytes(750), "base64.decode");
        assertTrue(bytesOf("digest.sha256(a)", X1000) >= Allocations.string(64), "digest");
        assertTrue(bytesOf("url.quote(a)", X1000) >= Allocations.string(1000), "url.quote");
        assertTrue(bytesOf("protobuf.decode(protobuf.encode({1: a}))", X1000) >= Allocations.bytes(1000) + 1000,
                "protobuf");
        byte[] reply = DnsMessage.query(7, "example.com", DnsMessage.A).reply(List.of(
                DnsMessage.ResourceRecord.of("example.com", DnsMessage.A, 300, DnsMessage.Address.of("192.0.2.1"))))
                .encode();
        assertTrue(bytesOf("dns.decode(a)", StarlarkBytes.immutableOf(reply)) >= 2 * Allocations.string(11), "dns");
    }

    @Test
    void anAllocationIsCountedBeforeItIsMade() throws Exception {
        com.sun.management.ThreadMXBean threads = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        for (String expression : List.of("'x' * 1000000000", "b'x' * 1000000000", "[0] * 1000000000",
                "(0,) * 1000000000", "list(range(1000000000))", "'xx' * 900000000")) {
            long allocated = threads.getCurrentThreadAllocatedBytes();
            long started = System.nanoTime();
            Call call = run("def f():\n    return " + expression + "\n", StarlarkScript.Limits.DEFAULT);
            long took = System.nanoTime() - started;
            long javaBytes = threads.getCurrentThreadAllocatedBytes() - allocated;
            assertNotNull(call.error(), expression);
            assertTrue(call.error().getMessage().contains("memory budget exceeded"), call.error().getMessage());
            assertEquals("memory", call.budget(), expression);
            assertTrue(javaBytes < 32L << 20, expression + " allocated " + javaBytes + " bytes before failing");
            assertTrue(took < Duration.ofSeconds(2).toNanos(), expression + " took " + took / 1_000_000 + " ms");
        }
    }

    // ---- budgets -------------------------------------------------------------------------

    @Test
    void theMemoryBudgetStopsGrowingListsAndDicts() throws Exception {
        StarlarkScript.Limits oneMiB = StarlarkScript.Limits.DEFAULT.withMaxAllocBytes(1 << 20);
        for (String loop : List.of("l.append(i)", "d[i] = i", "d.setdefault(i, i)", "l.extend([i, i])", "s += 'x'")) {
            Call call = run("""
                    def f():
                        l = []
                        d = {}
                        s = ""
                        for i in range(10000000):
                            %s
                    """.formatted(loop), oneMiB);
            assertNotNull(call.error(), loop);
            assertTrue(call.error().getMessage().contains("memory budget exceeded"), call.error().getMessage());
            assertEquals("memory", call.budget(), loop);
            assertTrue(call.allocBytes() > 1 << 20, loop + ": " + call.allocBytes());
            assertTrue(call.steps() < 10_000_000, loop + " stopped early: " + call.steps());
        }
    }

    @Test
    void theMemoryBudgetCoversTheStandardLibrary() throws Exception {
        StarlarkScript.Limits oneMiB = StarlarkScript.Limits.DEFAULT.withMaxAllocBytes(1 << 20);
        Call call = run("""
                load("@stdlib//base64", "base64")
                def f():
                    s = b"x"
                    for i in range(100):
                        s = base64.b64encode(s + s)
                """, oneMiB);
        assertNotNull(call.error());
        assertEquals("memory", call.budget());
        Call ok = run("""
                load("@stdlib//base64", "base64")
                def f():
                    return base64.b64encode(b"x" * 1000)
                """, oneMiB);
        assertNull(ok.error());
        assertTrue(ok.allocBytes() > Allocations.bytes(1000), "stdlib calls count: " + ok.allocBytes());
    }

    @Test
    void theStepBudgetStopsLongCalls() throws Exception {
        Call call = run("""
                def f():
                    n = 0
                    for i in range(100000000):
                        n += i
                    return n
                """, StarlarkScript.Limits.DEFAULT.withMaxSteps(1000));
        assertNotNull(call.error());
        assertTrue(call.error().getMessage().contains("too many steps"), call.error().getMessage());
        assertEquals("steps", call.budget());
        assertEquals(1000, call.steps());
    }

    @Test
    void theTimeBudgetStopsABusyLoop() throws Exception {
        StarlarkScript.Limits limits = new StarlarkScript.Limits(Long.MAX_VALUE, Duration.ofMillis(200), Long.MAX_VALUE);
        long started = System.nanoTime();
        Call call = run("""
                def f():
                    n = 0
                    for i in range(1000000):
                        for j in range(1000000):
                            n += 1
                    return n
                """, limits);
        long took = System.nanoTime() - started;
        assertNotNull(call.error());
        assertTrue(call.error().getMessage().contains("past expiration date"), call.error().getMessage());
        assertEquals("time", call.budget());
        assertTrue(call.nanos() >= Duration.ofMillis(200).toNanos(), "ran " + call.nanos());
        assertTrue(took < Duration.ofSeconds(5).toNanos(), "took " + took / 1_000_000 + " ms");
    }

    @Test
    void theTimeBudgetStopsARegularExpression() throws Exception {
        StarlarkScript.Limits limits = StarlarkScript.Limits.DEFAULT.withTimeout(Duration.ofMillis(200));
        for (String source : List.of(
                "def f():\n    return re.match('(.*a){12}x', 'a' * 30)\n",
                "load('@stdlib//re', 're')\ndef f():\n    return re.match(r'(?:.*a){12}b', 'a' * 60)\n")) {
            long started = System.nanoTime();
            Call call = run(source, limits);
            assertNotNull(call.error(), source);
            assertTrue(call.error().getMessage().contains("deadline"), call.error().getMessage());
            assertEquals("time", call.budget(), source);
            assertTrue(System.nanoTime() - started < Duration.ofSeconds(5).toNanos());
        }
    }

    @Test
    void aCallWithinItsBudgetsHasNone() throws Exception {
        Call call = run("def f(a):\n    return a * 2\n", StarlarkScript.Limits.DEFAULT, X1000);
        assertNull(call.error());
        assertNull(call.budget());
        assertTrue(call.steps() > 0 && call.allocBytes() > 0 && call.nanos() > 0, call.toString());
    }

    @Test
    void limitsCheckTheirBudgets() {
        assertEquals(StarlarkScript.Limits.DEFAULT_MAX_ALLOC_BYTES, StarlarkScript.Limits.DEFAULT.maxAllocBytes());
        assertEquals(256L << 20, StarlarkScript.Limits.DEFAULT.maxAllocBytes());
        assertThrows(IllegalArgumentException.class, () -> StarlarkScript.Limits.DEFAULT.withMaxAllocBytes(0));
        assertThrows(IllegalArgumentException.class, () -> StarlarkScript.Limits.DEFAULT.withMaxSteps(0));
        assertEquals(Duration.ZERO, StarlarkScript.Limits.DEFAULT.withTimeout(Duration.ZERO).timeout());
    }

    // ---- stats ---------------------------------------------------------------------------

    private static final String HOOKS = """
            def on_request(req, ctx):
                return [i for i in range(100)]

            def on_response(req, res, ctx):
                if req == "fail":
                    fail("broken")
                return None
            """;

    @Test
    void statsAreKeptPerScriptAndHook() throws Exception {
        StatsRegistry registry = StatsRegistry.create();
        StarlarkScript alpha = StarlarkScript.compile(HOOKS, "/etc/proxy/alpha.star", StarlarkScript.Limits.DEFAULT,
                Map.of(), registry);
        StarlarkScript beta = StarlarkScript.compile(HOOKS, "beta.star", StarlarkScript.Limits.DEFAULT, Map.of(), registry)
                .withStatsName("beta v2");
        assertEquals("alpha", alpha.statsName());
        assertEquals("beta_v2", beta.statsName());
        try (Mutability mu = Mutability.create("test")) {
            alpha.call("on_request", mu, "r", "c");
            int registered = registry.size();
            alpha.call("on_request", mu, "r", "c");
            alpha.call("on_response", mu, "r", "s", "c");
            assertThrows(EvalException.class, () -> alpha.call("on_response", mu, "fail", "s", "c"));
            beta.call("on_request", mu, "r", "c");
            assertEquals(registered + 8 + 8, registry.size(), "each hook's stats are made once, on its first call");
        }
        assertEquals(2, counter(registry, "hooks.starlark.alpha.on_request.invocations"));
        assertEquals(0, counter(registry, "hooks.starlark.alpha.on_request.errors"));
        assertEquals(2, counter(registry, "hooks.starlark.alpha.on_response.invocations"));
        assertEquals(1, counter(registry, "hooks.starlark.alpha.on_response.errors"));
        assertEquals(1, counter(registry, "hooks.starlark.beta_v2.on_request.invocations"));
        assertEquals(2, histogram(registry, "hooks.starlark.alpha.on_request.latency_us").count());
        Histogram.Snapshot steps = histogram(registry, "hooks.starlark.alpha.on_request.steps");
        assertEquals(2, steps.count());
        assertTrue(steps.sum() > 200, "a comprehension of 100 runs a few hundred steps: " + steps.sum());
        Histogram.Snapshot alloc = histogram(registry, "hooks.starlark.alpha.on_request.alloc_bytes");
        assertEquals(2, alloc.count());
        assertTrue(alloc.sum() >= 2 * Allocations.sequence(100), "alloc: " + alloc.sum());
        // Steps in powers of ten up to the limit, bytes in powers of four from 1 KiB up to the budget.
        assertEquals(10_000_000, steps.bounds()[steps.bounds().length - 1]);
        assertEquals(1024, alloc.bounds()[0]);
        assertEquals(256 << 20, alloc.bounds()[alloc.bounds().length - 1]);
        String scrape = StatsFormatter.prometheus(registry);
        assertTrue(scrape.contains("envoy_hooks_invocations{microproxy_script=\"alpha\",microproxy_script_hook=\"on_request\","
                + "microproxy_hook=\"starlark\"} 2"), scrape);
        assertTrue(scrape.contains("envoy_hooks_errors{microproxy_script=\"alpha\",microproxy_script_hook=\"on_response\","
                + "microproxy_hook=\"starlark\"} 1"), scrape);
        assertTrue(scrape.contains("envoy_hooks_steps_count{microproxy_script=\"beta_v2\","
                + "microproxy_script_hook=\"on_request\",microproxy_hook=\"starlark\"} 1"), scrape);
    }

    @Test
    void exceededBudgetsAreCountedByKind() throws Exception {
        StatsRegistry registry = StatsRegistry.create();
        StarlarkScript script = StarlarkScript.compile("""
                def steps():
                    for i in range(100000000):
                        pass

                def memory():
                    return "x" * 1000000000

                def time():
                    return re.match('(.*a){12}x', 'a' * 30)
                """, "budgets.star", new StarlarkScript.Limits(100_000, Duration.ofMillis(200)), Map.of(), registry);
        try (Mutability mu = Mutability.create("test")) {
            for (String hook : List.of("steps", "memory", "time", "steps")) {
                assertThrows(EvalException.class, () -> script.call(hook, mu));
            }
        }
        assertEquals(2, counter(registry, "hooks.starlark.budgets.steps.budget_exceeded.steps"));
        assertEquals(0, counter(registry, "hooks.starlark.budgets.steps.budget_exceeded.memory"));
        assertEquals(1, counter(registry, "hooks.starlark.budgets.memory.budget_exceeded.memory"));
        assertEquals(1, counter(registry, "hooks.starlark.budgets.time.budget_exceeded.time"));
        assertEquals(2, counter(registry, "hooks.starlark.budgets.steps.errors"));
        assertTrue(histogram(registry, "hooks.starlark.budgets.steps.steps").sum() >= 200_000);
        String scrape = StatsFormatter.prometheus(registry);
        assertTrue(scrape.contains("envoy_hooks_budget_exceeded{microproxy_budget=\"memory\",microproxy_script=\"budgets\","
                + "microproxy_script_hook=\"memory\",microproxy_hook=\"starlark\"} 1"), scrape);
    }

    @Test
    void withoutMetricsNothingIsRegistered() throws Exception {
        StarlarkScript script = StarlarkScript.compile(HOOKS, "quiet.star", StarlarkScript.Limits.DEFAULT, Map.of(),
                StatsRegistry.NOOP);
        try (Mutability mu = Mutability.create("test")) {
            script.call("on_request", mu, "r", "c");
        }
        assertEquals(0, StatsRegistry.NOOP.size());
    }

    private static long counter(StatsRegistry registry, String name) {
        Counter c = (Counter) registry.get(name);
        assertNotNull(c, name);
        return c.value();
    }

    private static Histogram.Snapshot histogram(StatsRegistry registry, String name) {
        Histogram h = (Histogram) registry.get(name);
        assertNotNull(h, name);
        return h.snapshot();
    }

    // ---- exchange totals and the observer --------------------------------------------------

    @Test
    void callsAddUpInTheirExchangeAndScriptsCanReadThem() throws Exception {
        Recorder recorder = new Recorder();
        StarlarkScript script = StarlarkScript.compile("""
                def on_request(req, ctx):
                    return [i for i in range(50)]

                def report(ctx):
                    s = ctx.script_stats
                    return (s.calls, s.steps, s.alloc_bytes, s.time_ms > 0)
                """, "totals.star", StarlarkScript.Limits.DEFAULT).withObserver(recorder);
        FlowContext flow = flow();
        try (Mutability mu = Mutability.create("test")) {
            ScriptContext ctx = new ScriptContext(flow, mu);
            script.call(flow, "on_request", mu, "r", ctx);
            script.call(flow, "on_request", mu, "r", ctx);
            long steps = recorder.calls.get(0).steps() + recorder.calls.get(1).steps();
            long alloc = recorder.calls.get(0).allocBytes() + recorder.calls.get(1).allocBytes();
            assertEquals(2, flow.scriptStats().calls());
            assertEquals(steps, flow.scriptStats().steps());
            assertEquals(alloc, flow.scriptStats().allocBytes());
            assertTrue(flow.scriptStats().nanos() > 0);
            // What the script sees is what the calls before it added up to.
            Object seen = script.call(flow, "report", mu, ctx);
            assertEquals("(2, " + steps + ", " + alloc + ", True)", seen.toString());
            assertEquals(3, flow.scriptStats().calls());
        }
        assertSame(flow, recorder.calls.getFirst().flow());
    }

    @Test
    void theObserverSeesEveryCallWithItsMeasuresAndError() throws Exception {
        Recorder recorder = new Recorder();
        StarlarkScript script = StarlarkScript.compile(HOOKS, "observed.star", StarlarkScript.Limits.DEFAULT)
                .withObserver(recorder);
        FlowContext flow = flow();
        try (Mutability mu = Mutability.create("test")) {
            script.call(flow, "on_request", mu, "r", "c");
            EvalException e = assertThrows(EvalException.class, () -> script.call(null, "on_response", mu, "fail", "s", "c"));
            assertThrows(EvalException.class, () -> script.call(flow, "not_a_hook", mu));
            assertEquals(List.of("on_request@observed", "on_response@observed"), recorder.starts,
                    "a function the script lacks is no call");
            Call ok = recorder.calls.get(0);
            assertEquals("on_request", ok.hook());
            assertEquals("observed", ok.script());
            assertSame(flow, ok.flow());
            assertNull(ok.error());
            assertTrue(ok.steps() > 0 && ok.allocBytes() > 0 && ok.nanos() > 0, ok.toString());
            Call failed = recorder.calls.get(1);
            assertSame(e, failed.error());
            assertNull(failed.flow());
            assertNull(failed.budget(), "fail() is no budget");
        }
    }

    @Test
    void theNoopObserverIsNoObserver() throws Exception {
        StarlarkScript script = StarlarkScript.compile(HOOKS, "noop.star", StarlarkScript.Limits.DEFAULT)
                .withObserver(ScriptCallObserver.NOOP);
        try (Mutability mu = Mutability.create("test")) {
            assertEquals(100, ((List<?>) script.call("on_request", mu, "r", "c")).size());
        }
    }

    // ---- the launcher's options ------------------------------------------------------------

    @Test
    void launcherOptionsParseDurationsAndSizes() {
        assertEquals(Duration.ofMillis(250), StarlarkLauncherExtension.duration("--script-max-time", "250ms"));
        assertEquals(Duration.ofSeconds(5), StarlarkLauncherExtension.duration("--script-max-time", "5s"));
        assertEquals(Duration.ofSeconds(3), StarlarkLauncherExtension.duration("--script-max-time", "3"));
        assertEquals(Duration.ofMinutes(1), StarlarkLauncherExtension.duration("--script-max-time", "1m"));
        assertEquals(Duration.ZERO, StarlarkLauncherExtension.duration("--script-max-time", "0"));
        assertThrows(IllegalArgumentException.class, () -> StarlarkLauncherExtension.duration("--script-max-time", "soon"));
        assertThrows(IllegalArgumentException.class, () -> StarlarkLauncherExtension.duration("--script-max-time", "-1s"));
        assertEquals(64L << 20, StarlarkLauncherExtension.bytes("--script-max-alloc", "64m"));
        assertEquals(512L << 10, StarlarkLauncherExtension.bytes("--script-max-alloc", "512KiB"));
        assertEquals(1L << 30, StarlarkLauncherExtension.bytes("--script-max-alloc", "1g"));
        assertEquals(1000, StarlarkLauncherExtension.bytes("--script-max-alloc", "1000"));
        assertThrows(IllegalArgumentException.class, () -> StarlarkLauncherExtension.bytes("--script-max-alloc", "lots"));
        assertThrows(IllegalArgumentException.class, () -> StarlarkLauncherExtension.bytes("--script-max-alloc", "-1"));
    }
}
