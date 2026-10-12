package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.microproxy.ClientDetails;
import org.microproxy.FlowContext;
import org.microproxy.ScriptCallObserver;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.Mutability;

/**
 * What measuring a hook call costs: a representative hook called 100,000 times bare (no metrics,
 * exchange, observer or budgets: the interpreter's allocation counting alone, which cannot be
 * turned off) and measured (metrics, the exchange's totals, an observer and the default budgets).
 * It prints both; it fails only on a gross regression, since a shared machine's timings vary.
 */
class ScriptOverheadTest {

    static final String HOOK = """
            ALLOWED = {"GET": True, "POST": True, "PUT": False}

            def on_request(req, ctx):
                path = req["path"]
                parts = path.split("/")
                if not ALLOWED.get(req["method"]):
                    return "deny"
                key = "%s:%s" % (req["method"], parts[1])
                tags = [p.upper() for p in parts if p]
                ctx["tags"] = ",".join(tags)
                if path.startswith("/api/") and len(parts) > 2:
                    ctx["user"] = parts[2]
                ctx["n"] = len(req["headers"])
                return key
            """;

    private static final int CALLS = 100_000;

    private static final Dict<Object, Object> REQUEST = Dict.builder()
            .put("path", "/api/alice/items/42").put("method", "GET")
            .put("headers", Dict.builder().put("host", "example.com").put("accept", "*/*").buildImmutable())
            .buildImmutable();

    private static Object sink;

    /** Nanoseconds per call, the median of five rounds of {@code calls}. */
    private static long perCall(StarlarkScript script, FlowContext flow, int calls) throws Exception {
        long[] rounds = new long[5];
        for (int r = 0; r < rounds.length; r++) {
            long start = System.nanoTime();
            for (int i = 0; i < calls / rounds.length; i++) {
                try (Mutability mu = Mutability.create("bench")) {
                    sink = script.call(flow, "on_request", mu, REQUEST, Dict.of(mu));
                }
            }
            rounds[r] = (System.nanoTime() - start) / (calls / rounds.length);
        }
        Arrays.sort(rounds);
        return rounds[rounds.length / 2];
    }

    @Test
    void measuringACallCostsLittle() throws Exception {
        StarlarkScript bare = StarlarkScript.compile(HOOK, "bench.star",
                new StarlarkScript.Limits(10_000_000, Duration.ZERO, Long.MAX_VALUE));
        StarlarkScript measured = StarlarkScript.compile(HOOK, "bench.star", StarlarkScript.Limits.DEFAULT, Map.of(),
                StatsRegistry.create()).withObserver(new ScriptCallObserver() {});
        FlowContext flow = new FlowContext(1, () -> new InetSocketAddress("127.0.0.1", 1), () -> null,
                new ClientDetails());
        // Warm both up, then alternate.
        perCall(bare, null, CALLS);
        perCall(measured, flow, CALLS);
        long bareNanos = Math.min(perCall(bare, null, CALLS), perCall(bare, null, CALLS));
        long measuredNanos = Math.min(perCall(measured, flow, CALLS), perCall(measured, flow, CALLS));
        long calls = flow.scriptStats().calls();
        System.out.printf("hook call: bare %d ns, measured %d ns (%+.1f%%); %d steps and %d bytes a call%n",
                bareNanos, measuredNanos, 100.0 * (measuredNanos - bareNanos) / bareNanos,
                flow.scriptStats().steps() / calls, flow.scriptStats().allocBytes() / calls);
        assertEquals(3L * CALLS, calls);
        assertTrue(measuredNanos < 2 * bareNanos, "measured " + measuredNanos + " ns, bare " + bareNanos + " ns");
    }
}
