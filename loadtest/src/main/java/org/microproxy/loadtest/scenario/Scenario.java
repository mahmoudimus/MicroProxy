package org.microproxy.loadtest.scenario;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.microproxy.loadtest.Json;
import org.microproxy.loadtest.Settings;
import org.microproxy.loadtest.client.ClientControl;

/**
 * A scenario, run once per proxy: each run starts a fresh proxy JVM and load generator, checks
 * that responses through the proxy validate, measures, and returns its results as a map for the
 * results file.
 */
abstract class Scenario {

    final RunContext ctx;
    final Settings s;

    Scenario(RunContext ctx) {
        this.ctx = ctx;
        this.s = ctx.settings;
    }

    /** The scenario's name in the settings, results and report. */
    abstract String name();

    /** Runs the scenario against {@code proxy}. */
    abstract Map<String, Object> run(String proxy) throws Exception;

    /**
     * Records whether the proxy came through the scenario: {@code survived} (pass), or {@code oom}
     * or {@code crashed} (fail). Limits reached and rates are data, not verdicts.
     */
    void survival(String proxy, ProxyProcess p, String detail) {
        String state = p.oom() ? "oom" : p.alive() ? "survived" : "crashed";
        ctx.verdict(proxy, name(), "survival", state, state.equals("survived"), detail + "; proxy " + p.state());
    }

    /** A command timeout: {@code seconds} plus slack for the load generator's own work. */
    static Duration timeout(double seconds) {
        return Duration.ofMillis((long) (seconds * 1000) + 60_000);
    }

    /**
     * Sends a few requests of each kind the scenarios use (empty, small, 64 KB, 1 MB, chunked, an
     * upload) and checks every one validates; a failure is a failed harness check, since every
     * later number would be meaningless.
     */
    Map<String, Object> validate(String proxy, ClientControl client) throws IOException, InterruptedException {
        List<Object[]> cases = new ArrayList<>();
        for (long n : new long[] {0, 1, 1000, 65536, 1048576}) cases.add(new Object[] {ctx.originUrl(0, "/bytes/" + n), n, 0L});
        cases.add(new Object[] {ctx.originUrl(0, "/chunked/100000"), 100000L, 0L});
        cases.add(new Object[] {ctx.originUrl(0, "/upload"), 6L, 100000L});
        Map<String, Object> results = new LinkedHashMap<>();
        boolean ok = true;
        StringBuilder bad = new StringBuilder();
        for (Object[] c : cases) {
            Map<String, Object> r = client.call(Json.obj("cmd", "requests", "url", c[0], "count", 3, "concurrency", 3,
                    "expectStatus", 200, "expectLength", c[1], "uploadBytes", c[2]), timeout(30));
            Map<String, Object> outcomes = Json.getObject(r, "outcomes");
            long good = Json.getLong(outcomes, "OK", 0);
            results.put(c[0] + (((Long) c[2]) > 0 ? " (upload " + c[2] + ")" : ""), outcomes);
            if (good != 3) {
                ok = false;
                bad.append(c[0]).append(": ").append(outcomes).append(' ').append(r.get("details")).append("; ");
            }
        }
        ctx.check(proxy, name(), "responses validate (status and length)", ok, ok ? "all valid" : bad.toString());
        return Json.obj("ok", ok, "cases", results);
    }
}
