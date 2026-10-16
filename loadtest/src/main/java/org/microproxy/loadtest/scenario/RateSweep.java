package org.microproxy.loadtest.scenario;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.microproxy.loadtest.Json;
import org.microproxy.loadtest.client.ClientControl;
import org.microproxy.loadtest.proc.GcLog;
import org.microproxy.loadtest.proc.ProcStats;
import org.microproxy.loadtest.proc.Sampler;

/**
 * The rate sweep: open-loop load over keep-alive connections with small responses, the rate
 * multiplied at each step, to find the knee. A step is sustainable when its p99 is within the SLO,
 * its error ratio within the tolerance, it achieved at least 95% of its target rate and left
 * almost nothing unsent; the knee is the first step of {@code sweep-knee-confirm} unsustainable
 * steps in a row (1: the first unsustainable step). With a confirmation of 2 or more, a lone
 * unsustainable step that the next step recovers from (a GC pause, or a burst of other work on a
 * shared machine) is kept in the results as such, but does not end the sweep. A step where the load
 * generator could not keep its own schedule ends the sweep as client-bound: its numbers say nothing
 * about the proxy.
 *
 * <p>The geometric steps only bracket the maximum sustainable rate to within one step, so when the
 * proxy made the knee, the sweep then refines it: it bisects between the highest sustained step
 * before the knee and the knee with more recorded steps ({@code refine.probes}), judged by the same
 * rules, until the bracket is within {@code sweep-refine-precision} or {@code sweep-refine-steps}
 * probes have run. The maximum sustainable rate is then the achieved rate of the highest sustained
 * step or probe, {@code maxSustainableBracket} the offered rates it lies between, and
 * {@code maxSustainableRateCoarse} the unrefined figure. Every step and probe records the proxy's CPU
 * time over it and per completed request.
 */
final class RateSweep extends Scenario {

    RateSweep(RunContext ctx) {
        super(ctx);
    }

    @Override
    String name() {
        return "sweep";
    }

    @Override
    Map<String, Object> run(String proxy) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        try (ProxyProcess p = ProxyProcess.start(ctx, proxy, name(), ProxyProcess.defaults(s));
                ClientControl client = ctx.startClient(proxy + "-" + name(), p.port, List.of());
                Sampler sampler = new Sampler(Map.of("proxy", p.pid(), "origin", ctx.origin.pid(), "client",
                        client.process().pid()), 1000)) {
            result.put("proxyProcess", p.describe());
            result.put("validation", validate(proxy, client));
            int connections = s.getInt("sweep-connections");
            long size = s.getLong("sweep-response-bytes");
            String url = ctx.originUrl(0, "/bytes/" + size);
            double sloMs = s.getDouble("slo-p99-ms");
            double tolerance = s.getDouble("error-tolerance");
            double rate = s.getDouble("sweep-start-rate");
            int stepSeconds = s.getInt("sweep-step-seconds");

            // Warm-up: JIT compilation and connection setup, not recorded.
            client.call(Json.obj("cmd", "rate", "url", url, "expectLength", size, "rate", rate, "connections", connections,
                    "durationMs", s.getInt("sweep-warmup-seconds") * 1000L), timeout(s.getInt("sweep-warmup-seconds")));
            result.put("baseline", p.memorySnapshot(false));

            List<Map<String, Object>> steps = new ArrayList<>();
            Integer knee = null;
            String kneeReason = null;
            String stopReason = "max steps";
            int afterKnee = s.getInt("sweep-steps-after-knee");
            int confirm = Math.max(1, s.getInt("sweep-knee-confirm"));
            int streak = 0;
            int streakStart = -1;
            String streakReason = null;
            List<Integer> transients = new ArrayList<>();
            for (int i = 0; i < s.getInt("sweep-max-steps") && rate <= s.getDouble("sweep-max-rate"); i++) {
                Map<String, Object> step = step(proxy, p, client, sampler, url, size, rate, connections, stepSeconds, sloMs, tolerance);
                steps.add(step);
                String why = Json.getString(step, "why", "");
                boolean saturated = Json.getBool(step, "clientSaturated", false);
                if (!p.alive()) {
                    stopReason = "proxy " + p.state();
                    if (knee == null) {
                        knee = i;
                        kneeReason = stopReason;
                    }
                    break;
                }
                if (saturated) {
                    stopReason = "client-bound: the load generator could not keep its schedule at " + Math.round(rate) + "/s";
                    if (knee == null) {
                        knee = i;
                        kneeReason = stopReason;
                    }
                    break;
                }
                if (knee == null) {
                    if (why.isEmpty()) {
                        if (streak > 0) transients.add(streakStart);
                        streak = 0;
                    } else {
                        if (streak++ == 0) {
                            streakStart = i;
                            streakReason = why;
                        }
                        if (streak >= confirm) {
                            knee = streakStart;
                            kneeReason = streakReason;
                        }
                    }
                }
                if (knee != null && i - knee >= Math.max(afterKnee, confirm - 1)) {
                    stopReason = "past the knee";
                    break;
                }
                if (errorRatio(step) > 0.5) {
                    stopReason = "more than half the requests failed";
                    break;
                }
                rate *= s.getDouble("sweep-factor");
            }
            if (knee == null && streak > 0) {
                // The sweep ended inside an unconfirmed run of unsustainable steps: the knee is its start.
                knee = streakStart;
                kneeReason = streakReason;
            }
            Double coarseMax = null;
            int lastSustained = -1;
            int bound = knee == null ? steps.size() : knee;
            for (int j = bound - 1; j >= 0 && coarseMax == null; j--) {
                if (Json.getBool(steps.get(j), "sustainable", false)) {
                    coarseMax = Json.getDouble(steps.get(j), "achievedRate", 0);
                    lastSustained = j;
                }
            }
            // Knee refinement: the geometric steps only bracket the maximum to within one step (a
            // factor of sweep-factor), so bisect between the last sustained step and the knee.
            Double max = coarseMax;
            List<Object> bracket = null;
            Map<String, Object> refine = null;
            boolean proxyKnee = knee != null && kneeReason != null && !kneeReason.startsWith("client-bound")
                    && !kneeReason.startsWith("proxy ");
            if (proxyKnee && lastSustained >= 0 && p.alive()) {
                double lo = Json.getDouble(steps.get(lastSustained), "targetRate", 0);
                double hi = Json.getDouble(steps.get(knee), "targetRate", 0);
                refine = refine(p, client, sampler, url, size, connections, stepSeconds, sloMs, tolerance, confirm, lo, hi,
                        coarseMax, proxy);
                if (Json.getBool(refine, "used", false)) {
                    max = Json.getDouble(refine, "maxSustainableRate", coarseMax);
                    bracket = List.of(refine.get("low"), refine.get("high"));
                } else {
                    bracket = List.of(lo, hi);
                }
            }
            result.put("sloP99Ms", sloMs);
            result.put("errorTolerance", tolerance);
            result.put("connections", connections);
            result.put("responseBytes", size);
            result.put("steps", steps);
            result.put("kneeStep", knee);
            result.put("kneeReason", kneeReason);
            result.put("kneeFound", knee != null);
            result.put("kneeConfirm", confirm);
            // Unsustainable steps before the knee that the next step recovered from.
            result.put("transientSteps", transients);
            // The highest sustained achieved rate: refined when the knee was bisected, else the coarse step.
            result.put("maxSustainableRate", max);
            result.put("maxSustainableRateCoarse", coarseMax);
            // The offered rates between which the maximum lies: the highest sustained and the lowest
            // unsustained one above it (null when no proxy-made knee was found).
            result.put("maxSustainableBracket", bracket);
            result.put("refined", refine != null && Json.getBool(refine, "used", false));
            result.put("refine", refine);
            result.put("stopReason", stopReason);
            boolean anyOk = steps.stream().anyMatch(st -> Json.getLong(st, "ok", 0) > 0);
            ctx.check(proxy, name(), "steps ran and returned valid responses", !steps.isEmpty() && anyOk,
                    steps.size() + " steps");

            // Optional cross-checks at half the maximum sustainable rate (or the first rate).
            List<Object> cross = new ArrayList<>();
            double crossRate = max != null ? Math.max(1, max / 2) : s.getDouble("sweep-start-rate");
            for (String tool : ExternalTools.available(ctx)) {
                if (tool.equals("h2load")) continue; // Needs h2c: run below on its own proxy.
                cross.add(ExternalTools.run(ctx, tool, proxy, p.port, crossRate, connections, s.getInt("crosscheck-seconds"),
                        "/bytes/" + size, size));
            }
            result.put("crossChecks", cross);
            result.put("series", sampler.toMap());
            result.put("gcEvents", GcLog.toList(p.gcEvents()));
            result.put("proxyState", p.state());
            survival(proxy, p, max == null ? "no step sustained" : "max sustainable " + max + " req/s");
        }
        // h2load needs h2c, which only MicroProxy offers: a separate proxy started with it.
        if (proxy.equals("microproxy") && ExternalTools.available(ctx).contains("h2load")) {
            ProxyProcess.Options o = ProxyProcess.defaults(s);
            try (ProxyProcess p = ProxyProcess.start(ctx, proxy, "h2load", new ProxyProcess.Options(o.idleTimeoutSeconds(),
                    o.heap(), o.direct(), o.cgroupLimit(), true))) {
                Double max = (Double) result.get("maxSustainableRate");
                double crossRate = max != null ? Math.max(1, max / 2) : s.getDouble("sweep-start-rate");
                @SuppressWarnings("unchecked")
                List<Object> cross = (List<Object>) result.get("crossChecks");
                cross.add(ExternalTools.run(ctx, "h2load", proxy, p.port, crossRate, s.getInt("sweep-connections"),
                        s.getInt("crosscheck-seconds"), "/bytes/" + s.getLong("sweep-response-bytes"), -1));
            }
        }
        return result;
    }

    /**
     * Runs one recorded step at {@code rate} and judges it: the load generator's results plus the
     * proxy's resources over the step (its CPU time read from /proc before and after, so the CPU per
     * completed request is exact to the clock tick), {@code sustainable} and, when not, {@code why}.
     */
    private Map<String, Object> step(String proxy, ProxyProcess p, ClientControl client, Sampler sampler, String url, long size,
            double rate, int connections, int stepSeconds, double sloMs, double tolerance) throws Exception {
        double from = sampler.elapsed();
        double upFrom = p.uptime();
        long cpuFrom = ProcStats.cpuMs(p.pid());
        long wallFrom = System.nanoTime();
        Map<String, Object> r = client.call(Json.obj("cmd", "rate", "url", url, "expectLength", size, "rate", rate,
                "connections", connections, "durationMs", stepSeconds * 1000L), timeout(stepSeconds));
        long cpuTo = ProcStats.cpuMs(p.pid());
        long wallTo = System.nanoTime();
        double upTo = p.uptime();
        r.remove("self");
        Map<String, Object> step = new LinkedHashMap<>(r);
        Map<String, Object> resources = new LinkedHashMap<>();
        resources.put("cpuPct", Trend.round(sampler.mean("proxy", "cpuPct", from)));
        long ok = Json.getLong(r, "ok", 0);
        if (cpuFrom >= 0 && cpuTo >= cpuFrom) {
            long cpuMs = cpuTo - cpuFrom;
            resources.put("cpuMs", cpuMs);
            resources.put("cpuWallPct", Trend.round(cpuMs * 1e8 / Math.max(1, wallTo - wallFrom)));
            // Proxy CPU time (user and system, every thread: GC and JIT included) per completed request.
            if (ok > 0) resources.put("cpuUsPerRequest", Trend.round(cpuMs * 1000.0 / ok));
        }
        resources.put("clientCpuPct", Trend.round(sampler.mean("client", "cpuPct", from)));
        resources.put("originCpuPct", Trend.round(sampler.mean("origin", "cpuPct", from)));
        // CPU the machine spent on anything but the proxy, origin and load generator (a shared machine).
        resources.put("foreignCpuPct", Trend.round(sampler.mean(Sampler.SYSTEM, "foreignCpuPct", from)));
        resources.put("gc", GcLog.summary(p.gcEvents(), upFrom, upTo));
        resources.putAll(p.memorySnapshot(false));
        if (p.adminPort > 0) resources.put("microproxyStats", p.adminStats());
        step.put("proxy", resources);

        Map<String, Object> lat = Json.getObject(r, "latencyMs");
        double p99 = Json.getDouble(lat, "p99", Double.MAX_VALUE);
        long attempted = Json.getLong(r, "attempted", 0);
        long errors = Json.getLong(r, "errorCount", 0);
        long intended = Math.max(1, Json.getLong(r, "intended", 1));
        double achieved = Json.getDouble(r, "achievedRate", 0);
        List<String> why = new ArrayList<>();
        if (p99 > sloMs) why.add("p99 " + p99 + " ms > SLO " + sloMs + " ms");
        if (errorRatio(r) > tolerance) why.add("errors " + errors + "/" + attempted);
        if (achieved < 0.95 * rate) why.add("achieved " + achieved + "/s < 95% of " + Math.round(rate) + "/s");
        if (Json.getLong(r, "backlog", 0) > intended / 100) why.add("backlog " + r.get("backlog"));
        boolean saturated = Json.getBool(r, "clientSaturated", false);
        step.put("sustainable", why.isEmpty() && !saturated);
        step.put("why", String.join("; ", why));
        RunContext.log(proxy + " sweep " + Math.round(rate) + "/s: achieved " + achieved + "/s p99 " + p99 + " ms"
                + (resources.get("cpuUsPerRequest") != null ? " cpu " + resources.get("cpuUsPerRequest") + " us/req" : "")
                + (why.isEmpty() ? "" : " (" + String.join("; ", why) + ")") + (saturated ? " [client saturated]" : ""));
        return step;
    }

    private static double errorRatio(Map<String, Object> r) {
        long attempted = Json.getLong(r, "attempted", 0);
        return attempted == 0 ? 1 : (double) Json.getLong(r, "errorCount", 0) / attempted;
    }

    /**
     * Bisects (geometrically) between {@code lo}, the highest sustained offered rate, and {@code hi},
     * the knee's, with recorded steps judged exactly like the sweep's, until the bracket is within
     * {@code sweep-refine-precision} or {@code sweep-refine-steps} probes have run. Each probe follows
     * {@code sweep-refine-settle-seconds} of unrecorded load at the bracket's lower rate, so that like
     * a sweep step it comes after sustained load rather than after an overload. An unsustained probe
     * is repeated up to {@code sweep-knee-confirm - 1} times, and counts as sustained if a repeat is:
     * the same allowance the sweep gives a lone noisy step. Returns every probe, the final bracket and
     * the maximum (the highest sustained achieved rate, never below the coarse one).
     */
    private Map<String, Object> refine(ProxyProcess p, ClientControl client, Sampler sampler, String url, long size,
            int connections, int stepSeconds, double sloMs, double tolerance, int confirm, double lo, double hi,
            double coarseMax, String proxy) throws Exception {
        int maxProbes = s.getInt("sweep-refine-steps");
        double precision = s.getDouble("sweep-refine-precision");
        int settle = s.getInt("sweep-refine-settle-seconds");
        Map<String, Object> out = new LinkedHashMap<>();
        List<Map<String, Object>> probes = new ArrayList<>();
        double best = coarseMax;
        int rounds = 0;
        String stop = null;
        boolean usable = true;
        while (stop == null) {
            if (hi / lo - 1 <= precision) {
                stop = "bracket within " + precision * 100 + "%";
                break;
            }
            if (rounds >= maxProbes) {
                stop = maxProbes == 0 ? "refinement off" : "probe limit (" + maxProbes + ")";
                break;
            }
            rounds++;
            double mid = Math.round(Math.sqrt(lo * hi));
            boolean sustained = false;
            for (int attempt = 1; attempt <= confirm && !sustained; attempt++) {
                if (settle > 0) {
                    client.call(Json.obj("cmd", "rate", "url", url, "expectLength", size, "rate", lo, "connections",
                            connections, "durationMs", settle * 1000L), timeout(settle));
                }
                Map<String, Object> probe = step(proxy, p, client, sampler, url, size, mid, connections, stepSeconds, sloMs, tolerance);
                probe.put("round", rounds);
                probe.put("attempt", attempt);
                probes.add(probe);
                if (!p.alive()) {
                    stop = "proxy " + p.state();
                    usable = false;
                    break;
                }
                if (Json.getBool(probe, "clientSaturated", false)) {
                    stop = "client-bound at " + Math.round(mid) + "/s";
                    usable = false;
                    break;
                }
                if (Json.getBool(probe, "sustainable", false)) {
                    sustained = true;
                    best = Math.max(best, Json.getDouble(probe, "achievedRate", 0));
                }
            }
            if (!usable) break;
            if (sustained) lo = mid;
            else hi = mid;
        }
        RunContext.log(proxy + " sweep refined: sustained " + Math.round(lo) + "/s, not " + Math.round(hi) + "/s (" + stop + ")");
        out.put("used", usable && rounds > 0);
        out.put("low", lo);
        out.put("high", hi);
        out.put("maxSustainableRate", best);
        out.put("rounds", rounds);
        out.put("precision", precision);
        out.put("settleSeconds", settle);
        out.put("stopReason", stop);
        out.put("probes", probes);
        return out;
    }
}
