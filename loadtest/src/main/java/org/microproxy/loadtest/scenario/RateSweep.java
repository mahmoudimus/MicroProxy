package org.microproxy.loadtest.scenario;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.microproxy.loadtest.Json;
import org.microproxy.loadtest.client.ClientControl;
import org.microproxy.loadtest.proc.GcLog;
import org.microproxy.loadtest.proc.Sampler;

/**
 * The rate sweep: open-loop load over keep-alive connections with small responses, the rate
 * multiplied at each step, to find the knee. A step is sustainable when its p99 is within the SLO,
 * its error ratio within the tolerance, it achieved at least 95% of its target rate and left
 * almost nothing unsent; the knee is the first step that is not, and the maximum sustainable rate
 * is the achieved rate of the last step before it. A step where the load generator could not keep
 * its own schedule ends the sweep as client-bound: its numbers say nothing about the proxy.
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
            for (int i = 0; i < s.getInt("sweep-max-steps") && rate <= s.getDouble("sweep-max-rate"); i++) {
                double from = sampler.elapsed();
                double upFrom = p.uptime();
                Map<String, Object> r = client.call(Json.obj("cmd", "rate", "url", url, "expectLength", size, "rate", rate,
                        "connections", connections, "durationMs", stepSeconds * 1000L), timeout(stepSeconds));
                double upTo = p.uptime();
                r.remove("self");
                Map<String, Object> step = new LinkedHashMap<>(r);
                Map<String, Object> resources = new LinkedHashMap<>();
                resources.put("cpuPct", Trend.round(sampler.mean("proxy", "cpuPct", from)));
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
                double errorRatio = attempted == 0 ? 1 : (double) errors / attempted;
                double achieved = Json.getDouble(r, "achievedRate", 0);
                List<String> why = new ArrayList<>();
                if (p99 > sloMs) why.add("p99 " + p99 + " ms > SLO " + sloMs + " ms");
                if (errorRatio > tolerance) why.add("errors " + errors + "/" + attempted);
                if (achieved < 0.95 * rate) why.add("achieved " + achieved + "/s < 95% of " + Math.round(rate) + "/s");
                if (Json.getLong(r, "backlog", 0) > intended / 100) why.add("backlog " + r.get("backlog"));
                boolean saturated = Json.getBool(r, "clientSaturated", false);
                step.put("sustainable", why.isEmpty() && !saturated);
                step.put("why", String.join("; ", why));
                steps.add(step);
                RunContext.log(proxy + " sweep " + Math.round(rate) + "/s: achieved " + achieved + "/s p99 " + p99 + " ms"
                        + (why.isEmpty() ? "" : " (" + String.join("; ", why) + ")") + (saturated ? " [client saturated]" : ""));
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
                if (knee == null && !why.isEmpty()) {
                    knee = i;
                    kneeReason = String.join("; ", why);
                }
                if (knee != null && i - knee >= afterKnee) {
                    stopReason = "past the knee";
                    break;
                }
                if (errorRatio > 0.5) {
                    stopReason = "more than half the requests failed";
                    break;
                }
                rate *= s.getDouble("sweep-factor");
            }
            Double max = null;
            int lastGood = (knee == null ? steps.size() : knee) - 1;
            if (lastGood >= 0) max = Json.getDouble(steps.get(lastGood), "achievedRate", 0);
            result.put("sloP99Ms", sloMs);
            result.put("errorTolerance", tolerance);
            result.put("connections", connections);
            result.put("responseBytes", size);
            result.put("steps", steps);
            result.put("kneeStep", knee);
            result.put("kneeReason", kneeReason);
            result.put("kneeFound", knee != null);
            result.put("maxSustainableRate", max);
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
}
