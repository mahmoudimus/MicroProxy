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
 * The soak: a fixed moderate rate held for a configured duration, tracking RSS, the heap after a
 * forced GC, file descriptors and threads over time. A least-squares slope through each series
 * (see {@link Trend}) flags monotonic growth as a possible leak: a heap-after-GC or RSS line that
 * climbs steadily and grows by a meaningful amount over the run. Short windows keep the latency
 * series so a slow drift in latency shows too.
 */
final class Soak extends Scenario {

    Soak(RunContext ctx) {
        super(ctx);
    }

    @Override
    String name() {
        return "soak";
    }

    @Override
    Map<String, Object> run(String proxy) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        int connections = s.getInt("soak-connections");
        double rate = s.getDouble("soak-rate");
        int total = s.getInt("soak-seconds");
        int window = Math.max(1, s.getInt("soak-window-seconds"));
        int sampleEvery = Math.max(window, s.getInt("soak-sample-seconds"));
        long size = 1024;
        String url = ctx.originUrl(0, "/bytes/" + size);

        try (ProxyProcess p = ProxyProcess.start(ctx, proxy, name(), ProxyProcess.defaults(s));
                ClientControl client = ctx.startClient(proxy + "-" + name(), p.port, List.of());
                Sampler sampler = new Sampler(Map.of("proxy", p.pid(), "origin", ctx.origin.pid(), "client",
                        client.process().pid()), 1000)) {
            result.put("proxyProcess", p.describe());
            result.put("validation", validate(proxy, client));
            result.put("rate", rate);
            result.put("connections", connections);
            result.put("seconds", total);

            // Warm up, then take the baseline after a forced GC.
            client.call(Json.obj("cmd", "rate", "url", url, "expectLength", size, "rate", rate, "connections", connections,
                    "durationMs", (long) Math.min(5, total) * 1000), timeout(5));
            List<Map<String, Object>> memSeries = new ArrayList<>();
            List<Map<String, Object>> windows = new ArrayList<>();
            memSeries.add(memSample(p, 0));

            long startNanos = System.nanoTime();
            long errors = 0;
            long requests = 0;
            int w = 0;
            double lastSample = 0;
            while ((System.nanoTime() - startNanos) / 1e9 < total && p.alive()) {
                double elapsed = (System.nanoTime() - startNanos) / 1e9;
                int dur = (int) Math.min(window, Math.ceil(total - elapsed));
                if (dur <= 0) break;
                Map<String, Object> r = client.call(Json.obj("cmd", "rate", "url", url, "expectLength", size, "rate", rate,
                        "connections", connections, "durationMs", dur * 1000L), timeout(dur));
                r.remove("self");
                Map<String, Object> win = new LinkedHashMap<>();
                win.put("t", Trend.round((System.nanoTime() - startNanos) / 1e9));
                win.put("achievedRate", r.get("achievedRate"));
                win.put("errorCount", r.get("errorCount"));
                win.put("latencyMs", Json.getObject(r, "latencyMs"));
                win.put("clientSaturated", r.get("clientSaturated"));
                windows.add(win);
                errors += Json.getLong(r, "errorCount", 0);
                requests += Json.getLong(r, "ok", 0);
                double now = (System.nanoTime() - startNanos) / 1e9;
                if (now - lastSample >= sampleEvery) {
                    memSeries.add(memSample(p, now));
                    lastSample = now;
                    RunContext.log(proxy + " soak " + Math.round(now) + "/" + total + "s: RSS "
                            + memSeries.get(memSeries.size() - 1).get("rssKb") + " KB, heap after GC "
                            + memSeries.get(memSeries.size() - 1).get("heapAfterGcKb") + " KB");
                }
                w++;
            }
            if (p.alive()) memSeries.add(memSample(p, (System.nanoTime() - startNanos) / 1e9));

            result.put("windows", windows);
            result.put("memSeries", memSeries);
            // The first fifth of the soak (at least 30 s) is warm-up: pools fill and the JIT settles.
            double warmup = Math.max(30, total * 0.2);
            List<Map<String, Object>> leakWindow = Trend.after(memSeries, warmup);
            boolean conclusive = leakWindow.size() >= 6 && Trend.span(leakWindow) >= 60;
            Map<String, Object> leak = new LinkedHashMap<>();
            // A leak must grow by at least 16 MB and 10% of its own mean, along a line with R^2 >= 0.8.
            leak.put("rssKb", Trend.fit(leakWindow, "rssKb", 16 * 1024, 0.10, 0.8));
            leak.put("heapAfterGcKb", Trend.fit(leakWindow, "heapAfterGcKb", 16 * 1024, 0.10, 0.8));
            leak.put("nmtTotalKb", Trend.fit(leakWindow, "nmtTotalKb", 16 * 1024, 0.10, 0.8));
            leak.put("fds", Trend.fit(leakWindow, "fds", 100, 0.20, 0.8));
            leak.put("threads", Trend.fit(leakWindow, "threads", 50, 0.20, 0.8));
            List<String> flaggedKeys = new ArrayList<>();
            for (Map.Entry<String, Object> e : leak.entrySet()) {
                if (e.getValue() instanceof Map<?, ?> fit && Boolean.TRUE.equals(fit.get("flagged"))) flaggedKeys.add(e.getKey());
            }
            boolean flagged = conclusive && !flaggedKeys.isEmpty();
            result.put("leakWarmupS", warmup);
            result.put("leakWindowConclusive", conclusive);
            result.put("leakCheck", leak);
            result.put("leakSuspected", flagged);
            if (!p.alive()) {
                ctx.verdict(proxy, name(), "leak", p.oom() ? "oom" : "crashed", false, "proxy " + p.state());
            } else if (!conclusive) {
                ctx.verdict(proxy, name(), "leak", "inconclusive", null, "window too short for a leak check: "
                        + leakWindow.size() + " samples over " + Trend.round(Trend.span(leakWindow)) + " s after a "
                        + Trend.round(warmup) + " s warm-up; needs 6 over 60 s");
            } else {
                ctx.verdict(proxy, name(), "leak", flagged ? "possible-leak" : "no-leak", !flagged,
                        flagged ? "steady growth in " + flaggedKeys : "no series grew steadily");
            }
            result.put("totalRequests", requests);
            result.put("totalErrors", errors);
            result.put("windowCount", w);
            result.put("series", sampler.toMap());
            result.put("gcEvents", GcLog.toList(p.gcEvents()));
            result.put("proxyState", p.state());
            // Harness self-check: the soak ran and memory was sampled (the proxy's survival is a verdict above).
            ctx.check(proxy, name(), "soak ran and memory was sampled", w > 0 && !memSeries.isEmpty(),
                    "ran " + w + " windows, " + requests + " requests, " + memSeries.size() + " memory samples");
        }
        return result;
    }

    private Map<String, Object> memSample(ProxyProcess p, double t) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("t", Trend.round(t));
        if (p.jvm) {
            m.put("heapAfterGcKb", ctx.jcmd.heapAfterGcKb(p.pid()));
            Map<String, Object> nmt = ctx.jcmd.nmt(p.pid());
            m.put("nmtTotalKb", nmt.get("totalKb"));
            m.put("threadKb", nmt.get("threadKb"));
            m.put("otherKb", nmt.get("otherKb"));
        }
        ProcStats.Sample s = ProcStats.sample(p.pid());
        if (s != null) {
            m.put("rssKb", s.rssKb());
            m.put("fds", s.fds());
            m.put("threads", s.threads());
        }
        return m;
    }
}
