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
            Map<String, Object> leak = new LinkedHashMap<>();
            // A leak must grow by at least 16 MB and 10% of its own mean, fitting a line (R^2>=0.5).
            leak.put("rssKb", Trend.fit(memSeries, "rssKb", 16 * 1024, 0.10));
            leak.put("heapAfterGcKb", Trend.fit(memSeries, "heapAfterGcKb", 16 * 1024, 0.10));
            leak.put("nmtTotalKb", Trend.fit(memSeries, "nmtTotalKb", 16 * 1024, 0.10));
            leak.put("fds", Trend.fit(memSeries, "fds", 100, 0.20));
            leak.put("threads", Trend.fit(memSeries, "threads", 50, 0.20));
            boolean flagged = false;
            for (Object v : leak.values()) {
                if (v instanceof Map<?, ?> fit && Boolean.TRUE.equals(fit.get("flagged"))) flagged = true;
            }
            result.put("leakCheck", leak);
            result.put("leakSuspected", flagged);
            result.put("totalRequests", requests);
            result.put("totalErrors", errors);
            result.put("windowCount", w);
            result.put("series", sampler.toMap());
            result.put("gcEvents", GcLog.toList(p.gcEvents()));
            result.put("proxyState", p.state());
            ctx.check(proxy, name(), "soak ran its full duration serving requests", p.alive() && requests > 0 && w > 0,
                    "ran " + w + " windows, " + requests + " requests, proxy " + p.state());
        }
        return result;
    }

    private Map<String, Object> memSample(ProxyProcess p, double t) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("t", Trend.round(t));
        m.put("heapAfterGcKb", ctx.jcmd.heapAfterGcKb(p.pid()));
        Map<String, Object> nmt = ctx.jcmd.nmt(p.pid());
        m.put("nmtTotalKb", nmt.get("totalKb"));
        m.put("threadKb", nmt.get("threadKb"));
        m.put("otherKb", nmt.get("otherKb"));
        ProcStats.Sample s = ProcStats.sample(p.pid());
        if (s != null) {
            m.put("rssKb", s.rssKb());
            m.put("fds", s.fds());
            m.put("threads", s.threads());
        }
        return m;
    }
}
