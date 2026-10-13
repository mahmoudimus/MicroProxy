package org.microproxy.loadtest.scenario;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.microproxy.loadtest.Json;
import org.microproxy.loadtest.client.ClientControl;
import org.microproxy.loadtest.proc.Environment;
import org.microproxy.loadtest.proc.ProcStats;
import org.microproxy.loadtest.proc.Sampler;

/**
 * The connection ramp: idle keep-alive connections opened in steps (1k, 5k, 10k, ...). At each step
 * it records the proxy's RSS, NMT committed memory (total, heap, thread and other), the heap in use
 * after a forced GC, the file-descriptor and thread counts and the setup rate, and runs a small
 * active probe to measure latency while the idle connections are held. It climbs until a step's
 * connections cannot be opened, recording how it failed: refused cleanly, accepted but unresponsive
 * (the probe stops working), or the proxy crashed or ran out of memory. Memory per idle connection
 * is the slope of RSS and of NMT total against the connection count, which separates the proxy's
 * fixed cost from its cost per connection.
 */
final class ConnectionRamp extends Scenario {

    ConnectionRamp(RunContext ctx) {
        super(ctx);
    }

    @Override
    String name() {
        return "ramp";
    }

    @Override
    Map<String, Object> run(String proxy) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        List<Integer> targets = new ArrayList<>();
        for (String t : s.getList("ramp-steps")) targets.add((int) org.microproxy.loadtest.Settings.bytes(t));
        int maxTarget = targets.isEmpty() ? 0 : targets.get(targets.size() - 1);

        // Enough source and origin addresses for the biggest step, under each address's ephemeral ports.
        int perSource = Math.min(s.getInt("ramp-per-source"), Math.max(1000, Environment.ephemeralPorts() - 2000));
        int sourceCount = Math.max(1, (int) Math.ceil((double) maxTarget / perSource));
        List<String> sources = RunContext.sourceAddresses(sourceCount);
        boolean warm = s.getBool("ramp-warm");
        // Warming also holds a proxy-to-origin connection per client connection; spread the origin too.
        int originAddrs = warm ? Math.max(ctx.originAddresses.size(), Math.min(sourceCount, 1 + maxTarget / perSource)) : 1;

        Map<String, Object> osLimits = Json.getObject(ctx.environment, "limits");
        long clientNofile = ProcStats.maxOpenFiles(ProcessHandle.current().pid());
        result.put("osLimits", osLimits);
        result.put("sourceAddresses", sources);
        result.put("perSource", perSource);
        result.put("warmed", warm);
        List<String> ceilings = new ArrayList<>();
        ceilings.add("client file descriptors (ulimit -n = " + osLimits.get("nofile") + ")");
        ceilings.add("source addresses x ephemeral ports = " + sources.size() + " x " + perSource + " = " + (long) sources.size() * perSource);
        result.put("clientCeilings", ceilings);

        ProxyProcess.Options base = ProxyProcess.defaults(s);
        ProxyProcess.Options o = new ProxyProcess.Options(s.getInt("ramp-idle-timeout"), base.heap(), base.direct(),
                base.cgroupLimit(), false);
        try (ProxyProcess p = ProxyProcess.start(ctx, proxy, name(), o);
                ClientControl client = ctx.startClient(proxy + "-" + name(), p.port, sources);
                ClientControl prober = ctx.startClient(proxy + "-" + name() + "-probe", p.port, List.of());
                Sampler sampler = new Sampler(Map.of("proxy", p.pid(), "client", client.process().pid()), 1000)) {
            result.put("proxyProcess", p.describe());
            result.put("validation", validate(proxy, prober));
            Map<String, Object> baseline = p.memorySnapshot(true);
            result.put("baseline", baseline);
            long baseRss = ProcStats.sample(p.pid()).rssKb();

            List<Map<String, Object>> steps = new ArrayList<>();
            List<String> warmUrls = new ArrayList<>();
            if (warm) for (int i = 0; i < originAddrs; i++) warmUrls.add(ctx.originUrl(i, "/bytes/64"));
            long held = 0;
            String failure = null;
            String failureKind = null;
            long maxFailures = Math.max(50, (long) (s.getDouble("ramp-failure-threshold") * maxTarget));
            for (int target : targets) {
                int add = (int) (target - held);
                if (add <= 0) continue;
                double from = sampler.elapsed();
                Map<String, Object> open = client.call(Json.obj("cmd", "hold", "count", add, "parallel",
                        s.getInt("ramp-parallel"), "warmUrls", warm ? warmUrls : List.of(), "expectLength", 64L,
                        "maxFailures", maxFailures), timeout(Math.max(60, add / 200.0)));
                open.remove("self");
                held = Json.getLong(open, "held", held);

                // Probe latency while the idle connections are held.
                Map<String, Object> probe = prober.call(Json.obj("cmd", "requests", "url", ctx.originUrl(0, "/bytes/64"),
                        "count", s.getInt("ramp-probe-rate") * s.getInt("ramp-probe-seconds"), "concurrency",
                        s.getInt("ramp-probe-rate"), "expectStatus", 200, "expectLength", 64L), timeout(s.getInt("ramp-probe-seconds") + 20));
                probe.remove("self");

                Map<String, Object> mem = p.memorySnapshot(true);
                Map<String, Object> step = new LinkedHashMap<>();
                step.put("target", target);
                step.put("held", held);
                step.put("setupRate", open.get("setupRate"));
                step.put("open", open);
                step.put("memory", mem);
                step.put("rssPerConnKb", held > 0 ? Trend.round((toLong(mem.get("rssKb")) - baseRss) / (double) held) : 0.0);
                step.put("nmtTotalPerConnKb", held > 0 ? perConn(baseline, mem, held) : 0.0);
                step.put("probe", Json.obj("outcomes", probe.get("outcomes"), "durationMs", probe.get("durationMs"),
                        "statuses", probe.get("statuses"), "details", probe.get("details")));
                if (p.adminPort > 0) step.put("microproxyStats", p.adminStats());
                steps.add(step);

                long probeOk = Json.getLong(Json.getObject(probe, "outcomes"), "OK", 0);
                long probeTotal = Json.getLong(probe, "count", 1);
                RunContext.log(proxy + " ramp " + target + ": held " + held + ", RSS " + mem.get("rssKb") + " KB, fds "
                        + mem.get("fds") + ", probe " + probeOk + "/" + probeTotal + " ok");

                String clientLimit = Json.getString(open, "clientLimit", null);
                if (clientLimit != null) {
                    failure = "client limit before the proxy's: " + clientLimit;
                    failureKind = "client-bound";
                    break;
                }
                long failedOpen = Json.getLong(open, "failed", 0);
                if (!p.alive()) {
                    failure = "proxy " + p.state() + " at " + held + " connections";
                    failureKind = p.oom() ? "oom" : "crashed";
                    break;
                }
                if (probeOk == 0 && probeTotal > 0) {
                    failure = "accepted but unresponsive: the probe got no response at " + held + " connections";
                    failureKind = "unresponsive";
                    break;
                }
                if (failedOpen > maxFailures) {
                    boolean refused = Json.getObject(open, "errors").containsKey("CONNECT_REFUSED");
                    failure = failedOpen + " of " + add + " connections failed at " + held + " held ("
                            + Json.getObject(open, "errors") + ")";
                    failureKind = refused ? "refused" : "errors";
                    break;
                }
            }
            result.put("steps", steps);
            result.put("maxConnectionsHeld", held);
            result.put("failure", failure);
            result.put("failureKind", failureKind == null ? "limit not reached" : failureKind);
            result.put("perConnection", perConnectionFit(steps, baseRss, baseline));
            boolean stepsRan = !steps.isEmpty();
            ctx.check(proxy, name(), "ramp opened connections and probed them", stepsRan && held > 0,
                    "held up to " + held + (failure != null ? "; stopped: " + failure : ""));
            result.put("series", sampler.toMap());
            result.put("proxyState", p.state());
            result.put("clientNofile", clientNofile);
        }
        return result;
    }

    private static long toLong(Object o) {
        return o instanceof Number n ? n.longValue() : -1;
    }

    private static double perConn(Map<String, Object> baseline, Map<String, Object> mem, long held) {
        long base = toLong(Json.getObject(baseline, "nmt").get("totalKb"));
        long now = toLong(Json.getObject(mem, "nmt").get("totalKb"));
        return base < 0 || now < 0 ? 0 : Trend.round((now - base) / (double) held);
    }

    /** Fits RSS, NMT total, heap-after-GC and threads against the connection count. */
    private static Map<String, Object> perConnectionFit(List<Map<String, Object>> steps, long baseRss,
            Map<String, Object> baseline) {
        List<Map<String, Object>> points = new ArrayList<>();
        for (Map<String, Object> step : steps) {
            Map<String, Object> mem = Json.getObject(step, "memory");
            Map<String, Object> nmt = Json.getObject(mem, "nmt");
            points.add(Json.obj("t", ((Number) step.get("held")).doubleValue(), "rssKb", mem.get("rssKb"), "nmtTotalKb",
                    nmt.get("totalKb"), "heapAfterGcKb", mem.get("heapAfterGcKb"), "threadKb", nmt.get("threadKb"),
                    "otherKb", nmt.get("otherKb"), "threads", mem.get("threads"), "fds", mem.get("fds")));
        }
        Map<String, Object> m = new LinkedHashMap<>();
        for (String key : List.of("rssKb", "nmtTotalKb", "heapAfterGcKb", "threadKb", "otherKb", "threads", "fds")) {
            Map<String, Object> fit = Trend.fit(points, key, 0, 0);
            m.put(key + "PerConn", fit.get("slopePerS"));
        }
        return m;
    }
}
