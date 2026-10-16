package org.microproxy.loadtest.scenario;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.microproxy.loadtest.Json;
import org.microproxy.loadtest.client.ClientControl;
import org.microproxy.loadtest.proc.ProcStats;
import org.microproxy.loadtest.proc.Sampler;

/**
 * Fault injection through the origin's built-in Toxiproxy-style relays (see
 * {@link org.microproxy.loadtest.origin.FaultRelay}): added latency, a bandwidth cap, a reset
 * before the first response byte, a reset in mid-body, a stall in mid-body and a blackhole. For
 * each fault the harness sends a batch of requests through the relay and checks that the proxy
 * turns the fault into a sensible outcome (a 5xx, a clean close or a timeout, never a hang past the
 * request timeout) and that it leaks nothing: the relay's open connections return to zero and the
 * proxy's file descriptors and RSS return to the baseline soon after.
 */
final class Faults extends Scenario {

    Faults(RunContext ctx) {
        super(ctx);
    }

    @Override
    String name() {
        return "faults";
    }

    @Override
    Map<String, Object> run(String proxy) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        int idle = s.getInt("fault-idle-timeout");
        ProxyProcess.Options base = ProxyProcess.defaults(s);
        ProxyProcess.Options o = new ProxyProcess.Options(idle, base.heap(), base.direct(), base.cgroupLimit(),
                base.socketsInLimit(), false);
        int count = s.getInt("fault-requests");
        int concurrency = s.getInt("fault-concurrency");
        int timeoutMs = s.getInt("request-timeout-ms");

        try (ProxyProcess p = ProxyProcess.start(ctx, proxy, name(), o);
                ClientControl client = ctx.startClient(proxy + "-" + name(), p.port, List.of());
                Sampler sampler = new Sampler(Map.of("proxy", p.pid(), "origin", ctx.origin.pid(), "client",
                        client.process().pid()), 1000)) {
            result.put("proxyProcess", p.describe());
            result.put("validation", validate(proxy, client));

            // Settle, then record the proxy's idle descriptors and RSS as the no-leak baseline.
            Thread.sleep(1000);
            long baseFds = ProcStats.sample(p.pid()).fds();
            long baseRss = ProcStats.sample(p.pid()).rssKb();
            result.put("baseline", Json.obj("fds", baseFds, "rssKb", baseRss));
            // Heap after a forced GC and NMT before the faults, to check none of them leaves memory behind.
            Map<String, Object> memBefore = p.memorySnapshot(true);
            result.put("memoryBefore", memBefore);

            // name -> [relay, path, longest acceptable ms, what a good proxy does]
            Object[][] faults = {
                {"latency", "latency", "/bytes/1000", (long) (s.getLong("fault-latency-ms") + timeoutMs), "slower, but succeeds"},
                {"bandwidth", "bandwidth", "/bytes/1048576", (long) timeoutMs * 4, "slower, but succeeds"},
                {"reset-before-headers", "reset-before-headers", "/bytes/1000", (long) timeoutMs, "502/504 or a clean error"},
                {"reset-mid-body", "reset-mid-body", "/bytes/1048576", (long) timeoutMs, "truncated or an error, not a hang"},
                {"stall-mid-body", "stall-mid-body", "/bytes/1048576", (long) idle * 1000 + timeoutMs, "times out at the idle timeout"},
                {"blackhole", "blackhole", "/bytes/1000", (long) idle * 1000 + timeoutMs, "times out, not a hang"},
            };
            List<Map<String, Object>> results = new ArrayList<>();
            boolean allBounded = true;
            StringBuilder detail = new StringBuilder();
            for (Object[] f : faults) {
                String relay = (String) f[1];
                String url = ctx.relayUrl(relay, (String) f[2]);
                long limitMs = (Long) f[3];
                double from = sampler.elapsed();
                Map<String, Object> r = client.call(Json.obj("cmd", "requests", "url", url, "count", count, "concurrency",
                        concurrency, "expectStatus", 200, "expectLength", -1, "timeoutMs", timeoutMs + idle * 1000),
                        timeout(limitMs / 1000.0 + 30));
                r.remove("self");

                // Give the proxy its idle timeout to release connections, then check for leaks. A proxy
                // that pools upstream connections (Envoy, Go's transport, Squid) keeps an idle one
                // until that timeout, which is not a leak.
                Thread.sleep(idle * 1000L + 2500);
                Map<String, Object> originStats = originStats();
                long relayOpen = relayOpen(originStats, relay);
                long fdsNow = ProcStats.sample(p.pid()).fds();
                long rssNow = ProcStats.sample(p.pid()).rssKb();
                Map<String, Object> durationMs = Json.getObject(r, "durationMs");
                double maxMs = Json.getDouble(durationMs, "max", 0);
                boolean noHang = maxMs <= limitMs * 1.5 + 2000;
                boolean relayDrained = relayOpen == 0;
                boolean fdsReturned = fdsNow <= baseFds + Math.max(5, concurrency);
                boolean alive = p.alive();
                boolean bounded = noHang && relayDrained && fdsReturned && alive;
                allBounded &= bounded;

                Map<String, Object> step = new LinkedHashMap<>();
                step.put("fault", (String) f[0]);
                step.put("expected", (String) f[4]);
                step.put("outcomes", r.get("outcomes"));
                step.put("statuses", r.get("statuses"));
                step.put("durationMs", durationMs);
                step.put("longestAcceptableMs", limitMs);
                step.put("details", r.get("details"));
                step.put("relayOpenAfter", relayOpen);
                step.put("fdsAfter", fdsNow);
                step.put("fdsBaseline", baseFds);
                step.put("rssAfterKb", rssNow);
                step.put("noHang", noHang);
                step.put("relayDrained", relayDrained);
                step.put("fdsReturned", fdsReturned);
                step.put("proxyAlive", alive);
                step.put("ok", bounded);
                results.add(step);
                if (!bounded) {
                    detail.append(f[0]).append(": ");
                    if (!noHang) detail.append("hung to ").append(maxMs).append(" ms; ");
                    if (!relayDrained) detail.append(relayOpen).append(" relay conns left; ");
                    if (!fdsReturned) detail.append("fds ").append(fdsNow).append(" vs ").append(baseFds).append("; ");
                    if (!alive) detail.append("proxy ").append(p.state()).append("; ");
                }
                String why = (noHang ? "" : "hung to " + Math.round(maxMs) + " ms; ")
                        + (relayDrained ? "" : relayOpen + " relay connections left open; ")
                        + (fdsReturned ? "" : "fds " + fdsNow + " vs baseline " + baseFds + "; ")
                        + (alive ? "" : "proxy " + p.state() + "; ");
                ctx.verdict(proxy, name(), (String) f[0], bounded ? "bounded" : (alive ? "leak-or-hang" : "crashed"), bounded,
                        r.get("outcomes") + ", max " + Math.round(maxMs) + " ms" + (bounded ? "" : "; " + why));
                RunContext.log(proxy + " fault " + f[0] + ": " + r.get("outcomes") + " max " + Math.round(maxMs)
                        + " ms, relay open after " + relayOpen + ", fds " + fdsNow + " (base " + baseFds + ")"
                        + (bounded ? " ok" : " LEAK/HANG"));
                if (!p.alive()) break;
            }
            result.put("faults", results);
            if (p.alive()) {
                Map<String, Object> memAfter = p.memorySnapshot(true);
                result.put("memoryAfter", memAfter);
                if (p.jvm) {
                    long heapDelta = num(memAfter.get("heapAfterGcKb")) - num(memBefore.get("heapAfterGcKb"));
                    long nmtDelta = num(Json.getObject(memAfter, "nmt").get("totalKb"))
                            - num(Json.getObject(memBefore, "nmt").get("totalKb"));
                    // Retained after every fault: more than 16 MB of live heap, or 32 MB of committed memory.
                    boolean retained = heapDelta > 16 * 1024 || nmtDelta > 32 * 1024;
                    ctx.verdict(proxy, name(), "memory", retained ? "memory-retained" : "bounded", !retained,
                            "heap after GC " + (heapDelta >= 0 ? "+" : "") + heapDelta + " KB, NMT total "
                                    + (nmtDelta >= 0 ? "+" : "") + nmtDelta + " KB across the faults");
                } else {
                    // No heap or NMT outside a JVM: RSS retained across the faults, at the same 32 MB bar.
                    long rssDelta = num(memAfter.get("rssKb")) - num(memBefore.get("rssKb"));
                    boolean retained = rssDelta > 32 * 1024;
                    ctx.verdict(proxy, name(), "memory", retained ? "memory-retained" : "bounded", !retained,
                            "RSS " + (rssDelta >= 0 ? "+" : "") + rssDelta + " KB across the faults (heap and NMT n/a)");
                }
            }
            result.put("allBounded", allBounded);
            result.put("series", sampler.toMap());
            result.put("proxyState", p.state());
            // Harness self-check: the faults ran (each one's outcome is a verdict above).
            ctx.check(proxy, name(), "faults ran", !results.isEmpty(), "ran " + results.size() + " faults, proxy " + p.state());
            // The pass condition is that every fault was bounded (no hang, no leak); reported, not a harness check.
            result.put("pass", allBounded);
            result.put("failDetail", detail.toString());
        }
        return result;
    }

    private static long num(Object o) {
        return o instanceof Number n ? n.longValue() : 0;
    }

    private Map<String, Object> originStats() {
        try {
            var c = (java.net.HttpURLConnection) java.net.URI.create(
                    "http://" + ctx.originAddresses.get(0) + ":" + ctx.originPort + "/__stats").toURL()
                    .openConnection(java.net.Proxy.NO_PROXY);
            c.setConnectTimeout(2000);
            c.setReadTimeout(5000);
            try (var in = c.getInputStream()) {
                return Json.parseObject(new String(in.readAllBytes()));
            }
        } catch (Exception e) {
            return Map.of();
        }
    }

    private static long relayOpen(Map<String, Object> originStats, String relay) {
        return Json.getLong(Json.getObject(Json.getObject(originStats, "relays"), relay), "open", -1);
    }
}
