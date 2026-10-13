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
 * Memory under adversarial clients: the proxy is started with its memory capped (a small heap and
 * direct-memory ceiling, and a cgroup limit where the machine allows one), then each workload from
 * {@link org.microproxy.loadtest.client.MemoryWorkloads} runs against it while the harness samples
 * RSS, NMT (total, heap, thread and other/direct) and the heap after a forced GC every second or
 * two. A normal client probes throughout, so the scenario also sees whether the proxy keeps serving
 * or sheds load under pressure. The pass condition is <em>bounded</em> (memory levels off within the
 * cap) or <em>shedding</em> (the proxy refuses or closes the adversarial connections and stays up);
 * an out-of-memory or a crash fails. Heap alone is misleading here — virtual-thread stacks sit on
 * the heap while direct buffers do not — so the outcome is read from RSS and NMT total, with heap
 * shown alongside.
 */
final class MemoryUnderAttack extends Scenario {

    MemoryUnderAttack(RunContext ctx) {
        super(ctx);
    }

    @Override
    String name() {
        return "memory";
    }

    @Override
    Map<String, Object> run(String proxy) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        List<Map<String, Object>> attacks = new ArrayList<>();
        int seconds = s.getInt("attack-seconds");
        int sampleEvery = Math.max(1, s.getInt("nmt-every-seconds"));
        int probeRate = s.getInt("attack-probe-rate");
        List<String> names = s.getList("attacks");

        for (String attack : names) {
            boolean h2c = attack.equals("rapidreset");
            if (h2c && !proxy.equals("microproxy")) {
                attacks.add(Json.obj("attack", attack, "skipped", "LittleProxy serves HTTP/1 only; no h2c for rapid reset"));
                continue;
            }
            ProxyProcess.Options o = new ProxyProcess.Options(s.getInt("idle-timeout"), s.get("attack-heap"),
                    s.get("attack-direct"), s.get("attack-cgroup-limit"), h2c);
            try (ProxyProcess p = ProxyProcess.start(ctx, proxy, name() + "-" + attack, o);
                    ClientControl attacker = ctx.startClient(proxy + "-" + name() + "-" + attack, p.port, List.of());
                    ClientControl prober = ctx.startClient(proxy + "-" + name() + "-" + attack + "-probe", p.port, List.of());
                    Sampler sampler = new Sampler(Map.of("proxy", p.pid(), "client", attacker.process().pid()), 1000)) {
                if (attacks.isEmpty()) result.put("validation", validate(proxy, prober));
                Map<String, Object> cap = Json.obj("heap", o.heap(), "direct", o.direct(), "cgroupLimit",
                        o.cgroupLimit().isBlank() ? null : o.cgroupLimit(), "cgroup", p.cgroupProcs == null ? null
                                : p.cgroupProcs.getParent().toString());
                Map<String, Object> baseline = p.memorySnapshot(true);
                long baseRss = ProcStats.sample(p.pid()).rssKb();

                Map<String, Object> cmd = attackCommand(attack, p, probeUrl(0));
                attacker.call(cmd, timeout(10));

                List<Map<String, Object>> mem = new ArrayList<>();
                List<Map<String, Object>> probes = new ArrayList<>();
                long start = System.nanoTime();
                String crash = null;
                while ((System.nanoTime() - start) / 1e9 < seconds) {
                    Thread.sleep(sampleEvery * 1000L);
                    double t = (System.nanoTime() - start) / 1e9;
                    if (!p.alive()) {
                        crash = "proxy " + p.state();
                        break;
                    }
                    mem.add(memSample(p, t));
                    // A normal client, to see whether the proxy still serves honest requests.
                    Map<String, Object> probe = prober.call(Json.obj("cmd", "requests", "url", probeUrl(0), "count",
                            probeRate, "concurrency", Math.max(1, probeRate / 2), "expectStatus", 200, "expectLength", 64L,
                            "timeoutMs", 5000), timeout(10));
                    probe.remove("self");
                    probes.add(Json.obj("t", Trend.round(t), "outcomes", probe.get("outcomes"), "durationMs", probe.get("durationMs")));
                }
                Map<String, Object> attackFinal = attacker.call(Json.obj("cmd", "attackStop", "attack", attack), timeout(30));
                attackFinal.remove("self");
                if (p.alive()) mem.add(memSample(p, (System.nanoTime() - start) / 1e9));

                String outcome = classify(mem, probes, p, baseRss, o);
                Map<String, Object> rec = new LinkedHashMap<>();
                rec.put("attack", attack);
                rec.put("cap", cap);
                rec.put("baseline", baseline);
                rec.put("workload", attackFinal);
                rec.put("memSeries", mem);
                rec.put("probes", probes);
                rec.put("peakRssKb", peak(mem, "rssKb"));
                rec.put("peakNmtTotalKb", peak(mem, "nmtTotalKb"));
                rec.put("peakHeapAfterGcKb", peak(mem, "heapAfterGcKb"));
                rec.put("peakOtherKb", peak(mem, "otherKb"));
                rec.put("rssGrowthKb", growth(mem, "rssKb"));
                rec.put("outcome", outcome);
                rec.put("pass", outcome.equals("bounded") || outcome.equals("shedding"));
                rec.put("proxyState", p.state());
                rec.put("series", sampler.toMap());
                rec.put("gcEvents", GcLog.toList(p.gcEvents()));
                if (crash != null) rec.put("crash", crash);
                attacks.add(rec);
                RunContext.log(proxy + " memory/" + attack + ": " + outcome + ", peak RSS " + peak(mem, "rssKb")
                        + " KB, peak NMT " + peak(mem, "nmtTotalKb") + " KB, proxy " + p.state());
                ctx.check(proxy, name(), attack + " ran and the proxy survived (bounded or shedding)",
                        rec.get("pass").equals(Boolean.TRUE), outcome + "; proxy " + p.state());
            }
        }
        result.put("attacks", attacks);
        boolean anyRan = attacks.stream().anyMatch(a -> !a.containsKey("skipped"));
        ctx.check(proxy, name(), "at least one memory workload ran", anyRan, attacks.size() + " workloads");
        return result;
    }

    private String probeUrl(int i) {
        return ctx.originUrl(i, "/bytes/64");
    }

    private Map<String, Object> attackCommand(String attack, ProxyProcess p, String probe) {
        Map<String, Object> cmd = Json.obj("cmd", "attackStart", "attack", attack);
        switch (attack) {
            case "slowloris" -> {
                cmd.put("connections", s.getInt("slowloris-connections"));
                cmd.put("intervalMs", s.getInt("slowloris-interval-ms"));
            }
            case "slowread" -> {
                cmd.put("connections", s.getInt("slowread-connections"));
                cmd.put("url", ctx.originUrl(0, "/bytes/" + s.getLong("slowread-bytes")));
                cmd.put("rate", s.getLong("slowread-rate"));
            }
            case "updown" -> {
                cmd.put("connections", s.getInt("updown-connections"));
                cmd.put("downUrl", ctx.originUrl(0, "/bytes/" + s.getLong("updown-bytes")));
                cmd.put("upUrl", ctx.originUrl(0, "/upload"));
                cmd.put("bytes", s.getLong("updown-bytes"));
            }
            case "rapidreset" -> {
                cmd.put("connections", s.getInt("rapidreset-connections"));
                cmd.put("authority", ctx.originAddresses.get(0) + ":" + ctx.originPort);
                cmd.put("path", "/bytes/1024");
            }
            default -> throw new IllegalArgumentException(attack);
        }
        return cmd;
    }

    /**
     * bounded: alive, RSS within the cap and not still climbing at the end; shedding: alive but the
     * probe failed a lot (the proxy refused honest requests too) or it kept closing attack
     * connections; oom/crashed otherwise.
     */
    private String classify(List<Map<String, Object>> mem, List<Map<String, Object>> probes, ProxyProcess p, long baseRss,
            ProxyProcess.Options o) {
        if (p.oom()) return "oom";
        if (!p.alive()) return "crashed";
        if (mem.size() < 2) return "inconclusive";
        // Rising to the end: the last sample is the peak and still climbing.
        long last = toLong(mem.get(mem.size() - 1).get("rssKb"));
        long prev = toLong(mem.get(mem.size() - 2).get("rssKb"));
        long peakRss = peak(mem, "rssKb");
        boolean stillClimbing = last >= peakRss && last - prev > 8 * 1024;
        long probeTotal = 0;
        long probeOk = 0;
        for (Map<String, Object> pr : probes) {
            Map<String, Object> out = Json.getObject(pr, "outcomes");
            probeOk += Json.getLong(out, "OK", 0);
            for (Object v : out.values()) if (v instanceof Number n) probeTotal += n.longValue();
        }
        boolean serving = probeTotal == 0 || probeOk >= probeTotal * 0.5;
        if (!serving) return "shedding";
        if (stillClimbing) return "unbounded-growth";
        return "bounded";
    }

    private Map<String, Object> memSample(ProxyProcess p, double t) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("t", Trend.round(t));
        m.put("heapAfterGcKb", ctx.jcmd.heapAfterGcKb(p.pid()));
        Map<String, Object> nmt = ctx.jcmd.nmt(p.pid());
        m.put("nmtTotalKb", nmt.get("totalKb"));
        m.put("heapKb", nmt.get("heapKb"));
        m.put("threadKb", nmt.get("threadKb"));
        m.put("otherKb", nmt.get("otherKb"));
        ProcStats.Sample sm = ProcStats.sample(p.pid());
        if (sm != null) {
            m.put("rssKb", sm.rssKb());
            m.put("fds", sm.fds());
            m.put("threads", sm.threads());
        }
        return m;
    }

    private static long peak(List<Map<String, Object>> mem, String key) {
        long max = -1;
        for (Map<String, Object> m : mem) max = Math.max(max, toLong(m.get(key)));
        return max;
    }

    private static long growth(List<Map<String, Object>> mem, String key) {
        if (mem.isEmpty()) return 0;
        return toLong(mem.get(mem.size() - 1).get(key)) - toLong(mem.get(0).get(key));
    }

    private static long toLong(Object o) {
        return o instanceof Number n ? n.longValue() : -1;
    }
}
