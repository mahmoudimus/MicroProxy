package org.microproxy.loadtest.scenario;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.microproxy.loadtest.Json;
import org.microproxy.loadtest.client.ClientControl;
import org.microproxy.loadtest.proc.Environment;
import org.microproxy.loadtest.proc.GcLog;
import org.microproxy.loadtest.proc.ProcStats;
import org.microproxy.loadtest.proc.Sampler;

/**
 * Memory under adversarial clients: the proxy is started with its memory capped (a small heap and
 * direct-memory ceiling, and a cgroup limit where the machine allows one), then each workload from
 * {@link org.microproxy.loadtest.client.MemoryWorkloads} runs against it while the harness samples
 * RSS, NMT (total, heap, thread and other/direct) and the heap after a forced GC every second or
 * two. A normal client probes throughout, so the scenario also sees whether the proxy keeps serving
 * under pressure. Each workload gets a verdict on the proxy (see {@link #classify}): <em>bounded</em>
 * or <em>shedding</em> pass; <em>unbounded-growth</em>, an out-of-memory or a crash fail; and a
 * window too short to tell growth from warm-up (the smoke preset's) is <em>inconclusive</em>, which
 * is reported but never fails a run. Heap alone is misleading here — virtual-thread stacks sit on
 * the heap while direct buffers do not — so growth is read from RSS and NMT total, with heap and
 * NMT "other" (direct memory) shown alongside.
 *
 * <p>The cgroup's TCP socket buffers (cgroup v2 charges them to it) are measured beside the proxy's
 * own memory. By default ({@code attack-cgroup-sockets=exclude}) the limit holds the proxy's own
 * memory only: how much a slow client leaves in the kernel's buffers is set mostly by the kernel,
 * and with a few hundred slow readers the buffers alone can fill a limit sized for the proxy.
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
            ExternalProxy ext = ctx.externals.get(proxy);
            String unsupported = ext == null ? null : ext.unsupportedReason(name() + "/" + attack);
            if (unsupported == null && h2c && !proxy.equals("microproxy")) {
                unsupported = proxy.equals("littleproxy") ? "LittleProxy serves HTTP/1 only; no h2c for rapid reset"
                        : "not configured for h2c in this harness; no h2c for rapid reset";
            }
            if (unsupported != null) {
                attacks.add(Json.obj("attack", attack, "skipped", unsupported));
                ctx.verdict(proxy, name(), attack, "not-applicable", null, unsupported);
                continue;
            }
            ProxyProcess.Options o = new ProxyProcess.Options(s.getInt("idle-timeout"), s.get("attack-heap"),
                    s.get("attack-direct"), s.get("attack-cgroup-limit"), s.get("attack-cgroup-sockets").equals("include"), h2c);
            try (ProxyProcess p = ProxyProcess.start(ctx, proxy, name() + "-" + attack, o);
                    ClientControl attacker = ctx.startClient(proxy + "-" + name() + "-" + attack, p.port, List.of());
                    ClientControl prober = ctx.startClient(proxy + "-" + name() + "-" + attack + "-probe", p.port, List.of());
                    Sampler sampler = new Sampler(Map.of("proxy", p.pid(), "client", attacker.process().pid()), 1000)) {
                if (attacks.isEmpty()) result.put("validation", validate(proxy, prober));
                // The heap and direct-memory caps are JVM flags; an external proxy has only the cgroup.
                Map<String, Object> cap = Json.obj("heap", p.jvm ? o.heap() : null, "direct", p.jvm ? o.direct() : null, "cgroupLimit",
                        o.cgroupLimit().isBlank() ? null : o.cgroupLimit(), "cgroup", p.cgroupProcs == null ? null
                                : p.cgroupProcs.getParent().toString(), "socketBuffers", p.cgroupProcs == null ? null
                                : o.socketsInLimit() ? "in the limit" : "beside the limit");
                Map<String, Object> baseline = p.memorySnapshot(true);

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
                // After the workload ends: shown, but not part of the growth fit (its connections are gone).
                Map<String, Object> afterStop = p.alive() ? memSample(p, (System.nanoTime() - start) / 1e9) : Map.of();

                Map<String, Object> judged = classify(attack, mem, probes, attackFinal, p, seconds);
                String outcome = (String) judged.get("verdict");
                Boolean pass = (Boolean) judged.get("pass");
                Map<String, Object> rec = new LinkedHashMap<>();
                rec.put("attack", attack);
                rec.put("cap", cap);
                rec.put("baseline", baseline);
                rec.put("workload", attackFinal);
                rec.put("memSeries", mem);
                rec.put("afterStop", afterStop);
                rec.put("judgement", judged);
                rec.put("probes", probes);
                rec.put("peakRssKb", peak(mem, "rssKb"));
                rec.put("peakNmtTotalKb", peak(mem, "nmtTotalKb"));
                rec.put("peakHeapAfterGcKb", peak(mem, "heapAfterGcKb"));
                rec.put("peakOtherKb", peak(mem, "otherKb"));
                // The cgroup's own memory and socket buffers, from the watch's 100 ms polls where it ran.
                rec.put("peakCgroupOwnKb", p.watch != null ? p.watch.peakOwnKb() : peak(mem, "cgroupOwnKb"));
                rec.put("peakSockKb", p.watch != null ? Math.max(p.watch.peakSockKb(), peak(mem, "sockKb")) : peak(mem, "sockKb"));
                rec.put("rssGrowthKb", growth(mem, "rssKb"));
                rec.put("outcome", outcome);
                rec.put("pass", pass);
                rec.put("proxyState", p.state());
                rec.put("series", sampler.toMap());
                rec.put("gcEvents", GcLog.toList(p.gcEvents()));
                if (crash != null) rec.put("crash", crash);
                attacks.add(rec);
                RunContext.log(proxy + " memory/" + attack + ": " + outcome + ", peak RSS " + peak(mem, "rssKb")
                        + " KB, peak NMT " + peak(mem, "nmtTotalKb") + " KB, proxy " + p.state());
                // Harness self-check: the workload ran and memory was sampled while it did.
                ctx.check(proxy, name(), attack + " ran and memory was sampled", crash != null || !mem.isEmpty(),
                        mem.size() + " samples over " + Trend.round(Trend.span(mem)) + " s");
                // Verdict on the proxy: bounded, shedding, unbounded-growth, oom, crashed or inconclusive.
                ctx.verdict(proxy, name(), attack, outcome, pass, (String) judged.get("detail"));
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

    /** Growth must clear this many KB along the fitted line to count. */
    static final long MIN_GROWTH_KB = 32 * 1024;
    /** ... and this fraction of the window's mean. */
    static final double MIN_GROWTH_FRACTION = 0.25;
    /** The line must fit at least this well (R²): a steady climb, not a step or a sawtooth. */
    static final double MIN_R2 = 0.8;
    /** A window shorter than this, or with fewer samples, cannot tell growth from warm-up. */
    static final double MIN_WINDOW_S = 20;
    static final int MIN_SAMPLES = 5;

    /**
     * Judges one workload; the result has {@code verdict}, {@code pass} (true, false, or null for
     * inconclusive) and {@code detail}.
     *
     * <ul>
     *   <li><b>oom</b> or <b>crashed</b> (fail): the proxy ran out of memory (even if it kept
     *       running) or exited;
     *   <li><b>inconclusive</b> (no verdict, never gates): after discarding the warm-up (the first
     *       10 s or quarter of the workload, whichever is longer, when buffer pools and the JIT
     *       settle) fewer than {@value #MIN_SAMPLES} samples or {@value #MIN_WINDOW_S} s remain;
     *   <li><b>shedding</b> (pass): the proxy closed or refused at least a tenth of the adversarial
     *       connections and stayed up;
     *   <li><b>unbounded-growth</b> (fail): RSS or NMT total climbs steadily over the window: a
     *       least-squares line with R² of at least {@value #MIN_R2} along which it grows by more than
     *       32 MB and a quarter of its mean;
     *   <li><b>bounded</b> (pass): otherwise; memory levelled off.
     * </ul>
     *
     * A rising peak alone is not growth: a pooled allocator warming up rises and then stays flat.
     */
    private Map<String, Object> classify(String attack, List<Map<String, Object>> mem, List<Map<String, Object>> probes,
            Map<String, Object> workload, ProxyProcess p, int seconds) {
        long probeTotal = 0;
        long probeOk = 0;
        for (Map<String, Object> pr : probes) {
            Map<String, Object> out = Json.getObject(pr, "outcomes");
            probeOk += Json.getLong(out, "OK", 0);
            for (Object v : out.values()) if (v instanceof Number n) probeTotal += n.longValue();
        }
        String availability = probeTotal == 0 ? "no probes" : "probe " + probeOk + "/" + probeTotal + " ok";
        long peakOther = peak(mem, "otherKb");
        long peakSock = p.watch != null ? Math.max(p.watch.peakSockKb(), peak(mem, "sockKb")) : peak(mem, "sockKb");
        String memory = "peak RSS " + peak(mem, "rssKb") / 1024 + " MB, peak NMT other (direct) " + peakOther / 1024 + " MB"
                + (peakSock >= 0 ? ", peak socket buffers " + peakSock / 1024 + " MB" : "");
        if (p.overOwnLimit()) {
            return Json.obj("verdict", "oom", "pass", false, "detail", "over the limit on its own memory (" + p.watch.overLimitBytes() / 1024 / 1024
                    + " MB of " + p.watch.limitBytes() / 1024 / 1024 + " MB, socket buffers aside), killed; " + memory + "; " + availability);
        }
        if (p.oom()) {
            return Json.obj("verdict", "oom", "pass", false, "detail", "out of memory (" + p.state() + "); " + memory
                    + "; " + availability);
        }
        if (!p.alive()) return Json.obj("verdict", "crashed", "pass", false, "detail", p.state() + "; " + availability);

        double warmup = Math.max(10, seconds * 0.25);
        List<Map<String, Object>> window = Trend.after(mem, warmup);
        double span = Trend.span(window);
        long closed = Json.getLong(workload, "closedByProxy", 0);
        long conns = Math.max(1, Json.getLong(workload, "connections", 1));
        boolean shedding = !attack.equals("updown") && closed >= Math.max(1, conns / 10);
        String shed = attack.equals("updown") ? "transfer errors " + Json.getLong(workload, "errors", 0)
                : "closed by the proxy " + closed + " of " + conns;
        if (window.size() < MIN_SAMPLES || span < MIN_WINDOW_S) {
            return Json.obj("verdict", "inconclusive", "pass", null, "detail", "window too short to tell growth from warm-up ("
                    + window.size() + " samples over " + Trend.round(span) + " s after a " + Trend.round(warmup)
                    + " s warm-up; needs " + MIN_SAMPLES + " over " + MIN_WINDOW_S + " s); " + memory + "; " + shed + "; "
                    + availability, "warmupS", warmup);
        }
        Map<String, Object> rssFit = Trend.fit(window, "rssKb", MIN_GROWTH_KB, MIN_GROWTH_FRACTION, MIN_R2);
        Map<String, Object> nmtFit = Trend.fit(window, "nmtTotalKb", MIN_GROWTH_KB, MIN_GROWTH_FRACTION, MIN_R2);
        String fits = "RSS slope " + rssFit.get("slopePerS") + " KB/s (R² " + rssFit.get("r2") + ", growth "
                + rssFit.get("growth") + " KB), NMT slope " + nmtFit.get("slopePerS") + " KB/s (R² " + nmtFit.get("r2") + ")";
        Map<String, Object> base = Json.obj("warmupS", warmup, "windowS", Trend.round(span), "rssFit", rssFit, "nmtFit", nmtFit);
        if (shedding) {
            base.put("verdict", "shedding");
            base.put("pass", true);
            base.put("detail", shed + "; " + memory + "; " + availability);
            return base;
        }
        boolean growing = Boolean.TRUE.equals(rssFit.get("flagged")) || Boolean.TRUE.equals(nmtFit.get("flagged"));
        base.put("verdict", growing ? "unbounded-growth" : "bounded");
        base.put("pass", !growing);
        base.put("detail", fits + "; " + memory + "; " + shed + "; " + availability);
        return base;
    }

    private Map<String, Object> memSample(ProxyProcess p, double t) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("t", Trend.round(t));
        if (p.jvm) {
            m.put("heapAfterGcKb", ctx.jcmd.heapAfterGcKb(p.pid()));
            Map<String, Object> nmt = ctx.jcmd.nmt(p.pid());
            m.put("nmtTotalKb", nmt.get("totalKb"));
            m.put("heapKb", nmt.get("heapKb"));
            m.put("threadKb", nmt.get("threadKb"));
            m.put("otherKb", nmt.get("otherKb"));
        }
        Environment.CgroupMemory cg = p.cgroupMemory();
        if (cg != null) {
            m.put("cgroupOwnKb", cg.ownBytes() / 1024);
            m.put("sockKb", cg.sockBytes() / 1024);
        }
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
