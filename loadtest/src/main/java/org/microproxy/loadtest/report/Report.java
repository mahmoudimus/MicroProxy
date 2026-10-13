package org.microproxy.loadtest.report;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.microproxy.loadtest.Json;

/**
 * Renders the Markdown report and the optional SVG charts from a run's {@code results.json}. The
 * report compares MicroProxy and LittleProxy per scenario: the maximum sustainable rate and the
 * latency curve, memory per idle connection and the connection limit, memory behaviour under each
 * adversarial workload, soak slopes, and fault outcomes. Memory is led by RSS and NMT total, with
 * heap shown alongside, because heap alone is misleading across a virtual-thread proxy and a
 * Netty one.
 */
public final class Report {

    private Report() {}

    /** Re-renders a results directory's report and charts in place. */
    public static void reRender(Path dir) throws IOException {
        Map<String, Object> top = Json.parseObject(Files.readString(dir.resolve("results.json")));
        write(dir, top, true);
        System.out.println("Report: " + dir.resolve("report.md").toAbsolutePath());
    }

    /** Writes {@code report.md} and, when {@code charts}, SVG charts under {@code charts/}. */
    public static void write(Path out, Map<String, Object> top, boolean charts) throws IOException {
        List<String> chartFiles = new ArrayList<>();
        if (charts) {
            Path chartDir = out.resolve("charts");
            Files.createDirectories(chartDir);
            chartFiles = Charts.write(chartDir, top);
        }
        StringBuilder md = new StringBuilder();
        Md w = new Md(md);
        header(w, top);
        verdicts(w, top, Report.strings(top.get("proxies")));
        Map<String, Object> results = Json.getObject(top, "results");
        List<String> proxies = strings(top.get("proxies"));
        for (String scenario : strings(top.get("scenarios"))) {
            Map<String, Object> perProxy = Json.getObject(results, scenario);
            switch (scenario) {
                case "sweep" -> sweep(w, perProxy, proxies);
                case "ramp" -> ramp(w, perProxy, proxies);
                case "memory" -> memory(w, perProxy, proxies);
                case "soak" -> soak(w, perProxy, proxies);
                case "faults" -> faults(w, perProxy, proxies);
                default -> {
                    // Unknown scenario: nothing to render.
                }
            }
        }
        if (!chartFiles.isEmpty()) {
            w.h2("Charts");
            for (String f : chartFiles) w.line("- [" + f + "](charts/" + f + ")");
            w.blank();
        }
        checks(w, top);
        Files.writeString(out.resolve("report.md"), md.toString());
    }

    private static void header(Md w, Map<String, Object> top) {
        List<String> proxies = strings(top.get("proxies"));
        boolean classic = proxies.equals(List.of("microproxy", "littleproxy"));
        w.h1(classic ? "MicroProxy vs LittleProxy load and capacity report" : "Load and capacity report: " + String.join(", ", proxies));
        Map<String, Object> versions = Json.getObject(top, "versions");
        w.line("- Preset: `" + top.get("preset") + "`  Timestamp (UTC): `" + top.get("timestamp") + "`");
        if (classic) {
            w.line("- MicroProxy `" + versions.getOrDefault("microproxy", "?") + "` vs LittleProxy `"
                    + versions.getOrDefault("littleproxy", "?") + "` (`io.github.littleproxy:littleproxy`)");
        } else {
            List<String> v = new ArrayList<>();
            for (String p : proxies) v.add(p + " `" + versions.getOrDefault(p, "?") + "`");
            w.line("- Versions: " + String.join(", ", v));
        }
        if (top.get("cpuSplit") instanceof Map<?, ?> split) w.line("- CPU split (taskset): " + split);
        Map<String, Object> env = Json.getObject(top, "environment");
        Map<String, Object> limits = Json.getObject(env, "limits");
        w.line("- Host: " + env.get("os") + ", " + env.getOrDefault("distribution", "?") + ", " + env.get("java"));
        w.line("- CPU: " + env.getOrDefault("cpuModel", "?") + "; memory " + mb(env.get("memTotalKb")) + " MB");
        w.line("- CPUs: " + env.get("cpus") + "; taskset present: " + env.get("taskset") + "; cgroup: " + env.get("cgroup"));
        w.line("- Limits: ulimit -n " + limits.get("nofile") + ", somaxconn " + limits.get("somaxconn")
                + ", ip_local_port_range " + limits.get("ip_local_port_range") + ", tcp_tw_reuse " + limits.get("tcp_tw_reuse"));
        Map<String, Object> tools = Json.getObject(env, "tools");
        w.line("- External cross-check tools found: " + presentTools(tools));
        w.blank();
        w.line("> Memory is reported as RSS and NMT committed total, with heap shown alongside: heap alone"
                + " understates a Netty proxy's direct buffers and is not comparable to a virtual-thread proxy's"
                + " heap-resident stacks. All results come from a single manual run; numbers are not published and"
                + " depend on the machine and its tuning.");
        w.blank();
        for (Object note : asList(top.get("notes"))) w.line("- Note: " + note);
        boolean ok = Boolean.TRUE.equals(top.get("harnessOk"));
        w.line("- Harness self-checks: " + (ok ? "all passed" : "**SOME FAILED** (see the end)"));
        w.line("- Gate: `" + top.getOrDefault("gate", "microproxy") + "`; gated verdicts failed: "
                + num(top.getOrDefault("gatedFailures", 0)));
        w.blank();
    }

    // --- Verdicts ---

    private static void verdicts(Md w, Map<String, Object> top, List<String> proxies) {
        List<Map<String, Object>> all = Json.getObjects(top, "verdicts");
        if (all.isEmpty()) return;
        String gate = String.valueOf(top.getOrDefault("gate", "microproxy"));
        w.h2("Verdicts");
        w.line("Judgements on each proxy under test, kept apart from the harness's own self-checks. **pass** and"
                + " **FAIL** are verdicts; **inconclusive** means the window was too short to tell (the smoke preset's"
                + " memory and soak windows are), and never fails a run; real verdicts come from the standard and full"
                + " presets. Under the gate `" + gate + "`, "
                + switch (gate) {
                    case "all" -> "a failed verdict on either proxy fails the run.";
                    case "none" -> "no verdict fails the run; only harness self-checks do.";
                    default -> "only MicroProxy's failed verdicts fail the run: MicroProxy is the system under"
                            + " development, and LittleProxy's verdicts are comparison data.";
                });
        w.blank();
        w.row("Proxy", "Scenario", "Subject", "Verdict", "Result", "Gates the run", "Detail");
        w.rule(7);
        for (String p : proxies) {
            for (Map<String, Object> v : all) {
                if (!p.equals(v.get("proxy"))) continue;
                Object pass = v.get("pass");
                boolean gates = switch (gate) {
                    case "all" -> true;
                    case "none" -> false;
                    default -> "microproxy".equals(p);
                };
                String result = pass == null ? "inconclusive" : Boolean.TRUE.equals(pass) ? "pass" : "**FAIL**";
                if ("not-applicable".equals(v.get("verdict"))) result = "n/a";
                w.row(p, String.valueOf(v.get("scenario")), String.valueOf(v.get("subject")), String.valueOf(v.get("verdict")),
                        result, gates ? "yes" : "no (comparison)", trunc(String.valueOf(v.get("detail")), 140));
            }
        }
        w.blank();
    }

    // --- Rate sweep ---

    private static void sweep(Md w, Map<String, Object> perProxy, List<String> proxies) {
        w.h2("Rate sweep (knee)");
        w.line("Open-loop load over keep-alive connections with small responses, the rate stepped up to find the"
                + " knee: the first step whose p99 passes the SLO, whose errors pass the tolerance, or that the proxy"
                + " could not keep up with. Latency is corrected for coordinated omission (measured from each"
                + " request's intended send time). Pass/fail: a run passes the harness check when its steps produced"
                + " valid responses; the maximum sustainable rate below is the comparison.");
        w.blank();
        w.row("Proxy", "Max sustainable rate (req/s)", "Knee at", "Why", "Proxy end");
        w.rule(5);
        for (String p : proxies) {
            Map<String, Object> r = Json.getObject(perProxy, p);
            if (skip(r)) {
                w.row(p, r.containsKey("unsupported") ? "not supported" : "error", "-", why(r), "-");
                continue;
            }
            Object max = r.get("maxSustainableRate");
            w.row(p, max == null ? "none sustained" : num(max), r.get("kneeFound").equals(Boolean.TRUE)
                    ? "step " + r.get("kneeStep") : "not reached", trunc(Json.getString(r, "kneeReason", "-"), 60),
                    Json.getString(r, "proxyState", "-"));
        }
        w.blank();
        for (String p : proxies) {
            Map<String, Object> r = Json.getObject(perProxy, p);
            if (skip(r)) continue;
            w.h3("Latency curve — " + p);
            w.row("Target req/s", "Achieved", "p50", "p90", "p99", "p99.9", "max", "errors", "proxy CPU%", "RSS MB", "sustained");
            w.rule(11);
            for (Map<String, Object> step : Json.getObjects(r, "steps")) {
                Map<String, Object> lat = Json.getObject(step, "latencyMs");
                Map<String, Object> res = Json.getObject(step, "proxy");
                w.row(num(step.get("targetRate")), num(step.get("achievedRate")), ms(lat, "p50"), ms(lat, "p90"),
                        ms(lat, "p99"), ms(lat, "p999"), ms(lat, "max"), num(step.get("errorCount")),
                        num(res.get("cpuPct")), mb(res.get("rssKb")), yes(step.get("sustainable")));
            }
            w.blank();
            crossChecks(w, r);
        }
    }

    private static void crossChecks(Md w, Map<String, Object> r) {
        List<Map<String, Object>> cross = Json.getObjects(r, "crossChecks");
        if (cross.isEmpty()) return;
        w.line("External cross-checks:");
        w.row("Tool", "Target req/s", "Achieved", "p50", "p99", "p99.9", "errors", "note");
        w.rule(8);
        for (Map<String, Object> c : cross) {
            Map<String, Object> lat = Json.getObject(c, "latencyMs");
            w.row(String.valueOf(c.get("tool")), num(c.get("targetRate")), num(c.getOrDefault("achievedRate", "-")),
                    ms(lat, "p50"), ms(lat, "p99"), ms(lat, "p999"), num(c.getOrDefault("errorCount", "-")),
                    trunc(Json.getString(c, "note", Json.getString(c, "error", "")), 40));
        }
        w.blank();
    }

    // --- Connection ramp ---

    private static void ramp(Md w, Map<String, Object> perProxy, List<String> proxies) {
        w.h2("Connection ramp (idle keep-alive connections)");
        w.line("Idle keep-alive connections held in steps, from several loopback source addresses to get past one"
                + " address's ephemeral ports. At each step: RSS, NMT committed memory, the heap after a forced GC,"
                + " file descriptors, threads, the setup rate, and an active probe's latency while the connections are"
                + " held. The ramp stops at the first step it cannot complete, and records how it failed.");
        w.blank();
        w.row("Proxy", "Max held", "Failure", "How it failed", "RSS/conn (KB)", "NMT total/conn (KB)", "thread/conn (KB)");
        w.rule(7);
        for (String p : proxies) {
            Map<String, Object> r = Json.getObject(perProxy, p);
            if (skip(r)) {
                w.row(p, r.containsKey("unsupported") ? "not supported" : "error", "-", why(r), "-", "-", "-");
                continue;
            }
            Map<String, Object> per = Json.getObject(r, "perConnection");
            w.row(p, num(r.get("maxConnectionsHeld")), Json.getString(r, "failureKind", "-"),
                    trunc(Json.getString(r, "failure", "limit not reached"), 50), num(per.get("rssKbPerConn")),
                    num(per.get("nmtTotalKbPerConn")), num(per.get("threadKbPerConn")));
        }
        w.blank();
        for (String p : proxies) {
            Map<String, Object> r = Json.getObject(perProxy, p);
            if (skip(r)) continue;
            w.h3("Per-step memory — " + p);
            w.row("Held", "Setup req/s", "RSS MB", "NMT total MB", "heap(GC) MB", "thread MB", "other MB", "fds", "threads", "probe ok", "probe p99 ms");
            w.rule(11);
            for (Map<String, Object> step : Json.getObjects(r, "steps")) {
                Map<String, Object> mem = Json.getObject(step, "memory");
                Map<String, Object> nmt = Json.getObject(mem, "nmt");
                Map<String, Object> probe = Json.getObject(step, "probe");
                Map<String, Object> outcomes = Json.getObject(probe, "outcomes");
                Map<String, Object> pd = Json.getObject(probe, "durationMs");
                w.row(num(step.get("held")), num(step.get("setupRate")), mb(mem.get("rssKb")), mb(nmt.get("totalKb")),
                        mb(mem.get("heapAfterGcKb")), mb(nmt.get("threadKb")), mb(nmt.get("otherKb")), num(mem.get("fds")),
                        num(mem.get("threads")), num(outcomes.getOrDefault("OK", 0)), ms(pd, "p99"));
            }
            w.line("OS limits seen: " + Json.getObject(r, "osLimits"));
            w.line("Client ceilings: " + String.join("; ", strings(r.get("clientCeilings"))));
            w.blank();
        }
    }

    // --- Memory under adversarial clients ---

    private static void memory(Md w, Map<String, Object> perProxy, List<String> proxies) {
        w.h2("Memory under adversarial clients");
        w.line("The proxy runs with its memory capped (small heap and direct-memory ceiling, plus a cgroup limit"
                + " where available). Each workload runs while the harness samples memory; a normal client probes"
                + " throughout. Verdicts: **bounded** (memory levels off) or **shedding** (the proxy closes or refuses"
                + " the adversarial connections and stays up) pass; **unbounded-growth** (RSS or NMT total climbs"
                + " steadily after the warm-up: a least-squares line with R² ≥ 0.8 along which it grows by more than"
                + " 32 MB and a quarter of its mean), an out-of-memory or a crash fail. A rising peak alone is not"
                + " growth: pooled buffers warm up and then stay flat. When too little of the window is left after the"
                + " warm-up (10 s or a quarter of the workload) to tell, the verdict is **inconclusive**. NMT \"other\""
                + " is where direct (off-heap) buffers are counted; for the slow readers, \"direct per reader\" is that"
                + " section's peak over the baseline, divided by the readers: what the proxy holds for each one.");
        w.blank();
        w.row("Workload", "Proxy", "Verdict", "Result", "Peak RSS MB", "Peak NMT MB", "Peak heap(GC) MB", "Peak other MB",
                "Direct per reader KB", "Proxy end");
        w.rule(10);
        // Collect every workload name across proxies.
        List<String> attackNames = new ArrayList<>();
        for (String p : proxies) {
            for (Map<String, Object> a : Json.getObjects(Json.getObject(perProxy, p), "attacks")) {
                String n = Json.getString(a, "attack", "?");
                if (!attackNames.contains(n)) attackNames.add(n);
            }
        }
        for (String attack : attackNames) {
            for (String p : proxies) {
                Map<String, Object> rec = findAttack(Json.getObject(perProxy, p), attack);
                if (rec == null) {
                    w.row(attack, p, "-", "-", "-", "-", "-", "-", "-", "-");
                } else if (rec.containsKey("skipped")) {
                    w.row(attack, p, "not-applicable", "n/a", "-", "-", "-", "-", "-", trunc(Json.getString(rec, "skipped", ""), 40));
                } else {
                    Object pass = rec.get("pass");
                    String result = pass == null ? "inconclusive" : Boolean.TRUE.equals(pass) ? "pass" : "**FAIL**";
                    w.row(attack, p, Json.getString(rec, "outcome", "-"), result, mb(rec.get("peakRssKb")),
                            mb(rec.get("peakNmtTotalKb")), mb(rec.get("peakHeapAfterGcKb")), mb(rec.get("peakOtherKb")),
                            directPerReader(rec), Json.getString(rec, "proxyState", "-"));
                }
            }
        }
        w.blank();
    }

    /** For slow readers: NMT "other" (direct memory) above the baseline per reader, in KB. */
    private static String directPerReader(Map<String, Object> rec) {
        if (!"slowread".equals(rec.get("attack"))) return "-";
        long readers = Json.getLong(Json.getObject(rec, "workload"), "connections", 0);
        long peak = Json.getLong(rec, "peakOtherKb", -1);
        long base = Json.getLong(Json.getObject(Json.getObject(rec, "baseline"), "nmt"), "otherKb", 0);
        if (readers <= 0 || peak < 0) return "-";
        return num(Math.round(Math.max(0, peak - base) / (double) readers));
    }

    private static Map<String, Object> findAttack(Map<String, Object> r, String name) {
        for (Map<String, Object> a : Json.getObjects(r, "attacks")) {
            if (name.equals(Json.getString(a, "attack", ""))) return a;
        }
        return null;
    }

    // --- Soak ---

    private static void soak(Md w, Map<String, Object> perProxy, List<String> proxies) {
        w.h2("Soak");
        w.line("A fixed moderate rate held for the configured duration, with RSS, heap-after-GC, file descriptors and"
                + " threads tracked over time. After a warm-up (a fifth of the soak, at least 30 s), a least-squares"
                + " slope with R² ≥ 0.8 that grows by more than a threshold is flagged as a possible leak. A soak too"
                + " short to judge (under 60 s left after the warm-up, as in the smoke preset) is inconclusive.");
        w.blank();
        w.row("Proxy", "Requests", "Errors", "Leak verdict", "RSS slope (KB/h)", "heap(GC) slope (KB/h)", "fd slope (/h)", "Proxy end");
        w.rule(8);
        for (String p : proxies) {
            Map<String, Object> r = Json.getObject(perProxy, p);
            if (skip(r)) {
                w.row(p, r.containsKey("unsupported") ? "not supported" : "error", "-", "-", "-", "-", "-", why(r));
                continue;
            }
            Map<String, Object> leak = Json.getObject(r, "leakCheck");
            String leakVerdict = !Boolean.TRUE.equals(r.get("leakWindowConclusive")) ? "inconclusive (window too short)"
                    : Boolean.TRUE.equals(r.get("leakSuspected")) ? "**possible leak**" : "no leak";
            w.row(p, num(r.get("totalRequests")), num(r.get("totalErrors")), leakVerdict,
                    slopeHour(leak, "rssKb"), slopeHour(leak, "heapAfterGcKb"), slopeHour(leak, "fds"),
                    Json.getString(r, "proxyState", "-"));
        }
        w.blank();
    }

    private static String slopeHour(Map<String, Object> leak, String key) {
        Map<String, Object> fit = Json.getObject(leak, key);
        Object v = fit.get("slopePerHour");
        String f = Boolean.TRUE.equals(fit.get("flagged")) ? " (flagged)" : "";
        return v == null ? "-" : num(v) + f;
    }

    // --- Faults ---

    private static void faults(Md w, Map<String, Object> perProxy, List<String> proxies) {
        w.h2("Fault injection");
        w.line("Each fault is injected by a Toxiproxy-style TCP relay between the proxy and the origin. For each the"
                + " harness checks that the proxy turns it into a sensible outcome without hanging past the request"
                + " timeout, leaks no relay connection (the relay's open count returns to zero) and leaks no file"
                + " descriptors.");
        w.blank();
        for (String p : proxies) {
            Map<String, Object> r = Json.getObject(perProxy, p);
            if (skip(r)) {
                w.line("**" + p + "**: " + why(r));
                continue;
            }
            w.h3("Faults — " + p + " (overall: " + (Boolean.TRUE.equals(r.get("pass")) ? "bounded" : "see below") + ")");
            w.row("Fault", "Outcomes", "max ms", "limit ms", "relay open after", "fds after/base", "bounded");
            w.rule(7);
            for (Map<String, Object> f : Json.getObjects(r, "faults")) {
                Map<String, Object> dur = Json.getObject(f, "durationMs");
                w.row(Json.getString(f, "fault", "?"), compact(Json.getObject(f, "outcomes")), ms(dur, "max"),
                        num(f.get("longestAcceptableMs")), num(f.get("relayOpenAfter")),
                        num(f.get("fdsAfter")) + "/" + num(f.get("fdsBaseline")), yes(f.get("ok")));
            }
            if (!Boolean.TRUE.equals(r.get("pass"))) w.line("Detail: " + r.get("failDetail"));
            w.blank();
        }
    }

    private static void checks(Md w, Map<String, Object> top) {
        w.h2("Harness self-checks");
        w.line("These verify the harness worked (each scenario ran, responses validated, metrics were sampled, the"
                + " report was written), not how well a proxy did. Any failure here fails the run, whichever proxy it"
                + " concerns.");
        w.blank();
        w.row("Proxy", "Scenario", "Check", "OK", "Detail");
        w.rule(5);
        for (Map<String, Object> c : Json.getObjects(top, "checks")) {
            w.row(String.valueOf(c.get("proxy")), String.valueOf(c.get("scenario")), String.valueOf(c.get("check")),
                    yes(c.get("ok")), trunc(String.valueOf(c.get("detail")), 70));
        }
        w.blank();
    }

    // --- formatting helpers ---

    /** Whether a proxy's scenario result has no data: it failed, or the proxy cannot run the scenario. */
    private static boolean skip(Map<String, Object> r) {
        return r.containsKey("error") || r.containsKey("unsupported");
    }

    /** Why a skipped result has no data. */
    private static String why(Map<String, Object> r) {
        return r.containsKey("unsupported") ? "not supported: " + r.get("unsupported") : "error: " + r.get("error");
    }

    private static String compact(Map<String, Object> m) {
        List<String> parts = new ArrayList<>();
        m.forEach((k, v) -> parts.add(k + ":" + v));
        return String.join(" ", parts);
    }

    private static String presentTools(Map<String, Object> tools) {
        List<String> present = new ArrayList<>();
        tools.forEach((k, v) -> {
            if (v != null) present.add(k);
        });
        return present.isEmpty() ? "none" : String.join(", ", present);
    }

    static String num(Object o) {
        if (o instanceof Double d) return Math.abs(d - Math.rint(d)) < 1e-9 ? Long.toString((long) (double) d) : String.format(java.util.Locale.ROOT, "%.2f", d);
        if (o instanceof Number n) return n.toString();
        return String.valueOf(o);
    }

    static String ms(Map<String, Object> lat, String key) {
        Object v = lat.get(key);
        return v == null ? "-" : String.format(java.util.Locale.ROOT, "%.2f", ((Number) v).doubleValue());
    }

    static String mb(Object kb) {
        if (!(kb instanceof Number n) || n.longValue() < 0) return "-";
        return String.format(java.util.Locale.ROOT, "%.1f", n.doubleValue() / 1024);
    }

    static String yes(Object b) {
        return Boolean.TRUE.equals(b) ? "yes" : Boolean.FALSE.equals(b) ? "no" : "-";
    }

    static String trunc(String s, int n) {
        if (s == null) return "-";
        s = s.replace("\n", " ").replace("|", "/");
        return s.length() > n ? s.substring(0, n - 1) + "…" : s;
    }

    @SuppressWarnings("unchecked")
    static List<String> strings(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof List<?> l) for (Object x : l) out.add(String.valueOf(x));
        return out;
    }

    static List<Object> asList(Object o) {
        return o instanceof List<?> l ? new ArrayList<>(l) : List.of();
    }

    /** A small Markdown builder. */
    private static final class Md {
        final StringBuilder b;

        Md(StringBuilder b) {
            this.b = b;
        }

        void h1(String s) {
            b.append("# ").append(s).append("\n\n");
        }

        void h2(String s) {
            b.append("## ").append(s).append("\n\n");
        }

        void h3(String s) {
            b.append("### ").append(s).append("\n\n");
        }

        void line(String s) {
            b.append(s).append("\n");
        }

        void blank() {
            b.append("\n");
        }

        void row(String... cells) {
            b.append("| ").append(String.join(" | ", cells)).append(" |\n");
        }

        void rule(int n) {
            b.append("|");
            for (int i = 0; i < n; i++) b.append("---|");
            b.append("\n");
        }
    }
}
