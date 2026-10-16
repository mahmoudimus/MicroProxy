package org.microproxy.loadtest.scenario;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.microproxy.loadtest.Json;
import org.microproxy.loadtest.Settings;
import org.microproxy.loadtest.report.Report;

/**
 * Drives a whole run: starts the shared origin, then runs each scenario against each proxy in a
 * fresh proxy JVM, writes one JSON file per proxy-and-scenario plus a combined {@code results.json},
 * and renders the Markdown report and charts.
 *
 * <p>Two kinds of result are kept apart. <b>Harness self-checks</b> say the harness worked: each
 * scenario ran, responses validated, metrics were sampled, the report was written. <b>Verdicts</b>
 * judge the proxy under test: bounded, shedding, unbounded-growth, oom or crashed, leak flags, fault
 * outcomes; a verdict can also be inconclusive, which never fails a run. The exit code is 0 unless a
 * self-check failed or a verdict the {@code gate} setting covers failed: by default MicroProxy's
 * only, the system under development; LittleProxy's verdicts are comparison data, reported but not
 * gating ({@code --gate all} gates both, {@code --gate none} neither).
 */
public final class Orchestrator {

    private Orchestrator() {}

    /** Runs {@code run --preset ... [--setting value ...]} and returns the process exit code. */
    public static int run(List<String> args) throws Exception {
        List<String> rest = new ArrayList<>();
        Settings settings = Settings.parse(args, rest);
        Path baseDir = Paths.get("loadtest", "results");
        for (int i = 0; i < rest.size() - 1; i++) {
            if (rest.get(i).equals("--out")) baseDir = Paths.get(rest.get(i + 1));
        }
        String stamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC).format(Instant.now());
        Path out = baseDir.resolve(stamp);
        Files.createDirectories(out.resolve("logs"));

        Path harnessJar = harnessJar();
        Path microproxyLib = harnessJar.getParent().resolve("microproxy-lib");
        RunContext ctx = new RunContext(settings, out, harnessJar, microproxyLib);

        List<String> proxies = settings.getList("proxies");
        List<String> scenarioNames = settings.getList("scenarios");
        Map<String, Object> top = new LinkedHashMap<>();
        top.put("timestamp", stamp);
        top.put("preset", settings.preset());
        top.put("settings", settings.toMap());
        top.put("environment", ctx.environment);
        top.put("versions", versions(ctx, proxies));
        top.put("proxies", proxies);
        Map<String, Object> externalDefs = new LinkedHashMap<>();
        for (String p : proxies) {
            if (ctx.externals.containsKey(p)) externalDefs.put(p, ctx.externals.get(p).describe());
        }
        top.put("externalProxies", externalDefs);
        top.put("cpuSplit", ctx.cpus);
        top.put("scenarios", scenarioNames);

        // Enough origin addresses for the ramp's warm-up connections.
        int rampMax = 0;
        for (String st : settings.getList("ramp-steps")) rampMax = Math.max(rampMax, (int) Settings.bytes(st));
        int originAddrs = Math.max(1, Math.min(32, 1 + rampMax / Math.max(1, settings.getInt("ramp-per-source"))));
        try {
            ctx.startOrigin(originAddrs);
            top.put("originPort", ctx.originPort);
            top.put("originAddresses", ctx.originAddresses);
            top.put("relays", ctx.relays);
            RunContext.log("origin on port " + ctx.originPort + " addresses " + ctx.originAddresses + " relays " + ctx.relays.keySet());

            Map<String, Object> results = new LinkedHashMap<>();
            for (String scenarioName : scenarioNames) {
                Map<String, Object> perProxy = new LinkedHashMap<>();
                for (String proxy : proxies) {
                    if (!ctx.knows(proxy)) {
                        throw new IllegalArgumentException("unknown proxy " + proxy + "; one of " + ctx.knownProxies()
                                + " (external proxies come from --external-proxies)");
                    }
                    RunContext.log("=== " + scenarioName + " / " + proxy + " ===");
                    Scenario scenario = scenario(scenarioName, ctx);
                    ExternalProxy ext = ctx.externals.get(proxy);
                    String unsupported = ext == null ? null : ext.unsupportedReason(scenarioName);
                    if (unsupported != null) {
                        // A scenario the proxy cannot run: reported as not supported, never dropped silently.
                        perProxy.put(proxy, Json.obj("unsupported", unsupported));
                        ctx.verdict(proxy, scenarioName, "scenario", "not-supported", null, unsupported);
                        RunContext.log(scenarioName + "/" + proxy + " not supported: " + unsupported);
                        continue;
                    }
                    Map<String, Object> r;
                    try {
                        r = scenario.run(proxy);
                    } catch (Exception e) {
                        r = Json.obj("error", e.toString());
                        ctx.check(proxy, scenarioName, "scenario completed without throwing", false, e.toString());
                        RunContext.log("scenario " + scenarioName + "/" + proxy + " threw: " + e);
                        e.printStackTrace();
                    }
                    if (!r.containsKey("error")) {
                        if (ctx.isJvm(proxy)) {
                            ctx.check(proxy, scenarioName, "proxy metrics were sampled (/proc and NMT)", sampled(r),
                                    sampled(r) ? "per-second /proc samples and NMT present" : "no /proc series or no NMT figures");
                        } else {
                            // An external proxy has no NMT: /proc is all there is to sample.
                            boolean ok = hasProcSeries(r);
                            ctx.check(proxy, scenarioName, "proxy metrics were sampled (/proc; NMT n/a)", ok,
                                    ok ? "per-second /proc samples present" : "no /proc series");
                        }
                    }
                    perProxy.put(proxy, r);
                    writeJson(out.resolve(scenarioName + "-" + proxy + ".json"), r);
                }
                results.put(scenarioName, perProxy);
            }
            top.put("results", results);
        } finally {
            if (ctx.origin != null) ctx.origin.stop(Duration.ofSeconds(3));
        }

        String gate = settings.get("gate");
        if (!List.of("microproxy", "all", "none").contains(gate)) {
            throw new IllegalArgumentException("--gate must be microproxy, all or none, not " + gate);
        }
        top.put("gate", gate);
        top.put("verdicts", ctx.verdicts);
        top.put("notes", ctx.notes);
        // When the measuring ended (UTC): with the timestamp, the window a host monitor's log is read over.
        top.put("finished", DateTimeFormatter.ISO_INSTANT.format(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS)));
        writeAndRender(out, top, ctx, settings);
        // The report is part of the harness's own job: check it was written, then record that check.
        Path report = out.resolve("report.md");
        boolean reported = Files.isRegularFile(report) && Files.size(report) > 0
                && Files.isRegularFile(out.resolve("results.json"));
        ctx.check("all", "report", "JSON results and the Markdown report were written", reported, report.toString());
        writeAndRender(out, top, ctx, settings);

        // Keep the newest run easy to find.
        try {
            Path latest = baseDir.resolve("latest");
            Files.deleteIfExists(latest);
            Files.createSymbolicLink(latest, out.getFileName());
        } catch (IOException | UnsupportedOperationException e) {
            // Symlinks may be unavailable; the timestamp directory is enough.
        }
        boolean harnessOk = ctx.checks.stream().allMatch(c -> Boolean.TRUE.equals(c.get("ok")));
        List<Map<String, Object>> gatedFailures = gatedFailures(ctx.verdicts, gate);
        System.out.println("Results: " + out.toAbsolutePath());
        System.out.println("Report:  " + report.toAbsolutePath());
        System.out.println("Harness self-checks: " + (harnessOk ? "all passed" : "SOME FAILED"));
        for (Map<String, Object> c : ctx.checks) {
            if (!Boolean.TRUE.equals(c.get("ok"))) {
                System.out.println("  FAIL " + c.get("proxy") + "/" + c.get("scenario") + ": " + c.get("check") + " -> " + c.get("detail"));
            }
        }
        System.out.println("Verdicts (gate: " + gate + "):");
        for (Map<String, Object> v : ctx.verdicts) {
            Object pass = v.get("pass");
            String mark = pass == null ? "    " : Boolean.TRUE.equals(pass) ? "  ok" : gates(gate, v) ? "FAIL" : "note";
            System.out.println("  " + mark + " " + v.get("proxy") + "/" + v.get("scenario") + "/" + v.get("subject") + ": "
                    + v.get("verdict"));
        }
        if (!gatedFailures.isEmpty()) {
            System.out.println(gatedFailures.size() + " gated verdict(s) failed.");
        }
        return harnessOk && gatedFailures.isEmpty() ? 0 : 1;
    }

    /** Writes results.json (with the checks so far) and renders the report. */
    private static void writeAndRender(Path out, Map<String, Object> top, RunContext ctx, Settings settings) throws IOException {
        boolean harnessOk = ctx.checks.stream().allMatch(c -> Boolean.TRUE.equals(c.get("ok")));
        top.put("checks", ctx.checks);
        top.put("harnessOk", harnessOk);
        top.put("gatedFailures", gatedFailures(ctx.verdicts, settings.get("gate")).size());
        writeJson(out.resolve("results.json"), top);
        Report.write(out, top, settings.getBool("charts"));
    }

    /** Whether a failed verdict on this proxy fails the run under {@code gate}. */
    static boolean gates(String gate, Map<String, Object> verdict) {
        return switch (gate) {
            case "all" -> true;
            case "none" -> false;
            default -> "microproxy".equals(verdict.get("proxy"));
        };
    }

    /** The failed verdicts the gate counts; inconclusive verdicts never count. */
    static List<Map<String, Object>> gatedFailures(List<Map<String, Object>> verdicts, String gate) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> v : verdicts) {
            if (Boolean.FALSE.equals(v.get("pass")) && gates(gate, v)) out.add(v);
        }
        return out;
    }

    /** Whether a scenario's results hold per-second /proc samples of the proxy and some NMT figure. */
    static boolean sampled(Object node) {
        return hasProcSeries(node) && hasNmt(node);
    }

    private static boolean hasProcSeries(Object node) {
        if (node instanceof Map<?, ?> m) {
            if (m.get("series") instanceof Map<?, ?> series && series.get("proxy") instanceof List<?> l && !l.isEmpty()) return true;
            for (Object v : m.values()) if (hasProcSeries(v)) return true;
        } else if (node instanceof List<?> l) {
            for (Object v : l) if (hasProcSeries(v)) return true;
        }
        return false;
    }

    private static boolean hasNmt(Object node) {
        if (node instanceof Map<?, ?> m) {
            for (String k : List.of("totalKb", "nmtTotalKb")) {
                if (m.get(k) instanceof Number n && n.longValue() > 0) return true;
            }
            for (Object v : m.values()) if (hasNmt(v)) return true;
        } else if (node instanceof List<?> l) {
            for (Object v : l) if (hasNmt(v)) return true;
        }
        return false;
    }

    private static Scenario scenario(String name, RunContext ctx) {
        return switch (name) {
            case "sweep" -> new RateSweep(ctx);
            case "ramp" -> new ConnectionRamp(ctx);
            case "memory" -> new MemoryUnderAttack(ctx);
            case "soak" -> new Soak(ctx);
            case "faults" -> new Faults(ctx);
            default -> throw new IllegalArgumentException("unknown scenario " + name + "; one of sweep, ramp, memory, soak, faults");
        };
    }

    private static Map<String, Object> versions(RunContext ctx, List<String> proxies) {
        Map<String, Object> m = new LinkedHashMap<>();
        ctx.versions.forEach((k, v) -> m.put(k.toString(), v.toString()));
        for (String p : proxies) {
            ExternalProxy e = ctx.externals.get(p);
            if (e != null) m.put(p, e.probeVersion());
        }
        return m;
    }

    private static void writeJson(Path file, Object value) throws IOException {
        Files.writeString(file, Json.pretty(value));
    }

    /** The harness jar this process runs from, so the child JVMs use the same one. */
    static Path harnessJar() {
        try {
            Path self = Paths.get(Orchestrator.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            if (Files.isRegularFile(self)) return self;
            // Running from target/classes (tests, IDE): use the shaded jar beside it.
            Path target = self.getParent();
            try (var s = Files.list(target)) {
                return s.filter(p -> p.getFileName().toString().equals("microproxy-loadtest.jar")).findFirst()
                        .orElseThrow(() -> new IllegalStateException("build the shaded jar: mvn -Pbench -DskipTests package"));
            }
        } catch (URISyntaxException | IOException e) {
            throw new IllegalStateException("cannot locate the harness jar", e);
        }
    }
}
