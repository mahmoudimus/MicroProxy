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
 * and renders the Markdown report and charts. Returns 0 only if every harness check passed, so a
 * CI smoke run fails when the harness itself did not work.
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
        top.put("versions", versions(ctx));
        top.put("proxies", proxies);
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
                    if (!RunContext.PROXIES.contains(proxy)) {
                        throw new IllegalArgumentException("unknown proxy " + proxy + "; one of " + RunContext.PROXIES);
                    }
                    RunContext.log("=== " + scenarioName + " / " + proxy + " ===");
                    Scenario scenario = scenario(scenarioName, ctx);
                    Map<String, Object> r;
                    try {
                        r = scenario.run(proxy);
                    } catch (Exception e) {
                        r = Json.obj("error", e.toString());
                        ctx.check(proxy, scenarioName, "scenario completed without throwing", false, e.toString());
                        RunContext.log("scenario " + scenarioName + "/" + proxy + " threw: " + e);
                        e.printStackTrace();
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

        boolean allChecksPassed = ctx.checks.stream().allMatch(c -> Boolean.TRUE.equals(c.get("ok")));
        top.put("checks", ctx.checks);
        top.put("notes", ctx.notes);
        top.put("harnessOk", allChecksPassed);
        writeJson(out.resolve("results.json"), top);

        Report.write(out, top, settings.getBool("charts"));
        // Keep the newest run easy to find.
        try {
            Path latest = baseDir.resolve("latest");
            Files.deleteIfExists(latest);
            Files.createSymbolicLink(latest, out.getFileName());
        } catch (IOException | UnsupportedOperationException e) {
            // Symlinks may be unavailable; the timestamp directory is enough.
        }
        System.out.println("Results: " + out.toAbsolutePath());
        System.out.println("Report:  " + out.resolve("report.md").toAbsolutePath());
        System.out.println("Harness checks: " + (allChecksPassed ? "all passed" : "SOME FAILED"));
        for (Map<String, Object> c : ctx.checks) {
            if (!Boolean.TRUE.equals(c.get("ok"))) {
                System.out.println("  FAIL " + c.get("proxy") + "/" + c.get("scenario") + ": " + c.get("check") + " -> " + c.get("detail"));
            }
        }
        return allChecksPassed ? 0 : 1;
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

    private static Map<String, Object> versions(RunContext ctx) {
        Map<String, Object> m = new LinkedHashMap<>();
        ctx.versions.forEach((k, v) -> m.put(k.toString(), v.toString()));
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
