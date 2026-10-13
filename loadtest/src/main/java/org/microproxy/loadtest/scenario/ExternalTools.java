package org.microproxy.loadtest.scenario;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.microproxy.loadtest.Json;
import org.microproxy.loadtest.proc.Environment;
import org.microproxy.loadtest.proc.ManagedProcess;

/**
 * Optional cross-checks with external load generators, used only when they are on the
 * {@code PATH}: wrk2 ({@code wrk -R}, open loop and corrected for coordinated omission like the
 * harness), h2load (HTTP/2 over h2c, MicroProxy only, since LittleProxy speaks HTTP/1 only) and
 * Fortio. Each one's output is parsed into the harness's own summary (achieved rate, errors and
 * latency percentiles in milliseconds), so the report can put them side by side.
 */
final class ExternalTools {

    private static final Pattern WRK_PCT = Pattern.compile("^\\s*(\\d+\\.\\d+)%\\s+([\\d.]+)(us|ms|s|m)\\s*$");
    private static final Pattern WRK_RPS = Pattern.compile("Requests/sec:\\s+([\\d.]+)");
    private static final Pattern WRK_NON2XX = Pattern.compile("Non-2xx or 3xx responses:\\s+(\\d+)");
    private static final Pattern WRK_SOCKET = Pattern.compile("Socket errors: connect (\\d+), read (\\d+), write (\\d+), timeout (\\d+)");
    private static final Pattern H2_REQUESTS = Pattern.compile("requests: (\\d+) total, (\\d+) started, (\\d+) done, (\\d+) succeeded, (\\d+) failed, (\\d+) errored, (\\d+) timeout");
    private static final Pattern H2_FINISHED = Pattern.compile("finished in ([\\d.]+)(m?s), ([\\d.]+) req/s");
    private static final Pattern H2_TIME = Pattern.compile("time for request:\\s+([\\d.]+)(us|ms|s)\\s+([\\d.]+)(us|ms|s)\\s+([\\d.]+)(us|ms|s)");

    private ExternalTools() {}

    /** The tools present, unless the settings turn cross-checks off. */
    static List<String> available(RunContext ctx) {
        List<String> out = new ArrayList<>();
        if (ctx.settings.get("external").equals("off")) return out;
        for (String tool : List.of("wrk", "h2load", "fortio")) {
            if (Environment.which(tool).isPresent()) out.add(tool);
        }
        return out;
    }

    /** Runs {@code tool} at {@code rate} through the proxy on {@code proxyPort}. */
    static Map<String, Object> run(RunContext ctx, String tool, String proxy, int proxyPort, double rate, int connections,
            int seconds, String path, long expectLength) throws IOException, InterruptedException {
        Path dir = ctx.out.resolve("logs");
        String origin = "127.0.0.1:" + ctx.originPort;
        List<String> cmd = new ArrayList<>(ctx.pinPrefix("client"));
        Map<String, String> env = new LinkedHashMap<>();
        Path jsonOut = dir.resolve("fortio-" + proxy + ".json");
        switch (tool) {
            case "wrk" -> {
                // wrk speaks to the proxy; the script turns its requests into absolute-form ones.
                Path script = dir.resolve("wrk-absolute.lua");
                Files.writeString(script, "wrk.path = \"http://" + origin + path + "\"\nwrk.headers[\"Host\"] = \"" + origin + "\"\n");
                cmd.addAll(List.of("wrk", "-t", "1", "-c", Integer.toString(connections), "-d", seconds + "s", "-R",
                        Long.toString(Math.round(rate)), "--latency", "-s", script.toString(), "http://127.0.0.1:" + proxyPort + "/"));
            }
            case "h2load" -> cmd.addAll(List.of("h2load", "-c", Integer.toString(connections), "-m", "1", "-D",
                    Integer.toString(seconds), "--rps", String.format(java.util.Locale.ROOT, "%.2f", rate / connections),
                    "-H", ":authority: " + origin, "http://127.0.0.1:" + proxyPort + path));
            case "fortio" -> {
                // Go never proxies loopback names; "localhost." (with the root dot) goes through HTTP_PROXY.
                env.put("HTTP_PROXY", "http://127.0.0.1:" + proxyPort);
                env.put("http_proxy", "http://127.0.0.1:" + proxyPort);
                cmd.addAll(List.of("fortio", "load", "-stdclient", "-qps", Long.toString(Math.round(rate)), "-c",
                        Integer.toString(connections), "-t", seconds + "s", "-json", jsonOut.toString(),
                        "http://localhost.:" + ctx.originPort + path));
            }
            default -> throw new IllegalArgumentException(tool);
        }
        ManagedProcess p = ManagedProcess.start(tool, cmd, dir.resolve(tool + "-" + proxy + ".log"), env);
        p.waitFor(Duration.ofSeconds(seconds + 60L));
        p.close();
        String output = Files.readString(p.log());
        Map<String, Object> m = switch (tool) {
            case "wrk" -> parseWrk(output);
            case "h2load" -> parseH2load(output);
            default -> Files.exists(jsonOut) ? parseFortio(Files.readString(jsonOut)) : Json.obj("error", "no JSON output");
        };
        m.put("tool", tool);
        m.put("targetRate", rate);
        m.put("connections", connections);
        m.put("seconds", seconds);
        m.put("log", ctx.out.relativize(p.log()).toString());
        return m;
    }

    /** Parses wrk2's {@code --latency} output. */
    static Map<String, Object> parseWrk(String out) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (!out.contains("HdrHistogram")) {
            m.put("error", "not wrk2 (no -R support or no latency distribution)");
            return m;
        }
        Map<String, Object> lat = new LinkedHashMap<>();
        for (String line : out.split("\n")) {
            Matcher p = WRK_PCT.matcher(line);
            if (p.find()) {
                double pct = Double.parseDouble(p.group(1));
                double ms = toMs(Double.parseDouble(p.group(2)), p.group(3));
                if (pct == 50) lat.put("p50", ms);
                else if (pct == 90) lat.put("p90", ms);
                else if (pct == 99) lat.put("p99", ms);
                else if (pct == 99.9) lat.put("p999", ms);
                else if (pct == 100) lat.put("max", ms);
            }
        }
        m.put("latencyMs", lat);
        Matcher rps = WRK_RPS.matcher(out);
        if (rps.find()) m.put("achievedRate", Double.parseDouble(rps.group(1)));
        long errors = 0;
        Matcher n = WRK_NON2XX.matcher(out);
        if (n.find()) errors += Long.parseLong(n.group(1));
        Matcher s = WRK_SOCKET.matcher(out);
        if (s.find()) for (int i = 1; i <= 4; i++) errors += Long.parseLong(s.group(i));
        m.put("errorCount", errors);
        return m;
    }

    /** Parses h2load's summary (it has no percentiles: min, mean and max only). */
    static Map<String, Object> parseH2load(String out) {
        Map<String, Object> m = new LinkedHashMap<>();
        Matcher r = H2_REQUESTS.matcher(out);
        if (!r.find()) {
            m.put("error", "no h2load summary");
            return m;
        }
        m.put("ok", Long.parseLong(r.group(4)));
        m.put("errorCount", Long.parseLong(r.group(5)) + Long.parseLong(r.group(6)) + Long.parseLong(r.group(7)));
        Matcher f = H2_FINISHED.matcher(out);
        if (f.find()) m.put("achievedRate", Double.parseDouble(f.group(3)));
        Matcher t = H2_TIME.matcher(out);
        if (t.find()) {
            m.put("latencyMs", Json.obj("min", toMs(Double.parseDouble(t.group(1)), t.group(2)), "max",
                    toMs(Double.parseDouble(t.group(3)), t.group(4)), "mean", toMs(Double.parseDouble(t.group(5)), t.group(6))));
        }
        m.put("note", "closed loop per connection (--rps): not corrected for coordinated omission");
        return m;
    }

    /** Parses Fortio's {@code -json} result. */
    static Map<String, Object> parseFortio(String json) {
        Map<String, Object> r = Json.parseObject(json);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("achievedRate", Json.getDouble(r, "ActualQPS", -1));
        Map<String, Object> codes = Json.getObject(r, "RetCodes");
        long ok = Json.getLong(codes, "200", 0);
        long total = 0;
        for (Object v : codes.values()) if (v instanceof Number n) total += n.longValue();
        m.put("ok", ok);
        m.put("errorCount", total - ok + Json.getLong(r, "ErrorsDurationHistogram", 0));
        Map<String, Object> hist = Json.getObject(r, "DurationHistogram");
        Map<String, Object> lat = new LinkedHashMap<>();
        for (Map<String, Object> p : Json.getObjects(hist, "Percentiles")) {
            double pct = Json.getDouble(p, "Percentile", -1);
            double ms = Json.getDouble(p, "Value", 0) * 1000;
            if (pct == 50) lat.put("p50", ms);
            else if (pct == 90) lat.put("p90", ms);
            else if (pct == 99) lat.put("p99", ms);
            else if (pct == 99.9) lat.put("p999", ms);
        }
        lat.put("max", Json.getDouble(hist, "Max", 0) * 1000);
        m.put("latencyMs", lat);
        m.put("note", "Fortio's -qps is not corrected for coordinated omission");
        return m;
    }

    private static double toMs(double v, String unit) {
        return switch (unit) {
            case "us" -> v / 1000;
            case "s" -> v * 1000;
            case "m" -> v * 60_000;
            default -> v;
        };
    }
}
