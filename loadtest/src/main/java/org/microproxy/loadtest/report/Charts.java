package org.microproxy.loadtest.report;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.microproxy.loadtest.Json;

/**
 * Writes the run's SVG charts (via {@link Svg}): the sweep's latency against rate and its memory
 * against rate, the ramp's RSS and NMT total against connection count, and each proxy's soak RSS
 * and heap-after-GC over time. Charts are optional; the report links whatever was written.
 */
final class Charts {

    private Charts() {}

    /** Writes the charts into {@code dir}; returns their file names. */
    static List<String> write(Path dir, Map<String, Object> top) throws IOException {
        List<String> files = new ArrayList<>();
        Map<String, Object> results = Json.getObject(top, "results");
        List<String> proxies = Report.strings(top.get("proxies"));

        // Sweep: p99 latency vs achieved rate, and RSS vs rate.
        Map<String, Object> sweep = Json.getObject(results, "sweep");
        if (!sweep.isEmpty()) {
            List<Svg.Series> lat = new ArrayList<>();
            List<Svg.Series> rss = new ArrayList<>();
            for (String p : proxies) {
                List<double[]> latPts = new ArrayList<>();
                List<double[]> rssPts = new ArrayList<>();
                for (Map<String, Object> step : Json.getObjects(Json.getObject(sweep, p), "steps")) {
                    double rate = Json.getDouble(step, "achievedRate", 0);
                    double p99 = Json.getDouble(Json.getObject(step, "latencyMs"), "p99", -1);
                    double r = Json.getDouble(Json.getObject(step, "proxy"), "rssKb", -1) / 1024;
                    if (p99 >= 0) latPts.add(new double[] {rate, p99});
                    if (r >= 0) rssPts.add(new double[] {rate, r});
                }
                lat.add(new Svg.Series(p, latPts));
                rss.add(new Svg.Series(p, rssPts));
            }
            files.add(save(dir, "sweep-latency.svg", Svg.lineChart("Rate sweep: p99 latency vs achieved rate",
                    "achieved req/s", "p99 latency (ms)", lat, false)));
            files.add(save(dir, "sweep-rss.svg", Svg.lineChart("Rate sweep: RSS vs achieved rate", "achieved req/s",
                    "RSS (MB)", rss, false)));
        }

        // Ramp: RSS and NMT total vs connections held.
        Map<String, Object> ramp = Json.getObject(results, "ramp");
        if (!ramp.isEmpty()) {
            List<Svg.Series> rss = new ArrayList<>();
            List<Svg.Series> nmt = new ArrayList<>();
            for (String p : proxies) {
                List<double[]> rssPts = new ArrayList<>();
                List<double[]> nmtPts = new ArrayList<>();
                for (Map<String, Object> step : Json.getObjects(Json.getObject(ramp, p), "steps")) {
                    double held = Json.getDouble(step, "held", 0);
                    Map<String, Object> mem = Json.getObject(step, "memory");
                    double r = Json.getDouble(mem, "rssKb", -1) / 1024;
                    double n = Json.getDouble(Json.getObject(mem, "nmt"), "totalKb", -1) / 1024;
                    if (r >= 0) rssPts.add(new double[] {held, r});
                    if (n >= 0) nmtPts.add(new double[] {held, n});
                }
                rss.add(new Svg.Series(p, rssPts));
                nmt.add(new Svg.Series(p, nmtPts));
            }
            files.add(save(dir, "ramp-rss.svg", Svg.lineChart("Connection ramp: RSS vs idle connections",
                    "idle connections", "RSS (MB)", rss, true)));
            files.add(save(dir, "ramp-nmt.svg", Svg.lineChart("Connection ramp: NMT committed total vs idle connections",
                    "idle connections", "NMT total (MB)", nmt, true)));
        }

        // Soak: RSS and heap-after-GC over time, one chart per proxy.
        Map<String, Object> soak = Json.getObject(results, "soak");
        if (!soak.isEmpty()) {
            for (String p : proxies) {
                List<Map<String, Object>> mem = Json.getObjects(Json.getObject(soak, p), "memSeries");
                if (mem.isEmpty()) continue;
                List<double[]> rssPts = new ArrayList<>();
                List<double[]> heapPts = new ArrayList<>();
                for (Map<String, Object> m : mem) {
                    double t = Json.getDouble(m, "t", 0);
                    double r = Json.getDouble(m, "rssKb", -1) / 1024;
                    double h = Json.getDouble(m, "heapAfterGcKb", -1) / 1024;
                    if (r >= 0) rssPts.add(new double[] {t, r});
                    if (h >= 0) heapPts.add(new double[] {t, h});
                }
                List<Svg.Series> s = List.of(new Svg.Series("RSS", rssPts), new Svg.Series("heap after GC", heapPts));
                files.add(save(dir, "soak-" + p + ".svg", Svg.lineChart("Soak: memory over time — " + p,
                        "seconds", "MB", s, false)));
            }
        }
        return files;
    }

    private static String save(Path dir, String name, String svg) throws IOException {
        Files.writeString(dir.resolve(name), svg);
        return name;
    }
}
