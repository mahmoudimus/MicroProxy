package org.microproxy.loadtest.scenario;

import java.util.List;
import java.util.Map;
import org.microproxy.loadtest.Json;

/**
 * A least-squares line through a series, for the soak's leak check: the slope, how much the series
 * grew along the line over the window, and how well the line fits (R²). A steady climb that fits
 * well and grows by more than a threshold is flagged as a possible leak; GC sawtooth and noise fit
 * badly or grow little.
 */
final class Trend {

    private Trend() {}

    /**
     * Fits {@code key} against {@code t} over {@code samples} and flags growth above both
     * {@code minAbsolute} (in the series' unit) and {@code minRelative} of the mean, with R² ≥ 0.5.
     */
    static Map<String, Object> fit(List<Map<String, Object>> samples, String key, double minAbsolute, double minRelative) {
        return fit(samples, key, minAbsolute, minRelative, 0.5);
    }

    /** As {@link #fit(List, String, double, double)}, flagging only fits with R² of at least {@code minR2}. */
    static Map<String, Object> fit(List<Map<String, Object>> samples, String key, double minAbsolute, double minRelative,
            double minR2) {
        double n = 0;
        double sx = 0;
        double sy = 0;
        double sxx = 0;
        double sxy = 0;
        double syy = 0;
        double t0 = Double.NaN;
        double t1 = Double.NaN;
        for (Map<String, Object> m : samples) {
            Object tv = m.get("t");
            Object yv = m.get(key);
            if (!(tv instanceof Number) || !(yv instanceof Number)) continue;
            double x = ((Number) tv).doubleValue();
            double y = ((Number) yv).doubleValue();
            if (y < 0) continue;
            if (Double.isNaN(t0)) t0 = x;
            t1 = x;
            n++;
            sx += x;
            sy += y;
            sxx += x * x;
            sxy += x * y;
            syy += y * y;
        }
        if (n < 3 || t1 <= t0) return Json.obj("key", key, "samples", (long) n, "flagged", false);
        double vx = n * sxx - sx * sx;
        double vy = n * syy - sy * sy;
        double slope = vx == 0 ? 0 : (n * sxy - sx * sy) / vx;
        double r2 = vx == 0 || vy == 0 ? 0 : Math.pow(n * sxy - sx * sy, 2) / (vx * vy);
        double mean = sy / n;
        double growth = slope * (t1 - t0);
        boolean flagged = slope > 0 && r2 >= minR2 && growth > minAbsolute && growth > minRelative * mean;
        return Json.obj("key", key, "samples", (long) n, "windowS", round(t1 - t0), "mean", round(mean),
                "slopePerS", round(slope), "slopePerHour", round(slope * 3600), "growth", round(growth),
                "growthPct", mean == 0 ? 0.0 : round(100 * growth / mean), "r2", round(r2), "flagged", flagged);
    }

    /** The samples at or after {@code fromT}. */
    static List<Map<String, Object>> after(List<Map<String, Object>> samples, double fromT) {
        List<Map<String, Object>> out = new java.util.ArrayList<>();
        for (Map<String, Object> m : samples) {
            if (m.get("t") instanceof Number n && n.doubleValue() >= fromT) out.add(m);
        }
        return out;
    }

    /** The span in seconds between the first and last sample. */
    static double span(List<Map<String, Object>> samples) {
        if (samples.size() < 2) return 0;
        return ((Number) samples.get(samples.size() - 1).get("t")).doubleValue() - ((Number) samples.get(0).get("t")).doubleValue();
    }

    static double round(double v) {
        return Math.round(v * 1000) / 1000.0;
    }
}
