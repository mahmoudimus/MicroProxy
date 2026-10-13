package org.microproxy.loadtest.report;

import java.util.List;
import java.util.Locale;

/**
 * A tiny SVG line-chart writer with no dependencies, used when no plotting library is available.
 * Each chart has labelled axes and one line per series, in two palettes (MicroProxy and
 * LittleProxy). Charts are optional: the report links them when present and reads fine without.
 */
final class Svg {

    private static final String[] COLORS = {"#2563eb", "#dc2626", "#059669", "#d97706", "#7c3aed", "#0891b2"};
    private final int width;
    private final int height;
    private final StringBuilder b = new StringBuilder();

    Svg(int width, int height) {
        this.width = width;
        this.height = height;
    }

    /** One named series of (x, y) points. */
    record Series(String name, List<double[]> points) {}

    /** Renders a line chart; x and y are linear, auto-scaled, with a legend. */
    static String lineChart(String title, String xLabel, String yLabel, List<Series> series, boolean xLog) {
        Svg svg = new Svg(720, 400);
        return svg.draw(title, xLabel, yLabel, series, xLog);
    }

    private String draw(String title, String xLabel, String yLabel, List<Series> series, boolean xLog) {
        double padL = 70;
        double padR = 150;
        double padT = 40;
        double padB = 55;
        double minX = Double.MAX_VALUE;
        double maxX = -Double.MAX_VALUE;
        double minY = 0;
        double maxY = -Double.MAX_VALUE;
        for (Series s : series) {
            for (double[] p : s.points()) {
                if (Double.isNaN(p[0]) || Double.isNaN(p[1]) || p[1] < 0) continue;
                double x = xLog ? Math.log10(Math.max(1, p[0])) : p[0];
                minX = Math.min(minX, x);
                maxX = Math.max(maxX, x);
                maxY = Math.max(maxY, p[1]);
            }
        }
        if (maxX <= minX) maxX = minX + 1;
        if (maxY <= minY) maxY = minY + 1;
        maxY *= 1.1;
        double plotW = width - padL - padR;
        double plotH = height - padT - padB;

        b.append(String.format(Locale.ROOT,
                "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" font-family=\"sans-serif\">%n",
                width, height, width, height));
        b.append("<rect width=\"100%\" height=\"100%\" fill=\"white\"/>\n");
        b.append(text(width / 2.0, 22, title, 15, "middle", "#111", true));
        // Axes.
        b.append(line(padL, padT, padL, padT + plotH, "#888", 1));
        b.append(line(padL, padT + plotH, padL + plotW, padT + plotH, "#888", 1));
        // Gridlines and y labels.
        for (int i = 0; i <= 4; i++) {
            double y = padT + plotH - plotH * i / 4;
            double v = minY + (maxY - minY) * i / 4;
            b.append(line(padL, y, padL + plotW, y, "#eee", 1));
            b.append(text(padL - 8, y + 4, fmt(v), 11, "end", "#444", false));
        }
        // x labels.
        for (int i = 0; i <= 4; i++) {
            double x = padL + plotW * i / 4;
            double lx = minX + (maxX - minX) * i / 4;
            double v = xLog ? Math.pow(10, lx) : lx;
            b.append(text(x, padT + plotH + 18, fmt(v), 11, "middle", "#444", false));
        }
        b.append(text(padL + plotW / 2, height - 10, xLabel, 12, "middle", "#222", false));
        b.append(String.format(Locale.ROOT, "<text transform=\"translate(18,%f) rotate(-90)\" text-anchor=\"middle\" font-size=\"12\" fill=\"#222\">%s</text>%n",
                padT + plotH / 2, esc(yLabel)));

        double finalMinX = minX;
        double finalMaxX = maxX;
        double finalMaxY = maxY;
        for (int si = 0; si < series.size(); si++) {
            Series s = series.get(si);
            String color = COLORS[si % COLORS.length];
            StringBuilder path = new StringBuilder();
            boolean first = true;
            for (double[] p : s.points()) {
                if (Double.isNaN(p[0]) || Double.isNaN(p[1]) || p[1] < 0) continue;
                double px = xLog ? Math.log10(Math.max(1, p[0])) : p[0];
                double x = padL + plotW * (px - finalMinX) / (finalMaxX - finalMinX);
                double y = padT + plotH - plotH * (p[1] - minY) / (finalMaxY - minY);
                path.append(first ? "M" : "L").append(String.format(Locale.ROOT, "%.1f %.1f ", x, y));
                b.append(String.format(Locale.ROOT, "<circle cx=\"%.1f\" cy=\"%.1f\" r=\"2.5\" fill=\"%s\"/>%n", x, y, color));
                first = false;
            }
            b.append(String.format(Locale.ROOT, "<path d=\"%s\" fill=\"none\" stroke=\"%s\" stroke-width=\"2\"/>%n", path, color));
            double ly = padT + 6 + si * 20;
            b.append(line(width - padR + 10, ly, width - padR + 30, ly, color, 2));
            b.append(text(width - padR + 34, ly + 4, s.name(), 11, "start", "#222", false));
        }
        b.append("</svg>\n");
        return b.toString();
    }

    private static String fmt(double v) {
        if (v == 0) return "0";
        double a = Math.abs(v);
        if (a >= 1e9) return String.format(Locale.ROOT, "%.1fG", v / 1e9);
        if (a >= 1e6) return String.format(Locale.ROOT, "%.1fM", v / 1e6);
        if (a >= 1e3) return String.format(Locale.ROOT, "%.1fk", v / 1e3);
        if (a >= 10) return String.format(Locale.ROOT, "%.0f", v);
        return String.format(Locale.ROOT, "%.2f", v);
    }

    private static String line(double x1, double y1, double x2, double y2, String color, double w) {
        return String.format(Locale.ROOT, "<line x1=\"%.1f\" y1=\"%.1f\" x2=\"%.1f\" y2=\"%.1f\" stroke=\"%s\" stroke-width=\"%s\"/>%n",
                x1, y1, x2, y2, color, w);
    }

    private static String text(double x, double y, String s, int size, String anchor, String fill, boolean bold) {
        return String.format(Locale.ROOT, "<text x=\"%.1f\" y=\"%.1f\" font-size=\"%d\" text-anchor=\"%s\" fill=\"%s\"%s>%s</text>%n",
                x, y, size, anchor, fill, bold ? " font-weight=\"bold\"" : "", esc(s));
    }

    private static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
