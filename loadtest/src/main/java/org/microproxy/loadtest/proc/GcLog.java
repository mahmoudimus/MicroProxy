package org.microproxy.loadtest.proc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads a proxy's GC log ({@code -Xlog:gc:file=...:uptime,level,tags}): each pause with its time,
 * the heap before and after it, and its length. The heap after each collection is a free series of
 * the live set, without forcing a GC.
 */
public final class GcLog {

    // [0.512s][info][gc] GC(0) Pause Young (Normal) (G1 Evacuation Pause) 23M->4M(256M) 3.456ms
    private static final Pattern PAUSE = Pattern.compile(
            "^\\[(\\d+\\.\\d+)s\\].*GC\\((\\d+)\\) (Pause [^0-9]*?)\\s*(\\d+)([KMG])->(\\d+)([KMG])\\((\\d+)([KMG])\\) (\\d+\\.\\d+)ms");
    // [1.234s][info][gc] GC(0) Garbage Collection (Warmup) 52M(10%)->22M(4%)  (ZGC)
    private static final Pattern ZGC = Pattern.compile(
            "^\\[(\\d+\\.\\d+)s\\].*GC\\((\\d+)\\) (Garbage Collection [^0-9]*?)\\s*(\\d+)([KMG])\\(\\d+%\\)->(\\d+)([KMG])\\(\\d+%\\)");

    private GcLog() {}

    /** One collection. */
    public record Event(double uptime, String type, long beforeKb, long afterKb, long heapKb, double pauseMs) {

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("t", uptime);
            m.put("type", type);
            m.put("beforeKb", beforeKb);
            m.put("afterKb", afterKb);
            m.put("heapKb", heapKb);
            m.put("pauseMs", pauseMs);
            return m;
        }
    }

    /** The log's collections, oldest first; empty if there is no log. */
    public static List<Event> read(Path log) {
        List<Event> out = new ArrayList<>();
        if (log == null || !Files.exists(log)) return out;
        List<String> lines;
        try {
            lines = Files.readAllLines(log);
        } catch (IOException e) {
            return out;
        }
        for (String line : lines) {
            Matcher m = PAUSE.matcher(line);
            if (m.find()) {
                out.add(new Event(Double.parseDouble(m.group(1)), m.group(3).trim(), kb(m.group(4), m.group(5)),
                        kb(m.group(6), m.group(7)), kb(m.group(8), m.group(9)), Double.parseDouble(m.group(10))));
                continue;
            }
            Matcher z = ZGC.matcher(line);
            if (z.find()) {
                out.add(new Event(Double.parseDouble(z.group(1)), z.group(3).trim(), kb(z.group(4), z.group(5)),
                        kb(z.group(6), z.group(7)), -1, 0));
            }
        }
        return out;
    }

    /**
     * A summary of the collections between {@code fromUptime} and {@code toUptime} (seconds of the
     * JVM's uptime): count, total and longest pause, full collections, and the heap after the last.
     */
    public static Map<String, Object> summary(List<Event> events, double fromUptime, double toUptime) {
        int count = 0;
        int full = 0;
        double total = 0;
        double max = 0;
        long lastAfter = -1;
        for (Event e : events) {
            if (e.uptime() < fromUptime || e.uptime() > toUptime) continue;
            count++;
            total += e.pauseMs();
            max = Math.max(max, e.pauseMs());
            if (e.type().contains("Full")) full++;
            lastAfter = e.afterKb();
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("collections", count);
        m.put("fullCollections", full);
        m.put("pauseTotalMs", Math.round(total * 100) / 100.0);
        m.put("pauseMaxMs", Math.round(max * 100) / 100.0);
        m.put("heapAfterLastKb", lastAfter);
        return m;
    }

    /** Every event, for the results file. */
    public static List<Object> toList(List<Event> events) {
        List<Object> out = new ArrayList<>();
        for (Event e : events) out.add(e.toMap());
        return out;
    }

    private static long kb(String v, String unit) {
        long n = Long.parseLong(v);
        return switch (unit) {
            case "M" -> n * 1024;
            case "G" -> n * 1024 * 1024;
            default -> n;
        };
    }
}
