package org.microproxy.loadtest.proc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Runs {@code jcmd} against a proxy JVM: Native Memory Tracking summaries, a forced GC and the
 * heap in use after it. Each call starts a {@code jcmd} JVM (a few hundred milliseconds of CPU), so
 * the scenarios call it between steps, or pinned to the load generator's CPUs.
 */
public final class Jcmd {

    private static final Pattern NMT_TOTAL = Pattern.compile("Total: reserved=(\\d+)KB, committed=(\\d+)KB");
    private static final Pattern NMT_CATEGORY = Pattern.compile("^-\\s+(.+?) \\(reserved=(\\d+)KB, committed=(\\d+)KB\\)");
    private static final Pattern NMT_THREADS = Pattern.compile("\\(thread #(\\d+)\\)");
    private static final Pattern HEAP_USED = Pattern.compile("used (\\d+)([KMG])");

    private final List<String> prefix;

    /**
     * A jcmd runner; {@code prefix} goes before the command (such as {@code taskset -c 3}), and may
     * be empty.
     */
    public Jcmd(List<String> prefix) {
        this.prefix = List.copyOf(prefix);
    }

    /** Runs {@code jcmd pid command...}; returns its output, or null if it failed. */
    public String run(long pid, String... command) {
        List<String> cmd = new ArrayList<>(prefix);
        cmd.add(jcmdPath());
        cmd.add(Long.toString(pid));
        cmd.addAll(List.of(command));
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(false);
            pb.environment().remove("JAVA_TOOL_OPTIONS");
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            Process p = pb.start();
            byte[] out = p.getInputStream().readAllBytes();
            if (!p.waitFor(60, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return null;
            }
            return p.exitValue() == 0 ? new String(out, StandardCharsets.UTF_8) : null;
        } catch (IOException e) {
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /**
     * The NMT summary of {@code pid} (committed KB per category, and {@code total}); empty if the
     * JVM does not track native memory or is gone. Also derives {@code heap}, {@code thread},
     * {@code class}, {@code gc}, {@code other} (where direct buffers are counted) and
     * {@code nonHeap} (total minus heap).
     */
    public Map<String, Object> nmt(long pid) {
        String out = run(pid, "VM.native_memory", "summary", "scale=KB");
        return parseNmt(out);
    }

    /** Parses {@code VM.native_memory summary scale=KB} output. */
    public static Map<String, Object> parseNmt(String out) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (out == null) return m;
        Map<String, Object> categories = new LinkedHashMap<>();
        String last = null;
        for (String line : out.split("\n")) {
            Matcher t = NMT_TOTAL.matcher(line);
            if (t.find()) {
                m.put("totalKb", Long.parseLong(t.group(2)));
                m.put("reservedKb", Long.parseLong(t.group(1)));
                continue;
            }
            Matcher c = NMT_CATEGORY.matcher(line.trim().isEmpty() ? "" : line.stripLeading());
            if (c.find()) {
                last = c.group(1).trim();
                categories.put(last, Long.parseLong(c.group(3)));
                continue;
            }
            Matcher th = NMT_THREADS.matcher(line);
            if (th.find() && "Thread".equals(last)) m.put("threadCount", Long.parseLong(th.group(1)));
        }
        if (m.isEmpty()) return m;
        long heap = (Long) categories.getOrDefault("Java Heap", 0L);
        m.put("heapKb", heap);
        m.put("threadKb", categories.getOrDefault("Thread", 0L));
        m.put("classKb", categories.getOrDefault("Class", 0L));
        m.put("gcKb", categories.getOrDefault("GC", 0L));
        m.put("otherKb", categories.getOrDefault("Other", 0L));
        m.put("nonHeapKb", ((Long) m.get("totalKb")) - heap);
        m.put("categoriesKb", categories);
        return m;
    }

    /** Forces a full collection ({@code GC.run}). */
    public boolean gc(long pid) {
        return run(pid, "GC.run") != null;
    }

    /** The heap in use, in KB, per {@code GC.heap_info}; -1 if unknown. */
    public long heapUsedKb(long pid) {
        return parseHeapUsed(run(pid, "GC.heap_info"));
    }

    /** Parses {@code GC.heap_info}: the sum of the heap's "used" figures, metaspace excluded. */
    public static long parseHeapUsed(String out) {
        if (out == null) return -1;
        long total = 0;
        boolean found = false;
        for (String line : out.split("\n")) {
            String l = line.toLowerCase();
            if (l.contains("metaspace") || l.contains("class space")) continue;
            Matcher m = HEAP_USED.matcher(line);
            if (m.find()) {
                long v = Long.parseLong(m.group(1));
                total += switch (m.group(2)) {
                    case "M" -> v * 1024;
                    case "G" -> v * 1024 * 1024;
                    default -> v;
                };
                found = true;
                // G1 and Z print the whole heap on their first line.
                if (l.contains("garbage-first heap") || l.contains("zheap") || l.contains("shenandoah")) break;
            }
        }
        return found ? total : -1;
    }

    /** Forces a GC, then reads the heap in use (KB). */
    public long heapAfterGcKb(long pid) {
        if (!gc(pid)) return -1;
        return heapUsedKb(pid);
    }

    /** Dumps a running JFR recording to {@code file}. */
    public void jfrDump(long pid, Path file) {
        run(pid, "JFR.dump", "filename=" + file.toAbsolutePath());
    }

    private static String jcmdPath() {
        Path p = Path.of(System.getProperty("java.home"), "bin", "jcmd");
        return Files.isExecutable(p) ? p.toString() : "jcmd";
    }
}
