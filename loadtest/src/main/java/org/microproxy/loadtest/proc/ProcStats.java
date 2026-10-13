package org.microproxy.loadtest.proc;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads a process's resources from {@code /proc}: resident memory and its peak, threads, open file
 * descriptors and CPU time. Cheap enough to sample every second. On a system without {@code /proc}
 * every value is -1.
 */
public final class ProcStats {

    /** Clock ticks per second of {@code /proc/<pid>/stat}'s CPU times. */
    private static final long CLK_TCK = clockTicks();

    private ProcStats() {}

    /** One sample of a process. */
    public record Sample(long rssKb, long hwmKb, long threads, long fds, long cpuMs) {

        /** The sample as a map, for the results file. */
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("rssKb", rssKb);
            m.put("hwmKb", hwmKb);
            m.put("threads", threads);
            m.put("fds", fds);
            m.put("cpuMs", cpuMs);
            return m;
        }
    }

    /** Samples {@code pid}; null if it is gone. */
    public static Sample sample(long pid) {
        Path dir = Path.of("/proc", Long.toString(pid));
        if (!Files.isDirectory(dir)) return null;
        long rss = -1;
        long hwm = -1;
        long threads = -1;
        try {
            for (String line : Files.readAllLines(dir.resolve("status"))) {
                if (line.startsWith("VmRSS:")) rss = kb(line);
                else if (line.startsWith("VmHWM:")) hwm = kb(line);
                else if (line.startsWith("Threads:")) threads = Long.parseLong(line.substring(8).trim());
            }
        } catch (IOException | RuntimeException e) {
            return null;
        }
        return new Sample(rss, hwm, threads, fds(pid), cpuMs(pid));
    }

    /** Open file descriptors of {@code pid}, or -1. */
    public static long fds(long pid) {
        long n = 0;
        try (DirectoryStream<Path> s = Files.newDirectoryStream(Path.of("/proc", Long.toString(pid), "fd"))) {
            for (Path ignored : s) n++;
        } catch (IOException | RuntimeException e) {
            return -1;
        }
        return n;
    }

    /** User plus system CPU time of {@code pid} in milliseconds, or -1. */
    public static long cpuMs(long pid) {
        try {
            String stat = new String(Files.newInputStream(Path.of("/proc", Long.toString(pid), "stat")).readAllBytes(),
                    java.nio.charset.StandardCharsets.UTF_8);
            // The command name (field 2) may hold spaces: count from the closing parenthesis.
            String[] f = stat.substring(stat.lastIndexOf(')') + 2).split(" ");
            long ticks = Long.parseLong(f[11]) + Long.parseLong(f[12]);
            return ticks * 1000 / CLK_TCK;
        } catch (IOException | RuntimeException e) {
            return -1;
        }
    }

    /**
     * The machine's CPU counters from {@code /proc/stat}: for every CPU, its process time (user, nice
     * and system), its total, and its interrupt time (irq and softirq, which no process is charged
     * with: on loopback, much of it is the benchmark's own traffic), in jiffies; null without
     * {@code /proc}.
     */
    public static Map<Integer, long[]> cpuJiffies() {
        Map<Integer, long[]> out = new LinkedHashMap<>();
        try {
            for (String line : Files.readAllLines(Path.of("/proc/stat"))) {
                if (!line.startsWith("cpu") || line.startsWith("cpu ")) continue;
                String[] f = line.trim().split("\\s+");
                if (!Character.isDigit(f[0].charAt(3))) continue;
                long total = 0;
                for (int i = 1; i < Math.min(f.length, 9); i++) total += Long.parseLong(f[i]);
                long process = Long.parseLong(f[1]) + Long.parseLong(f[2]) + Long.parseLong(f[3]);
                long interrupt = Long.parseLong(f[6]) + Long.parseLong(f[7]);
                out.put(Integer.parseInt(f[0].substring(3)), new long[] {process, total, interrupt});
            }
        } catch (IOException | RuntimeException e) {
            return null;
        }
        return out;
    }

    /** {@code pid}'s soft limit of open files, or -1. */
    public static long maxOpenFiles(long pid) {
        try {
            for (String line : Files.readAllLines(Path.of("/proc", Long.toString(pid), "limits"))) {
                if (line.startsWith("Max open files")) {
                    String[] f = line.substring("Max open files".length()).trim().split("\\s+");
                    return f[0].equals("unlimited") ? Long.MAX_VALUE : Long.parseLong(f[0]);
                }
            }
        } catch (IOException | RuntimeException e) {
            // Not Linux.
        }
        return -1;
    }

    private static long kb(String line) {
        String[] f = line.split("\\s+");
        return Long.parseLong(f[1]);
    }

    private static long clockTicks() {
        try {
            Process p = new ProcessBuilder(List.of("getconf", "CLK_TCK")).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            return Long.parseLong(out);
        } catch (IOException | RuntimeException e) {
            return 100;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return 100;
        }
    }
}
