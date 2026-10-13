package org.microproxy.loadtest.proc;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * What the machine allows: CPUs, memory, the limits that cap connection counts ({@code ulimit -n},
 * {@code somaxconn}, the ephemeral port range, {@code tcp_tw_reuse}, {@code file-max}), whether
 * {@code taskset} and the external load tools are on the {@code PATH}, and which memory cgroup the
 * harness can use.
 */
public final class Environment {

    private Environment() {}

    /** The OS limits and machine facts, for the results file and the report. */
    public static Map<String, Object> describe() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("os", System.getProperty("os.name") + " " + System.getProperty("os.version") + " " + System.getProperty("os.arch"));
        m.put("java", System.getProperty("java.vm.name") + " " + System.getProperty("java.runtime.version"));
        m.put("distribution", distribution());
        m.put("kernel", sysctl("kernel/osrelease"));
        m.put("cpuModel", cpuModel());
        m.put("cpus", allowedCpus());
        m.put("memTotalKb", memTotalKb());
        Map<String, Object> limits = new LinkedHashMap<>();
        limits.put("nofile", ProcStats.maxOpenFiles(ProcessHandle.current().pid()));
        limits.put("somaxconn", sysctl("net/core/somaxconn"));
        limits.put("ip_local_port_range", sysctl("net/ipv4/ip_local_port_range"));
        limits.put("tcp_tw_reuse", sysctl("net/ipv4/tcp_tw_reuse"));
        limits.put("tcp_max_syn_backlog", sysctl("net/ipv4/tcp_max_syn_backlog"));
        limits.put("file-max", sysctl("fs/file-max"));
        limits.put("nr_open", sysctl("fs/nr_open"));
        m.put("limits", limits);
        m.put("taskset", which("taskset").isPresent());
        m.put("cgroup", cgroupKind());
        Map<String, Object> tools = new LinkedHashMap<>();
        for (String tool : List.of("wrk", "h2load", "fortio")) tools.put(tool, which(tool).map(Path::toString).orElse(null));
        m.put("tools", tools);
        return m;
    }

    /** A {@code /proc/sys} value, trimmed, or null. ({@code /proc} files report size 0, so stream them.) */
    public static String sysctl(String path) {
        try {
            byte[] bytes = Files.newInputStream(Path.of("/proc/sys", path)).readAllBytes();
            return new String(bytes, java.nio.charset.StandardCharsets.UTF_8).trim().replaceAll("\\s+", " ");
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * Sets this process's scheduling autogroup nice ({@code /proc/self/autogroup}); false when the
     * kernel has no autogroups or the process may not lower it.
     */
    public static boolean setAutogroupNice(String nice) {
        Path ag = Path.of("/proc/self/autogroup");
        if (!"1".equals(sysctl("kernel/sched_autogroup_enabled")) || !Files.exists(ag)) return false;
        try {
            Files.writeString(ag, nice.trim());
            return Files.readString(ag).trim().endsWith("nice " + nice.trim());
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    /** The size of the ephemeral port range, or 28232 (Linux's default) if unknown. */
    public static int ephemeralPorts() {
        String r = sysctl("net/ipv4/ip_local_port_range");
        if (r == null) return 28232;
        String[] f = r.split(" ");
        return Integer.parseInt(f[1]) - Integer.parseInt(f[0]) + 1;
    }

    /** The CPUs this process may run on, from {@code Cpus_allowed_list}, or 0..n-1. */
    public static List<Integer> allowedCpus() {
        try {
            for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
                if (line.startsWith("Cpus_allowed_list:")) return parseCpuList(line.substring(18).trim());
            }
        } catch (IOException | RuntimeException e) {
            // Not Linux.
        }
        List<Integer> all = new ArrayList<>();
        for (int i = 0; i < Runtime.getRuntime().availableProcessors(); i++) all.add(i);
        return all;
    }

    /** Parses a CPU list such as {@code 0-3,6}. */
    public static List<Integer> parseCpuList(String list) {
        List<Integer> out = new ArrayList<>();
        for (String part : list.split(",")) {
            if (part.isBlank()) continue;
            String[] r = part.trim().split("-");
            int a = Integer.parseInt(r[0]);
            int b = r.length > 1 ? Integer.parseInt(r[1]) : a;
            for (int i = a; i <= b; i++) out.add(i);
        }
        return out;
    }

    /** Formats CPUs as a taskset list. */
    public static String cpuList(List<Integer> cpus) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < cpus.size(); i++) {
            int start = cpus.get(i);
            int end = start;
            while (i + 1 < cpus.size() && cpus.get(i + 1) == end + 1) end = cpus.get(++i);
            if (b.length() > 0) b.append(',');
            b.append(start == end ? Integer.toString(start) : start + "-" + end);
        }
        return b.toString();
    }

    /**
     * The default CPU split: half the CPUs to the proxy, a quarter each to the origin and the load
     * generator (with two CPUs, the origin and the load generator share one); null when there are
     * too few CPUs to pin.
     */
    public static Map<String, String> defaultSplit(List<Integer> cpus) {
        int n = cpus.size();
        if (n < 2) return null;
        Map<String, String> m = new LinkedHashMap<>();
        if (n == 2) {
            m.put("proxy", cpuList(cpus.subList(0, 1)));
            m.put("origin", cpuList(cpus.subList(1, 2)));
            m.put("client", cpuList(cpus.subList(1, 2)));
        } else if (n == 3) {
            m.put("proxy", cpuList(cpus.subList(0, 1)));
            m.put("origin", cpuList(cpus.subList(1, 2)));
            m.put("client", cpuList(cpus.subList(2, 3)));
        } else {
            int proxy = n / 2;
            int origin = Math.max(1, (n - proxy) / 2);
            m.put("proxy", cpuList(cpus.subList(0, proxy)));
            m.put("origin", cpuList(cpus.subList(proxy, proxy + origin)));
            m.put("client", cpuList(cpus.subList(proxy + origin, n)));
        }
        return m;
    }

    /** The executable {@code name} on the PATH. */
    public static Optional<Path> which(String name) {
        String path = System.getenv("PATH");
        if (path == null) return Optional.empty();
        for (String dir : path.split(File.pathSeparator)) {
            Path p = Path.of(dir, name);
            if (Files.isExecutable(p) && !Files.isDirectory(p)) return Optional.of(p);
        }
        return Optional.empty();
    }

    /** "v2", "v1" or "none": the memory cgroup the harness can create children in. */
    public static String cgroupKind() {
        if (Files.exists(Path.of("/sys/fs/cgroup/cgroup.controllers"))) {
            return Files.isWritable(Path.of("/sys/fs/cgroup")) ? "v2" : "none";
        }
        if (Files.isDirectory(Path.of("/sys/fs/cgroup/memory"))) {
            return Files.isWritable(Path.of("/sys/fs/cgroup/memory")) ? "v1" : "none";
        }
        return "none";
    }

    /**
     * Creates a memory cgroup named {@code name} limited to {@code limitBytes}; returns its
     * {@code cgroup.procs} file, or null if the harness cannot.
     */
    public static Path createMemoryCgroup(String name, long limitBytes) {
        try {
            switch (cgroupKind()) {
                case "v2" -> {
                    Path dir = Path.of("/sys/fs/cgroup", name);
                    Files.createDirectories(dir);
                    Files.writeString(dir.resolve("memory.max"), Long.toString(limitBytes));
                    Path swap = dir.resolve("memory.swap.max");
                    if (Files.exists(swap)) Files.writeString(swap, "0");
                    return dir.resolve("cgroup.procs");
                }
                case "v1" -> {
                    Path dir = Path.of("/sys/fs/cgroup/memory", name);
                    Files.createDirectories(dir);
                    Files.writeString(dir.resolve("memory.limit_in_bytes"), Long.toString(limitBytes));
                    return dir.resolve("cgroup.procs");
                }
                default -> {
                    return null;
                }
            }
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /** Whether the cgroup of {@code procs} saw an OOM kill. */
    public static boolean cgroupOomKilled(Path procs) {
        if (procs == null) return false;
        Path dir = procs.getParent();
        try {
            Path events = dir.resolve("memory.events");
            if (Files.exists(events)) {
                for (String line : Files.readAllLines(events)) {
                    if (line.startsWith("oom_kill ") && !line.endsWith(" 0")) return true;
                }
            }
            Path control = dir.resolve("memory.oom_control");
            if (Files.exists(control)) {
                for (String line : Files.readAllLines(control)) {
                    if (line.startsWith("oom_kill ") && !line.endsWith(" 0")) return true;
                }
            }
        } catch (IOException e) {
            return false;
        }
        return false;
    }

    /** Removes a cgroup made by {@link #createMemoryCgroup}, once empty. */
    public static void removeCgroup(Path procs) {
        if (procs == null) return;
        try {
            Files.deleteIfExists(procs.getParent());
        } catch (IOException e) {
            // Still populated; the OS keeps it.
        }
    }

    /** The CPU's model name from {@code /proc/cpuinfo}, or null. */
    static String cpuModel() {
        try {
            for (String line : Files.readAllLines(Path.of("/proc/cpuinfo"))) {
                if (line.startsWith("model name")) return line.substring(line.indexOf(':') + 1).trim();
            }
        } catch (IOException | RuntimeException e) {
            // Not Linux.
        }
        return null;
    }

    /** The distribution's name from {@code /etc/os-release}, or null. */
    static String distribution() {
        try {
            for (String line : Files.readAllLines(Path.of("/etc/os-release"))) {
                if (line.startsWith("PRETTY_NAME=")) return line.substring(12).replace("\"", "").trim();
            }
        } catch (IOException | RuntimeException e) {
            // Not Linux.
        }
        return null;
    }

    private static long memTotalKb() {
        try {
            for (String line : Files.readAllLines(Path.of("/proc/meminfo"))) {
                if (line.startsWith("MemTotal:")) return Long.parseLong(line.replaceAll("[^0-9]", ""));
            }
        } catch (IOException | RuntimeException e) {
            // Not Linux.
        }
        return -1;
    }
}
