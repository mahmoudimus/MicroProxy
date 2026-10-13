package org.microproxy.loadtest.scenario;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.microproxy.loadtest.Json;
import org.microproxy.loadtest.Settings;
import org.microproxy.loadtest.proc.Environment;
import org.microproxy.loadtest.proc.GcLog;
import org.microproxy.loadtest.proc.ManagedProcess;

/**
 * A proxy under test in a process of its own. The built-in proxies run in a JVM: MicroProxy through
 * its real launcher ({@code org.microproxy.Launcher}, from the project's jars) or LittleProxy through
 * {@link org.microproxy.loadtest.proxy.LittleProxyLauncher}, both configured alike (forward proxy on
 * a loopback port, the same idle and connect timeouts, errors-only logging) and started with Native
 * Memory Tracking, a GC log, an OOM marker, optionally JFR, the configured heap, direct memory,
 * {@code MaxRAM} and memory cgroup limits. An external proxy ({@link ExternalProxy}) runs its own
 * command with its configuration rendered from a template; of the memory caps only the cgroup
 * limit applies to it. Every proxy is pinned to the proxy's CPUs.
 */
public final class ProxyProcess implements AutoCloseable {

    /** How a scenario wants the proxy started. */
    record Options(int idleTimeoutSeconds, String heap, String direct, String cgroupLimit, boolean h2c) {}

    final String kind;
    final String label;
    final ManagedProcess process;
    final int port;
    final int adminPort;
    final Path gcLog;
    final Path oomFlag;
    final Path jfr;
    final Path cgroupProcs;
    final List<String> command;
    /** Whether the proxy runs in a JVM: false for an external proxy, which has no NMT, heap or GC log. */
    final boolean jvm;
    /** The rendered configuration file of an external proxy, or null. */
    final Path config;
    private final RunContext ctx;

    private ProxyProcess(RunContext ctx, String kind, String label, ManagedProcess process, int port, int adminPort,
            Path gcLog, Path oomFlag, Path jfr, Path cgroupProcs, List<String> command, boolean jvm, Path config) {
        this.ctx = ctx;
        this.jvm = jvm;
        this.config = config;
        this.kind = kind;
        this.label = label;
        this.process = process;
        this.port = port;
        this.adminPort = adminPort;
        this.gcLog = gcLog;
        this.oomFlag = oomFlag;
        this.jfr = jfr;
        this.cgroupProcs = cgroupProcs;
        this.command = command;
    }

    /** The default options: the run's idle timeout and memory settings, HTTP/1 only. */
    static Options defaults(Settings s) {
        return new Options(s.getInt("idle-timeout"), s.get("proxy-heap"), s.get("proxy-direct"), s.get("proxy-cgroup-limit"), false);
    }

    /** Starts {@code kind} for the scenario {@code label} and waits until it accepts connections. */
    static ProxyProcess start(RunContext ctx, String kind, String label, Options o) throws IOException, InterruptedException {
        Settings s = ctx.settings;
        Path logs = ctx.out.resolve("logs");
        Files.createDirectories(logs);
        String base = kind + "-" + label;
        if (!ctx.isJvm(kind)) return startExternal(ctx, ctx.externals.get(kind), label, base, logs, o);
        boolean admin = kind.equals("microproxy") && s.getBool("mp-admin");
        int[] ports = RunContext.freePorts(admin ? 2 : 1);
        int port = ports[0];
        int adminPort = admin ? ports[1] : 0;
        Path gcLog = logs.resolve(base + "-gc.log");
        Path oomFlag = logs.resolve(base + ".oom");
        Files.deleteIfExists(oomFlag);
        Files.deleteIfExists(gcLog);
        Path jfr = s.getBool("jfr") ? logs.resolve(base + ".jfr") : null;

        List<String> cmd = new ArrayList<>();
        Path procs = null;
        if (!o.cgroupLimit().isBlank()) {
            procs = Environment.createMemoryCgroup("microproxy-loadtest-" + ProcessHandle.current().pid() + "-" + base,
                    Settings.bytes(o.cgroupLimit()));
            if (procs != null) {
                cmd.addAll(List.of("sh", "-c", "echo $$ > '" + procs + "' && exec \"$@\"", "sh"));
            } else {
                ctx.notes.add("No writable memory cgroup: the " + o.cgroupLimit() + " limit for " + base
                        + " fell back to -XX:MaxRAM.");
            }
        }
        cmd.addAll(ctx.pinPrefix("proxy"));
        cmd.add(RunContext.java());
        cmd.add("-Xmx" + o.heap());
        if (!o.direct().isBlank()) cmd.add("-XX:MaxDirectMemorySize=" + o.direct());
        if (!s.get("proxy-max-ram").isBlank()) cmd.add("-XX:MaxRAM=" + s.get("proxy-max-ram"));
        else if (!o.cgroupLimit().isBlank() && procs == null) cmd.add("-XX:MaxRAM=" + o.cgroupLimit());
        cmd.add("-XX:+Use" + s.get("proxy-gc") + "GC");
        cmd.add("-XX:NativeMemoryTracking=summary");
        cmd.add("-Xlog:gc:file=" + gcLog + ":uptime,level,tags");
        cmd.add("-XX:OnOutOfMemoryError=touch " + oomFlag);
        if (jfr != null) cmd.add("-XX:StartFlightRecording=filename=" + jfr + ",settings=profile,dumponexit=true");
        cmd.addAll(s.getArgs("proxy-jvm-args"));
        boolean quiet = s.get("proxy-log-level").equals("off");
        if (kind.equals("microproxy")) {
            Path logging = logs.resolve("microproxy-logging.properties");
            String level = quiet ? "OFF" : "SEVERE";
            Files.writeString(logging, "handlers=java.util.logging.ConsoleHandler\n.level=" + level
                    + "\njava.util.logging.ConsoleHandler.level=" + level + "\n");
            cmd.add("-Djava.util.logging.config.file=" + logging);
            cmd.addAll(List.of("-cp", ctx.microproxyLib.resolve("*").toString(), "org.microproxy.Launcher",
                    "--port", Integer.toString(port), "--idle-timeout", Integer.toString(o.idleTimeoutSeconds()),
                    "--connect-timeout", s.get("connect-timeout-ms"), "--proxy-alias", "loadtest"));
            if (adminPort > 0) cmd.addAll(List.of("--admin-port", Integer.toString(adminPort)));
            if (o.h2c()) cmd.add("--http2-cleartext");
            cmd.addAll(s.getArgs("mp-args"));
        } else if (kind.equals("littleproxy")) {
            cmd.add("-Dorg.slf4j.simpleLogger.defaultLogLevel=" + (quiet ? "off" : "error"));
            cmd.add("-Dorg.slf4j.simpleLogger.logFile=System.out");
            cmd.addAll(List.of("-cp", ctx.harnessJar.toString(), "org.microproxy.loadtest.proxy.LittleProxyLauncher",
                    "--port", Integer.toString(port), "--idle-timeout", Integer.toString(o.idleTimeoutSeconds()),
                    "--connect-timeout", s.get("connect-timeout-ms")));
            if (s.getInt("lp-workers") > 0) cmd.addAll(List.of("--workers", s.get("lp-workers")));
        } else {
            throw new IllegalArgumentException("unknown proxy " + kind);
        }
        ManagedProcess p = ManagedProcess.start(base, cmd, logs.resolve(base + ".log"), null);
        ProxyProcess proxy = new ProxyProcess(ctx, kind, label, p, port, adminPort, gcLog, oomFlag, jfr, procs, cmd, true, null);
        if (!RunContext.awaitPort(p, port, Duration.ofSeconds(60))) {
            proxy.close();
            throw new IOException(kind + " did not start listening; see " + p.log());
        }
        return proxy;
    }

    /**
     * Starts an external proxy: renders its configuration template into the run's logs, then runs
     * its command pinned to the proxy's CPUs, inside a memory cgroup when {@code o} sets a limit.
     * The JVM-only options (heap, direct memory, GC, NMT, JFR) do not apply.
     */
    private static ProxyProcess startExternal(RunContext ctx, ExternalProxy def, String label, String base, Path logs,
            Options o) throws IOException, InterruptedException {
        Settings s = ctx.settings;
        int port = RunContext.freePort();
        Map<String, String> values = def.baseValues();
        values.put("port", Integer.toString(port));
        values.put("idleSeconds", Integer.toString(o.idleTimeoutSeconds()));
        long connectMs = s.getLong("connect-timeout-ms");
        values.put("connectTimeoutMs", Long.toString(connectMs));
        values.put("connectTimeoutSeconds", connectMs % 1000 == 0 ? Long.toString(connectMs / 1000)
                : String.format(java.util.Locale.ROOT, "%.3f", connectMs / 1000.0));
        values.put("workers", Integer.toString(ctx.cpuCount("proxy")));
        values.put("logs", logs.toAbsolutePath().toString());
        values.put("name", base);
        Path config = null;
        if (def.config() != null) {
            Path template = def.home().resolve(def.config());
            String file = template.getFileName().toString();
            config = logs.resolve(base + "-" + file).toAbsolutePath();
            values.put("config", config.toString());
            Files.writeString(config, ExternalProxy.render(Files.readString(template), values));
        }
        List<String> cmd = new ArrayList<>();
        Path procs = null;
        if (!o.cgroupLimit().isBlank()) {
            procs = Environment.createMemoryCgroup("microproxy-loadtest-" + ProcessHandle.current().pid() + "-" + base,
                    Settings.bytes(o.cgroupLimit()));
            if (procs != null) {
                cmd.addAll(List.of("sh", "-c", "echo $$ > '" + procs + "' && exec \"$@\"", "sh"));
            } else {
                ctx.notes.add("No writable memory cgroup: " + base + " ran without its " + o.cgroupLimit()
                        + " memory limit (an external proxy has no JVM flag to fall back on).");
            }
        }
        cmd.addAll(ctx.pinPrefix("proxy"));
        for (String c : def.command()) cmd.add(ExternalProxy.render(c, values));
        Map<String, String> env = new LinkedHashMap<>();
        def.env().forEach((k, v) -> env.put(k, ExternalProxy.render(v, values)));
        Path oomFlag = logs.resolve(base + ".oom");
        Files.deleteIfExists(oomFlag);
        ManagedProcess p = ManagedProcess.start(base, cmd, logs.resolve(base + ".log"), env);
        ProxyProcess proxy = new ProxyProcess(ctx, def.name(), label, p, port, 0, logs.resolve(base + "-gc.log"), oomFlag,
                null, procs, cmd, false, config);
        if (!RunContext.awaitPort(p, port, Duration.ofSeconds(60))) {
            proxy.close();
            throw new IOException(def.name() + " did not start listening; see " + p.log());
        }
        return proxy;
    }

    /** The JVM's process id. */
    long pid() {
        return process.pid();
    }

    /** Whether the proxy still runs. */
    boolean alive() {
        return process.alive();
    }

    /** Seconds since the JVM started (close to its own uptime, which the GC log uses). */
    double uptime() {
        return process.uptimeSeconds();
    }

    /** Whether the proxy ran out of memory: the OOM marker, its log, or a cgroup OOM kill. */
    boolean oom() {
        if (!jvm) {
            // An external proxy: the cgroup's OOM killer, or a runtime's own out-of-memory abort.
            return Environment.cgroupOomKilled(cgroupProcs) || process.logContains("runtime: out of memory")
                    || process.logContains("std::bad_alloc");
        }
        // "java.lang.OutOfMemoryError" in the log, not the "-XX:OnOutOfMemoryError" flag echoed in it.
        return Files.exists(oomFlag) || process.logContains("java.lang.OutOfMemoryError")
                || process.logContains("OutOfMemoryError: ") || Environment.cgroupOomKilled(cgroupProcs);
    }

    /** What happened to the proxy: running, out of memory, or exited with a code. */
    String state() {
        if (oom()) return alive() ? "oom (still running)" : "oom";
        if (alive()) return "running";
        Integer code = process.exitCode();
        return "exited " + code + (code != null && code == 137 ? " (killed)" : "");
    }

    /** The GC log's collections so far. */
    List<GcLog.Event> gcEvents() {
        if (!jvm) return List.of();
        return GcLog.read(gcLog);
    }

    /** NMT, heap after a forced GC (a JVM only), and /proc figures now. */
    Map<String, Object> memorySnapshot(boolean forceGc) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (!alive()) return m;
        if (jvm && forceGc) m.put("heapAfterGcKb", ctx.jcmd.heapAfterGcKb(pid()));
        m.put("nmt", jvm ? ctx.jcmd.nmt(pid()) : Map.of());
        var s = org.microproxy.loadtest.proc.ProcStats.sample(pid());
        if (s != null) m.putAll(s.toMap());
        return m;
    }

    /** MicroProxy's own stats from its admin listener (name to value), or empty. */
    Map<String, Object> adminStats() {
        Map<String, Object> m = new LinkedHashMap<>();
        if (adminPort <= 0 || !alive()) return m;
        try {
            HttpURLConnection c = (HttpURLConnection) URI.create("http://127.0.0.1:" + adminPort + "/stats?format=json&usedonly")
                    .toURL().openConnection(Proxy.NO_PROXY);
            c.setConnectTimeout(2000);
            c.setReadTimeout(5000);
            try (InputStream in = c.getInputStream()) {
                Map<String, Object> json = Json.parseObject(new String(in.readAllBytes(), StandardCharsets.UTF_8));
                for (Map<String, Object> stat : Json.getObjects(json, "stats")) {
                    if (stat.containsKey("name") && stat.get("value") instanceof Number) m.put(stat.get("name").toString(), stat.get("value"));
                }
            }
        } catch (IOException | RuntimeException e) {
            m.put("error", e.toString());
        }
        return m;
    }

    /** A description for the results file. */
    Map<String, Object> describe() {
        return Json.obj("kind", kind, "label", label, "jvm", jvm, "pid", pid(), "port", port, "adminPort", adminPort,
                "command", command, "cgroup", cgroupProcs == null ? null : cgroupProcs.getParent().toString(),
                "log", ctx.out.relativize(process.log()).toString(),
                "gcLog", jvm ? ctx.out.relativize(gcLog).toString() : null,
                "config", config == null ? null : ctx.out.toAbsolutePath().relativize(config).toString(),
                "jfr", jfr == null ? null : ctx.out.relativize(jfr).toString());
    }

    @Override
    public void close() {
        if (jfr != null && alive()) ctx.jcmd.jfrDump(pid(), jfr);
        process.stop(Duration.ofSeconds(3));
        Environment.removeCgroup(cgroupProcs);
    }
}
