package org.microproxy.loadtest.scenario;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.microproxy.loadtest.Json;
import org.microproxy.loadtest.Settings;
import org.microproxy.loadtest.client.ClientControl;
import org.microproxy.loadtest.proc.Environment;
import org.microproxy.loadtest.proc.Jcmd;
import org.microproxy.loadtest.proc.ManagedProcess;

/**
 * Everything a scenario needs: the settings, where results go, how to start JVMs (pinned to
 * their CPUs when {@code taskset} is present), the shared origin, and the checks that decide
 * whether the harness itself worked (as opposed to how well a proxy did).
 */
public final class RunContext {

    /** The proxies the harness can test. */
    public static final List<String> PROXIES = List.of("microproxy", "littleproxy");

    final Settings settings;
    final Path out;
    final Path harnessJar;
    final Path microproxyLib;
    final Map<String, String> cpus;
    final Jcmd jcmd;
    final Map<String, Object> environment;
    final Properties versions = new Properties();
    final List<Map<String, Object>> checks = new ArrayList<>();
    final List<Map<String, Object>> verdicts = new ArrayList<>();
    final List<String> notes = new ArrayList<>();
    ManagedProcess origin;
    int originPort;
    List<String> originAddresses = List.of("127.0.0.1");
    Map<String, Object> relays = new LinkedHashMap<>();

    RunContext(Settings settings, Path out, Path harnessJar, Path microproxyLib) throws IOException {
        this.settings = settings;
        this.out = out;
        this.harnessJar = harnessJar;
        this.microproxyLib = microproxyLib;
        this.environment = Environment.describe();
        try (InputStream in = RunContext.class.getResourceAsStream("/org/microproxy/loadtest/versions.properties")) {
            if (in != null) versions.load(in);
        }
        boolean taskset = Boolean.TRUE.equals(environment.get("taskset"));
        Map<String, String> split = null;
        if (!settings.get("pin").equals("off") && taskset) {
            split = Environment.defaultSplit(Environment.allowedCpus());
            if (split != null) {
                for (String role : List.of("proxy", "origin", "client")) {
                    String v = settings.get("cpus-" + role);
                    if (!v.equals("auto")) split.put(role, v);
                }
            }
        }
        this.cpus = split;
        if (split == null) {
            notes.add(taskset ? "Processes ran unpinned: too few CPUs to give each its own."
                    : "Processes ran unpinned: taskset is not on the PATH, so the proxy, origin and load generator shared every CPU.");
        }
        this.jcmd = new Jcmd(pinPrefix("client"));
    }

    /** The {@code taskset -c} prefix for {@code role}, or nothing when unpinned. */
    List<String> pinPrefix(String role) {
        if (cpus == null || cpus.get(role) == null) return List.of();
        return List.of("taskset", "-c", cpus.get(role));
    }

    /** The java executable running the harness. */
    static String java() {
        Path p = Path.of(System.getProperty("java.home"), "bin", "java");
        return Files.isExecutable(p) ? p.toString() : "java";
    }

    /** A free TCP port on the loopback address. */
    static int freePort() throws IOException {
        return freePorts(1)[0];
    }

    /**
     * {@code n} distinct free TCP ports on the loopback address. The sockets are held open together
     * so the OS hands out different ports (two sequential binds can otherwise reuse the just-freed
     * port), then closed before the ports are used.
     */
    static int[] freePorts(int n) throws IOException {
        List<ServerSocket> sockets = new ArrayList<>();
        int[] ports = new int[n];
        try {
            for (int i = 0; i < n; i++) {
                ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
                sockets.add(s);
                ports[i] = s.getLocalPort();
            }
        } finally {
            for (ServerSocket s : sockets) {
                try {
                    s.close();
                } catch (IOException e) {
                    // Already closed.
                }
            }
        }
        return ports;
    }

    /** Waits until {@code port} accepts connections, or the process dies; false on timeout. */
    static boolean awaitPort(ManagedProcess p, int port, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            if (!p.alive()) return false;
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 500);
                return true;
            } catch (IOException e) {
                Thread.sleep(50);
            }
        }
        return false;
    }

    /** The loopback addresses the origin listens on: 127.0.0.1, then 127.0.1.1, 127.0.1.2, ... */
    static List<String> originAddresses(int count) {
        List<String> out = new ArrayList<>();
        out.add("127.0.0.1");
        for (int i = 1; i < count; i++) out.add("127.0.1." + i);
        return out;
    }

    /** The load generator's source addresses: 127.0.0.2, 127.0.0.3, ... */
    static List<String> sourceAddresses(int count) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < count; i++) out.add("127.0.0." + (2 + i));
        return out;
    }

    /** Starts the origin (once per run) with its fault relays. */
    void startOrigin(int addresses) throws IOException, InterruptedException {
        originAddresses = originAddresses(addresses);
        List<String> cmd = new ArrayList<>(pinPrefix("origin"));
        cmd.addAll(List.of(java(), "-Xmx" + settings.get("origin-heap"), "-XX:+UseParallelGC", "-cp", harnessJar.toString(),
                "org.microproxy.loadtest.Main", "origin", "--addresses", String.join(",", originAddresses)));
        long latency = settings.getLong("fault-latency-ms");
        long bps = settings.getLong("fault-bandwidth-bps");
        for (String relay : List.of("latency:latency:ms=" + latency, "bandwidth:bandwidth:bps=" + bps,
                "reset-before-headers:reset:after=0", "reset-mid-body:reset:after=16384", "stall-mid-body:stall:after=16384",
                "blackhole:blackhole")) {
            cmd.add("--relay");
            cmd.add(relay);
        }
        origin = ManagedProcess.start("origin", cmd, out.resolve("logs/origin.log"), null);
        String line = origin.nextProtocolLine(Duration.ofSeconds(30));
        if (line == null) throw new IOException("the origin did not start; see " + origin.log());
        Map<String, Object> ready = Json.parseObject(line);
        originPort = (int) Json.getLong(ready, "port", 0);
        relays = Json.getObject(ready, "relays");
    }

    /** The origin's URL for {@code path} on its {@code i}-th address. */
    String originUrl(int i, String path) {
        return "http://" + originAddresses.get(i % originAddresses.size()) + ":" + originPort + path;
    }

    /** The URL of {@code path} through the relay named {@code relay}. */
    String relayUrl(String relay, String path) {
        return "http://127.0.0.1:" + Json.getLong(relays, relay, 0) + path;
    }

    /** Starts a load generator for {@code proxyPort}, with {@code sources} source addresses. */
    ClientControl startClient(String label, int proxyPort, List<String> sources) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>(pinPrefix("client"));
        cmd.addAll(List.of(java(), "-Xmx" + settings.get("client-heap"), "-Xss512k", "-XX:+UseParallelGC", "-cp",
                harnessJar.toString(), "org.microproxy.loadtest.Main", "client"));
        ManagedProcess p = ManagedProcess.start("client", cmd, out.resolve("logs/client-" + label + ".log"), null);
        ClientControl c = new ClientControl(p);
        c.call(Json.obj("cmd", "config", "proxyHost", "127.0.0.1", "proxyPort", proxyPort, "sources", sources,
                "perSource", settings.getInt("ramp-per-source"), "connectTimeoutMs", 5000, "readTimeoutMs",
                settings.getInt("request-timeout-ms")), Duration.ofSeconds(30));
        return c;
    }

    /**
     * Records a self-check of the harness (a scenario ran, responses validated, metrics were
     * sampled, a report was written): a failed one fails the run, whichever proxy it concerns.
     */
    void check(String proxy, String scenario, String what, boolean ok, String detail) {
        checks.add(Json.obj("proxy", proxy, "scenario", scenario, "check", what, "ok", ok, "detail", detail));
        if (!ok) System.err.println("[loadtest] harness check failed: " + proxy + "/" + scenario + ": " + what + ": " + detail);
    }

    /**
     * Records a verdict on the proxy under test, such as bounded, unbounded-growth or oom for a
     * memory workload, a leak flag, or a fault's outcome. {@code pass} is true, false, or null for
     * inconclusive (the window was too short to tell), which never fails a run. Whether a failed
     * verdict fails the run depends on the {@code gate} setting (see {@link Orchestrator}).
     */
    void verdict(String proxy, String scenario, String subject, String verdict, Boolean pass, String detail) {
        verdicts.add(Json.obj("proxy", proxy, "scenario", scenario, "subject", subject, "verdict", verdict, "pass", pass,
                "detail", detail));
        if (Boolean.FALSE.equals(pass)) {
            System.err.println("[loadtest] verdict: " + proxy + "/" + scenario + "/" + subject + " = " + verdict + ": " + detail);
        }
    }

    /** Logs progress to standard error. */
    static void log(String msg) {
        System.err.println("[loadtest] " + msg);
    }
}
