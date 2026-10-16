package org.microproxy.loadtest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The run's settings: a preset's values ({@code smoke}, {@code standard} or {@code full}) with
 * {@code --name value} overrides from the command line. Every setting is kept as a string and
 * written to the results file as it was used, so a run can be repeated exactly.
 */
public final class Settings {

    /** The presets' names, in increasing size. */
    public static final List<String> PRESETS = List.of("smoke", "standard", "full");

    /** Every setting: name, then its smoke, standard and full values, then what it means. */
    private static final String[][] TABLE = {
        // General
        {"proxies", "microproxy,littleproxy", "microproxy,littleproxy", "microproxy,littleproxy", "the proxies to test, in order: microproxy, littleproxy, or a name from external-proxies"},
        {"external-proxies", "", "", "", "a JSON file of external (non-JVM) proxies to test, such as loadtest/competitors/proxies.json; empty for none"},
        {"scenarios", "sweep,ramp,memory,soak,faults", "sweep,ramp,memory,soak,faults", "sweep,ramp,memory,soak,faults", "the scenarios to run, in order"},
        {"gate", "microproxy", "microproxy", "microproxy", "whose failed verdicts fail the run: microproxy (the system under development), all, or none; harness self-checks always do"},
        {"pin", "auto", "auto", "auto", "auto: pin each process to its own CPUs with taskset when present; off: never"},
        {"cpus-proxy", "auto", "auto", "auto", "CPU list for the proxy under test (taskset -c syntax), auto splits the allowed CPUs"},
        {"cpus-origin", "auto", "auto", "auto", "CPU list for the origin"},
        {"cpus-client", "auto", "auto", "auto", "CPU list for the load generator (and jcmd)"},
        {"nice", "", "", "", "a nice value (e.g. -20) for the proxy, origin and load generator, so that other work on a shared machine yields to them; empty for none"},
        {"proxy-heap", "512m", "1g", "2g", "the proxy's -Xmx"},
        {"proxy-direct", "", "", "", "the proxy's -XX:MaxDirectMemorySize, empty for the JVM default"},
        {"proxy-max-ram", "", "", "", "the proxy's -XX:MaxRAM, empty for none"},
        {"proxy-cgroup-limit", "", "", "", "a memory cgroup limit for the proxy in every scenario (e.g. 2g), empty for none; needs a writable cgroup"},
        {"proxy-gc", "G1", "G1", "G1", "the proxies' garbage collector: G1, Parallel, Serial or Z"},
        {"proxy-jvm-args", "", "", "", "extra JVM arguments for both proxies, space-separated"},
        {"proxy-java", "", "", "", "the java executable for the JVM proxies, empty for the harness's own (to compare JDK versions)"},
        {"proxy-log-level", "error", "error", "error", "the proxies' log level: error or off"},
        {"jfr", "false", "false", "false", "record a JFR file (profile settings) of each proxy run"},
        {"idle-timeout", "70", "70", "70", "both proxies' idle connection timeout in seconds (matches the JMH benchmarks)"},
        {"connect-timeout-ms", "40000", "40000", "40000", "both proxies' upstream connect timeout in ms (matches the JMH benchmarks)"},
        {"lp-workers", "0", "0", "0", "LittleProxy's client-to-proxy and proxy-to-server worker threads (0 = Netty's defaults)"},
        {"mp-admin", "true", "false", "false", "enable MicroProxy's admin listener (implies its metrics) to read /stats?format=json"},
        {"mp-args", "", "", "", "extra MicroProxy launcher flags, space-separated"},
        {"client-heap", "1g", "2g", "4g", "the load generator's -Xmx"},
        {"origin-heap", "512m", "1g", "2g", "the origin's -Xmx"},
        {"request-timeout-ms", "10000", "10000", "10000", "the load generator's read timeout per response"},
        {"slo-p99-ms", "100", "50", "50", "the p99 latency (ms) above which a rate step is past the knee"},
        {"error-tolerance", "0.001", "0.001", "0.001", "the error ratio above which a rate step is past the knee"},
        {"external", "auto", "auto", "auto", "auto: cross-check with wrk2, h2load and Fortio when on PATH; off: never"},
        {"crosscheck-seconds", "3", "15", "30", "how long each external cross-check runs"},
        {"charts", "true", "true", "true", "write SVG charts next to the report"},
        // Rate sweep
        {"sweep-start-rate", "200", "1000", "2000", "the first step's target rate (requests/s)"},
        {"sweep-factor", "1.5", "1.5", "1.5", "each step's rate is the previous one's times this"},
        {"sweep-max-rate", "1000000", "1000000", "2000000", "the highest rate to try"},
        {"sweep-max-steps", "3", "20", "30", "the most steps to run"},
        {"sweep-step-seconds", "2", "15", "30", "how long each step runs"},
        {"sweep-warmup-seconds", "2", "10", "30", "a warm-up at the first rate, not recorded"},
        {"sweep-connections", "16", "128", "512", "keep-alive connections the load is spread over"},
        {"sweep-response-bytes", "128", "128", "128", "the response body size"},
        {"sweep-steps-after-knee", "1", "1", "2", "steps to run past the knee, to show the curve"},
        {"sweep-knee-confirm", "1", "1", "1", "unsustainable steps in a row that make the knee (2 or more lets a lone noisy step pass)"},
        {"sweep-refine-steps", "2", "4", "6", "after the knee, probes bisecting between the last sustained step and the knee (0: off); an unsustained probe is repeated like a knee step"},
        {"sweep-refine-precision", "0.02", "0.02", "0.02", "refinement stops once the knee's bracket (highest sustained to lowest unsustained rate) is within this ratio"},
        {"sweep-refine-settle-seconds", "1", "2", "3", "unrecorded load at the bracket's lower rate before each refinement probe"},
        // Connection ramp
        {"ramp-steps", "200,500,1000", "1000,5000,10000,25000,50000", "1000,5000,10000,25000,50000,100000,150000,200000", "idle connections to hold at each step"},
        {"ramp-warm", "true", "true", "true", "send one request on each connection before it idles (so the proxy also holds an upstream connection)"},
        {"ramp-parallel", "32", "64", "128", "connections opened concurrently"},
        {"ramp-probe-rate", "20", "20", "20", "the active probe's rate while the idle connections are held"},
        {"ramp-probe-seconds", "2", "10", "15", "how long the probe runs at each step"},
        {"ramp-idle-timeout", "3600", "3600", "3600", "both proxies' idle timeout in the ramp, long enough to hold every step"},
        {"ramp-failure-threshold", "0.01", "0.01", "0.01", "the failed-connection ratio that ends the ramp"},
        {"ramp-per-source", "25000", "25000", "25000", "connections per loopback source (or origin) address, under the ephemeral port range"},
        // Memory under adversarial clients
        {"attacks", "slowloris,slowread,updown,rapidreset", "slowloris,slowread,updown,rapidreset", "slowloris,slowread,updown,rapidreset", "the memory-pressure workloads to run, each run with the proxy's memory capped"},
        {"attack-seconds", "4", "60", "300", "how long each workload runs"},
        {"attack-heap", "128m", "256m", "512m", "the proxy's -Xmx while capped"},
        {"attack-direct", "64m", "128m", "256m", "the proxy's -XX:MaxDirectMemorySize while capped"},
        {"attack-cgroup-limit", "", "", "", "a memory cgroup limit for the capped proxy (e.g. 512m), empty for none"},
        {"attack-cgroup-sockets", "exclude", "exclude", "exclude", "whether the proxy's TCP socket buffers count against attack-cgroup-limit (cgroup v2 charges them): exclude (the limit holds the proxy's own memory; the buffers are measured beside it) or include (the kernel's limit covers both, as in a container)"},
        {"nmt-every-seconds", "1", "5", "15", "NMT and RSS samples during a workload, every this many seconds"},
        {"slowloris-connections", "100", "2000", "10000", "connections trickling their request headers"},
        {"slowloris-interval-ms", "1000", "5000", "10000", "milliseconds between one connection's header lines"},
        {"slowread-connections", "20", "200", "1000", "connections that read a large response slowly"},
        {"slowread-bytes", "4m", "16m", "64m", "the response each slow reader asks for"},
        {"slowread-rate", "16384", "8192", "4096", "bytes per second each slow reader reads"},
        {"updown-connections", "2", "16", "64", "uploading connections, and as many downloading"},
        {"updown-bytes", "8m", "64m", "256m", "the size of each parallel upload and download"},
        {"rapidreset-connections", "2", "8", "32", "h2c connections opening and cancelling streams in a burst"},
        {"attack-probe-rate", "10", "10", "10", "a normal client's probe rate during a workload"},
        // Soak
        {"soak-rate", "200", "2000", "5000", "the soak's fixed rate"},
        {"soak-seconds", "10", "600", "14400", "how long the soak runs"},
        {"soak-connections", "16", "64", "256", "keep-alive connections in the soak"},
        {"soak-window-seconds", "2", "10", "30", "latency is reported per window of this many seconds"},
        {"soak-sample-seconds", "2", "30", "60", "a forced GC, heap and NMT sample every this many seconds"},
        // Faults
        {"fault-idle-timeout", "2", "5", "10", "both proxies' idle timeout (seconds) in the fault scenario"},
        {"fault-requests", "4", "20", "100", "requests per fault"},
        {"fault-concurrency", "2", "4", "8", "concurrent requests per fault"},
        {"fault-latency-ms", "200", "200", "200", "latency the relay adds to each request"},
        {"fault-bandwidth-bps", "262144", "262144", "262144", "the relay's bandwidth cap (bytes/s)"},
    };

    private static final Map<String, String> DESCRIPTIONS = new LinkedHashMap<>();

    static {
        for (String[] row : TABLE) DESCRIPTIONS.put(row[0], row[4]);
    }

    private final String preset;
    private final Map<String, String> values = new LinkedHashMap<>();

    private Settings(String preset) {
        this.preset = preset;
        int column = 1 + PRESETS.indexOf(preset);
        for (String[] row : TABLE) values.put(row[0], row[column]);
    }

    /** The preset's settings, without overrides. */
    public static Settings preset(String name) {
        if (!PRESETS.contains(name)) throw new IllegalArgumentException("unknown preset " + name + "; one of " + PRESETS);
        return new Settings(name);
    }

    /**
     * Parses {@code --preset p} and {@code --name value} pairs; arguments it does not know are
     * returned in {@code rest}.
     */
    public static Settings parse(List<String> args, List<String> rest) {
        String preset = "smoke";
        for (int i = 0; i < args.size() - 1; i++) {
            if (args.get(i).equals("--preset")) preset = args.get(i + 1);
        }
        Settings s = preset(preset);
        for (int i = 0; i < args.size(); i++) {
            String a = args.get(i);
            if (a.equals("--preset")) {
                i++;
                continue;
            }
            if (a.startsWith("--") && s.values.containsKey(a.substring(2))) {
                if (i + 1 >= args.size()) throw new IllegalArgumentException(a + " needs a value");
                s.values.put(a.substring(2), args.get(++i));
            } else {
                rest.add(a);
            }
        }
        return s;
    }

    /** The preset these settings started from. */
    public String preset() {
        return preset;
    }

    /** Overrides a setting. */
    public void set(String name, String value) {
        if (!values.containsKey(name)) throw new IllegalArgumentException("unknown setting " + name);
        values.put(name, value);
    }

    /** A setting's value as given. */
    public String get(String name) {
        String v = values.get(name);
        if (v == null) throw new IllegalArgumentException("unknown setting " + name);
        return v;
    }

    /** A setting as an int. */
    public int getInt(String name) {
        return (int) bytes(get(name));
    }

    /** A setting as a long; sizes may end in k, m or g. */
    public long getLong(String name) {
        return bytes(get(name));
    }

    /** A setting as a double. */
    public double getDouble(String name) {
        return Double.parseDouble(get(name));
    }

    /** A setting as a boolean. */
    public boolean getBool(String name) {
        return Boolean.parseBoolean(get(name));
    }

    /** A comma-separated setting as a list (empty entries dropped). */
    public List<String> getList(String name) {
        List<String> out = new ArrayList<>();
        for (String p : get(name).split(",")) {
            if (!p.isBlank()) out.add(p.trim());
        }
        return out;
    }

    /** A space-separated setting as arguments. */
    public List<String> getArgs(String name) {
        String v = get(name).trim();
        return v.isEmpty() ? List.of() : Arrays.asList(v.split("\\s+"));
    }

    /** Parses a size such as {@code 512}, {@code 64k}, {@code 16m} or {@code 2g} into bytes. */
    public static long bytes(String v) {
        String s = v.trim().toLowerCase(Locale.ROOT);
        long mul = 1;
        if (s.endsWith("k")) mul = 1024;
        else if (s.endsWith("m")) mul = 1024 * 1024;
        else if (s.endsWith("g")) mul = 1024L * 1024 * 1024;
        if (mul != 1) s = s.substring(0, s.length() - 1);
        if (s.contains(".")) return (long) (Double.parseDouble(s) * mul);
        return Long.parseLong(s) * mul;
    }

    /** Every setting, as used. */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("preset", preset);
        m.putAll(values);
        return m;
    }

    /** The settings' help text. */
    public static String help() {
        StringBuilder b = new StringBuilder();
        b.append(String.format("  %-26s %-16s %-16s %-16s %s%n", "setting", "smoke", "standard", "full", ""));
        for (String[] row : TABLE) {
            b.append(String.format("  --%-24s %-16s %-16s %-16s %s%n", row[0], abbreviate(row[1]), abbreviate(row[2]),
                    abbreviate(row[3]), row[4]));
        }
        return b.toString();
    }

    private static String abbreviate(String s) {
        if (s.isEmpty()) return "\"\"";
        return s.length() > 16 ? s.substring(0, 13) + "..." : s;
    }
}
