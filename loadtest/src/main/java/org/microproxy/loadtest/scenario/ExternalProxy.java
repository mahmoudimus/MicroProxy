package org.microproxy.loadtest.scenario;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.microproxy.loadtest.Json;

/**
 * A proxy under test that is not one of the built-in JVM proxies: any external command (Envoy, a Go
 * or Rust proxy, Squid, ...) described in a JSON file named by the {@code external-proxies} setting
 * (see {@code loadtest/competitors/proxies.json}). Each entry gives the command line, an optional
 * configuration template, environment variables, a command that prints the version, and the
 * workloads the proxy cannot run. The process is started like the JVM proxies: pinned to the
 * proxy's CPUs, inside the memory cgroup when a scenario caps memory, and ready once its port
 * accepts connections. Its memory is sampled from {@code /proc} only; JVM-only figures (NMT, the
 * heap after a GC, the GC log) are absent for it and reported as n/a.
 *
 * <p>Placeholders, written {@code {{name}}}, are replaced in the command, the environment and the
 * configuration template: {@code port}, {@code idleSeconds}, {@code connectTimeoutMs},
 * {@code connectTimeoutSeconds}, {@code workers} (the number of CPUs the proxy is pinned to),
 * {@code config} (the rendered configuration file), {@code logs} (the run's log directory),
 * {@code name} (the proxy and scenario, unique per process), {@code home} (the JSON file's
 * directory) and {@code tools} ({@code home}/.tools, where the setup script puts binaries).
 */
record ExternalProxy(String name, String label, String language, String version, List<String> command,
        String config, Map<String, String> env, List<String> versionCommand, Map<String, String> unsupported,
        String notes, Path home) {

    /** Reads every entry of {@code file}; an empty map when {@code file} is blank. */
    static Map<String, ExternalProxy> load(String file) throws IOException {
        Map<String, ExternalProxy> out = new LinkedHashMap<>();
        if (file == null || file.isBlank()) return out;
        Path path = Path.of(file).toAbsolutePath().normalize();
        Map<String, Object> json = Json.parseObject(Files.readString(path));
        for (Map.Entry<String, Object> e : json.entrySet()) {
            if (e.getKey().startsWith("_") || !(e.getValue() instanceof Map<?, ?>)) continue;
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) e.getValue();
            out.put(e.getKey(), new ExternalProxy(e.getKey(), Json.getString(m, "label", e.getKey()),
                    Json.getString(m, "language", null), Json.getString(m, "version", null), strings(m.get("command")),
                    Json.getString(m, "config", null), stringMap(m.get("env")), strings(m.get("versionCommand")),
                    stringMap(m.get("unsupported")), Json.getString(m, "notes", null), path.getParent()));
        }
        return out;
    }

    /** Why this proxy cannot run {@code what} (a scenario, or scenario/workload), or null if it can. */
    String unsupportedReason(String what) {
        return unsupported.get(what);
    }

    /** Replaces every {@code {{key}}} of {@code text}. */
    static String render(String text, Map<String, String> values) {
        String out = text;
        for (Map.Entry<String, String> v : values.entrySet()) out = out.replace("{{" + v.getKey() + "}}", v.getValue());
        return out;
    }

    /** The placeholders shared by every process of this proxy. */
    Map<String, String> baseValues() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("home", home.toString());
        m.put("tools", home.resolve(".tools").toString());
        return m;
    }

    /** The output of the version command (first line), or the declared version. */
    String probeVersion() {
        if (versionCommand.isEmpty()) return version;
        List<String> cmd = new ArrayList<>();
        Map<String, String> values = baseValues();
        for (String c : versionCommand) cmd.add(render(c, values));
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            String text = new String(p.getInputStream().readAllBytes()).trim();
            if (!p.waitFor(30, TimeUnit.SECONDS)) p.destroyForcibly();
            for (String line : text.split("\n")) {
                if (!line.isBlank()) return line.trim();
            }
        } catch (IOException e) {
            return version + " (version command failed: " + e.getMessage() + ")";
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return version;
    }

    /** A description for the results file. */
    Map<String, Object> describe() {
        return Json.obj("label", label, "language", language, "version", version, "command", command, "config", config,
                "env", env, "unsupported", unsupported, "notes", notes);
    }

    private static List<String> strings(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof List<?> l) for (Object x : l) out.add(String.valueOf(x));
        return out;
    }

    private static Map<String, String> stringMap(Object o) {
        Map<String, String> out = new LinkedHashMap<>();
        if (o instanceof Map<?, ?> m) m.forEach((k, v) -> out.put(String.valueOf(k), String.valueOf(v)));
        return out;
    }
}
