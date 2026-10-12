package org.microproxy.starlark;

import java.io.IOException;
import java.io.PrintStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.TreeSet;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.LauncherExtension;

/** Adds {@code --script} to the command line when this module is on the class path. */
public final class StarlarkLauncherExtension implements LauncherExtension {

    /** Creates an extension with script reloading enabled and no script selected. */
    public StarlarkLauncherExtension() {}

    private Path script;
    private boolean reload = true;
    private StarlarkScript.Limits limits = StarlarkScript.Limits.DEFAULT;
    private String name;
    /** {@code --script-var} entries and {@code --script-var-file} paths, in command-line order. */
    private final List<Object> vars = new ArrayList<>();

    @Override
    public String usage() {
        return """
                  --script <file.star>         drive the proxy with a Starlark script (docs/guides/scripting.md)
                  --script-no-reload           do not re-read the script when it changes
                  --script-var <NAME=VALUE>    a string constant for the script (repeatable)
                  --script-var-file <file>     string constants for the script, from a properties file
                  --script-name <name>         the name the script's hooks.starlark stats are tagged with
                  --script-max-steps <n>       interpreter steps a hook call may run (default 10000000)
                  --script-max-time <time>     wall-clock budget of a hook call: 250ms, 5s, 1m (default 5s; 0 = none)
                  --script-max-alloc <bytes>   bytes of values a hook call may create, an estimate: 512k, 64m, 1g
                                               (default 256m; 0 = no limit)
                """;
    }

    @Override
    public boolean parseOption(String option, Deque<String> args) {
        switch (option) {
            case "--script" -> {
                String value = args.poll();
                if (value == null) throw new IllegalArgumentException("--script needs a value");
                script = Path.of(value);
                return true;
            }
            case "--script-no-reload" -> {
                reload = false;
                return true;
            }
            case "--script-var" -> {
                String value = args.poll();
                int eq = value == null ? -1 : value.indexOf('=');
                if (eq <= 0) throw new IllegalArgumentException("--script-var needs NAME=VALUE");
                String name = value.substring(0, eq);
                ScriptConstants.checkName(name);
                vars.add(Map.entry(name, value.substring(eq + 1)));
                return true;
            }
            case "--script-var-file" -> {
                String value = args.poll();
                if (value == null) throw new IllegalArgumentException("--script-var-file needs a value");
                vars.add(Path.of(value));
                return true;
            }
            case "--script-name" -> {
                String value = args.poll();
                if (value == null || value.isBlank()) throw new IllegalArgumentException("--script-name needs a value");
                name = value;
                return true;
            }
            case "--script-max-steps" -> {
                long steps = number(option, args.poll());
                if (steps <= 0) throw new IllegalArgumentException("--script-max-steps needs a positive number");
                limits = limits.withMaxSteps(steps);
                return true;
            }
            case "--script-max-time" -> {
                limits = limits.withTimeout(duration(option, args.poll()));
                return true;
            }
            case "--script-max-alloc" -> {
                long bytes = bytes(option, args.poll());
                limits = limits.withMaxAllocBytes(bytes == 0 ? Long.MAX_VALUE : bytes);
                return true;
            }
            default -> {
                return false;
            }
        }
    }

    @Override
    public void configure(HttpProxyServerBootstrap bootstrap, PrintStream console) throws IOException {
        if (script == null) {
            if (!vars.isEmpty()) throw new IllegalArgumentException("--script-var needs --script");
            return;
        }
        Map<String, String> constants = constants();
        ScriptedProxy proxy;
        try {
            proxy = ScriptedProxy.builder(script)
                    .reload(reload)
                    .fallback(bootstrap.getChainProxyManager())
                    .constants(constants)
                    .stats(bootstrap.getStats())
                    .limits(limits)
                    .statsName(name)
                    .observer(bootstrap.getScriptCallObserver())
                    .build();
        } catch (ScriptException e) {
            throw new IllegalArgumentException("cannot load " + script + ":\n" + e.getMessage(), e);
        }
        bootstrap.plusFiltersSource(proxy).withChainProxyManager(proxy);
        boolean authenticates = proxy.definesAuthenticate();
        if (authenticates) {
            bootstrap.withProxyAuthenticator(proxy);
        }
        boolean frames = proxy.definesFrameHook();
        if (frames) {
            // Only then: a proxy without an interceptor pays nothing per HTTP/2 frame.
            bootstrap.withFrameInterceptor(proxy.frameInterceptor());
        }
        boolean tcp = proxy.definesTcpHooks();
        if (tcp) {
            // Only then: without an interceptor, tunnels copy bytes through pooled buffers.
            bootstrap.withTcpInterceptor(proxy.tcpInterceptor());
        }
        boolean udp = proxy.definesUdpHooks();
        if (udp) {
            bootstrap.withUdpInterceptor(proxy.udpInterceptor());
        }
        boolean quic = proxy.definesQuicHooks();
        if (quic) {
            // Only then: with an interceptor, QUIC that is not HTTP/3 is intercepted rather than relayed.
            bootstrap.withQuicInterceptor(proxy.quicInterceptor());
        }
        boolean framer = proxy.definesQuicFramer();
        if (framer) {
            // Named for the framing rules: --quic-framing myproto=script.
            bootstrap.withQuicFraming(bootstrap.getQuicFraming().withFramer("script", proxy.quicFramer()));
        }
        if (!constants.isEmpty()) {
            // Names only: the values may be secrets.
            console.println("Script constants: " + String.join(", ", constants.keySet()));
        }
        console.println("Scripting with " + script.toAbsolutePath() + (reload ? " (reloads on change)" : "")
                + (authenticates ? "; clients authenticate with its authenticate()" : "")
                + (frames ? "; HTTP/2 and HTTP/3 frames go through its on_frame()" : "")
                + (tcp ? "; raw TCP tunnels go through its on_tcp_*() hooks" : "")
                + (udp ? "; CONNECT-UDP flows go through its on_udp_*() hooks" : "")
                + (quic ? "; QUIC other than HTTP/3 goes through its on_quic_*() hooks" : "")
                + (framer ? "; its quic_message_length() frames the QUIC streams --quic-framing gives to script" : ""));
    }

    private static long number(String option, String value) {
        if (value == null) throw new IllegalArgumentException(option + " needs a value");
        try {
            return Long.parseLong(value.strip());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(option + " needs a number, not " + value, e);
        }
    }

    /** A duration: a number of seconds, or a number with {@code ms}, {@code s} or {@code m}. */
    static Duration duration(String option, String value) {
        if (value == null) throw new IllegalArgumentException(option + " needs a value");
        String v = value.strip().toLowerCase(Locale.ROOT);
        try {
            Duration d;
            if (v.endsWith("ms")) {
                d = Duration.ofMillis(Long.parseLong(v.substring(0, v.length() - 2)));
            } else if (v.endsWith("s")) {
                d = Duration.ofSeconds(Long.parseLong(v.substring(0, v.length() - 1)));
            } else if (v.endsWith("m")) {
                d = Duration.ofMinutes(Long.parseLong(v.substring(0, v.length() - 1)));
            } else {
                d = Duration.ofSeconds(Long.parseLong(v));
            }
            if (d.isNegative()) throw new IllegalArgumentException(option + " needs a duration of 0 or more");
            return d;
        } catch (NumberFormatException | ArithmeticException e) {
            throw new IllegalArgumentException(option + " needs a duration such as 250ms, 5s or 1m, not " + value, e);
        }
    }

    /** A size: a number of bytes, or a number with {@code k}, {@code m} or {@code g} (powers of 1024). */
    static long bytes(String option, String value) {
        if (value == null) throw new IllegalArgumentException(option + " needs a value");
        String v = value.strip().toLowerCase(Locale.ROOT);
        if (v.endsWith("ib")) v = v.substring(0, v.length() - 2);
        else if (v.endsWith("b")) v = v.substring(0, v.length() - 1);
        int shift = 0;
        if (v.endsWith("k")) shift = 10;
        else if (v.endsWith("m")) shift = 20;
        else if (v.endsWith("g")) shift = 30;
        if (shift > 0) v = v.substring(0, v.length() - 1);
        try {
            long n = Long.parseLong(v);
            if (n < 0 || n > (Long.MAX_VALUE >> shift)) {
                throw new IllegalArgumentException(option + " needs a size of 0 or more, not " + value);
            }
            return n << shift;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(option + " needs a size such as 512k, 64m or 1g, not " + value, e);
        }
    }

    /** The constants from the command line; later ones replace earlier ones of the same name. */
    private Map<String, String> constants() throws IOException {
        Map<String, String> out = new LinkedHashMap<>();
        for (Object var : vars) {
            if (var instanceof Path file) {
                Properties properties = new Properties();
                try (Reader in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                    properties.load(in);
                }
                for (String name : new TreeSet<>(properties.stringPropertyNames())) {
                    try {
                        ScriptConstants.checkName(name);
                    } catch (IllegalArgumentException e) {
                        throw new IllegalArgumentException(file + ": " + e.getMessage(), e);
                    }
                    out.put(name, properties.getProperty(name));
                }
            } else if (var instanceof Map.Entry<?, ?> e) {
                out.put((String) e.getKey(), (String) e.getValue());
            }
        }
        return out;
    }
}
