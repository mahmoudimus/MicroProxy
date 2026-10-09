package org.microproxy.starlark;

import java.io.IOException;
import java.io.PrintStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeSet;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.LauncherExtension;

/** Adds {@code --script} to the command line when this module is on the class path. */
public final class StarlarkLauncherExtension implements LauncherExtension {

    private Path script;
    private boolean reload = true;
    /** {@code --script-var} entries and {@code --script-var-file} paths, in command-line order. */
    private final List<Object> vars = new ArrayList<>();

    @Override
    public String usage() {
        return """
                  --script <file.star>         drive the proxy with a Starlark script (see README)
                  --script-no-reload           do not re-read the script when it changes
                  --script-var <NAME=VALUE>    a string constant for the script (repeatable)
                  --script-var-file <file>     string constants for the script, from a properties file
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
                    .build();
        } catch (ScriptException e) {
            throw new IllegalArgumentException("cannot load " + script + ":\n" + e.getMessage(), e);
        }
        bootstrap.plusFiltersSource(proxy).withChainProxyManager(proxy);
        boolean authenticates = proxy.definesAuthenticate();
        if (authenticates) {
            bootstrap.withProxyAuthenticator(proxy);
        }
        if (!constants.isEmpty()) {
            // Names only: the values may be secrets.
            console.println("Script constants: " + String.join(", ", constants.keySet()));
        }
        console.println("Scripting with " + script.toAbsolutePath() + (reload ? " (reloads on change)" : "")
                + (authenticates ? "; clients authenticate with its authenticate()" : ""));
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
