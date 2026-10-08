package org.microproxy.starlark;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.Deque;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.LauncherExtension;

/** Adds {@code --script} to the command line when this module is on the class path. */
public final class StarlarkLauncherExtension implements LauncherExtension {

    private Path script;
    private boolean reload = true;

    @Override
    public String usage() {
        return """
                  --script <file.star>         drive the proxy with a Starlark script (see README)
                  --script-no-reload           do not re-read the script when it changes
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
            default -> {
                return false;
            }
        }
    }

    @Override
    public void configure(HttpProxyServerBootstrap bootstrap, PrintStream console) throws IOException {
        if (script == null) return;
        ScriptedProxy proxy;
        try {
            proxy = ScriptedProxy.builder(script)
                    .reload(reload)
                    .fallback(bootstrap.getChainProxyManager())
                    .build();
        } catch (ScriptException e) {
            throw new IllegalArgumentException("cannot load " + script + ":\n" + e.getMessage(), e);
        }
        bootstrap.withFiltersSource(proxy).withChainProxyManager(proxy);
        console.println("Scripting with " + script.toAbsolutePath() + (reload ? " (reloads on change)" : ""));
    }
}
