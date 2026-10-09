package org.microproxy;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Deque;

/**
 * Adds command-line options to {@link Launcher}. Implementations are found with {@link
 * java.util.ServiceLoader}, so an optional module on the class path (such as {@code
 * microproxy-starlark}) can contribute options without the core depending on it.
 */
public interface LauncherExtension {

    /** {@return help lines for the options this extension adds, formatted like the built-in ones} */
    String usage();

    /**
     * Consumes {@code option} if it belongs to this extension, taking any values from the front of
     * {@code args}. Returns false for options it does not recognise.
     *
     * @param option the command-line option to parse
     * @param args the remaining command-line arguments
     * @return whether this extension consumed the option
     */
    boolean parseOption(String option, Deque<String> args);

    /**
     * Applies the parsed options, after the built-in ones; {@link
     * HttpProxyServerBootstrap#getChainProxyManager()} shows any upstream configuration to wrap.
     *
     * @param bootstrap the proxy configuration to extend
     * @param console the output stream for status messages and diagnostics
     * @throws IOException if extension configuration cannot be loaded or initialized
     */
    void configure(HttpProxyServerBootstrap bootstrap, PrintStream console) throws IOException;
}
