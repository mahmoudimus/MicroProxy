package org.microproxy.impl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * The admin listener's {@code /logging}: the proxy logs through {@link System.Logger}, which the
 * JDK backs with {@code java.util.logging} unless a {@link System.LoggerFinder} on the class path
 * (such as SLF4J's {@code slf4j-jdk-platform-logging}) takes over. With {@code java.util.logging}
 * the proxy's loggers (those under {@code org.microproxy} and {@code io.github.mahmoudimus}) are
 * listed and their levels set, with Envoy's level names; with another backend, levels are that
 * backend's to set, and this says so.
 */
final class AdminLogging {

    /** The JDK's own finder, which backs {@link System.Logger} with {@code java.util.logging}. */
    private static final String JUL_FINDER = "sun.util.logging.internal.LoggingProviderImpl";
    /** The loggers listed and set by {@code ?level=}: the proxy's own. */
    private static final List<String> ROOTS = List.of("org.microproxy", "io.github.mahmoudimus");
    /**
     * Loggers whose level was set here, kept so that it lasts: {@code java.util.logging} holds
     * loggers weakly, and one nobody else holds would come back without its level.
     */
    private static final Set<Logger> SET = ConcurrentHashMap.newKeySet();

    private AdminLogging() {}

    /** {@return whether {@link System.Logger} goes to {@code java.util.logging}} */
    static boolean julBackend() {
        return System.LoggerFinder.getLoggerFinder().getClass().getName().equals(JUL_FINDER);
    }

    /** {@return the class of the {@link System.Logger} backend} */
    static String backend() {
        return System.LoggerFinder.getLoggerFinder().getClass().getName();
    }

    /**
     * The proxy's loggers and their effective levels, Envoy's way: {@code active loggers:}, then
     * {@code   name: level} per logger, sorted.
     */
    static String list() {
        if (!julBackend()) {
            return "the System.Logger backend is " + backend() + ", not java.util.logging: set levels there\n";
        }
        StringBuilder sb = new StringBuilder("active loggers:\n");
        for (Map.Entry<String, Level> e : loggers().entrySet()) {
            sb.append("  ").append(e.getKey()).append(": ").append(envoyName(e.getValue())).append('\n');
        }
        return sb.toString();
    }

    /** The proxy's loggers known to {@code java.util.logging} (and the roots), with their effective levels. */
    private static Map<String, Level> loggers() {
        LogManager manager = LogManager.getLogManager();
        Map<String, Level> loggers = new TreeMap<>();
        for (String root : ROOTS) loggers.put(root, effectiveLevel(Logger.getLogger(root)));
        for (String name : Collections.list(manager.getLoggerNames())) {
            if (!ours(name)) continue;
            Logger logger = manager.getLogger(name);
            if (logger != null) loggers.put(name, effectiveLevel(logger));
        }
        return loggers;
    }

    private static boolean ours(String name) {
        for (String root : ROOTS) {
            if (name.equals(root) || name.startsWith(root + ".")) return true;
        }
        return false;
    }

    private static Level effectiveLevel(Logger logger) {
        for (Logger l = logger; l != null; l = l.getParent()) {
            if (l.getLevel() != null) return l.getLevel();
        }
        return Level.INFO;
    }

    /**
     * Sets levels as {@code POST /logging} asks: {@code level=<level>} sets every one of the
     * proxy's loggers, {@code <logger>=<level>} sets that one (and so its children without a level
     * of their own). A handler of the root logger that would drop the records of a lower level is
     * lowered to it, so that they show. Returns the loggers set.
     *
     * @throws IllegalArgumentException for an unknown level, or a logger outside the proxy's
     * @throws IllegalStateException when {@code java.util.logging} is not the backend
     */
    static List<String> set(Map<String, String> params) {
        if (!julBackend()) {
            throw new IllegalStateException("the System.Logger backend is " + backend()
                    + ", not java.util.logging: set levels there");
        }
        // Checked first, so that a bad parameter changes nothing.
        Map<Logger, Level> changes = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, String> e : params.entrySet()) {
            Level level = level(e.getValue());
            if (e.getKey().equals("level")) {
                for (String name : loggers().keySet()) changes.put(Logger.getLogger(name), level);
            } else if (ours(e.getKey())) {
                changes.put(Logger.getLogger(e.getKey()), level);
            } else {
                throw new IllegalArgumentException("not one of the proxy's loggers (" + String.join(", ", ROOTS)
                        + " and below): " + e.getKey());
            }
        }
        List<String> set = new ArrayList<>();
        for (Map.Entry<Logger, Level> change : changes.entrySet()) {
            Logger logger = change.getKey();
            Level level = change.getValue();
            logger.setLevel(level);
            SET.add(logger);
            lowerRootHandlers(level);
            set.add(logger.getName());
        }
        return set;
    }

    private static void lowerRootHandlers(Level level) {
        for (Handler h : Logger.getLogger("").getHandlers()) {
            if (h.getLevel().intValue() > level.intValue()) h.setLevel(level);
        }
    }

    /**
     * The {@code java.util.logging} level of an Envoy level name ({@code trace}, {@code debug},
     * {@code info}, {@code warning} or {@code warn}, {@code error}, {@code critical}, {@code off})
     * or of a {@code java.util.logging} one ({@code FINE}, {@code ALL}, ...), in any case.
     */
    static Level level(String name) {
        String n = name.strip().toLowerCase(Locale.ROOT);
        return switch (n) {
            case "trace" -> Level.FINEST;
            case "debug" -> Level.FINE;
            case "info" -> Level.INFO;
            case "warning", "warn" -> Level.WARNING;
            case "error", "critical" -> Level.SEVERE;
            case "off" -> Level.OFF;
            default -> {
                try {
                    yield Level.parse(n.toUpperCase(Locale.ROOT));
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("unknown level: " + name
                            + "; expected trace, debug, info, warning, error, critical or off");
                }
            }
        };
    }

    /** Envoy's name for a {@code java.util.logging} level. */
    static String envoyName(Level level) {
        int v = level.intValue();
        if (v == Level.OFF.intValue()) return "off";
        if (v >= Level.SEVERE.intValue()) return "error";
        if (v >= Level.WARNING.intValue()) return "warning";
        if (v >= Level.INFO.intValue()) return "info";
        if (v >= Level.FINE.intValue()) return "debug";
        return "trace";
    }
}
