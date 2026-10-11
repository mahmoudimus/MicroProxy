// Ported from mitmproxy (MIT License, see META-INF/LICENSE-mitmproxy.txt):
// mitmproxy/addons/next_layer.py, NextLayer._ignore_connection: matching ignore_hosts and
// allow_hosts against host:port names of the connection.
// Changes: the names are the CONNECT target and the SNI (no original destination address or Host
// header, which the proxy does not consult for TLS).
package org.microproxy.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Which TLS connections to intercept, by host name: mitmproxy's {@code ignore_hosts} and {@code
 * allow_hosts}. Each rule is a regular expression searched for (not matched whole), ignoring case,
 * in {@code host:port} names of the connection: the {@code CONNECT} target, and the client's SNI
 * with the same port. A connection is ignored (tunnelled untouched) when any ignore rule finds any
 * name; with allow rules, it is also ignored when no allow rule finds any name.
 */
final class HostRules {

    private final List<Pattern> ignore;
    private final List<Pattern> allow;

    private HostRules(List<Pattern> ignore, List<Pattern> allow) {
        this.ignore = ignore;
        this.allow = allow;
    }

    /** The rules, or null when there are none. */
    static HostRules of(List<String> ignore, List<String> allow) {
        if (ignore.isEmpty() && allow.isEmpty()) return null;
        return new HostRules(compile(ignore), compile(allow));
    }

    static List<Pattern> compile(List<String> rules) {
        List<Pattern> patterns = new ArrayList<>(rules.size());
        for (String rule : rules) {
            try {
                patterns.add(Pattern.compile(rule, Pattern.CASE_INSENSITIVE));
            } catch (PatternSyntaxException e) {
                throw new IllegalArgumentException("invalid host pattern " + rule + ": " + e.getDescription(), e);
            }
        }
        return List.copyOf(patterns);
    }

    /**
     * Whether a connection with these {@code host:port} names is ignored. Names that are null are
     * skipped.
     */
    boolean ignored(String... names) {
        if (!allow.isEmpty() && !anyFinds(allow, names)) return true;
        return anyFinds(ignore, names);
    }

    /**
     * Whether a connection to {@code connectTarget} is ignored whatever its SNI: an ignore rule
     * finds the target. (Allow rules can only be decided with the SNI as well.)
     */
    boolean ignoredByTarget(String connectTarget) {
        return anyFinds(ignore, connectTarget);
    }

    private static boolean anyFinds(List<Pattern> patterns, String... names) {
        for (Pattern p : patterns) {
            for (String name : names) {
                if (name != null && p.matcher(name).find()) return true;
            }
        }
        return false;
    }

    /**
     * Splits a comma-separated list of patterns, as properties and command lines give them;
     * commas inside braces ({@code {1,3}}) belong to a pattern.
     */
    static List<String> split(String list) {
        List<String> out = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        int depth = 0;
        for (int i = 0; i < list.length(); i++) {
            char ch = list.charAt(i);
            if (ch == '\\' && i + 1 < list.length()) {
                current.append(ch).append(list.charAt(++i));
                continue;
            }
            if (ch == '{') depth++;
            if (ch == '}' && depth > 0) depth--;
            if (ch == ',' && depth == 0) {
                add(out, current);
                continue;
            }
            current.append(ch);
        }
        add(out, current);
        return out;
    }

    private static void add(List<String> out, StringBuilder current) {
        String rule = current.toString().strip();
        if (!rule.isEmpty()) out.add(rule);
        current.setLength(0);
    }
}
