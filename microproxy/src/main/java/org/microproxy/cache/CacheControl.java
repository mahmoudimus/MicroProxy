package org.microproxy.cache;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.microproxy.http.HttpHeaders;

/** Parsed {@code Cache-Control} directives (RFC 9111 section 5.2); names are lower-cased. */
final class CacheControl {

    static final CacheControl NONE = new CacheControl(Map.of());

    private final Map<String, String> directives;

    private CacheControl(Map<String, String> directives) {
        this.directives = directives;
    }

    /** Parses all {@code Cache-Control} fields; for requests, {@code Pragma: no-cache} counts too. */
    static CacheControl of(HttpHeaders headers, boolean request) {
        Map<String, String> d = new HashMap<>();
        for (String element : headers.getAllElements("Cache-Control")) {
            int eq = element.indexOf('=');
            String name = (eq < 0 ? element : element.substring(0, eq)).strip().toLowerCase(Locale.ROOT);
            String value = eq < 0 ? "" : unquote(element.substring(eq + 1).strip());
            if (!name.isEmpty()) d.putIfAbsent(name, value);
        }
        if (request && d.isEmpty()) {
            for (String pragma : headers.getAllElements("Pragma")) {
                if (pragma.strip().equalsIgnoreCase("no-cache")) d.put("no-cache", "");
            }
        }
        return d.isEmpty() ? NONE : new CacheControl(d);
    }

    boolean has(String name) {
        return directives.containsKey(name);
    }

    /**
     * The delta-seconds value of {@code name}: -1 if absent, and 0 if malformed (RFC 9111 treats an
     * invalid freshness value as stale).
     */
    long seconds(String name) {
        String v = directives.get(name);
        if (v == null) return -1;
        if (v.isEmpty() || !v.chars().allMatch(Character::isDigit)) return 0;
        try {
            return Long.parseLong(v);
        } catch (NumberFormatException e) {
            return Integer.MAX_VALUE; // larger than any useful lifetime
        }
    }

    /** Like {@link #seconds} but a directive without a value means "any" ({@code Long.MAX_VALUE}). */
    long secondsOrAny(String name) {
        String v = directives.get(name);
        if (v == null) return -1;
        return v.isEmpty() ? Long.MAX_VALUE : seconds(name);
    }

    private static String unquote(String v) {
        return v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"") ? v.substring(1, v.length() - 1) : v;
    }
}
