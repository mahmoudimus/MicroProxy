package org.microproxy.extras;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Cookie parsing after RFC 6265: {@code Cookie} request headers, {@code Set-Cookie} response
 * headers, and the lenient cookie-date algorithm (section 5.1.1), which also reads the HTTP date
 * formats ({@code Date}, {@code Expires}).
 */
final class Cookies {

    private Cookies() {}

    /**
     * A {@code Set-Cookie} header: name, value and attributes (names lower-cased, in order; {@code
     * secure} and {@code httponly} map to an empty string).
     */
    record SetCookie(String name, String value, Map<String, String> attributes) {

        String attribute(String name) {
            return attributes.get(name);
        }
    }

    /** Parses one {@code Set-Cookie} value; null if it has no name-value pair (RFC 6265 5.2). */
    static SetCookie parseSetCookie(String header) {
        String[] parts = header.split(";");
        String pair = parts[0];
        int eq = pair.indexOf('=');
        if (eq < 0) return null;
        String name = pair.substring(0, eq).strip();
        if (name.isEmpty()) return null;
        String value = pair.substring(eq + 1).strip();
        Map<String, String> attributes = new LinkedHashMap<>();
        for (int i = 1; i < parts.length; i++) {
            String av = parts[i];
            int e = av.indexOf('=');
            String key = (e < 0 ? av : av.substring(0, e)).strip().toLowerCase(Locale.ROOT);
            if (key.isEmpty()) continue;
            attributes.put(key, e < 0 ? "" : av.substring(e + 1).strip());
        }
        return new SetCookie(name, value, attributes);
    }

    /** The name-value pairs of a {@code Cookie} header, in order. */
    static List<Map.Entry<String, String>> parseCookieHeader(String header) {
        List<Map.Entry<String, String>> out = new ArrayList<>();
        for (String pair : header.split(";")) {
            int eq = pair.indexOf('=');
            String name = (eq < 0 ? pair : pair.substring(0, eq)).strip();
            if (name.isEmpty()) continue;
            out.add(Map.entry(name, eq < 0 ? "" : pair.substring(eq + 1).strip()));
        }
        return out;
    }

    /**
     * When the cookie expires: {@code Max-Age} wins over {@code Expires} (RFC 6265 5.3); null for a
     * session cookie. A non-positive {@code Max-Age} means already expired.
     */
    static Instant expiry(SetCookie cookie, Instant now) {
        String maxAge = cookie.attribute("max-age");
        if (maxAge != null && maxAge.matches("-?\\d+")) {
            long seconds;
            try {
                seconds = Long.parseLong(maxAge);
            } catch (NumberFormatException e) {
                seconds = maxAge.startsWith("-") ? Long.MIN_VALUE : Long.MAX_VALUE;
            }
            if (seconds <= 0) return Instant.EPOCH;
            return seconds > 1L << 40 ? Instant.MAX : now.plusSeconds(seconds);
        }
        String expires = cookie.attribute("expires");
        return expires == null ? null : parseDate(expires);
    }

    private static final String[] MONTHS = {"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct",
        "nov", "dec"};

    /**
     * The cookie-date algorithm of RFC 6265 section 5.1.1, which reads RFC 1123, RFC 850 and
     * asctime dates and the usual variants; null if the value is not a date.
     */
    static Instant parseDate(String value) {
        int hour = -1;
        int minute = -1;
        int second = -1;
        int day = -1;
        int month = -1;
        int year = -1;
        for (String token : value.split("[\\x09\\x20-\\x2F\\x3B-\\x40\\x5B-\\x60\\x7B-\\x7E]+")) {
            if (token.isEmpty()) continue;
            if (hour < 0 && token.matches("\\d{1,2}:\\d{1,2}:\\d{1,2}.*")) {
                String[] hms = token.split(":");
                hour = Integer.parseInt(hms[0]);
                minute = Integer.parseInt(hms[1]);
                second = Integer.parseInt(hms[2].replaceAll("\\D.*", ""));
            } else if (day < 0 && token.matches("\\d{1,2}(\\D.*)?")) {
                day = Integer.parseInt(token.replaceAll("\\D.*", ""));
            } else if (month < 0 && token.length() >= 3 && monthOf(token) >= 0) {
                month = monthOf(token);
            } else if (year < 0 && token.matches("\\d{2,4}(\\D.*)?")) {
                year = Integer.parseInt(token.replaceAll("\\D.*", ""));
            }
        }
        if (year >= 70 && year <= 99) year += 1900;
        if (year >= 0 && year <= 69) year += 2000;
        if (hour < 0 || day < 1 || day > 31 || month < 0 || year < 1601 || hour > 23 || minute > 59 || second > 59) {
            return null;
        }
        try {
            return LocalDate.of(year, month + 1, day).atTime(hour, minute, second).toInstant(ZoneOffset.UTC);
        } catch (java.time.DateTimeException e) {
            return null;
        }
    }

    private static int monthOf(String token) {
        String prefix = token.substring(0, 3).toLowerCase(Locale.ROOT);
        for (int i = 0; i < MONTHS.length; i++) {
            if (MONTHS[i].equals(prefix)) return i;
        }
        return -1;
    }

    /**
     * Whether {@code host} domain-matches {@code domain} (RFC 6265 5.1.3): equal, or a subdomain
     * of it when the host is a name rather than an IP address.
     */
    static boolean domainMatches(String host, String domain) {
        if (host.equals(domain)) return true;
        return host.endsWith("." + domain) && !isIpAddress(host);
    }

    static boolean isIpAddress(String host) {
        return host.indexOf(':') >= 0 || host.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    /** The default path of RFC 6265 5.1.4: the request path up to its last {@code /}. */
    static String defaultPath(String path) {
        if (path.isEmpty() || path.charAt(0) != '/') return "/";
        int last = path.lastIndexOf('/');
        return last == 0 ? "/" : path.substring(0, last);
    }

    /** Whether {@code requestPath} path-matches the cookie path (RFC 6265 5.1.4). */
    static boolean pathMatches(String requestPath, String cookiePath) {
        if (requestPath.equals(cookiePath)) return true;
        if (!requestPath.startsWith(cookiePath)) return false;
        return cookiePath.endsWith("/") || requestPath.charAt(cookiePath.length()) == '/';
    }
}
