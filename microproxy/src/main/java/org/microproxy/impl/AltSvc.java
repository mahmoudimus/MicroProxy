package org.microproxy.impl;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.microproxy.http.HttpHeaders;

/**
 * Removes HTTP/3 alternatives from {@code Alt-Svc} response fields (RFC 7838), so that clients
 * keep talking to an origin over TCP, through the proxy, instead of switching to QUIC over UDP,
 * which bypasses it.
 *
 * <p>The removed protocol ids are {@code h3}, the draft versions ({@code h3-29}, {@code h3-Q050},
 * {@code h3-T051}, ...) and Google QUIC's {@code quic}, compared case-insensitively. Every other
 * alternative ({@code h2=":443"}, say) is kept exactly as received, parameters ({@code ma}, {@code
 * persist}, ...) included. A field left with no alternative is removed, and {@code clear} is never
 * touched. Quoted strings are respected, so commas and semicolons inside them do not split
 * alternatives.
 *
 * <p>HTTP/2 can also advertise alternatives in {@code ALTSVC} frames (RFC 7838 section 4); the
 * proxy drops them as frames of a type it does not handle.
 *
 * <p>It also reads the HTTP/3 alternative a server advertises for itself ({@link #http3}), which
 * the proxy learns from before removing it, to reach that server over HTTP/3 ({@link
 * Http3Origins}).
 */
final class AltSvc {

    /** The max-age of an alternative without {@code ma} (RFC 7838 section 3.1): 24 hours. */
    static final long DEFAULT_MAX_AGE_SECONDS = 86_400;

    /**
     * An HTTP/3 alternative of an origin, on the origin's own host.
     *
     * @param port the UDP port
     * @param maxAgeSeconds how long it may be remembered ({@code ma}), 0 to forget it
     */
    record Http3Alternative(int port, long maxAgeSeconds) {}

    /** The field name; lookups are case-insensitive. */
    static final String NAME = "Alt-Svc";

    private AltSvc() {}

    /**
     * Removes the HTTP/3 alternatives from every {@code Alt-Svc} field of {@code headers}. Fields
     * that advertise no HTTP/3 alternative are left as they are; otherwise the remaining
     * alternatives of all fields are combined into one field (in the position of the first), or
     * the fields are removed when none remain.
     *
     * @return whether anything was removed
     */
    static boolean stripHttp3(HttpHeaders headers) {
        if (!headers.contains(NAME)) {
            return false;
        }
        List<String> fields = headers.getAll(NAME);
        List<String> kept = new ArrayList<>(fields.size());
        boolean changed = false;
        for (String field : fields) {
            String stripped = stripHttp3(field);
            changed |= stripped != field;
            if (stripped != null) {
                kept.add(stripped);
            }
        }
        if (!changed) {
            return false;
        }
        if (kept.isEmpty()) {
            headers.remove(NAME);
        } else {
            headers.set(NAME, String.join(", ", kept));
        }
        return true;
    }

    /**
     * Removes the HTTP/3 alternatives from one {@code Alt-Svc} field value.
     *
     * @return {@code value} itself if it has no HTTP/3 alternative (or is {@code clear}), the
     *     remaining alternatives joined by {@code ", "}, or {@code null} if none remain
     */
    static String stripHttp3(String value) {
        if (value.strip().equals("clear")) {
            return value;
        }
        List<String> alternatives = split(value);
        if (alternatives.stream().noneMatch(AltSvc::isHttp3)) {
            return value;
        }
        List<String> kept = new ArrayList<>(alternatives.size());
        for (String alternative : alternatives) {
            if (!alternative.isEmpty() && !isHttp3(alternative)) {
                kept.add(alternative);
            }
        }
        return kept.isEmpty() ? null : String.join(", ", kept);
    }

    /**
     * Splits a field value at the commas outside quoted strings, stripping whitespace around each
     * element. An unterminated quoted string runs to the end of the value.
     */
    static List<String> split(String value) {
        List<String> elements = new ArrayList<>(4);
        int start = 0;
        boolean quoted = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (quoted) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    quoted = false;
                }
            } else if (c == '"') {
                quoted = true;
            } else if (c == ',') {
                elements.add(value.substring(start, i).strip());
                start = i + 1;
            }
        }
        elements.add(value.substring(Math.min(start, value.length())).strip());
        return elements;
    }

    /**
     * The first {@code h3} alternative in {@code headers}' {@code Alt-Svc} fields that is on
     * {@code host} itself (an alt-authority of {@code ":port"}, or with {@code host}'s name), or
     * {@link #CLEAR} when a field is {@code clear}, or null when there is neither. Alternatives on
     * other hosts are ignored: the proxy reaches an origin only at the origin's own address. Draft
     * versions ({@code h3-29}) are ignored too.
     */
    static Http3Alternative http3(HttpHeaders headers, String host) {
        for (String field : headers.getAll(NAME)) {
            if (field.strip().equals("clear")) return CLEAR;
            for (String alternative : split(field)) {
                Http3Alternative h3 = parseHttp3(alternative, host);
                if (h3 != null) return h3;
            }
        }
        return null;
    }

    /** {@code Alt-Svc: clear}: forget every alternative of the origin. */
    static final Http3Alternative CLEAR = new Http3Alternative(0, 0);

    private static Http3Alternative parseHttp3(String alternative, String host) {
        int eq = alternative.indexOf('=');
        if (eq < 0) return null;
        String protocol = alternative.substring(0, eq).strip();
        if (protocol.indexOf('%') >= 0) protocol = percentDecode(protocol);
        if (!protocol.equalsIgnoreCase("h3")) return null;
        List<String> parts = splitParameters(alternative.substring(eq + 1));
        String authority = unquote(parts.getFirst().strip());
        int colon = authority.lastIndexOf(':');
        if (colon < 0) return null;
        String altHost = authority.substring(0, colon);
        if (altHost.startsWith("[") && altHost.endsWith("]")) altHost = altHost.substring(1, altHost.length() - 1);
        String bareHost = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        if (!altHost.isEmpty() && !altHost.equalsIgnoreCase(bareHost)) return null;
        int port;
        try {
            port = Integer.parseInt(authority.substring(colon + 1));
        } catch (NumberFormatException e) {
            return null;
        }
        if (port <= 0 || port > 65_535) return null;
        long maxAge = DEFAULT_MAX_AGE_SECONDS;
        for (int i = 1; i < parts.size(); i++) {
            String p = parts.get(i).strip();
            int peq = p.indexOf('=');
            if (peq > 0 && p.substring(0, peq).strip().equalsIgnoreCase("ma")) {
                try {
                    maxAge = Long.parseLong(unquote(p.substring(peq + 1).strip()));
                } catch (NumberFormatException e) {
                    return null;
                }
                if (maxAge < 0) return null;
            }
        }
        return new Http3Alternative(port, maxAge);
    }

    /** Splits {@code alt-authority *(";" parameter)} at the semicolons outside quoted strings. */
    private static List<String> splitParameters(String value) {
        List<String> parts = new ArrayList<>(3);
        int start = 0;
        boolean quoted = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (quoted) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    quoted = false;
                }
            } else if (c == '"') {
                quoted = true;
            } else if (c == ';') {
                parts.add(value.substring(start, i));
                start = i + 1;
            }
        }
        parts.add(value.substring(Math.min(start, value.length())));
        return parts;
    }

    private static String unquote(String s) {
        if (s.length() < 2 || s.charAt(0) != '"' || s.charAt(s.length() - 1) != '"') return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 1; i < s.length() - 1; i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length() - 1) c = s.charAt(++i);
            sb.append(c);
        }
        return sb.toString();
    }

    /** Whether {@code alternative} ({@code protocol-id "=" alt-authority *(";" parameter)}) is HTTP/3 or QUIC. */
    static boolean isHttp3(String alternative) {
        int eq = alternative.indexOf('=');
        String protocol = (eq < 0 ? alternative : alternative.substring(0, eq)).strip();
        if (protocol.indexOf('%') >= 0) {
            // ALPN ids are percent-encoded; "h3" should not be, but a lenient client may decode it.
            protocol = percentDecode(protocol);
        }
        return protocol.equalsIgnoreCase("h3")
                || protocol.regionMatches(true, 0, "h3-", 0, 3)
                || protocol.equalsIgnoreCase("quic");
    }

    private static String percentDecode(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length()
                    && HexFormat.isHexDigit(s.charAt(i + 1)) && HexFormat.isHexDigit(s.charAt(i + 2))) {
                sb.append((char) HexFormat.fromHexDigits(s, i + 1, i + 3));
                i += 2;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
