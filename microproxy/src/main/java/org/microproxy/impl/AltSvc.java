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
 * <p>HTTP/2 can also advertise alternatives in {@code ALTSVC} frames (RFC 7838 section 4). The
 * proxy does not speak HTTP/2 to clients yet; an HTTP/2 transport must filter those frames the
 * same way.
 */
final class AltSvc {

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
