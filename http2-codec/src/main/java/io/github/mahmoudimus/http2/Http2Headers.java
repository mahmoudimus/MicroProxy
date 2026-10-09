package io.github.mahmoudimus.http2;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * HTTP semantics of HTTP/2 field sections (RFC 9113 §8.2, §8.3): validating decoded header lists
 * into {@link RequestHeaders} and {@link ResponseHeaders}, and building header lists from
 * HTTP/1-style messages.
 *
 * <p>A request or response that breaks these rules is malformed, which is a stream error of type
 * PROTOCOL_ERROR (§8.1.1); the validators throw exactly that. They check:
 *
 * <ul>
 *   <li>names: not empty, no upper-case letters, no octets 0x00-0x20 or 0x7f-0xff, and no colon
 *       except as the first character of a pseudo-header;
 *   <li>values: no NUL, CR or LF, and no leading or trailing space or tab;
 *   <li>no connection-specific fields ({@link #CONNECTION_SPECIFIC}), and {@code te} only with the
 *       value {@code trailers};
 *   <li>pseudo-headers: only the defined ones for the message kind, each at most once, all before
 *       the regular fields, and the required ones present; none in trailers;
 *   <li>{@code content-length}: digits only, and every value the same.
 * </ul>
 */
public final class Http2Headers {

    /** Fields that are specific to an HTTP/1 connection and must not appear in HTTP/2 (§8.2.2). */
    public static final Set<String> CONNECTION_SPECIFIC =
            Set.of("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade");

    private Http2Headers() {}

    /** Validates a decoded request header section. */
    public static RequestHeaders toRequest(int streamId, List<HeaderField> fields) throws Http2Exception {
        String method = null;
        String scheme = null;
        String authority = null;
        String path = null;
        String host = null;
        long contentLength = -1;
        boolean regularSeen = false;
        List<HeaderField> out = new ArrayList<>(fields.size());
        int cookieAt = -1;
        StringBuilder cookie = null;
        boolean cookieSensitive = false;
        for (HeaderField f : fields) {
            String name = f.name();
            checkValue(streamId, f);
            if (name.startsWith(":")) {
                if (regularSeen) throw malformed(streamId, "pseudo-header field " + name + " after a regular field");
                switch (name) {
                    case ":method" -> method = once(streamId, method, f);
                    case ":scheme" -> scheme = once(streamId, scheme, f);
                    case ":authority" -> authority = once(streamId, authority, f);
                    case ":path" -> path = once(streamId, path, f);
                    default -> throw malformed(streamId, "pseudo-header field " + name + " is not allowed in a request");
                }
                continue;
            }
            regularSeen = true;
            checkRegular(streamId, f);
            switch (name) {
                case "cookie" -> {
                    // Crumbs are joined into one field (§8.2.3).
                    if (cookie == null) {
                        cookie = new StringBuilder(f.value());
                        cookieAt = out.size();
                        out.add(f);
                    } else {
                        cookie.append("; ").append(f.value());
                    }
                    cookieSensitive |= f.sensitive();
                    continue;
                }
                case "host" -> {
                    if (host != null) throw malformed(streamId, "more than one host field");
                    host = f.value();
                }
                case "content-length" -> contentLength = mergeContentLength(streamId, contentLength, f.value());
                default -> {}
            }
            out.add(f);
        }
        if (cookie != null) out.set(cookieAt, new HeaderField("cookie", cookie.toString(), cookieSensitive));

        if (method == null || method.isEmpty()) throw malformed(streamId, "missing :method");
        if (method.equals("CONNECT")) {
            // §8.5: only :method and :authority.
            if (scheme != null || path != null) throw malformed(streamId, "CONNECT with :scheme or :path");
            if (authority == null || authority.isEmpty()) throw malformed(streamId, "CONNECT without :authority");
        } else {
            if (scheme == null || scheme.isEmpty()) throw malformed(streamId, "missing :scheme");
            if (path == null || path.isEmpty()) throw malformed(streamId, "missing :path");
            boolean httpScheme = scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https");
            if (httpScheme) {
                if (!path.startsWith("/") && !(path.equals("*") && method.equals("OPTIONS"))) {
                    throw malformed(streamId, ":path must start with / (or be * for OPTIONS), got " + path);
                }
                if (authority == null && host == null) throw malformed(streamId, "no :authority or host");
                if (host != null && host.isEmpty()) throw malformed(streamId, "empty host");
            }
        }
        if (authority != null) {
            if (authority.isEmpty()) throw malformed(streamId, "empty :authority");
            if (authority.indexOf('@') >= 0) throw malformed(streamId, ":authority includes userinfo");
            if (host != null && !host.equalsIgnoreCase(authority)) {
                throw malformed(streamId, "host " + host + " differs from :authority " + authority);
            }
        }
        return new RequestHeaders(method, scheme, authority != null ? authority : host, path, out, contentLength);
    }

    /** Validates a decoded response header section (final or 1xx). */
    public static ResponseHeaders toResponse(int streamId, List<HeaderField> fields) throws Http2Exception {
        String status = null;
        long contentLength = -1;
        boolean regularSeen = false;
        List<HeaderField> out = new ArrayList<>(fields.size());
        for (HeaderField f : fields) {
            String name = f.name();
            checkValue(streamId, f);
            if (name.startsWith(":")) {
                if (regularSeen) throw malformed(streamId, "pseudo-header field " + name + " after a regular field");
                if (!name.equals(":status")) throw malformed(streamId, "pseudo-header field " + name + " is not allowed in a response");
                status = once(streamId, status, f);
                continue;
            }
            regularSeen = true;
            checkRegular(streamId, f);
            if (name.equals("content-length")) contentLength = mergeContentLength(streamId, contentLength, f.value());
            out.add(f);
        }
        if (status == null) throw malformed(streamId, "missing :status");
        if (status.length() != 3 || !isDigits(status) || status.charAt(0) == '0') {
            throw malformed(streamId, "invalid :status " + status);
        }
        return new ResponseHeaders(Integer.parseInt(status), out, contentLength);
    }

    /** Validates a trailer section: regular fields only. */
    public static List<HeaderField> validateTrailers(int streamId, List<HeaderField> fields) throws Http2Exception {
        for (HeaderField f : fields) {
            checkValue(streamId, f);
            if (f.name().startsWith(":")) throw malformed(streamId, "pseudo-header field " + f.name() + " in trailers");
            checkRegular(streamId, f);
        }
        return List.copyOf(fields);
    }

    /**
     * Checks DATA received against a declared {@code content-length} (§8.1.1). Call it after each
     * DATA frame with the running total of data octets (padding excluded). Skip it where the
     * content is empty whatever the field says: responses to HEAD, and 204 and 304 responses.
     *
     * @param declared the content length, or -1 if none was declared (then nothing is checked)
     */
    public static void checkContentLength(int streamId, long declared, long received, boolean endStream) throws Http2Exception {
        if (declared < 0) return;
        if (received > declared) {
            throw malformed(streamId, "received " + received + " octets of content, more than content-length " + declared);
        }
        if (endStream && received != declared) {
            throw malformed(streamId, "stream ended after " + received + " octets of content, content-length is " + declared);
        }
    }

    /**
     * An HTTP/2 request header list for an HTTP/1-style request: pseudo-headers first, then the
     * fields with lower-cased names, minus connection-specific fields (and any named in
     * {@code connection}), {@code host} (carried by {@code :authority}) and a {@code te} other than
     * {@code trailers}; {@code cookie} is split into crumbs (§8.2.3), which compress better.
     *
     * @param authority the target authority, or null to take it from the {@code host} field
     * @throws IllegalArgumentException if a name or value cannot be sent in HTTP/2
     */
    public static List<HeaderField> fromHttp1Request(
            String method, String scheme, String authority, String path, Collection<? extends Map.Entry<String, String>> headers) {
        List<HeaderField> out = new ArrayList<>(headers.size() + 4);
        if (authority == null) {
            for (Map.Entry<String, String> h : headers) {
                if (h.getKey().equalsIgnoreCase("host")) {
                    authority = h.getValue().strip();
                    break;
                }
            }
        }
        out.add(new HeaderField(":method", method));
        if (!method.equals("CONNECT")) {
            out.add(new HeaderField(":scheme", scheme));
        }
        if (authority != null) out.add(new HeaderField(":authority", authority));
        if (!method.equals("CONNECT")) {
            out.add(new HeaderField(":path", path));
        }
        for (HeaderField f : out) checkOutgoing(f);
        addHttp1Fields(out, headers, true);
        return out;
    }

    /** An HTTP/2 response header list for an HTTP/1-style response; see {@link #fromHttp1Request}. */
    public static List<HeaderField> fromHttp1Response(int status, Collection<? extends Map.Entry<String, String>> headers) {
        if (status < 100 || status > 999) throw new IllegalArgumentException("invalid status " + status);
        List<HeaderField> out = new ArrayList<>(headers.size() + 1);
        out.add(new HeaderField(":status", Integer.toString(status)));
        addHttp1Fields(out, headers, false);
        return out;
    }

    private static void addHttp1Fields(List<HeaderField> out, Collection<? extends Map.Entry<String, String>> headers, boolean request) {
        Set<String> nominated = new HashSet<>();
        for (Map.Entry<String, String> h : headers) {
            if (h.getKey().equalsIgnoreCase("connection")) {
                for (String token : h.getValue().split(",")) {
                    String t = token.strip().toLowerCase(Locale.ROOT);
                    if (!t.isEmpty()) nominated.add(t);
                }
            }
        }
        for (Map.Entry<String, String> h : headers) {
            String name = h.getKey().toLowerCase(Locale.ROOT);
            String value = h.getValue().strip();
            if (CONNECTION_SPECIFIC.contains(name) || nominated.contains(name) || name.equals("http2-settings")) continue;
            if (request && name.equals("host")) continue;
            if (name.equals("te")) {
                if (request && hasToken(value, "trailers")) out.add(new HeaderField("te", "trailers"));
                continue;
            }
            if (name.equals("cookie")) {
                for (String crumb : value.split(";")) {
                    String c = crumb.strip();
                    if (!c.isEmpty()) out.add(checkOutgoing(new HeaderField("cookie", c)));
                }
                continue;
            }
            out.add(checkOutgoing(new HeaderField(name, value)));
        }
    }

    private static boolean hasToken(String value, String token) {
        for (String part : value.split(",")) {
            String t = part.strip();
            int semi = t.indexOf(';');
            if (semi >= 0) t = t.substring(0, semi).strip();
            if (t.equalsIgnoreCase(token)) return true;
        }
        return false;
    }

    private static HeaderField checkOutgoing(HeaderField f) {
        String problem = nameProblem(f.name());
        if (problem == null) problem = valueProblem(f.value());
        if (problem != null) throw new IllegalArgumentException(f.name() + ": " + problem);
        return f;
    }

    static String first(List<HeaderField> fields, String name) {
        for (HeaderField f : fields) {
            if (f.name().equals(name)) return f.value();
        }
        return null;
    }

    private static String once(int streamId, String previous, HeaderField f) throws Http2Exception {
        if (previous != null) throw malformed(streamId, "duplicate " + f.name());
        return f.value();
    }

    private static void checkValue(int streamId, HeaderField f) throws Http2Exception {
        String problem = valueProblem(f.value());
        if (problem != null) throw malformed(streamId, "field " + f.name() + ": " + problem);
    }

    private static void checkRegular(int streamId, HeaderField f) throws Http2Exception {
        String name = f.name();
        String problem = nameProblem(name);
        if (problem != null) throw malformed(streamId, problem);
        if (CONNECTION_SPECIFIC.contains(name)) throw malformed(streamId, "connection-specific field " + name);
        if (name.equals("te") && !f.value().equalsIgnoreCase("trailers")) {
            throw malformed(streamId, "te other than trailers: " + f.value());
        }
    }

    /** What is wrong with a field name (§8.2.1), or null. Pseudo-header names may start with a colon. */
    private static String nameProblem(String name) {
        if (name.isEmpty() || name.equals(":")) return "empty field name";
        for (int i = name.startsWith(":") ? 1 : 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c >= 'A' && c <= 'Z') return "upper-case field name " + name;
            if (c <= 0x20 || c >= 0x7f || c == ':') return "invalid character in field name " + printable(name);
        }
        return null;
    }

    /** What is wrong with a field value (§8.2.1), or null. */
    private static String valueProblem(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == 0 || c == '\r' || c == '\n') return "NUL, CR or LF in value";
            if (c > 0xff) return "value is not octets";
        }
        if (!value.isEmpty()) {
            char a = value.charAt(0);
            char z = value.charAt(value.length() - 1);
            if (a == ' ' || a == '\t' || z == ' ' || z == '\t') return "leading or trailing whitespace in value";
        }
        return null;
    }

    private static long mergeContentLength(int streamId, long previous, String value) throws Http2Exception {
        long result = previous;
        for (String part : value.split(",", -1)) {
            String v = part.strip();
            if (v.isEmpty() || v.length() > 18 || !isDigits(v)) throw malformed(streamId, "invalid content-length " + value);
            long n = Long.parseLong(v);
            if (result >= 0 && result != n) throw malformed(streamId, "conflicting content-length values");
            result = n;
        }
        return result;
    }

    private static boolean isDigits(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    private static String printable(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c > 0x20 && c < 0x7f) b.append(c);
            else b.append(String.format("\\x%02x", (int) c));
        }
        return b.toString();
    }

    private static Http2Exception malformed(int streamId, String message) {
        return Http2Exception.streamError(streamId, ErrorCode.PROTOCOL_ERROR, "malformed message: " + message);
    }
}
