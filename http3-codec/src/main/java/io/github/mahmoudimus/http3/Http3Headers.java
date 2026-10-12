package io.github.mahmoudimus.http3;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * HTTP semantics of HTTP/3 field sections (RFC 9114 §4.2, §4.3): validating decoded field lists
 * into {@link RequestHeaders} and {@link ResponseHeaders}. The rules are those of HTTP/2 (RFC 9113
 * §8.2, §8.3), plus extended CONNECT (RFC 9220).
 *
 * <p>A request or response that breaks these rules is malformed, which is a stream error of type
 * H3_MESSAGE_ERROR (RFC 9114 §4.1.2); the validators throw exactly that. They check:
 *
 * <ul>
 *   <li>names: not empty, no upper-case letters, no octets 0x00-0x20 or 0x7f-0xff, and no colon
 *       except as the first character of a pseudo-header;
 *   <li>values: no NUL, CR or LF, and no leading or trailing space or tab;
 *   <li>no connection-specific fields ({@link #CONNECTION_SPECIFIC}), and {@code te} only with the
 *       value {@code trailers};
 *   <li>pseudo-headers: only the defined ones for the message kind, each at most once, all before
 *       the regular fields, and the required ones present; none in trailers;
 *   <li>CONNECT: only {@code :method} and {@code :authority}, unless {@code :protocol} makes it an
 *       extended CONNECT, which needs {@code :scheme}, {@code :path} and {@code :authority} too;
 *   <li>{@code content-length}: digits only, and every value the same.
 * </ul>
 */
public final class Http3Headers {

    /** Fields that are specific to an HTTP/1 connection and must not appear in HTTP/3 (RFC 9114 §4.2). */
    public static final Set<String> CONNECTION_SPECIFIC =
            Set.of("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade");

    private Http3Headers() {}

    /**
     * Validates a decoded request header section, accepting extended CONNECT (the caller rejects
     * it if it did not send SETTINGS_ENABLE_CONNECT_PROTOCOL; see
     * {@link #toRequest(long, List, boolean)}).
     *
     * @param streamId the stream, for errors
     * @param fields the decoded section
     * @return the request
     * @throws Http3Exception a stream error H3_MESSAGE_ERROR if it is malformed
     */
    public static RequestHeaders toRequest(long streamId, List<HeaderField> fields) throws Http3Exception {
        return toRequest(streamId, fields, true);
    }

    /**
     * Validates a decoded request header section.
     *
     * @param extendedConnect whether this endpoint sent SETTINGS_ENABLE_CONNECT_PROTOCOL = 1, which
     *     allows {@code :protocol} (RFC 9220 §3)
     * @param streamId the stream, for errors
     * @param fields the decoded section
     * @return the request
     * @throws Http3Exception a stream error H3_MESSAGE_ERROR if it is malformed
     */
    public static RequestHeaders toRequest(long streamId, List<HeaderField> fields, boolean extendedConnect) throws Http3Exception {
        String method = null;
        String scheme = null;
        String authority = null;
        String path = null;
        String protocol = null;
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
                    case ":protocol" -> {
                        if (!extendedConnect) throw malformed(streamId, ":protocol without SETTINGS_ENABLE_CONNECT_PROTOCOL");
                        protocol = once(streamId, protocol, f);
                    }
                    default -> throw malformed(streamId, "pseudo-header field " + name + " is not allowed in a request");
                }
                continue;
            }
            regularSeen = true;
            checkRegular(streamId, f);
            switch (name) {
                case "cookie" -> {
                    // Crumbs are joined into one field (RFC 9114 §4.2.1).
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
        if (protocol != null) {
            // RFC 9220 §3, RFC 8441 §4: an extended CONNECT carries all four plus :protocol.
            if (!method.equals("CONNECT")) throw malformed(streamId, ":protocol with :method " + method);
            if (protocol.isEmpty()) throw malformed(streamId, "empty :protocol");
            if (scheme == null || scheme.isEmpty()) throw malformed(streamId, "extended CONNECT without :scheme");
            if (path == null || path.isEmpty()) throw malformed(streamId, "extended CONNECT without :path");
            if (authority == null || authority.isEmpty()) throw malformed(streamId, "extended CONNECT without :authority");
        } else if (method.equals("CONNECT")) {
            // RFC 9114 §4.4: only :method and :authority.
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
        return new RequestHeaders(method, scheme, authority != null ? authority : host, path, protocol, out, contentLength);
    }

    /**
     * Validates a decoded response header section (final or 1xx).
     *
     * @param streamId the stream, for errors
     * @param fields the decoded section
     * @return the response
     * @throws Http3Exception a stream error H3_MESSAGE_ERROR if it is malformed
     */
    public static ResponseHeaders toResponse(long streamId, List<HeaderField> fields) throws Http3Exception {
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

    /**
     * Validates a trailer section: regular fields only.
     *
     * @param streamId the stream, for errors
     * @param fields the decoded section
     * @return the fields
     * @throws Http3Exception a stream error H3_MESSAGE_ERROR if it is malformed
     */
    public static List<HeaderField> validateTrailers(long streamId, List<HeaderField> fields) throws Http3Exception {
        for (HeaderField f : fields) {
            checkValue(streamId, f);
            if (f.name().startsWith(":")) throw malformed(streamId, "pseudo-header field " + f.name() + " in trailers");
            checkRegular(streamId, f);
        }
        return List.copyOf(fields);
    }

    /**
     * Checks DATA received against a declared {@code content-length} (RFC 9114 §4.1.2). Call it
     * after each DATA frame with the running total of content octets. Skip it where the content is
     * empty whatever the field says: responses to HEAD, and 204 and 304 responses.
     *
     * @param streamId the stream, for errors
     * @param declared the content length, or -1 if none was declared (then nothing is checked)
     * @param received the content octets received so far
     * @param endStream whether the stream has ended
     * @throws Http3Exception a stream error H3_MESSAGE_ERROR if the content does not match
     */
    public static void checkContentLength(long streamId, long declared, long received, boolean endStream) throws Http3Exception {
        if (declared < 0) return;
        if (received > declared) {
            throw malformed(streamId, "received " + received + " octets of content, more than content-length " + declared);
        }
        if (endStream && received != declared) {
            throw malformed(streamId, "stream ended after " + received + " octets of content, content-length is " + declared);
        }
    }

    static String first(List<HeaderField> fields, String name) {
        for (HeaderField f : fields) {
            if (f.name().equals(name)) return f.value();
        }
        return null;
    }

    static List<String> all(List<HeaderField> fields, String name) {
        List<String> values = new ArrayList<>();
        for (HeaderField f : fields) {
            if (f.name().equals(name)) values.add(f.value());
        }
        return values;
    }

    private static String once(long streamId, String previous, HeaderField f) throws Http3Exception {
        if (previous != null) throw malformed(streamId, "duplicate " + f.name());
        return f.value();
    }

    private static void checkValue(long streamId, HeaderField f) throws Http3Exception {
        String problem = valueProblem(f.value());
        if (problem != null) throw malformed(streamId, "field " + printable(f.name()) + ": " + problem);
    }

    private static void checkRegular(long streamId, HeaderField f) throws Http3Exception {
        String name = f.name();
        String problem = nameProblem(name);
        if (problem != null) throw malformed(streamId, problem);
        if (CONNECTION_SPECIFIC.contains(name)) throw malformed(streamId, "connection-specific field " + name);
        if (name.equals("te") && !f.value().equalsIgnoreCase("trailers")) {
            throw malformed(streamId, "te other than trailers: " + printable(f.value()));
        }
    }

    /** What is wrong with a field name, or null. Pseudo-header names may start with a colon. */
    private static String nameProblem(String name) {
        if (name.isEmpty() || name.equals(":")) return "empty field name";
        for (int i = name.startsWith(":") ? 1 : 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c >= 'A' && c <= 'Z') return "upper-case field name " + name;
            if (c <= 0x20 || c >= 0x7f || c == ':') return "invalid character in field name " + printable(name);
        }
        return null;
    }

    /** What is wrong with a field value, or null. */
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

    private static long mergeContentLength(long streamId, long previous, String value) throws Http3Exception {
        long result = previous;
        for (String part : value.split(",", -1)) {
            String v = part.strip();
            if (v.isEmpty() || v.length() > 18 || !isDigits(v)) throw malformed(streamId, "invalid content-length " + printable(value));
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

    private static Http3Exception malformed(long streamId, String message) {
        return Http3Exception.streamError(streamId, Http3ErrorCode.H3_MESSAGE_ERROR, "malformed message: " + message);
    }
}
