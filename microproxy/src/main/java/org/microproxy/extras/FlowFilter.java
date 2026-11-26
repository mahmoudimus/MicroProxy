/*
 * Ported from mitmproxy's mitmproxy/flowfilter.py (https://github.com/mitmproxy/mitmproxy),
 * Copyright (c) 2013, Aldo Cortesi. Licensed under the MIT License; see
 * META-INF/LICENSE-mitmproxy.txt. MicroProxy changes: a hand-written parser instead of pyparsing,
 * a subset of the operators, quoted strings that keep regular-expression escapes, and
 * three-valued evaluation so that body matchers stay lazy.
 */
package org.microproxy.extras;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.HttpBodies;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpMessage;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpUtil;

/**
 * A flow filter expression, in the syntax of mitmproxy's filters, which the addons ({@link
 * MapLocal}, {@link MapRemote}, {@link ModifyBody}, {@link ModifyHeaders}, {@link BlockList},
 * {@link AntiCache}, {@link StickyCookie}, {@link HarRecorder}) take to choose the exchanges they
 * act on.
 *
 * <table>
 *   <caption>Operators</caption>
 *   <tr><th>expression</th><th>matches</th></tr>
 *   <tr><td>{@code ~u regex}, or a bare {@code regex}</td><td>the URL (absolute, {@code https://}
 *       inside intercepted sessions), normalized: lower-case scheme and host, no user info, no
 *       trailing dot on the host, the port as the proxy reads it ({@code :080}, {@code :+80} and
 *       {@code :} are port 80) and dropped when it is the scheme's default, escapes of
 *       unreserved characters (letters, digits, {@code - . _ ~}) decoded and other escapes in
 *       upper-case hex, and dot segments removed from the path. Escaped {@code /} and {@code \},
 *       {@code ;} parameters and {@code //} are left as they are. A rule that looks for something
 *       the normalized URL cannot have logs a warning when parsed</td></tr>
 *   <tr><td>{@code ~d regex}</td><td>the request's host</td></tr>
 *   <tr><td>{@code ~m regex}</td><td>the method</td></tr>
 *   <tr><td>{@code ~h regex}, {@code ~hq regex}, {@code ~hs regex}</td><td>a header line ({@code
 *       Name: value}) of the request or the response, the request, the response</td></tr>
 *   <tr><td>{@code ~t regex}, {@code ~tq regex}, {@code ~ts regex}</td><td>the {@code
 *       Content-Type} of the request or the response, the request, the response</td></tr>
 *   <tr><td>{@code ~b regex}, {@code ~bq regex}, {@code ~bs regex}</td><td>the decoded body of the
 *       request or the response, the request, the response</td></tr>
 *   <tr><td>{@code ~c code}</td><td>the response status</td></tr>
 *   <tr><td>{@code ~q}, {@code ~s}</td><td>a request without a response yet, an exchange with a
 *       response</td></tr>
 *   <tr><td>{@code ~a}</td><td>an asset response: CSS, JavaScript, images, fonts</td></tr>
 *   <tr><td>{@code ~all}</td><td>everything</td></tr>
 *   <tr><td>{@code !x}, {@code x & y}, {@code x | y}, {@code (x)}</td><td>not, and, or,
 *       grouping</td></tr>
 * </table>
 *
 * <p>{@code !} binds tightest, then {@code &}, then {@code |}; expressions written next to each
 * other are joined by "and" with the lowest precedence of all, as in mitmproxy ({@code a b | c}
 * means {@code a & (b | c)}). Regular expressions are {@link Pattern java.util.regex} patterns,
 * searched for anywhere in the subject, ignoring case. One that contains spaces or any of {@code
 * ( ) ~ ' "} goes in single or double quotes; inside quotes a backslash escapes only the quote
 * and itself, so {@code "\d+ items"} keeps its {@code \d}. Operators need spaces around them
 * after a bare word: {@code ~u a|b} is the URL regex {@code a|b}.
 *
 * <p>Request-only addons evaluate filters before the response exists, so {@code ~s}, {@code ~c}
 * and the response matchers are false there, as in mitmproxy. A body matcher can only be decided
 * once its body has been buffered. {@link #matches} counts an unknown body as not matching;
 * {@link #mayMatch} tells whether the filter could still match once the bodies are known, which
 * is how the addons buffer only the exchanges a filter might select.
 */
public final class FlowFilter {

    private static final System.Logger LOG = System.getLogger(FlowFilter.class.getName());

    /**
     * In a URL rule's source: something the normalized URL no longer has in its authority or
     * path (an escaped unreserved character, the scheme's default port, user info, a dot
     * segment), so the rule may no longer match. A heuristic, for a warning only.
     */
    private static final Pattern STALE_URL_PATTERN = Pattern.compile(String.join("|",
            "%(2[de]|3[0-9]|4[1-9a-f]|5[0-9a]|5f|6[1-9a-f]|7[0-9a]|7e)",
            "http:/+(?:\\[[^\\]]*\\]|[^/\\[])*:80(?![0-9\\\\\\[{(])",
            "https:/+(?:\\[[^\\]]*\\]|[^/\\[])*:443(?![0-9\\\\\\[{(])",
            "://(?:\\[[^\\]]*\\]|[^/@\\[])*@",
            "(?:^|/)(?:\\\\?\\.\\\\?\\.(?:/|\\$|\\(|$)|\\\\?\\./)"),
            Pattern.CASE_INSENSITIVE);

    /** Whether a URL rule's regex looks written for URLs as clients spell them; see {@link #normalizedUrl}. */
    static boolean looksStale(String regex) {
        return STALE_URL_PATTERN.matcher(regex).find();
    }

    /** The filter that matches every exchange ({@code ~all}). */
    public static final FlowFilter ALL = parse("~all");

    private final String expression;
    private final Node root;

    private FlowFilter(String expression, Node root) {
        this.expression = expression;
        this.root = root;
    }

    /**
     * Parses a filter expression.
     *
     * @param expression the expression, such as {@code ~d example.com & !~m GET}
     * @return the parsed filter
     * @throws IllegalArgumentException if the expression is empty or invalid
     */
    public static FlowFilter parse(String expression) {
        Objects.requireNonNull(expression, "expression");
        if (expression.isBlank()) throw new IllegalArgumentException("empty filter expression");
        return new FlowFilter(expression, new Parser(expression).parse());
    }

    /** {@return the expression this filter was parsed from} */
    public String expression() {
        return expression;
    }

    /**
     * Whether {@code flow} matches. Body matchers whose body is not available do not match.
     *
     * @param flow the exchange to test
     * @return whether the exchange matches
     */
    public boolean matches(Flow flow) {
        return root.eval(flow) == Tri.YES;
    }

    /**
     * Whether {@code flow} could match once the bodies that are not available yet are known: false
     * only when the parts already known rule a match out.
     *
     * @param flow the exchange to test, perhaps without its bodies
     * @return whether the exchange might match
     */
    public boolean mayMatch(Flow flow) {
        return root.eval(flow) != Tri.NO;
    }

    /** {@return whether the expression looks at the request body ({@code ~b}, {@code ~bq})} */
    public boolean usesRequestBody() {
        return root.uses(Scope.REQUEST);
    }

    /** {@return whether the expression has a URL rule ({@code ~u} or a bare regex)} */
    public boolean usesUrl() {
        return root.usesUrl();
    }

    /** {@return whether the expression looks at the response body ({@code ~b}, {@code ~bs})} */
    public boolean usesResponseBody() {
        return root.uses(Scope.RESPONSE);
    }

    @Override
    public String toString() {
        return expression;
    }

    /**
     * An exchange as filters see it: the request, the response once there is one, and the bodies
     * when they have been buffered.
     */
    public interface Flow {

        /** {@return the request} */
        HttpRequest request();

        /** {@return the absolute URL of the request} */
        String url();

        /** {@return the response, or null before there is one} */
        default HttpResponse response() {
            return null;
        }

        /** {@return the decoded request body, or null if it is not available} */
        default byte[] requestBody() {
            return null;
        }

        /** {@return the decoded response body, or null if it is not available} */
        default byte[] responseBody() {
            return null;
        }
    }

    /**
     * A view of an exchange for filters. A body is available when its message is a {@link
     * FullHttpMessage} (buffered) or declares no body; it is decoded (gzip, deflate, ...) only when
     * a body matcher asks for it, and used as received if it cannot be decoded.
     *
     * @param request the request
     * @param url the absolute URL of the request
     * @param response the response, or null before there is one
     * @return a view of the exchange
     */
    public static Flow flow(HttpRequest request, String url, HttpResponse response) {
        return new MessageFlow(request, url, response);
    }

    /**
     * {@code flow} as URL rules see it with the query of its normalized URL decoded, in each way
     * an origin may decode it: escapes as UTF-8 with {@code +} kept and with {@code +} as a space,
     * each also with the query delimiters {@code & = # ;} left escaped (so {@code [^&]*} does not
     * stop at a decoded {@code %26} the origin reads inside one value). A form with a decoded
     * line terminator is offered twice, for URL rules with {@code .} crossing it and stopping at
     * it. Forms equal to the normalized URL or to each other are left out, so the list is
     * empty when decoding changes nothing. Origins decode query values, so {@code
     * ?file=%2Ffiles%2Fx} is {@code ?file=/files/x} to them; {@link BlockList} blocks when a rule
     * matches the normalized URL or any of these forms. Only URL rules see the difference.
     *
     * @param flow the exchange
     * @return the exchange with its query decoded for URL rules, one flow per distinct form
     */
    public static List<Flow> queryDecoded(Flow flow) {
        String normalized = normalizedUrl(flow.url());
        List<Flow> forms = new ArrayList<>(8);
        List<String> seen = new ArrayList<>(5);
        seen.add(normalized);
        for (boolean keepDelimiters : new boolean[] {false, true}) {
            for (boolean plusAsSpace : new boolean[] {false, true}) {
                String decoded = decodeQuery(normalized, plusAsSpace, keepDelimiters);
                if (!seen.contains(decoded)) {
                    seen.add(decoded);
                    forms.add(new QueryDecodedFlow(flow, decoded, true));
                    if (hasLineTerminator(decoded)) forms.add(new QueryDecodedFlow(flow, decoded, false));
                }
            }
        }
        return forms;
    }

    /**
     * {@code url} with everything after its first {@code ?} decoded: escapes as UTF-8 ({@code
     * U+FFFD} for bad sequences, malformed escapes kept; origins that decode as ISO-8859-1 are not
     * modelled), {@code +} as a space when {@code plusAsSpace}, and escapes of {@code & = # ;}
     * kept when {@code keepDelimiters}. The fragment is included: a request-target has none, and origins that keep a
     * {@code #} in the query decode what follows it too. Decoded control characters are left as
     * they are, as the origin sees them; URL patterns are not {@code MULTILINE}, so they cannot
     * make {@code ^} or {@code $} match inside the URL.
     */
    static String decodeQuery(String url, boolean plusAsSpace, boolean keepDelimiters) {
        int q = url.indexOf('?');
        if (q < 0 || (url.indexOf('%', q) < 0 && (!plusAsSpace || url.indexOf('+', q) < 0))) return url;
        StringBuilder sb = new StringBuilder(url.length());
        sb.append(url, 0, q + 1);
        java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        int end = url.length();
        for (int i = q + 1; i < end; i++) {
            char c = url.charAt(i);
            int hi = c == '%' && i + 2 < end ? hex(url.charAt(i + 1)) : -1;
            int lo = hi >= 0 ? hex(url.charAt(i + 2)) : -1;
            int b = lo >= 0 ? hi * 16 + lo : -1;
            if (b >= 0 && !(keepDelimiters && (b == '&' || b == '=' || b == '#' || b == ';'))) {
                bytes.write(b);
                i += 2;
                continue;
            }
            if (bytes.size() > 0) {
                sb.append(bytes.toString(UTF_8));
                bytes.reset();
            }
            if (b >= 0) {
                sb.append(url, i, i + 3);
                i += 2;
                continue;
            }
            sb.append(plusAsSpace && c == '+' ? ' ' : c);
        }
        if (bytes.size() > 0) sb.append(bytes.toString(UTF_8));
        return sb.toString();
    }

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    /**
     * {@code s}, raw request text, with control characters and every non-ASCII character escaped.
     * HTTP/1, HPACK and QPACK all give request text one character per byte (ISO-8859-1), so each
     * is escaped as the byte it is; a character above {@code U+00FF}, from a URL handed to {@link
     * #normalizedUrl} directly, is escaped as UTF-8. A raw {@code é} and {@code %C3%A9} then look
     * the same to a rule, and no line terminator reaches the regex.
     */
    private static String escapeRaw(String s) {
        StringBuilder sb = null;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 0x20 && c < 0x7f) {
                if (sb != null) sb.append(c);
                continue;
            }
            if (sb == null) sb = new StringBuilder(s.length() + 8).append(s, 0, i);
            byte[] encoded = c > 0xff ? String.valueOf(c).getBytes(UTF_8) : new byte[] {(byte) c};
            for (byte b : encoded) sb.append('%').append(HEX[(b >> 4) & 0xf]).append(HEX[b & 0xf]);
        }
        return sb == null ? s : sb.toString();
    }

    /** Whether {@code s} has a character {@link Pattern} treats as a line terminator. */
    private static boolean hasLineTerminator(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\n' || c == '\r' || c == '\u0085' || c == '\u2028' || c == '\u2029') return true;
        }
        return false;
    }

    /**
     * A flow whose URL rules see {@link #ruleUrl}, matched with or without {@link Pattern#DOTALL};
     * everything else is the delegate's.
     */
    private static final class QueryDecodedFlow implements Flow {
        private final Flow delegate;
        private final String ruleUrl;
        private final boolean dotAll;

        QueryDecodedFlow(Flow delegate, String ruleUrl, boolean dotAll) {
            this.delegate = delegate;
            this.ruleUrl = ruleUrl;
            this.dotAll = dotAll;
        }

        @Override
        public HttpRequest request() {
            return delegate.request();
        }

        @Override
        public String url() {
            return delegate.url();
        }

        @Override
        public HttpResponse response() {
            return delegate.response();
        }

        @Override
        public byte[] requestBody() {
            return delegate.requestBody();
        }

        @Override
        public byte[] responseBody() {
            return delegate.responseBody();
        }
    }

    private static final class MessageFlow implements Flow {
        private final HttpRequest request;
        private final String url;
        private final HttpResponse response;
        private byte[] requestBody;
        private byte[] responseBody;

        MessageFlow(HttpRequest request, String url, HttpResponse response) {
            this.request = request;
            this.url = url;
            this.response = response;
        }

        @Override
        public HttpRequest request() {
            return request;
        }

        @Override
        public String url() {
            return url;
        }

        @Override
        public HttpResponse response() {
            return response;
        }

        @Override
        public byte[] requestBody() {
            if (requestBody == null) requestBody = body(request);
            return requestBody;
        }

        @Override
        public byte[] responseBody() {
            if (responseBody == null && response != null) responseBody = body(response);
            return responseBody;
        }

        private static byte[] body(HttpMessage message) {
            if (message instanceof FullHttpMessage full) {
                try {
                    return HttpBodies.decoded(full);
                } catch (IOException e) {
                    return full.content();
                }
            }
            boolean declaresNone = !HttpUtil.isTransferEncodingChunked(message)
                    && HttpUtil.getContentLength(message, message instanceof HttpRequest ? 0 : -1) == 0;
            return declaresNone ? new byte[0] : null;
        }
    }

    // ---------------------------------------------------------------------------------------
    // Evaluation
    // ---------------------------------------------------------------------------------------

    /** A truth value that may not be known yet (a body matcher without its body). */
    private enum Tri {
        YES, NO, MAYBE;

        static Tri of(boolean b) {
            return b ? YES : NO;
        }

        Tri not() {
            return this == YES ? NO : this == NO ? YES : MAYBE;
        }
    }

    private enum Scope {
        REQUEST, RESPONSE, BOTH;

        boolean includes(Scope s) {
            return this == BOTH || this == s;
        }
    }

    private sealed interface Node {
        Tri eval(Flow f);

        default boolean uses(Scope bodyScope) {
            return false;
        }

        default boolean usesUrl() {
            return false;
        }
    }

    private record Not(Node node) implements Node {
        @Override
        public Tri eval(Flow f) {
            return node.eval(f).not();
        }

        @Override
        public boolean uses(Scope s) {
            return node.uses(s);
        }

        @Override
        public boolean usesUrl() {
            return node.usesUrl();
        }
    }

    private record And(List<Node> nodes) implements Node {
        @Override
        public Tri eval(Flow f) {
            Tri result = Tri.YES;
            for (Node n : nodes) {
                Tri t = n.eval(f);
                if (t == Tri.NO) return Tri.NO;
                if (t == Tri.MAYBE) result = Tri.MAYBE;
            }
            return result;
        }

        @Override
        public boolean uses(Scope s) {
            return nodes.stream().anyMatch(n -> n.uses(s));
        }

        @Override
        public boolean usesUrl() {
            return nodes.stream().anyMatch(Node::usesUrl);
        }
    }

    private record Or(List<Node> nodes) implements Node {
        @Override
        public Tri eval(Flow f) {
            Tri result = Tri.NO;
            for (Node n : nodes) {
                Tri t = n.eval(f);
                if (t == Tri.YES) return Tri.YES;
                if (t == Tri.MAYBE) result = Tri.MAYBE;
            }
            return result;
        }

        @Override
        public boolean uses(Scope s) {
            return nodes.stream().anyMatch(n -> n.uses(s));
        }

        @Override
        public boolean usesUrl() {
            return nodes.stream().anyMatch(Node::usesUrl);
        }
    }

    private record All() implements Node {
        @Override
        public Tri eval(Flow f) {
            return Tri.YES;
        }
    }

    /** {@code ~q} (no response yet) or {@code ~s} (has a response). */
    private record HasResponse(boolean wanted) implements Node {
        @Override
        public Tri eval(Flow f) {
            return Tri.of((f.response() != null) == wanted);
        }
    }

    /**
     * A URL rule, compiled with {@link Pattern#DOTALL} and without. The normalized URL has no line
     * terminator, so the two agree on it; a decoded query may hold one, and a rule can then match
     * under either ({@code .*} across it, or a lookaround that relies on {@code .} stopping at
     * it), so {@link #queryDecoded} offers such a form under each.
     */
    private record Url(Pattern dotAll, Pattern lines) implements Node {
        @Override
        public Tri eval(Flow f) {
            if (f instanceof QueryDecodedFlow q) return Tri.of((q.dotAll ? dotAll : lines).matcher(q.ruleUrl).find());
            return Tri.of(dotAll.matcher(normalizedUrl(f.url())).find());
        }

        @Override
        public boolean usesUrl() {
            return true;
        }
    }

    private record Domain(Pattern pattern) implements Node {
        @Override
        public Tri eval(Flow f) {
            String host = urlHost(f.url());
            String hostHeader = f.request().headers().get(HttpHeaderNames.HOST);
            return Tri.of(pattern.matcher(host).find()
                    || (hostHeader != null && pattern.matcher(stripPort(hostHeader)).find()));
        }
    }

    private record Method(Pattern pattern) implements Node {
        @Override
        public Tri eval(Flow f) {
            return Tri.of(pattern.matcher(f.request().method().name()).find());
        }
    }

    private record Code(int code) implements Node {
        @Override
        public Tri eval(Flow f) {
            return Tri.of(f.response() != null && f.response().status().code() == code);
        }
    }

    private record Header(Pattern pattern, Scope scope) implements Node {
        @Override
        public Tri eval(Flow f) {
            if (scope.includes(Scope.REQUEST) && pattern.matcher(headerBlock(f.request())).find()) return Tri.YES;
            HttpResponse response = f.response();
            return Tri.of(scope.includes(Scope.RESPONSE) && response != null
                    && pattern.matcher(headerBlock(response)).find());
        }
    }

    private record ContentType(Pattern pattern, Scope scope) implements Node {
        @Override
        public Tri eval(Flow f) {
            if (scope.includes(Scope.REQUEST) && contentTypeMatches(pattern, f.request())) return Tri.YES;
            HttpResponse response = f.response();
            return Tri.of(scope.includes(Scope.RESPONSE) && response != null && contentTypeMatches(pattern, response));
        }
    }

    /** {@code ~a}: the response is an asset (script, style sheet, image, font). */
    private record Asset() implements Node {
        private static final List<Pattern> TYPES = List.of("text/javascript", "application/x-javascript",
                "application/javascript", "text/css", "image/.*", "font/.*", "application/font.*").stream()
                .map(Pattern::compile).toList();

        @Override
        public Tri eval(Flow f) {
            HttpResponse response = f.response();
            return Tri.of(response != null && TYPES.stream().anyMatch(p -> contentTypeMatches(p, response)));
        }
    }

    /**
     * {@code ~b}, {@code ~bq}, {@code ~bs}. The pattern runs over the body's bytes as ISO-8859-1
     * characters, and was compiled from the UTF-8 bytes of the expression the same way, so it
     * matches bytes as mitmproxy's binary patterns do.
     */
    private record Body(Pattern pattern, Scope scope) implements Node {
        @Override
        public Tri eval(Flow f) {
            Tri result = Tri.NO;
            if (scope.includes(Scope.REQUEST)) {
                byte[] body = f.requestBody();
                if (body == null) result = Tri.MAYBE;
                else if (pattern.matcher(new String(body, ISO_8859_1)).find()) return Tri.YES;
            }
            if (scope.includes(Scope.RESPONSE) && f.response() != null) {
                byte[] body = f.responseBody();
                if (body == null) result = Tri.MAYBE;
                else if (pattern.matcher(new String(body, ISO_8859_1)).find()) return Tri.YES;
            }
            return result;
        }

        @Override
        public boolean uses(Scope s) {
            return scope.includes(s);
        }
    }

    private static boolean contentTypeMatches(Pattern pattern, HttpMessage message) {
        for (String value : message.headers().getAll(HttpHeaderNames.CONTENT_TYPE)) {
            if (pattern.matcher(value).find()) return true;
        }
        return false;
    }

    /** The header block as {@code Name: value} lines, which {@code ~h} searches line by line. */
    private static String headerBlock(HttpMessage message) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> h : message.headers().entries()) {
            sb.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
        }
        return sb.toString();
    }

    /**
     * {@code url} as URL rules ({@code ~u}, bare regexes) see it, so that a rule cannot be passed
     * by spelling the URL the proxy routes, and the origin serves, another way:
     *
     * <ul>
     *   <li>the scheme and host in lower case, without user info (the proxy routes on the host
     *       after the last {@code @}) and without a trailing {@code .} on the host;</li>
     *   <li>the port as the proxy reads it: dropped when empty or the scheme's default ({@code
     *       80} for http and ws, {@code 443} for https and wss), otherwise in plain decimal, so
     *       {@code :080}, {@code :+80} and {@code :} are all port 80;</li>
     *   <li>percent-escapes of unreserved characters (RFC 3986 section 2.3: letters, digits and
     *       {@code - . _ ~}) decoded; other escapes stay escaped, in upper-case hex, and a
     *       malformed escape is kept as it is;</li>
     *   <li>dot segments ({@code /./}, {@code /x/../}, escaped or not) removed from the path, as
     *       in RFC 3986 section 5.2.4;</li>
     *   <li>control characters and non-ASCII bytes the client sent raw escaped, so a raw {@code
     *       é} is {@code %C3%A9} and no line terminator reaches the regex.</li>
     * </ul>
     *
     * <p>Escaped {@code /} and {@code \}, {@code ;} parameters and empty segments ({@code //})
     * are left alone: origins disagree on what they mean. A URL without a scheme only has its
     * escapes normalized.
     *
     * @param url an absolute URL, as {@link Flow#url()} gives it
     * @return the normalized URL
     */
    static String normalizedUrl(String url) {
        int sep = url.indexOf("://");
        if (sep <= 0 || !url.substring(0, sep).chars().allMatch(c -> (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')) {
            return escapeRaw(decodeUnreserved(url));
        }
        String scheme = url.substring(0, sep).toLowerCase(Locale.ROOT);
        int start = sep + 3;
        int end = start;
        while (end < url.length() && "/?#".indexOf(url.charAt(end)) < 0) end++;
        String authority = url.substring(start, end);
        String hostPort = authority.substring(authority.lastIndexOf('@') + 1);
        // An IPv6 literal's zone id may hold escapes that are part of the literal; leave them.
        if (!hostPort.startsWith("[")) hostPort = decodeUnreserved(hostPort);
        int close = hostPort.startsWith("[") ? hostPort.indexOf(']') : -1;
        int colon = close >= 0 ? (hostPort.length() > close + 1 && hostPort.charAt(close + 1) == ':' ? close + 1 : -1)
                : hostPort.indexOf(':') == hostPort.lastIndexOf(':') ? hostPort.indexOf(':') : -1;
        String host = colon >= 0 ? hostPort.substring(0, colon) : hostPort;
        String port = colon >= 0 ? hostPort.substring(colon + 1) : null;
        if (close < 0 && host.endsWith(".") && host.length() > 1) host = host.substring(0, host.length() - 1);
        if (port != null) port = canonicalPort(port, switch (scheme) {
            case "http", "ws" -> 80;
            case "https", "wss" -> 443;
            default -> -1;
        });
        String rest = decodeUnreserved(url.substring(end));
        int pathEnd = 0;
        while (pathEnd < rest.length() && "?#".indexOf(rest.charAt(pathEnd)) < 0) pathEnd++;
        return escapeRaw(scheme + "://" + asciiLowerCase(host) + (port == null ? "" : ":" + port)
                + removeDotSegments(rest.substring(0, pathEnd)) + rest.substring(pathEnd));
    }

    /** {@code s} with ASCII letters in lower case; raw bytes above {@code 0x7F} are left for escaping. */
    private static String asciiLowerCase(String s) {
        StringBuilder sb = null;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                if (sb == null) sb = new StringBuilder(s);
                sb.setCharAt(i, (char) (c + 32));
            }
        }
        return sb == null ? s : sb.toString();
    }

    /**
     * {@code port} as the proxy reads it ({@link Integer#parseInt}, empty for the default): null
     * when it is the scheme's default, plain decimal otherwise, and as written if it is not a port.
     */
    private static String canonicalPort(String port, int defaultPort) {
        if (port.isEmpty()) return defaultPort > 0 ? null : port;
        try {
            int n = Integer.parseInt(port);
            if (defaultPort > 0 && n == defaultPort) return null;
            return n >= 1 && n <= 65535 ? Integer.toString(n) : port;
        } catch (NumberFormatException e) {
            return port;
        }
    }

    /** RFC 3986 section 5.2.4, in one pass over {@code path}. */
    static String removeDotSegments(String path) {
        if (path.indexOf('.') < 0) return path;
        StringBuilder out = new StringBuilder(path.length());
        int i = 0;
        int n = path.length();
        while (i < n) {
            if (path.startsWith("../", i)) {
                i += 3;
            } else if (path.startsWith("./", i)) {
                i += 2;
            } else if (path.startsWith("/./", i)) {
                i += 2;
            } else if (i + 2 == n && path.startsWith("/.", i)) {
                out.append('/');
                i = n;
            } else if (path.startsWith("/../", i)) {
                i += 3;
                out.setLength(Math.max(out.lastIndexOf("/"), 0));
            } else if (i + 3 == n && path.startsWith("/..", i)) {
                out.setLength(Math.max(out.lastIndexOf("/"), 0));
                out.append('/');
                i = n;
            } else if ((i + 1 == n && path.charAt(i) == '.') || (i + 2 == n && path.startsWith("..", i))) {
                i = n;
            } else {
                int next = path.indexOf('/', path.charAt(i) == '/' ? i + 1 : i);
                if (next < 0) next = n;
                out.append(path, i, next);
                i = next;
            }
        }
        return out.toString();
    }

    /** {@code s} with escapes of unreserved characters decoded and the rest in upper-case hex. */
    private static String decodeUnreserved(String s) {
        if (s.indexOf('%') < 0) return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int hi = i + 2 < s.length() ? hex(s.charAt(i + 1)) : -1;
            int lo = hi >= 0 ? hex(s.charAt(i + 2)) : -1;
            if (c != '%' || lo < 0) {
                sb.append(c);
                continue;
            }
            char decoded = (char) (hi * 16 + lo);
            if ((decoded >= 'a' && decoded <= 'z') || (decoded >= 'A' && decoded <= 'Z')
                    || (decoded >= '0' && decoded <= '9') || "-._~".indexOf(decoded) >= 0) {
                sb.append(decoded);
            } else {
                sb.append('%').append(Character.toUpperCase(s.charAt(i + 1))).append(Character.toUpperCase(s.charAt(i + 2)));
            }
            i += 2;
        }
        return sb.toString();
    }

    /** The value of an ASCII hex digit, or -1. */
    private static int hex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /** The host of an absolute URL, without port, brackets or user info. */
    static String urlHost(String url) {
        int start = url.indexOf("://");
        start = start < 0 ? 0 : start + 3;
        int end = start;
        while (end < url.length() && "/?#".indexOf(url.charAt(end)) < 0) end++;
        String authority = url.substring(start, end);
        int at = authority.lastIndexOf('@');
        return stripPort(at >= 0 ? authority.substring(at + 1) : authority);
    }

    private static String stripPort(String authority) {
        String a = authority.strip().toLowerCase(Locale.ROOT);
        if (a.startsWith("[")) {
            int close = a.indexOf(']');
            return close > 0 ? a.substring(1, close) : a;
        }
        int colon = a.lastIndexOf(':');
        String host = colon >= 0 && a.indexOf(':') == colon ? a.substring(0, colon) : a;
        // A trailing dot names the same host.
        return host.length() > 1 && host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
    }

    // ---------------------------------------------------------------------------------------
    // Parsing
    // ---------------------------------------------------------------------------------------

    /**
     * A recursive-descent parser for: {@code filter := or+} (joined by "and"), {@code or := and
     * ('|' and)*}, {@code and := unary ('&' unary)*}, {@code unary := '!' unary | atom}, {@code atom
     * := '(' filter ')' | '~' code [argument] | regex}.
     */
    private static final class Parser {
        private static final String NOT_IN_WORDS = "()~'\"";
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        Node parse() {
            Node n = sequence();
            skipSpace();
            if (pos < s.length()) throw error("unexpected '" + s.charAt(pos) + "'");
            return n;
        }

        /** One or more "or" expressions, joined by "and"; ends at ')' or the end. */
        private Node sequence() {
            List<Node> parts = new ArrayList<>();
            do {
                parts.add(or());
                skipSpace();
            } while (pos < s.length() && s.charAt(pos) != ')');
            return parts.size() == 1 ? parts.getFirst() : new And(List.copyOf(parts));
        }

        private Node or() {
            List<Node> parts = new ArrayList<>(List.of(and()));
            while (operator('|')) parts.add(and());
            return parts.size() == 1 ? parts.getFirst() : new Or(List.copyOf(parts));
        }

        private Node and() {
            List<Node> parts = new ArrayList<>(List.of(unary()));
            while (operator('&')) parts.add(unary());
            return parts.size() == 1 ? parts.getFirst() : new And(List.copyOf(parts));
        }

        /** Consumes {@code op} if it comes next (after spaces). */
        private boolean operator(char op) {
            skipSpace();
            if (pos < s.length() && s.charAt(pos) == op) {
                pos++;
                return true;
            }
            return false;
        }

        private Node unary() {
            skipSpace();
            if (pos >= s.length()) throw error("expected an expression");
            char c = s.charAt(pos);
            if (c == '!') {
                pos++;
                return new Not(unary());
            }
            if (c == '(') {
                pos++;
                skipSpace();
                if (pos < s.length() && s.charAt(pos) == ')') throw error("empty parentheses");
                Node inner = sequence();
                if (pos >= s.length() || s.charAt(pos) != ')') throw error("missing ')'");
                pos++;
                return inner;
            }
            if (c == ')') throw error("unexpected ')'");
            if (c == '~') return code();
            return url(argument());
        }

        private Node code() {
            int start = ++pos;
            while (pos < s.length() && Character.isLetter(s.charAt(pos))) pos++;
            String code = s.substring(start, pos);
            if (pos < s.length() && !Character.isWhitespace(s.charAt(pos)) && "()".indexOf(s.charAt(pos)) < 0) {
                throw error("unknown operator ~" + code + s.charAt(pos));
            }
            return switch (code) {
                case "all" -> new All();
                case "q" -> new HasResponse(false);
                case "s" -> new HasResponse(true);
                case "a" -> new Asset();
                case "u" -> url(argument());
                case "d" -> new Domain(regex(argument(), false));
                case "m" -> new Method(regex(argument(), false));
                case "h" -> new Header(regex(argument(), false), Scope.BOTH);
                case "hq" -> new Header(regex(argument(), false), Scope.REQUEST);
                case "hs" -> new Header(regex(argument(), false), Scope.RESPONSE);
                case "t" -> new ContentType(regex(argument(), false), Scope.BOTH);
                case "tq" -> new ContentType(regex(argument(), false), Scope.REQUEST);
                case "ts" -> new ContentType(regex(argument(), false), Scope.RESPONSE);
                case "b" -> new Body(regex(argument(), true), Scope.BOTH);
                case "bq" -> new Body(regex(argument(), true), Scope.REQUEST);
                case "bs" -> new Body(regex(argument(), true), Scope.RESPONSE);
                case "c" -> new Code(statusCode());
                default -> throw error("unknown operator ~" + code);
            };
        }

        private int statusCode() {
            skipSpace();
            int start = pos;
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
            if (start == pos || pos - start > 3) throw error("~c needs a status code");
            return Integer.parseInt(s.substring(start, pos));
        }

        /** A word or a quoted string. */
        private String argument() {
            skipSpace();
            if (pos >= s.length()) throw error("expected a regular expression");
            char c = s.charAt(pos);
            if (c == '"' || c == '\'') return quoted(c);
            int start = pos;
            while (pos < s.length() && !Character.isWhitespace(s.charAt(pos)) && NOT_IN_WORDS.indexOf(s.charAt(pos)) < 0) {
                pos++;
            }
            if (start == pos) throw error("expected a regular expression");
            return s.substring(start, pos);
        }

        private String quoted(char quote) {
            StringBuilder sb = new StringBuilder();
            pos++;
            while (pos < s.length()) {
                char c = s.charAt(pos++);
                if (c == quote) return sb.toString();
                if (c == '\\' && pos < s.length() && (s.charAt(pos) == quote || s.charAt(pos) == '\\')) {
                    c = s.charAt(pos++);
                }
                sb.append(c);
            }
            throw error("unterminated string");
        }

        /** A URL rule; warns about a pattern that can no longer match a normalized URL. */
        private Url url(String regex) {
            if (looksStale(regex)) {
                LOG.log(System.Logger.Level.WARNING, "URL rule " + regex + " may no longer match: URL rules see"
                        + " the normalized URL, whose authority and path have no escaped unreserved characters,"
                        + " default port, user info or dot segments (see the ~u operator in FlowFilter)");
            }
            // One line: a line terminator must not let ^ or $ match inside the URL. A decoded query
            // is tried with . crossing its control characters and with . stopping at them.
            Pattern pattern = regex(regex, false);
            int flags = pattern.flags() & ~Pattern.MULTILINE;
            return new Url(Pattern.compile(pattern.pattern(), flags | Pattern.DOTALL), Pattern.compile(pattern.pattern(), flags));
        }

        private Pattern regex(String regex, boolean bytes) {
            try {
                if (bytes) {
                    // Over bytes: the expression's UTF-8 bytes, as the subjects are, one char per byte.
                    return Pattern.compile(new String(regex.getBytes(UTF_8), ISO_8859_1),
                            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
                }
                return Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.MULTILINE);
            } catch (PatternSyntaxException e) {
                throw error("invalid regular expression " + regex + ": " + e.getDescription());
            }
        }

        private void skipSpace() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++;
        }

        private IllegalArgumentException error(String what) {
            return new IllegalArgumentException("invalid filter expression '" + s + "': " + what + " at " + pos);
        }
    }
}
