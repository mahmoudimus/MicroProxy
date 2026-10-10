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
 *       inside intercepted sessions)</td></tr>
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

    private record Url(Pattern pattern) implements Node {
        @Override
        public Tri eval(Flow f) {
            return Tri.of(pattern.matcher(f.url()).find());
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
        return colon >= 0 && a.indexOf(':') == colon ? a.substring(0, colon) : a;
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
            return new Url(regex(argument(), false));
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
                case "u" -> new Url(regex(argument(), false));
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
