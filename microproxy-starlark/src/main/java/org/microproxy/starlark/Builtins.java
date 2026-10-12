package org.microproxy.starlark;

import com.google.common.collect.ImmutableMap;
import java.lang.System.Logger.Level;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpUtil;
import org.microproxy.http.HttpVersion;
import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkCallable;
import org.microproxy.thirdparty.starlark.eval.StarlarkFloat;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkList;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;
import org.microproxy.thirdparty.starlark.eval.Tuple;
import org.microproxy.thirdparty.starlark.eval.TypeConstructorValue;
import org.microproxy.thirdparty.starlark.lib.json.Json;

/**
 * The names every proxy script sees besides the Starlark built-ins: {@code response()} and the
 * modules {@code json}, {@code re}, {@code base64}, {@code digest}, {@code codecs}, {@code url},
 * {@code time} and {@code log}.
 */
final class Builtins {

    static final ImmutableMap<String, Object> PREDECLARED;

    static {
        ImmutableMap.Builder<String, Object> env = ImmutableMap.builder();
        env.put("json", Json.INSTANCE);
        env.put("re", new Re());
        env.put("base64", new Base64Module());
        env.put("digest", new DigestModule());
        env.put("codecs", new CodecsModule());
        env.put("url", new UrlModule());
        env.put("time", new TimeModule());
        env.put("log", new LogModule());
        Starlark.addMethods(env, new Functions());
        // Names for annotations, as in `def on_request(req: Request, ctx: Context) -> Response | None`.
        env.put("Request", TypeConstructorValue.of(ScriptType.REQUEST_CONSTRUCTOR));
        env.put("Response", TypeConstructorValue.of(ScriptType.RESPONSE_CONSTRUCTOR));
        env.put("Headers", TypeConstructorValue.of(ScriptType.HEADERS_CONSTRUCTOR));
        env.put("Context", TypeConstructorValue.of(ScriptType.CONTEXT_CONSTRUCTOR));
        env.put("WebSocketFrame", TypeConstructorValue.of(ScriptType.FRAME_CONSTRUCTOR));
        env.put("Failure", TypeConstructorValue.of(ScriptType.FAILURE_CONSTRUCTOR));
        env.put("Timings", TypeConstructorValue.of(ScriptType.TIMINGS_CONSTRUCTOR));
        env.put("ClientHello", TypeConstructorValue.of(ScriptType.CLIENT_HELLO_CONSTRUCTOR));
        PREDECLARED = env.buildOrThrow();
    }

    private Builtins() {}

    static byte[] bytes(Object data, String what) throws EvalException {
        if (data instanceof String s) return s.getBytes(StandardCharsets.UTF_8);
        if (data instanceof StarlarkBytes b) return b.toByteArray();
        throw Starlark.errorf("%s must be bytes or string, not %s", what, Starlark.type(data));
    }

    /** Top-level functions. */
    public static final class Functions {

        @StarlarkMethod(
                name = "response",
                doc = "Makes a response; return it from on_request to answer without contacting the server, "
                        + "or from on_response to replace the server's response.",
                parameters = {
                    @Param(name = "status", named = true, defaultValue = "200"),
                    @Param(name = "body", named = true, defaultValue = "''"),
                    @Param(name = "headers", named = true, defaultValue = "None"),
                    @Param(name = "content_type", named = true, defaultValue = "None"),
                })
        public ScriptResponse response(StarlarkInt status, Object body, Object headers, Object contentType)
                throws EvalException {
            byte[] content = body == Starlark.NONE ? new byte[0] : bytes(body, "body");
            FullHttpResponse response = new DefaultFullHttpResponse(
                    HttpVersion.HTTP_1_1, ScriptResponse.status(status.toInt("status")), content);
            ScriptResponse result = new ScriptResponse(response, false);
            if (contentType instanceof String type) {
                result.headers().set(HttpHeaderNames.CONTENT_TYPE, type);
            } else if (contentType != Starlark.NONE) {
                throw Starlark.errorf("content_type must be a string, not %s", Starlark.type(contentType));
            } else if (content.length > 0) {
                result.headers().set(HttpHeaderNames.CONTENT_TYPE,
                        body instanceof String ? "text/plain; charset=utf-8" : "application/octet-stream");
            }
            if (headers instanceof Dict<?, ?> dict) {
                for (Map.Entry<?, ?> e : dict.entrySet()) {
                    if (!(e.getKey() instanceof String name)) {
                        throw Starlark.errorf("header names are strings, not %s", Starlark.type(e.getKey()));
                    }
                    result.headers().set(name, e.getValue());
                }
            } else if (headers != Starlark.NONE) {
                throw Starlark.errorf("headers must be a dict, not %s", Starlark.type(headers));
            }
            HttpUtil.setContentLength(response, content.length);
            return result;
        }
    }

    // ---------------------------------------------------------------------------------------
    // re
    // ---------------------------------------------------------------------------------------

    /**
     * Regular expressions with Python's {@code re} function names over {@link java.util.regex}
     * syntax ({@code (?P<name>...)} is accepted too). Matching is abandoned when the calling
     * thread's deadline passes, so a pathological pattern cannot hang a connection.
     */
    @StarlarkBuiltin(name = "re", doc = "Regular expressions (java.util.regex syntax).")
    public static final class Re implements StarlarkValue {

        private static final int CACHE_LIMIT = 512;
        private static final long DEFAULT_BUDGET_MILLIS = 2_000;
        private static final Map<String, Pattern> CACHE = new ConcurrentHashMap<>();
        private static final Pattern PY_NAMED_GROUP = Pattern.compile("\\(\\?P<");
        private static final Pattern PY_BACKREF = Pattern.compile("\\(\\?P=(\\w+)\\)");

        static Pattern compile(String pattern) throws EvalException {
            Pattern p = CACHE.get(pattern);
            if (p != null) return p;
            String java = PY_NAMED_GROUP.matcher(pattern).replaceAll("(?<");
            java = PY_BACKREF.matcher(java).replaceAll("\\\\k<$1>");
            try {
                p = Pattern.compile(java);
            } catch (PatternSyntaxException e) {
                throw Starlark.errorf("bad regular expression: %s", e.getDescription());
            }
            if (CACHE.size() >= CACHE_LIMIT) CACHE.clear();
            CACHE.put(pattern, p);
            return p;
        }

        private static Matcher matcher(String pattern, String input, StarlarkThread thread) throws EvalException {
            long deadline = thread.getExpirationMs();
            if (deadline == Long.MAX_VALUE) deadline = System.currentTimeMillis() + DEFAULT_BUDGET_MILLIS;
            return compile(pattern).matcher(new Deadline(input, deadline));
        }

        private interface Op<T> {
            T run() throws EvalException, InterruptedException;
        }

        private static <T> T bounded(Op<T> op) throws EvalException, InterruptedException {
            try {
                return op.run();
            } catch (Deadline.Expired e) {
                throw Starlark.errorf("regular expression ran past the deadline");
            } catch (StackOverflowError e) {
                throw Starlark.errorf("regular expression too complex for this input");
            }
        }

        private static final String P = "pattern";

        @StarlarkMethod(name = "match", doc = "Matches at the start of string; a match or None.", allowReturnNones = true,
                useStarlarkThread = true, parameters = {@Param(name = P), @Param(name = "string")})
        public Object match(String pattern, String string, StarlarkThread thread) throws EvalException, InterruptedException {
            return bounded(() -> {
                Matcher m = matcher(pattern, string, thread);
                return m.lookingAt() ? new ReMatch(m.toMatchResult(), m.pattern()) : Starlark.NONE;
            });
        }

        @StarlarkMethod(name = "search", doc = "Finds the first match anywhere; a match or None.", allowReturnNones = true,
                useStarlarkThread = true, parameters = {@Param(name = P), @Param(name = "string")})
        public Object search(String pattern, String string, StarlarkThread thread) throws EvalException, InterruptedException {
            return bounded(() -> {
                Matcher m = matcher(pattern, string, thread);
                return m.find() ? new ReMatch(m.toMatchResult(), m.pattern()) : Starlark.NONE;
            });
        }

        @StarlarkMethod(name = "fullmatch", doc = "Matches the whole string; a match or None.", allowReturnNones = true,
                useStarlarkThread = true, parameters = {@Param(name = P), @Param(name = "string")})
        public Object fullmatch(String pattern, String string, StarlarkThread thread) throws EvalException, InterruptedException {
            return bounded(() -> {
                Matcher m = matcher(pattern, string, thread);
                return m.matches() ? new ReMatch(m.toMatchResult(), m.pattern()) : Starlark.NONE;
            });
        }

        @StarlarkMethod(name = "findall", doc = "All matches: strings, or tuples of groups when the pattern has several.",
                useStarlarkThread = true, parameters = {@Param(name = P), @Param(name = "string")})
        public StarlarkList<Object> findall(String pattern, String string, StarlarkThread thread)
                throws EvalException, InterruptedException {
            return bounded(() -> {
                Matcher m = matcher(pattern, string, thread);
                List<Object> out = new ArrayList<>();
                int groups = m.groupCount();
                while (m.find()) {
                    if (groups == 0) {
                        out.add(m.group());
                    } else if (groups == 1) {
                        out.add(orEmpty(m.group(1)));
                    } else {
                        Object[] g = new Object[groups];
                        for (int i = 0; i < groups; i++) g[i] = orEmpty(m.group(i + 1));
                        out.add(Tuple.of(g));
                    }
                }
                return StarlarkList.immutableCopyOf(out);
            });
        }

        @StarlarkMethod(
                name = "sub",
                doc = "Replaces matches with repl: a string (\\1, \\g<name> refer to groups) or a function of the match.",
                useStarlarkThread = true,
                parameters = {
                    @Param(name = P), @Param(name = "repl"), @Param(name = "string"),
                    @Param(name = "count", named = true, defaultValue = "0"),
                })
        public String sub(String pattern, Object repl, String string, StarlarkInt count, StarlarkThread thread)
                throws EvalException, InterruptedException {
            int limit = count.toInt("count");
            if (!(repl instanceof String) && !(repl instanceof StarlarkCallable)) {
                throw Starlark.errorf("repl must be a string or function, not %s", Starlark.type(repl));
            }
            return bounded(() -> {
                Matcher m = matcher(pattern, string, thread);
                StringBuilder out = new StringBuilder();
                int last = 0;
                int n = 0;
                while ((limit <= 0 || n < limit) && m.find()) {
                    out.append(string, last, m.start());
                    MatchResult r = m.toMatchResult();
                    if (repl instanceof String template) {
                        expand(template, r, m.pattern(), out);
                    } else {
                        Object s = Starlark.call(thread, repl, List.of(new ReMatch(r, m.pattern())), Map.of());
                        if (!(s instanceof String str)) {
                            throw Starlark.errorf("repl function must return a string, not %s", Starlark.type(s));
                        }
                        out.append(str);
                    }
                    last = m.end();
                    n++;
                }
                out.append(string, last, string.length());
                return out.toString();
            });
        }

        @StarlarkMethod(
                name = "split",
                doc = "Splits string by matches; captured groups are included, as in Python.",
                useStarlarkThread = true,
                parameters = {@Param(name = P), @Param(name = "string"), @Param(name = "maxsplit", named = true, defaultValue = "0")})
        public StarlarkList<Object> split(String pattern, String string, StarlarkInt maxsplit, StarlarkThread thread)
                throws EvalException, InterruptedException {
            int limit = maxsplit.toInt("maxsplit");
            return bounded(() -> {
                Matcher m = matcher(pattern, string, thread);
                List<Object> out = new ArrayList<>();
                int last = 0;
                int n = 0;
                while ((limit <= 0 || n < limit) && m.find()) {
                    if (m.end() == 0 && m.start() == 0) continue;
                    out.add(string.substring(last, m.start()));
                    for (int i = 1; i <= m.groupCount(); i++) {
                        out.add(m.group(i) == null ? Starlark.NONE : m.group(i));
                    }
                    last = m.end();
                    n++;
                }
                out.add(string.substring(last));
                return StarlarkList.immutableCopyOf(out);
            });
        }

        @StarlarkMethod(name = "escape", doc = "Escapes regular expression metacharacters in s.",
                parameters = {@Param(name = "s")})
        public String escape(String s) {
            StringBuilder out = new StringBuilder(s.length());
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if ("\\^$.|?*+()[]{}-#&~ \t\n".indexOf(c) >= 0) out.append('\\');
                out.append(c);
            }
            return out.toString();
        }

        private static String orEmpty(String s) {
            return s == null ? "" : s;
        }

        /** Expands a Python-style replacement template. */
        static void expand(String template, MatchResult m, Pattern pattern, StringBuilder out) throws EvalException {
            for (int i = 0; i < template.length(); i++) {
                char c = template.charAt(i);
                if (c != '\\' || i + 1 == template.length()) {
                    out.append(c);
                    continue;
                }
                char n = template.charAt(++i);
                if (Character.isDigit(n)) {
                    int j = i;
                    while (j < template.length() && j < i + 2 && Character.isDigit(template.charAt(j))) j++;
                    out.append(orEmpty(group(m, pattern, Integer.parseInt(template.substring(i, j)))));
                    i = j - 1;
                } else if (n == 'g' && i + 1 < template.length() && template.charAt(i + 1) == '<') {
                    int close = template.indexOf('>', i);
                    if (close < 0) throw Starlark.errorf("unterminated \\g< in replacement");
                    String ref = template.substring(i + 2, close);
                    out.append(orEmpty(ref.chars().allMatch(Character::isDigit)
                            ? group(m, pattern, Integer.parseInt(ref)) : named(m, ref)));
                    i = close;
                } else {
                    switch (n) {
                        case '\\' -> out.append('\\');
                        case 'n' -> out.append('\n');
                        case 't' -> out.append('\t');
                        case 'r' -> out.append('\r');
                        default -> out.append('\\').append(n);
                    }
                }
            }
        }

        static String group(MatchResult m, Pattern pattern, int index) throws EvalException {
            if (index < 0 || index > m.groupCount()) throw Starlark.errorf("invalid group reference %d", index);
            return m.group(index);
        }

        static String named(MatchResult m, String name) throws EvalException {
            try {
                return m.group(name);
            } catch (IllegalArgumentException e) {
                throw Starlark.errorf("unknown group name '%s'", name);
            }
        }
    }

    /** One regular expression match. */
    @StarlarkBuiltin(name = "re.match", doc = "A regular expression match.")
    public static final class ReMatch implements StarlarkValue {

        private final MatchResult m;
        private final Pattern pattern;

        ReMatch(MatchResult m, Pattern pattern) {
            this.m = m;
            this.pattern = pattern;
        }

        private int index(Object g) throws EvalException {
            if (g instanceof StarlarkInt i) {
                int index = i.toInt("group");
                if (index < 0 || index > m.groupCount()) throw Starlark.errorf("no such group %d", index);
                return index;
            }
            if (g instanceof String name) {
                Integer index = pattern.namedGroups().get(name);
                if (index == null) throw Starlark.errorf("no such group '%s'", name);
                return index;
            }
            throw Starlark.errorf("group must be an int or string, not %s", Starlark.type(g));
        }

        @StarlarkMethod(name = "group", doc = "The text of a group (0 = the whole match), or None.",
                allowReturnNones = true, parameters = {@Param(name = "g", defaultValue = "0")})
        public Object group(Object g) throws EvalException {
            String s = m.group(index(g));
            return s == null ? Starlark.NONE : s;
        }

        @StarlarkMethod(name = "groups", doc = "All groups as a tuple; None for groups that did not match.")
        public Tuple groups() {
            Object[] out = new Object[m.groupCount()];
            for (int i = 0; i < out.length; i++) {
                String s = m.group(i + 1);
                out[i] = s == null ? Starlark.NONE : s;
            }
            return Tuple.of(out);
        }

        @StarlarkMethod(name = "groupdict", doc = "Named groups as a dict.", useStarlarkThread = true)
        public Dict<String, Object> groupdict(StarlarkThread thread) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Integer> e : pattern.namedGroups().entrySet()) {
                String s = m.group(e.getValue());
                out.put(e.getKey(), s == null ? Starlark.NONE : s);
            }
            return Dict.copyOf(thread.mutability(), out);
        }

        @StarlarkMethod(name = "start", doc = "Start offset of a group, or -1.", parameters = {@Param(name = "g", defaultValue = "0")})
        public StarlarkInt start(Object g) throws EvalException {
            return StarlarkInt.of(m.start(index(g)));
        }

        @StarlarkMethod(name = "end", doc = "End offset of a group, or -1.", parameters = {@Param(name = "g", defaultValue = "0")})
        public StarlarkInt end(Object g) throws EvalException {
            return StarlarkInt.of(m.end(index(g)));
        }
    }

    /** Input that aborts matching once a deadline passes. */
    static final class Deadline implements CharSequence {

        static final class Expired extends RuntimeException {
            private static final long serialVersionUID = 1L;

            Expired() {
                super(null, null, false, false);
            }
        }

        private final CharSequence s;
        private final long deadline;
        private int reads;

        Deadline(CharSequence s, long deadline) {
            this.s = s;
            this.deadline = deadline;
        }

        @Override
        public char charAt(int index) {
            if ((++reads & 0xFFF) == 0 && System.currentTimeMillis() > deadline) {
                throw new Expired();
            }
            return s.charAt(index);
        }

        @Override
        public int length() {
            return s.length();
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            return s.subSequence(start, end);
        }

        @Override
        public String toString() {
            return s.toString();
        }
    }

    // ---------------------------------------------------------------------------------------
    // base64, digest, codecs
    // ---------------------------------------------------------------------------------------

    @StarlarkBuiltin(name = "base64", doc = "Base64 encoding.")
    public static final class Base64Module implements StarlarkValue {

        @StarlarkMethod(name = "encode", doc = "Encodes bytes (or a string's UTF-8) as base64 text.",
                parameters = {@Param(name = "data"), @Param(name = "urlsafe", named = true, defaultValue = "False")})
        public String encode(Object data, Boolean urlsafe) throws EvalException {
            return (urlsafe ? Base64.getUrlEncoder() : Base64.getEncoder()).encodeToString(bytes(data, "data"));
        }

        @StarlarkMethod(name = "decode", doc = "Decodes base64 text (padding optional) to bytes.",
                parameters = {@Param(name = "data"), @Param(name = "urlsafe", named = true, defaultValue = "False")})
        public StarlarkBytes decode(String data, Boolean urlsafe) throws EvalException {
            try {
                return StarlarkBytes.of(null, (urlsafe ? Base64.getUrlDecoder() : Base64.getDecoder()).decode(data.strip()));
            } catch (IllegalArgumentException e) {
                throw Starlark.errorf("invalid base64: %s", e.getMessage());
            }
        }
    }

    /**
     * Hashes and HMACs as lowercase hex, and {@code equal}, which compares secrets in constant
     * time: {@code ==} stops at the first differing character, so the time a comparison takes
     * tells an attacker how much of a guessed token was right.
     */
    @StarlarkBuiltin(name = "digest", doc = "Hashes and HMACs, returned as lowercase hex.")
    public static final class DigestModule implements StarlarkValue {

        private static String hash(String algorithm, Object data) throws EvalException {
            try {
                return HexFormat.of().formatHex(MessageDigest.getInstance(algorithm).digest(bytes(data, "data")));
            } catch (GeneralSecurityException e) {
                throw Starlark.errorf("%s unavailable: %s", algorithm, e.getMessage());
            }
        }

        @StarlarkMethod(name = "md5", doc = "MD5 of data, as hex.", parameters = {@Param(name = "data")})
        public String md5(Object data) throws EvalException {
            return hash("MD5", data);
        }

        @StarlarkMethod(name = "sha1", doc = "SHA-1 of data, as hex.", parameters = {@Param(name = "data")})
        public String sha1(Object data) throws EvalException {
            return hash("SHA-1", data);
        }

        @StarlarkMethod(name = "sha256", doc = "SHA-256 of data, as hex.", parameters = {@Param(name = "data")})
        public String sha256(Object data) throws EvalException {
            return hash("SHA-256", data);
        }

        @StarlarkMethod(name = "sha512", doc = "SHA-512 of data, as hex.", parameters = {@Param(name = "data")})
        public String sha512(Object data) throws EvalException {
            return hash("SHA-512", data);
        }

        @StarlarkMethod(
                name = "equal",
                doc = "Whether a and b (bytes, or strings as UTF-8) are equal, in time that does not depend on "
                        + "where they differ. Use it to compare secrets; compare digests of both sides so that "
                        + "lengths do not leak either.",
                parameters = {@Param(name = "a"), @Param(name = "b")})
        public boolean equal(Object a, Object b) throws EvalException {
            return MessageDigest.isEqual(bytes(a, "a"), bytes(b, "b"));
        }

        @StarlarkMethod(name = "hmac_sha256", doc = "HMAC-SHA256 of data with key, as hex.",
                parameters = {@Param(name = "key"), @Param(name = "data")})
        public String hmacSha256(Object key, Object data) throws EvalException {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                byte[] k = bytes(key, "key");
                mac.init(new SecretKeySpec(k.length == 0 ? new byte[1] : k, "HmacSHA256"));
                return HexFormat.of().formatHex(mac.doFinal(bytes(data, "data")));
            } catch (GeneralSecurityException e) {
                throw Starlark.errorf("HMAC failed: %s", e.getMessage());
            }
        }
    }

    @StarlarkBuiltin(name = "codecs", doc = "Converts between bytes and strings.")
    public static final class CodecsModule implements StarlarkValue {

        private static Charset charset(String name) throws EvalException {
            try {
                return Charset.forName(name);
            } catch (IllegalArgumentException e) {
                throw Starlark.errorf("unknown encoding %s", name);
            }
        }

        @StarlarkMethod(name = "decode", doc = "Decodes bytes to a string (invalid sequences become U+FFFD).",
                parameters = {@Param(name = "data"), @Param(name = "encoding", defaultValue = "'utf-8'")})
        public String decode(StarlarkBytes data, String encoding) throws EvalException {
            return new String(data.toByteArray(), charset(encoding));
        }

        @StarlarkMethod(name = "encode", doc = "Encodes a string to bytes.",
                parameters = {@Param(name = "s"), @Param(name = "encoding", defaultValue = "'utf-8'")})
        public StarlarkBytes encode(String s, String encoding) throws EvalException {
            return StarlarkBytes.of(null, s.getBytes(charset(encoding)));
        }
    }

    // ---------------------------------------------------------------------------------------
    // url, time, log
    // ---------------------------------------------------------------------------------------

    @StarlarkBuiltin(name = "url", doc = "Percent-encoding and query strings.")
    public static final class UrlModule implements StarlarkValue {

        private static final String UNRESERVED =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        private static final HexFormat HEX_UPPER = HexFormat.of().withUpperCase();

        @StarlarkMethod(name = "quote", doc = "Percent-encodes s (UTF-8), leaving unreserved characters and safe alone.",
                parameters = {@Param(name = "s"), @Param(name = "safe", named = true, defaultValue = "'/'")})
        public String quote(String s, String safe) {
            StringBuilder out = new StringBuilder();
            for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
                char c = (char) (b & 0xff);
                if (c < 0x80 && (UNRESERVED.indexOf(c) >= 0 || safe.indexOf(c) >= 0)) {
                    out.append(c);
                } else {
                    out.append('%').append(HEX_UPPER.toHexDigits(b));
                }
            }
            return out.toString();
        }

        @StarlarkMethod(name = "unquote", doc = "Decodes %XX escapes (UTF-8); '+' is left alone.",
                parameters = {@Param(name = "s")})
        public String unquote(String s) throws EvalException {
            try {
                return URLDecoder.decode(s.replace("+", "%2B"), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                throw Starlark.errorf("invalid percent-encoding: %s", e.getMessage());
            }
        }

        @StarlarkMethod(name = "parse_query", doc = "Parses a query string into a dict of name to list of values.",
                useStarlarkThread = true, parameters = {@Param(name = "query")})
        public Dict<String, Object> parseQuery(String query, StarlarkThread thread) throws EvalException {
            Map<String, List<String>> values = new LinkedHashMap<>();
            for (String pair : query.split("&")) {
                if (pair.isEmpty()) continue;
                int eq = pair.indexOf('=');
                String name = form(eq >= 0 ? pair.substring(0, eq) : pair);
                String value = eq >= 0 ? form(pair.substring(eq + 1)) : "";
                values.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            values.forEach((k, v) -> out.put(k, StarlarkList.copyOf(thread.mutability(), v)));
            return Dict.copyOf(thread.mutability(), out);
        }

        @StarlarkMethod(name = "encode_query", doc = "Builds a query string from a dict of name to value or list of values.",
                parameters = {@Param(name = "params")})
        public String encodeQuery(Dict<?, ?> params) throws EvalException {
            StringBuilder out = new StringBuilder();
            for (Map.Entry<?, ?> e : params.entrySet()) {
                String name = Starlark.str(e.getKey(), StarlarkSemantics.DEFAULT);
                Iterable<?> values = e.getValue() instanceof String || !(e.getValue() instanceof Iterable<?>)
                        ? List.of(e.getValue()) : Starlark.toIterable(e.getValue());
                for (Object v : values) {
                    if (!out.isEmpty()) out.append('&');
                    out.append(quote(name, "")).append('=').append(quote(Starlark.str(v, StarlarkSemantics.DEFAULT), ""));
                }
            }
            return out.toString();
        }

        private String form(String s) throws EvalException {
            return unquote(s.replace('+', ' '));
        }
    }

    @StarlarkBuiltin(name = "time", doc = "Clocks.")
    public static final class TimeModule implements StarlarkValue {

        @StarlarkMethod(name = "now", doc = "Seconds since the epoch, as a float.")
        public StarlarkFloat now() {
            return StarlarkFloat.of(System.currentTimeMillis() / 1000.0);
        }

        @StarlarkMethod(name = "monotonic", doc = "Seconds from an arbitrary origin that never goes backwards.")
        public StarlarkFloat monotonic() {
            return StarlarkFloat.of(System.nanoTime() / 1e9);
        }
    }

    @StarlarkBuiltin(name = "log", doc = "Writes to the proxy's log (logger microproxy.script).")
    public static final class LogModule implements StarlarkValue {

        private static final System.Logger LOG = System.getLogger("microproxy.script");

        private static void log(Level level, Object msg, StarlarkThread thread) {
            if (LOG.isLoggable(level)) {
                LOG.log(level, "{0}: {1}", thread.getCallerLocation(),
                        msg instanceof String s ? s : Starlark.str(msg, thread.getSemantics()));
            }
        }

        @StarlarkMethod(name = "debug", useStarlarkThread = true, parameters = {@Param(name = "msg")})
        public void debug(Object msg, StarlarkThread thread) {
            log(Level.DEBUG, msg, thread);
        }

        @StarlarkMethod(name = "info", useStarlarkThread = true, parameters = {@Param(name = "msg")})
        public void info(Object msg, StarlarkThread thread) {
            log(Level.INFO, msg, thread);
        }

        @StarlarkMethod(name = "warn", useStarlarkThread = true, parameters = {@Param(name = "msg")})
        public void warn(Object msg, StarlarkThread thread) {
            log(Level.WARNING, msg, thread);
        }

        @StarlarkMethod(name = "error", useStarlarkThread = true, parameters = {@Param(name = "msg")})
        public void error(Object msg, StarlarkThread thread) {
            log(Level.ERROR, msg, thread);
        }
    }
}
