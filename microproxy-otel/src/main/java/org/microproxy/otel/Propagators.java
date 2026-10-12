package org.microproxy.otel;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.microproxy.http.HttpHeaders;

/**
 * The propagators, by the names {@code OTEL_PROPAGATORS} uses: {@code tracecontext} (W3C Trace
 * Context: {@code traceparent} and {@code tracestate}), {@code b3} (B3's single {@code b3}
 * header), {@code b3multi} (B3's {@code X-B3-*} headers) and {@code jaeger} ({@code
 * uber-trace-id}). {@code baggage} is accepted and leaves the {@code baggage} header as it is.
 */
public final class Propagators {

    /** W3C Trace Context ({@code traceparent}, {@code tracestate}), version {@code 00}. */
    public static final Propagator TRACE_CONTEXT = new TraceContext();

    /** B3 in one header: {@code b3: {trace-id}-{span-id}-{sampled}}. */
    public static final Propagator B3 = new B3Single();

    /** B3 in several headers: {@code X-B3-TraceId}, {@code X-B3-SpanId}, {@code X-B3-Sampled}. */
    public static final Propagator B3_MULTI = new B3Multi();

    /** Jaeger's {@code uber-trace-id: {trace-id}:{span-id}:{parent-span-id}:{flags}}. */
    public static final Propagator JAEGER = new Jaeger();

    /** The W3C list-member limit of {@code tracestate}. */
    static final int MAX_TRACESTATE_MEMBERS = 32;

    private Propagators() {}

    /**
     * The propagators named in {@code list}, a comma-separated list as in {@code OTEL_PROPAGATORS}:
     * {@code tracecontext}, {@code b3}, {@code b3multi}, {@code jaeger}; {@code baggage} adds none
     * (baggage passes through untouched), and {@code none} means none at all.
     *
     * @param list the names
     * @return the propagators, in order, without duplicates
     * @throws IllegalArgumentException for a name this module does not know
     */
    public static List<Propagator> parse(String list) {
        if (list.strip().equalsIgnoreCase("none")) return List.of();
        List<Propagator> out = new ArrayList<>();
        for (String raw : list.split(",")) {
            String name = raw.strip().toLowerCase(Locale.ROOT);
            Propagator p = switch (name) {
                case "", "baggage", "none" -> null;
                case "tracecontext" -> TRACE_CONTEXT;
                case "b3" -> B3;
                case "b3multi" -> B3_MULTI;
                case "jaeger" -> JAEGER;
                default -> throw new IllegalArgumentException("unknown propagator: " + raw.strip()
                        + " (known: tracecontext, baggage, b3, b3multi, jaeger, none)");
            };
            if (p != null && !out.contains(p)) out.add(p);
        }
        return List.copyOf(out);
    }

    // ---------------------------------------------------------------------------------------
    // W3C Trace Context

    /**
     * Parses a {@code traceparent} value as W3C Trace Context says: version {@code 00} exactly
     * ({@code 00-<32 hex>-<16 hex>-<2 hex>}, lower-case), or a later version that starts the same
     * way and continues only after a {@code -}; never version {@code ff}, an all-zero trace id or an
     * all-zero parent id.
     *
     * @param value the header's value
     * @return the remote context, without {@code tracestate}, or {@code null} when it is not valid
     */
    public static SpanContext parseTraceparent(String value) {
        if (value == null) return null;
        String v = trimOws(value);
        if (v.length() < 55 || !SpanContext.isLowerHex(v, 0, 2) || v.startsWith("ff")) return null;
        boolean version00 = v.startsWith("00");
        if (version00 ? v.length() != 55 : v.length() > 55 && v.charAt(55) != '-') return null;
        if (v.charAt(2) != '-' || v.charAt(35) != '-' || v.charAt(52) != '-') return null;
        if (!SpanContext.isLowerHex(v, 3, 32) || !SpanContext.isLowerHex(v, 36, 16)
                || !SpanContext.isLowerHex(v, 53, 2)) {
            return null;
        }
        long high = SpanContext.hexValue(v, 3, 16);
        long low = SpanContext.hexValue(v, 19, 16);
        long parent = SpanContext.hexValue(v, 36, 16);
        int flags = (int) SpanContext.hexValue(v, 53, 2);
        SpanContext context = new SpanContext(high, low, parent, flags, "", true);
        return context.isValid() ? context : null;
    }

    /**
     * Formats a {@code traceparent} value, version {@code 00}, with only the sampled flag.
     *
     * @param context the context
     * @return {@code 00-<trace-id>-<span-id>-<flags>}
     */
    public static String formatTraceparent(SpanContext context) {
        return "00-" + context.traceIdHex() + "-" + context.spanIdHex() + (context.isSampled() ? "-01" : "-00");
    }

    /**
     * Parses the {@code tracestate} header's values (several are joined with commas, as HTTP does):
     * up to 32 list members {@code key=value}, separated by commas with optional spaces and tabs
     * around them, empty members ignored. A key is a simple key (a lower-case letter, then up to 255
     * lower-case letters, digits, {@code _}, {@code -}, {@code *} and {@code /}) or a multi-tenant
     * one ({@code tenant@system}); a value is 1 to 256 printable characters but {@code ,} and {@code
     * =}, not ending in a space.
     *
     * @param values the header's values
     * @return the members joined with commas, an empty string for none, or {@code null} when the
     *     list is not valid (a malformed member, a duplicate key, too many members) and must be
     *     dropped
     */
    public static String parseTracestate(List<String> values) {
        if (values.isEmpty()) return "";
        StringBuilder out = new StringBuilder();
        Set<String> keys = new HashSet<>();
        for (String value : values) {
            for (String raw : value.split(",", -1)) {
                String member = trimOws(raw);
                if (member.isEmpty()) continue;
                int eq = member.indexOf('=');
                if (eq <= 0) return null;
                String key = member.substring(0, eq);
                String val = member.substring(eq + 1);
                if (!validKey(key) || !validValue(val) || !keys.add(key)) return null;
                if (keys.size() > MAX_TRACESTATE_MEMBERS) return null;
                if (!out.isEmpty()) out.append(',');
                out.append(key).append('=').append(val);
            }
        }
        return out.toString();
    }

    private static boolean validKey(String key) {
        int at = key.indexOf('@');
        if (at < 0) {
            return key.length() <= 256 && isLcAlpha(key.charAt(0)) && keyChars(key, 1, key.length());
        }
        if (key.indexOf('@', at + 1) >= 0) return false;
        int tenant = at;
        int system = key.length() - at - 1;
        return tenant >= 1 && tenant <= 241 && (isLcAlpha(key.charAt(0)) || isDigit(key.charAt(0)))
                && keyChars(key, 1, at)
                && system >= 1 && system <= 14 && isLcAlpha(key.charAt(at + 1)) && keyChars(key, at + 2, key.length());
    }

    private static boolean keyChars(String key, int from, int to) {
        for (int i = from; i < to; i++) {
            char c = key.charAt(i);
            if (!(isLcAlpha(c) || isDigit(c) || c == '_' || c == '-' || c == '*' || c == '/')) return false;
        }
        return true;
    }

    private static boolean validValue(String value) {
        int n = value.length();
        if (n == 0 || n > 256 || value.charAt(n - 1) == ' ') return false;
        for (int i = 0; i < n; i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c > 0x7e || c == ',' || c == '=') return false;
        }
        return true;
    }

    private static boolean isLcAlpha(char c) {
        return c >= 'a' && c <= 'z';
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    /** Removes the spaces and tabs (HTTP's optional whitespace) around {@code s}. */
    static String trimOws(String s) {
        int start = 0;
        int end = s.length();
        while (start < end && (s.charAt(start) == ' ' || s.charAt(start) == '\t')) start++;
        while (end > start && (s.charAt(end - 1) == ' ' || s.charAt(end - 1) == '\t')) end--;
        return start == 0 && end == s.length() ? s : s.substring(start, end);
    }

    private static final class TraceContext implements Propagator {
        @Override
        public String name() {
            return "tracecontext";
        }

        @Override
        public List<String> fields() {
            return List.of("traceparent", "tracestate");
        }

        @Override
        public SpanContext extract(HttpHeaders headers) {
            List<String> parents = headers.getAll("traceparent");
            // Two traceparent headers are ambiguous: the trace restarts.
            if (parents.size() != 1) return null;
            SpanContext parent = parseTraceparent(parents.getFirst());
            if (parent == null) return null;
            String state = parseTracestate(headers.getAll("tracestate"));
            return state == null || state.isEmpty() ? parent
                    : new SpanContext(parent.traceIdHigh(), parent.traceIdLow(), parent.spanId(), parent.flags(), state, true);
        }

        @Override
        public void inject(SpanContext context, HttpHeaders headers) {
            headers.set("traceparent", formatTraceparent(context));
            if (context.traceState().isEmpty()) {
                headers.remove("tracestate");
            } else {
                headers.set("tracestate", context.traceState());
            }
        }

        @Override
        public String toString() {
            return name();
        }
    }

    // ---------------------------------------------------------------------------------------
    // B3

    /**
     * Reads a B3 trace id (16 or 32 lower-case hex digits, the short form padded with zeros) and
     * span id (16 digits) and the sampling state; null when they are not valid.
     */
    static SpanContext b3(String traceId, String spanId, boolean sampled) {
        if (traceId == null || spanId == null) return null;
        traceId = trimOws(traceId);
        spanId = trimOws(spanId);
        int n = traceId.length();
        if (n != 16 && n != 32 || !SpanContext.isLowerHex(traceId, 0, n)) return null;
        if (spanId.length() != 16 || !SpanContext.isLowerHex(spanId, 0, 16)) return null;
        long high = n == 32 ? SpanContext.hexValue(traceId, 0, 16) : 0;
        long low = SpanContext.hexValue(traceId, n - 16, 16);
        SpanContext context = new SpanContext(high, low, SpanContext.hexValue(spanId, 0, 16),
                sampled ? SpanContext.SAMPLED : 0, "", true);
        return context.isValid() ? context : null;
    }

    private static final class B3Single implements Propagator {
        @Override
        public String name() {
            return "b3";
        }

        @Override
        public List<String> fields() {
            return List.of("b3");
        }

        @Override
        public SpanContext extract(HttpHeaders headers) {
            String value = headers.get("b3");
            if (value == null) return null;
            // {trace}-{span}[-{sampled}[-{parent}]]; a lone sampling state carries no context.
            String[] parts = trimOws(value).split("-", -1);
            if (parts.length < 2 || parts.length > 4) return null;
            boolean sampled = false;
            if (parts.length >= 3) {
                switch (parts[2]) {
                    case "1", "d" -> sampled = true;
                    case "0" -> sampled = false;
                    default -> {
                        return null;
                    }
                }
            }
            if (parts.length == 4 && (parts[3].length() != 16 || !SpanContext.isLowerHex(parts[3], 0, 16))) return null;
            return b3(parts[0], parts[1], sampled);
        }

        @Override
        public void inject(SpanContext context, HttpHeaders headers) {
            headers.set("b3", context.traceIdHex() + "-" + context.spanIdHex() + (context.isSampled() ? "-1" : "-0"));
        }

        @Override
        public String toString() {
            return name();
        }
    }

    private static final class B3Multi implements Propagator {
        @Override
        public String name() {
            return "b3multi";
        }

        @Override
        public List<String> fields() {
            return List.of("x-b3-traceid", "x-b3-spanid", "x-b3-sampled", "x-b3-parentspanid", "x-b3-flags");
        }

        @Override
        public SpanContext extract(HttpHeaders headers) {
            String sampled = headers.get("x-b3-sampled");
            boolean debug = "1".equals(headers.get("x-b3-flags"));
            boolean on = debug || sampled != null && (sampled.equals("1") || sampled.equalsIgnoreCase("true"));
            if (sampled != null && !on && !sampled.equals("0") && !sampled.equalsIgnoreCase("false")) return null;
            return b3(headers.get("x-b3-traceid"), headers.get("x-b3-spanid"), on);
        }

        @Override
        public void inject(SpanContext context, HttpHeaders headers) {
            headers.remove("x-b3-parentspanid");
            headers.remove("x-b3-flags");
            headers.set("X-B3-TraceId", context.traceIdHex());
            headers.set("X-B3-SpanId", context.spanIdHex());
            headers.set("X-B3-Sampled", context.isSampled() ? "1" : "0");
        }

        @Override
        public String toString() {
            return name();
        }
    }

    // ---------------------------------------------------------------------------------------
    // Jaeger

    private static final class Jaeger implements Propagator {
        @Override
        public String name() {
            return "jaeger";
        }

        @Override
        public List<String> fields() {
            return List.of("uber-trace-id");
        }

        @Override
        public SpanContext extract(HttpHeaders headers) {
            String value = headers.get("uber-trace-id");
            if (value == null) return null;
            // Clients sometimes URL-encode the separators.
            String v = trimOws(value);
            if (v.contains("%")) v = v.replace("%3A", ":").replace("%3a", ":");
            String[] parts = v.split(":", -1);
            if (parts.length != 4) return null;
            String trace = parts[0];
            String span = parts[1];
            String flags = parts[3];
            if (trace.isEmpty() || trace.length() > 32 || !SpanContext.isLowerHex(trace, 0, trace.length())) return null;
            if (span.isEmpty() || span.length() > 16 || !SpanContext.isLowerHex(span, 0, span.length())) return null;
            if (parts[2].isEmpty() || parts[2].length() > 16 || !SpanContext.isLowerHex(parts[2], 0, parts[2].length())) {
                return null;
            }
            if (flags.isEmpty() || flags.length() > 2 || !SpanContext.isLowerHex(flags, 0, flags.length())) return null;
            int n = trace.length();
            long high = n > 16 ? SpanContext.hexValue(trace, 0, n - 16) : 0;
            long low = SpanContext.hexValue(trace, Math.max(0, n - 16), Math.min(16, n));
            int bits = (int) SpanContext.hexValue(flags, 0, flags.length());
            // Bit 0: sampled; bit 1: debug, which is sampled too.
            boolean sampled = (bits & 0x03) != 0;
            SpanContext context = new SpanContext(high, low, SpanContext.hexValue(span, 0, span.length()),
                    sampled ? SpanContext.SAMPLED : 0, "", true);
            return context.isValid() ? context : null;
        }

        @Override
        public void inject(SpanContext context, HttpHeaders headers) {
            headers.set("uber-trace-id", context.traceIdHex() + ":" + context.spanIdHex() + ":0:"
                    + (context.isSampled() ? "1" : "0"));
        }

        @Override
        public String toString() {
            return name();
        }
    }
}
