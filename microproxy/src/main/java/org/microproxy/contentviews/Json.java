package org.microproxy.contentviews;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A small JSON parser and pretty-printer (RFC 8259) for the views: objects keep their key order,
 * numbers keep their text, and nesting is bounded.
 */
final class Json {

    /** JSON's {@code null}. */
    static final Object NULL = new Object() {
        @Override
        public String toString() {
            return "null";
        }
    };

    /**
     * A number, as written.
     *
     * @param text the number's text
     */
    record Num(String text) {}

    static final int MAX_DEPTH = 256;

    private final String s;
    private int pos;

    private Json(String s) {
        this.s = s;
    }

    /** Parses a JSON text: objects are {@code Map}s, arrays {@code List}s, {@code null} is {@link #NULL}. */
    static Object parse(String text) throws DecodeException {
        Json p = new Json(text);
        p.space();
        Object value = p.value(0);
        p.space();
        if (p.pos < text.length()) throw p.error("unexpected data after the value");
        return value;
    }

    private Object value(int depth) throws DecodeException {
        if (depth > MAX_DEPTH) throw error("nested more than " + MAX_DEPTH + " deep");
        if (pos >= s.length()) throw error("unexpected end");
        char c = s.charAt(pos);
        switch (c) {
            case '{' -> {
                pos++;
                Map<String, Object> out = new LinkedHashMap<>();
                space();
                if (peek('}')) return out;
                while (true) {
                    space();
                    if (pos >= s.length() || s.charAt(pos) != '"') throw error("expected a string key");
                    String key = string();
                    space();
                    expect(':');
                    space();
                    out.put(key, value(depth + 1));
                    space();
                    if (peek('}')) return out;
                    expect(',');
                }
            }
            case '[' -> {
                pos++;
                List<Object> out = new ArrayList<>();
                space();
                if (peek(']')) return out;
                while (true) {
                    space();
                    out.add(value(depth + 1));
                    space();
                    if (peek(']')) return out;
                    expect(',');
                }
            }
            case '"' -> {
                return string();
            }
            default -> {
                if (s.startsWith("true", pos)) {
                    pos += 4;
                    return Boolean.TRUE;
                }
                if (s.startsWith("false", pos)) {
                    pos += 5;
                    return Boolean.FALSE;
                }
                if (s.startsWith("null", pos)) {
                    pos += 4;
                    return NULL;
                }
                return number();
            }
        }
    }

    private Num number() throws DecodeException {
        int start = pos;
        peek('-');
        if (pos < s.length() && s.charAt(pos) == '0') {
            pos++;
        } else if (!digits()) {
            throw error("unexpected character");
        }
        if (peek('.') && !digits()) throw error("digits expected after '.'");
        if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
            pos++;
            if (!peek('+')) peek('-');
            if (!digits()) throw error("digits expected in the exponent");
        }
        return new Num(s.substring(start, pos));
    }

    private boolean digits() {
        int start = pos;
        while (pos < s.length() && s.charAt(pos) >= '0' && s.charAt(pos) <= '9') pos++;
        return pos > start;
    }

    private String string() throws DecodeException {
        pos++;
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= s.length()) throw error("unterminated string");
            char c = s.charAt(pos++);
            if (c == '"') return sb.toString();
            if (c < 0x20) throw error("control character in a string");
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            if (pos >= s.length()) throw error("unterminated string");
            char e = s.charAt(pos++);
            switch (e) {
                case '"', '\\', '/' -> sb.append(e);
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                case 'u' -> {
                    if (pos + 4 > s.length()) throw error("bad \\u escape");
                    try {
                        sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                    } catch (NumberFormatException x) {
                        throw error("bad \\u escape");
                    }
                    pos += 4;
                }
                default -> throw error("bad escape \\" + e);
            }
        }
    }

    private void space() {
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') return;
            pos++;
        }
    }

    private boolean peek(char c) {
        if (pos < s.length() && s.charAt(pos) == c) {
            pos++;
            return true;
        }
        return false;
    }

    private void expect(char c) throws DecodeException {
        if (!peek(c)) throw error("expected '" + c + "'");
    }

    private DecodeException error(String what) {
        return new DecodeException("invalid JSON: " + what + " at character " + pos);
    }

    // ---------------------------------------------------------------------------------------
    // Writing
    // ---------------------------------------------------------------------------------------

    /** {@code value} as indented JSON. */
    static String pretty(Object value, String indent) {
        StringBuilder sb = new StringBuilder();
        write(sb, value, indent, "");
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object value, String indent, String current) {
        switch (value) {
            case Map<?, ?> map when map.isEmpty() -> sb.append("{}");
            case Map<?, ?> map -> {
                sb.append("{\n");
                String inner = current + indent;
                int i = 0;
                for (Map.Entry<?, ?> e : map.entrySet()) {
                    sb.append(inner);
                    quote(sb, String.valueOf(e.getKey()));
                    sb.append(": ");
                    write(sb, e.getValue(), indent, inner);
                    sb.append(++i < map.size() ? ",\n" : "\n");
                }
                sb.append(current).append('}');
            }
            case List<?> list when list.isEmpty() -> sb.append("[]");
            case List<?> list -> {
                sb.append("[\n");
                String inner = current + indent;
                for (int i = 0; i < list.size(); i++) {
                    sb.append(inner);
                    write(sb, list.get(i), indent, inner);
                    sb.append(i + 1 < list.size() ? ",\n" : "\n");
                }
                sb.append(current).append(']');
            }
            case String str -> quote(sb, str);
            case Num n -> sb.append(n.text());
            default -> sb.append(value);
        }
    }

    /** {@code value} as compact JSON. */
    static String compact(Object value) {
        StringBuilder sb = new StringBuilder();
        compact(sb, value);
        return sb.toString();
    }

    private static void compact(StringBuilder sb, Object value) {
        switch (value) {
            case Map<?, ?> map -> {
                sb.append('{');
                int i = 0;
                for (Map.Entry<?, ?> e : map.entrySet()) {
                    if (i++ > 0) sb.append(',');
                    quote(sb, String.valueOf(e.getKey()));
                    sb.append(':');
                    compact(sb, e.getValue());
                }
                sb.append('}');
            }
            case List<?> list -> {
                sb.append('[');
                for (int i = 0; i < list.size(); i++) {
                    if (i > 0) sb.append(',');
                    compact(sb, list.get(i));
                }
                sb.append(']');
            }
            case String str -> quote(sb, str);
            case Num n -> sb.append(n.text());
            default -> sb.append(value);
        }
    }

    static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20 || Character.isSurrogate(c) && !validPair(s, i)) {
                        sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private static boolean validPair(String s, int i) {
        char c = s.charAt(i);
        if (Character.isHighSurrogate(c)) return i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1));
        return i > 0 && Character.isHighSurrogate(s.charAt(i - 1));
    }
}
