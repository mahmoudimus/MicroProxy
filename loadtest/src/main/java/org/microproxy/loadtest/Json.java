package org.microproxy.loadtest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal JSON writer and parser, enough for the harness's results files and the line protocol
 * between the orchestrator and the load generator. Objects are {@link LinkedHashMap}s (key order is
 * kept), arrays {@link List}s, numbers {@link Long} or {@link Double}, plus strings, booleans and
 * null.
 */
public final class Json {

    private Json() {}

    /** Serializes {@code value} compactly, on one line. */
    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value, -1, 0);
        return out.toString();
    }

    /** Serializes {@code value} with two-space indentation. */
    public static String pretty(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value, 2, 0);
        return out.append('\n').toString();
    }

    private static void write(StringBuilder out, Object value, int indent, int depth) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String s) {
            quote(out, s);
        } else if (value instanceof Double d) {
            out.append(d.isNaN() || d.isInfinite() ? "null" : number(d));
        } else if (value instanceof Float f) {
            write(out, f.doubleValue(), indent, depth);
        } else if (value instanceof Number || value instanceof Boolean) {
            out.append(value);
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (!first) out.append(',');
                first = false;
                newline(out, indent, depth + 1);
                quote(out, String.valueOf(e.getKey()));
                out.append(indent < 0 ? ":" : ": ");
                write(out, e.getValue(), indent, depth + 1);
            }
            if (!map.isEmpty()) newline(out, indent, depth);
            out.append('}');
        } else if (value instanceof Iterable<?> list) {
            out.append('[');
            boolean first = true;
            boolean scalars = true;
            for (Object o : list) scalars &= !(o instanceof Map || o instanceof Iterable);
            for (Object o : list) {
                if (!first) out.append(scalars && indent >= 0 ? ", " : ",");
                if (!scalars) newline(out, indent, depth + 1);
                first = false;
                write(out, o, indent, depth + 1);
            }
            if (!first && !scalars) newline(out, indent, depth);
            out.append(']');
        } else if (value instanceof double[] arr) {
            List<Object> l = new ArrayList<>();
            for (double d : arr) l.add(d);
            write(out, l, indent, depth);
        } else if (value instanceof long[] arr) {
            List<Object> l = new ArrayList<>();
            for (long d : arr) l.add(d);
            write(out, l, indent, depth);
        } else {
            quote(out, value.toString());
        }
    }

    private static String number(double d) {
        if (d == Math.rint(d) && Math.abs(d) < 1e15) return Long.toString((long) d);
        String s = String.format(java.util.Locale.ROOT, "%.6g", d);
        if (s.contains("e") || s.contains("E")) return s;
        if (s.contains(".")) s = s.replaceAll("0+$", "").replaceAll("\\.$", "");
        return s;
    }

    private static void newline(StringBuilder out, int indent, int depth) {
        if (indent < 0) return;
        out.append('\n');
        out.append(" ".repeat(indent * depth));
    }

    private static void quote(StringBuilder out, String s) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        out.append('"');
    }

    /** Parses one JSON value. */
    public static Object parse(String text) {
        Parser p = new Parser(text);
        p.skip();
        Object v = p.value();
        p.skip();
        if (p.pos != text.length()) throw new IllegalArgumentException("trailing data at " + p.pos);
        return v;
    }

    /** Parses a JSON object. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        return (Map<String, Object>) parse(text);
    }

    private static final class Parser {
        final String s;
        int pos;

        Parser(String s) {
            this.s = s;
        }

        void skip() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++;
        }

        Object value() {
            if (pos >= s.length()) throw new IllegalArgumentException("unexpected end");
            char c = s.charAt(pos);
            switch (c) {
                case '{' -> {
                    pos++;
                    Map<String, Object> m = new LinkedHashMap<>();
                    skip();
                    if (peek('}')) return m;
                    while (true) {
                        skip();
                        String k = string();
                        skip();
                        expect(':');
                        skip();
                        m.put(k, value());
                        skip();
                        if (peek('}')) return m;
                        expect(',');
                    }
                }
                case '[' -> {
                    pos++;
                    List<Object> l = new ArrayList<>();
                    skip();
                    if (peek(']')) return l;
                    while (true) {
                        skip();
                        l.add(value());
                        skip();
                        if (peek(']')) return l;
                        expect(',');
                    }
                }
                case '"' -> {
                    return string();
                }
                case 't' -> {
                    literal("true");
                    return Boolean.TRUE;
                }
                case 'f' -> {
                    literal("false");
                    return Boolean.FALSE;
                }
                case 'n' -> {
                    literal("null");
                    return null;
                }
                default -> {
                    return number();
                }
            }
        }

        boolean peek(char c) {
            if (pos < s.length() && s.charAt(pos) == c) {
                pos++;
                return true;
            }
            return false;
        }

        void expect(char c) {
            if (!peek(c)) throw new IllegalArgumentException("expected '" + c + "' at " + pos);
        }

        void literal(String word) {
            if (!s.startsWith(word, pos)) throw new IllegalArgumentException("bad literal at " + pos);
            pos += word.length();
        }

        String string() {
            expect('"');
            StringBuilder b = new StringBuilder();
            while (true) {
                char c = s.charAt(pos++);
                if (c == '"') return b.toString();
                if (c != '\\') {
                    b.append(c);
                    continue;
                }
                char e = s.charAt(pos++);
                switch (e) {
                    case 'n' -> b.append('\n');
                    case 'r' -> b.append('\r');
                    case 't' -> b.append('\t');
                    case 'b' -> b.append('\b');
                    case 'f' -> b.append('\f');
                    case 'u' -> {
                        b.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                        pos += 4;
                    }
                    default -> b.append(e);
                }
            }
        }

        Object number() {
            int start = pos;
            boolean real = false;
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == '.' || c == 'e' || c == 'E') real = true;
                else if (!(c == '-' || c == '+' || (c >= '0' && c <= '9'))) break;
                pos++;
            }
            String n = s.substring(start, pos);
            if (n.isEmpty()) throw new IllegalArgumentException("unexpected character at " + start);
            return real ? (Object) Double.parseDouble(n) : (Object) Long.parseLong(n);
        }
    }

    // Typed accessors for parsed values.

    /** The value at {@code key} as a long, or {@code def} if absent. */
    public static long getLong(Map<String, Object> m, String key, long def) {
        Object v = m.get(key);
        return v instanceof Number n ? n.longValue() : def;
    }

    /** The value at {@code key} as a double, or {@code def} if absent. */
    public static double getDouble(Map<String, Object> m, String key, double def) {
        Object v = m.get(key);
        return v instanceof Number n ? n.doubleValue() : def;
    }

    /** The value at {@code key} as a string, or {@code def} if absent. */
    public static String getString(Map<String, Object> m, String key, String def) {
        Object v = m.get(key);
        return v == null ? def : v.toString();
    }

    /** The value at {@code key} as a boolean, or {@code def} if absent. */
    public static boolean getBool(Map<String, Object> m, String key, boolean def) {
        Object v = m.get(key);
        return v instanceof Boolean b ? b : def;
    }

    /** The object at {@code key}, or an empty map. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> getObject(Map<String, Object> m, String key) {
        Object v = m == null ? null : m.get(key);
        return v instanceof Map<?, ?> ? (Map<String, Object>) v : new LinkedHashMap<>();
    }

    /** The objects of the array at {@code key}, or an empty list. */
    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> getObjects(Map<String, Object> m, String key) {
        Object v = m == null ? null : m.get(key);
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List<?> l) {
            for (Object o : l) if (o instanceof Map<?, ?>) out.add((Map<String, Object>) o);
        }
        return out;
    }

    /** A new ordered map from alternating keys and values. */
    public static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put(String.valueOf(kv[i]), kv[i + 1]);
        return m;
    }
}
