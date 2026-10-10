package org.microproxy.extras;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The small amount of JSON the extras need, without a library: escaping and an object writer (for
 * {@link ActivityLogger}, {@link HttpLogger} and {@link HarRecorder}), and a parser (for HAR
 * files). Objects are written field by field, in order; parsed objects keep their order too.
 */
final class Json {

    private static final HexFormat HEX = HexFormat.of();

    private final StringBuilder sb = new StringBuilder("{");

    /** Escapes a string for inclusion in a JSON string literal. */
    static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20 || Character.isSurrogate(c) && !validSurrogate(s, i)) {
                        sb.append("\\u").append(HEX.toHexDigits(c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    private static boolean validSurrogate(String s, int i) {
        char c = s.charAt(i);
        if (Character.isHighSurrogate(c)) return i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1));
        return i > 0 && Character.isHighSurrogate(s.charAt(i - 1));
    }

    /** {@return {@code s} as a JSON string literal, or {@code null}} */
    static String string(String s) {
        return s == null ? "null" : "\"" + escape(s) + "\"";
    }

    /** {@return a JSON array of the given JSON values} */
    static String array(List<String> jsonValues) {
        return "[" + String.join(",", jsonValues) + "]";
    }

    Json field(String name, String value) {
        return raw(name, string(value));
    }

    Json field(String name, long value) {
        return raw(name, String.valueOf(value));
    }

    Json field(String name, boolean value) {
        return raw(name, String.valueOf(value));
    }

    /** A number with up to three decimals, as HAR timings are written. */
    Json field(String name, double value) {
        return raw(name, number(value));
    }

    static String number(double value) {
        if (value == Math.rint(value) && Math.abs(value) < 1e15) return String.valueOf((long) value);
        return String.format(java.util.Locale.ROOT, "%.3f", value);
    }

    /** Adds a field whose value is already JSON. */
    Json raw(String name, String json) {
        if (sb.length() > 1) sb.append(',');
        sb.append('"').append(escape(name)).append("\":").append(json);
        return this;
    }

    String end() {
        return sb + "}";
    }

    // ---------------------------------------------------------------------------------------
    // Parsing
    // ---------------------------------------------------------------------------------------

    /**
     * Parses a JSON text: objects become {@link LinkedHashMap}s, arrays {@link ArrayList}s,
     * numbers {@link Long}s or {@link Double}s, and {@code null} null.
     *
     * @throws IllegalArgumentException if the text is not valid JSON
     */
    static Object parse(String text) {
        Parser p = new Parser(text);
        Object value = p.value(0);
        p.space();
        if (p.pos < text.length()) throw p.error("trailing characters");
        return value;
    }

    private static final class Parser {
        private static final int MAX_DEPTH = 512;
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        Object value(int depth) {
            if (depth > MAX_DEPTH) throw error("nested too deeply");
            space();
            if (pos >= s.length()) throw error("unexpected end");
            char c = s.charAt(pos);
            return switch (c) {
                case '{' -> object(depth);
                case '[' -> array(depth);
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> number();
            };
        }

        private Map<String, Object> object(int depth) {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++;
            space();
            if (peek('}')) return map;
            while (true) {
                space();
                if (pos >= s.length() || s.charAt(pos) != '"') throw error("expected a field name");
                String name = string();
                space();
                expect(':');
                map.put(name, value(depth + 1));
                space();
                if (peek('}')) return map;
                expect(',');
            }
        }

        private List<Object> array(int depth) {
            List<Object> list = new ArrayList<>();
            pos++;
            space();
            if (peek(']')) return list;
            while (true) {
                list.add(value(depth + 1));
                space();
                if (peek(']')) return list;
                expect(',');
            }
        }

        private String string() {
            pos++;
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos >= s.length()) throw error("unterminated string");
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                if (pos >= s.length()) throw error("unterminated escape");
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
                        } catch (NumberFormatException ex) {
                            throw error("bad \\u escape");
                        }
                        pos += 4;
                    }
                    default -> throw error("bad escape \\" + e);
                }
            }
        }

        private Object number() {
            int start = pos;
            while (pos < s.length() && "+-0123456789.eE".indexOf(s.charAt(pos)) >= 0) pos++;
            String n = s.substring(start, pos);
            if (n.isEmpty()) throw error("unexpected character '" + s.charAt(start) + "'");
            try {
                if (n.indexOf('.') < 0 && n.indexOf('e') < 0 && n.indexOf('E') < 0) {
                    try {
                        return Long.parseLong(n);
                    } catch (NumberFormatException tooLong) {
                        return Double.parseDouble(n);
                    }
                }
                return Double.parseDouble(n);
            } catch (NumberFormatException e) {
                throw error("bad number " + n);
            }
        }

        private Object literal(String word, Object value) {
            if (!s.startsWith(word, pos)) throw error("unexpected character '" + s.charAt(pos) + "'");
            pos += word.length();
            return value;
        }

        private boolean peek(char c) {
            if (pos < s.length() && s.charAt(pos) == c) {
                pos++;
                return true;
            }
            return false;
        }

        private void expect(char c) {
            if (!peek(c)) throw error("expected '" + c + "'");
        }

        void space() {
            while (pos < s.length() && (s.charAt(pos) == ' ' || s.charAt(pos) == '\t' || s.charAt(pos) == '\n'
                    || s.charAt(pos) == '\r')) {
                pos++;
            }
        }

        IllegalArgumentException error(String what) {
            return new IllegalArgumentException("invalid JSON: " + what + " at offset " + pos);
        }
    }
}
