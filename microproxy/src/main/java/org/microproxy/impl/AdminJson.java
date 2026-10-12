package org.microproxy.impl;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

/**
 * Writes the admin listener's JSON from maps (objects, in their order), collections (arrays),
 * strings, numbers, booleans and nulls, indented by two spaces as Envoy's admin pages are; any
 * other value is written as its {@code toString()}.
 */
final class AdminJson {

    private AdminJson() {}

    /** {@return {@code value} as an indented JSON document, with a final newline} */
    static String write(Object value) {
        StringBuilder sb = new StringBuilder(1024);
        write(sb, value, "");
        return sb.append('\n').toString();
    }

    private static void write(StringBuilder sb, Object value, String indent) {
        switch (value) {
            case null -> sb.append("null");
            case Boolean b -> sb.append(b);
            case Integer i -> sb.append(i);
            case Long l -> sb.append(l);
            case Number n -> sb.append(Double.isFinite(n.doubleValue()) ? n.toString() : "null");
            case Map<?, ?> map -> {
                if (map.isEmpty()) {
                    sb.append("{}");
                    return;
                }
                String inner = indent + "  ";
                sb.append("{\n");
                Iterator<? extends Map.Entry<?, ?>> it = map.entrySet().iterator();
                while (it.hasNext()) {
                    Map.Entry<?, ?> e = it.next();
                    sb.append(inner);
                    string(sb, String.valueOf(e.getKey()));
                    sb.append(": ");
                    write(sb, e.getValue(), inner);
                    if (it.hasNext()) sb.append(',');
                    sb.append('\n');
                }
                sb.append(indent).append('}');
            }
            case Collection<?> list -> {
                if (list.isEmpty()) {
                    sb.append("[]");
                    return;
                }
                String inner = indent + "  ";
                sb.append("[\n");
                Iterator<?> it = list.iterator();
                while (it.hasNext()) {
                    sb.append(inner);
                    write(sb, it.next(), inner);
                    if (it.hasNext()) sb.append(',');
                    sb.append('\n');
                }
                sb.append(indent).append(']');
            }
            default -> string(sb, value.toString());
        }
    }

    /** Appends {@code s} as a JSON string literal. */
    static void string(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x2028 || c == 0x2029) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }
}
