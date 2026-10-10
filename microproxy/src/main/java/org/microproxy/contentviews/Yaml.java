package org.microproxy.contentviews;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Writes trees of mappings, sequences and scalars as block YAML, in the layout of serde_yaml (which
 * mitmproxy's views use): sequences under a key are not indented, nested mappings are indented by
 * two spaces, and scalars may carry a trailing {@code # comment}.
 */
final class Yaml {

    private Yaml() {}

    /** A node of the tree. */
    sealed interface Node permits Scalar, Mapping, Sequence {}

    /**
     * A scalar, already written as YAML.
     *
     * @param text the YAML text (see {@link #string})
     * @param comment a comment for the end of the line, or {@code null}
     */
    record Scalar(String text, String comment) implements Node {
        Scalar(String text) {
            this(text, null);
        }
    }

    /**
     * A mapping; keys are YAML text.
     *
     * @param tag a tag such as {@code !group}, or {@code null}
     * @param entries the entries, in order
     */
    record Mapping(String tag, List<Entry> entries) implements Node {
        Mapping() {
            this(null, new ArrayList<>());
        }

        Mapping put(String key, Node value) {
            entries.add(new Entry(key, value));
            return this;
        }
    }

    /**
     * One entry of a mapping.
     *
     * @param key the key, as YAML text
     * @param value the value
     */
    record Entry(String key, Node value) {}

    /**
     * A sequence.
     *
     * @param items the items
     */
    record Sequence(List<Node> items) implements Node {}

    /** {@code node} as a YAML document, ending with a newline. */
    static String emit(Node node) {
        StringBuilder sb = new StringBuilder();
        switch (node) {
            case Scalar s -> sb.append(line(s.text(), s.comment())).append('\n');
            case Mapping m when m.entries().isEmpty() -> sb.append(m.tag() == null ? "{}" : m.tag() + " {}").append('\n');
            case Mapping m -> {
                if (m.tag() != null) sb.append(m.tag()).append('\n');
                mapping(sb, m, "");
            }
            case Sequence s when s.items().isEmpty() -> sb.append("[]\n");
            case Sequence s -> sequence(sb, s, "");
        }
        return sb.toString();
    }

    private static void mapping(StringBuilder sb, Mapping m, String indent) {
        for (Entry e : m.entries()) {
            sb.append(indent).append(e.key()).append(':');
            switch (e.value()) {
                case Scalar s -> sb.append(' ').append(line(s.text(), s.comment())).append('\n');
                case Mapping child when child.entries().isEmpty() ->
                        sb.append(' ').append(child.tag() == null ? "{}" : child.tag() + " {}").append('\n');
                case Mapping child -> {
                    if (child.tag() != null) sb.append(' ').append(child.tag());
                    sb.append('\n');
                    mapping(sb, child, indent + "  ");
                }
                case Sequence s when s.items().isEmpty() -> sb.append(" []\n");
                case Sequence s -> {
                    sb.append('\n');
                    sequence(sb, s, indent);
                }
            }
        }
    }

    private static void sequence(StringBuilder sb, Sequence s, String indent) {
        for (Node item : s.items()) {
            switch (item) {
                case Scalar scalar -> sb.append(indent).append("- ").append(line(scalar.text(), scalar.comment())).append('\n');
                case Mapping m when m.entries().isEmpty() ->
                        sb.append(indent).append("- ").append(m.tag() == null ? "{}" : m.tag() + " {}").append('\n');
                case Sequence child when child.items().isEmpty() -> sb.append(indent).append("- []\n");
                default -> {
                    // The item's first line goes after the dash, the rest indented to line up.
                    StringBuilder nested = new StringBuilder();
                    String inner = indent + "  ";
                    if (item instanceof Mapping m && m.tag() != null) {
                        sb.append(indent).append("- ").append(m.tag()).append('\n');
                        mapping(sb, m, inner);
                        continue;
                    }
                    if (item instanceof Mapping m) mapping(nested, m, inner);
                    else sequence(nested, (Sequence) item, inner);
                    sb.append(indent).append("- ").append(nested, inner.length(), nested.length());
                }
            }
        }
    }

    private static String line(String text, String comment) {
        return comment == null ? text : text + "  # " + comment;
    }

    // ---------------------------------------------------------------------------------------
    // Scalars
    // ---------------------------------------------------------------------------------------

    /** Strings a plain scalar would turn into another type in YAML 1.1 or 1.2. */
    private static final Pattern NOT_A_STRING = Pattern.compile(
            "[-+]?[0-9][0-9_]*"
                    + "|[-+]?0[xX][0-9a-fA-F_]+|0[oO][0-7_]+|[-+]?0[bB][01_]+"
                    + "|[-+]?([0-9][0-9_]*)?\\.[0-9_]*([eE][-+]?[0-9]+)?"
                    + "|[-+]?[0-9][0-9_]*([.][0-9_]*)?[eE][-+]?[0-9]+"
                    + "|[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+(\\.[0-9_]*)?"
                    + "|[-+]?\\.(inf|Inf|INF)|\\.(nan|NaN|NAN)"
                    + "|~|null|Null|NULL|y|Y|n|N|yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE"
                    + "|on|On|ON|off|Off|OFF|=|<<");

    private static final String INDICATORS = "-?:,[]{}#&*!|>'\"%@`";

    /** {@code s} as a YAML scalar: plain when that reads back as the same string, else quoted. */
    static String string(String s) {
        if (plain(s)) return s;
        if (printable(s)) return "'" + s.replace("'", "''") + "'";
        return doubleQuoted(s);
    }

    private static boolean plain(String s) {
        if (s.isEmpty() || NOT_A_STRING.matcher(s).matches()) return false;
        char first = s.charAt(0);
        char last = s.charAt(s.length() - 1);
        if (Character.isWhitespace(first) || Character.isWhitespace(last) || last == ':') return false;
        if (INDICATORS.indexOf(first) >= 0) return false;
        if (s.contains(": ") || s.contains(" #")) return false;
        return printable(s);
    }

    /** Whether every character may stand in a single-line scalar. */
    private static boolean printable(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7f || c >= 0x80 && c < 0xa0 || c == 0x2028 || c == 0x2029 || c == 0xfeff) {
                return false;
            }
            if (Character.isSurrogate(c)) {
                // Only valid pairs.
                if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                    i++;
                } else {
                    return false;
                }
            }
        }
        return true;
    }

    private static String doubleQuoted(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\t' -> sb.append("\\t");
                case '\r' -> sb.append("\\r");
                case '\0' -> sb.append("\\0");
                default -> {
                    boolean lonely = Character.isSurrogate(c) && !(Character.isHighSurrogate(c) && i + 1 < s.length()
                            && Character.isLowSurrogate(s.charAt(i + 1)));
                    if (c < 0x20 || c == 0x7f || c >= 0x80 && c < 0xa0) {
                        sb.append(String.format(Locale.ROOT, "\\x%02x", (int) c));
                    } else if (c == 0x2028 || c == 0x2029 || c == 0xfeff || lonely) {
                        sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                        if (Character.isHighSurrogate(c)) sb.append(s.charAt(++i));
                    }
                }
            }
        }
        return sb.append('"').toString();
    }
}
