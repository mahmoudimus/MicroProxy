package org.microproxy.frames;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * One field of a decoded header block (HTTP/2 HPACK, HTTP/3 QPACK): a name, which is lower case
 * on the wire and starts with {@code :} for a pseudo-header, and a value.
 *
 * @param name the field name
 * @param value the field value
 * @param sensitive whether the field must never be added to a compression table (HPACK and QPACK's
 *     never-indexed literals): kept when a field is edited with {@link #withValue(String)}
 */
public record Field(String name, String value, boolean sensitive) {

    /** The pseudo-headers of requests and responses (RFC 9113 section 8.3, RFC 8441, RFC 9220). */
    private static final Set<String> PSEUDO = Set.of(":method", ":scheme", ":authority", ":path", ":protocol", ":status");

    /** Fields that are about one HTTP/1 connection, which HTTP/2 and HTTP/3 forbid. */
    private static final Set<String> CONNECTION_SPECIFIC =
            Set.of("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade");

    /**
     * Creates a field.
     *
     * @param name the field name
     * @param value the field value
     * @param sensitive whether the field must never be added to a compression table
     * @throws NullPointerException if the name or value is null
     */
    public Field {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(value, "value");
    }

    /**
     * Creates a field that compression tables may hold.
     *
     * @param name the field name
     * @param value the field value
     */
    public Field(String name, String value) {
        this(name, value, false);
    }

    /**
     * This field with another value.
     *
     * @param newValue the new value
     * @return a copy with {@code newValue}
     */
    public Field withValue(String newValue) {
        return new Field(name, newValue, sensitive);
    }

    /**
     * Whether this is a pseudo-header ({@code :method}, {@code :status}, ...).
     *
     * @return whether the name starts with a colon
     */
    public boolean isPseudo() {
        return name.startsWith(":");
    }

    /**
     * Checks that {@code fields} can be sent as an HTTP/2 or HTTP/3 header block: names that are
     * non-empty lower-case tokens; values without NUL, CR or LF and without leading or trailing
     * white space; pseudo-headers that are known ({@code :method}, {@code :scheme}, {@code
     * :authority}, {@code :path}, {@code :protocol} or {@code :status}), not repeated, all before
     * the regular fields, and not mixing a request's with a response's; and no connection-specific
     * field ({@code connection}, {@code keep-alive}, {@code proxy-connection}, {@code
     * transfer-encoding}, {@code upgrade}, and {@code te} other than {@code trailers}). Whether the
     * block is a complete request or response is not checked here.
     *
     * @param fields the header block
     * @throws IllegalArgumentException naming the first problem
     */
    public static void validate(List<Field> fields) {
        Set<String> pseudo = new HashSet<>();
        boolean regular = false;
        for (Field f : fields) {
            String name = f.name;
            String problem = nameProblem(name);
            if (problem == null) problem = valueProblem(f.value);
            if (problem != null) throw new IllegalArgumentException("field " + printable(name) + ": " + problem);
            if (f.isPseudo()) {
                if (!PSEUDO.contains(name)) throw new IllegalArgumentException("unknown pseudo-header " + name);
                if (regular) throw new IllegalArgumentException("pseudo-header " + name + " after a regular field");
                if (!pseudo.add(name)) throw new IllegalArgumentException("pseudo-header " + name + " repeated");
            } else {
                regular = true;
                if (CONNECTION_SPECIFIC.contains(name)) {
                    throw new IllegalArgumentException("connection-specific field " + name);
                }
                if (name.equals("te") && !f.value.equals("trailers")) {
                    throw new IllegalArgumentException("te other than trailers");
                }
            }
        }
        if (pseudo.contains(":status") && pseudo.size() > 1) {
            throw new IllegalArgumentException(":status with request pseudo-headers");
        }
    }

    private static String nameProblem(String name) {
        if (name.isEmpty() || name.equals(":")) return "empty name";
        for (int i = name.startsWith(":") ? 1 : 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c >= 'A' && c <= 'Z') return "upper-case name";
            if (!isTokenChar(c)) return "invalid character in name";
        }
        return null;
    }

    private static boolean isTokenChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
    }

    private static String valueProblem(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == 0 || c == '\r' || c == '\n') return "NUL, CR or LF in value";
            if (c > 0xff) return "character outside ISO-8859-1 in value";
        }
        if (!value.isEmpty()) {
            char first = value.charAt(0);
            char last = value.charAt(value.length() - 1);
            if (first == ' ' || first == '\t' || last == ' ' || last == '\t') return "white space around value";
        }
        return null;
    }

    private static String printable(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length() && i < 64; i++) {
            char c = s.charAt(i);
            out.append(c >= 0x20 && c < 0x7f ? c : '?');
        }
        return out.toString();
    }
}
