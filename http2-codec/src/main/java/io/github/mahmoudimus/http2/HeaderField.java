package io.github.mahmoudimus.http2;

import java.util.Objects;

/**
 * One header or trailer field (a name and a value) as HPACK carries it. Names and values are
 * octet strings; they are held as Strings with one char per octet (ISO-8859-1), so no input is
 * lost and none is reinterpreted. {@link Http2Headers} checks which octets HTTP allows.
 *
 * @param sensitive the field was, or must be, sent as a never-indexed literal (RFC 7541 §6.2.3):
 *     an intermediary must re-encode it the same way so that it never enters a compression context
 */
public record HeaderField(String name, String value, boolean sensitive) {

    /** The per-entry overhead HPACK adds to the octet lengths of name and value (RFC 7541 §4.1). */
    public static final int ENTRY_OVERHEAD = 32;

    public HeaderField {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(value, "value");
    }

    public HeaderField(String name, String value) {
        this(name, value, false);
    }

    /** The size HPACK and SETTINGS_MAX_HEADER_LIST_SIZE count for this field: name + value + 32. */
    public int size() {
        return name.length() + value.length() + ENTRY_OVERHEAD;
    }

    @Override
    public String toString() {
        return name + ": " + value + (sensitive ? " (never indexed)" : "");
    }
}
