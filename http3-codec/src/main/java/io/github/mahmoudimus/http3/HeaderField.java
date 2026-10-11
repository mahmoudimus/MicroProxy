package io.github.mahmoudimus.http3;

import java.util.Objects;

/**
 * One header or trailer field (a name and a value) as QPACK carries it. Names and values are
 * octet strings; they are held as Strings with one char per octet (ISO-8859-1), so no input is
 * lost and none is reinterpreted. {@link Http3Headers} checks which octets HTTP allows.
 *
 * @param name the field name, one char per octet
 * @param value the field value, one char per octet
 * @param sensitive the field was, or must be, sent as a literal with the 'N' (never-indexed) bit
 *     set (RFC 9204 §4.5.4): an intermediary must forward it as a literal with the bit set, so that
 *     it never enters a compression context
 */
public record HeaderField(String name, String value, boolean sensitive) {

    /** The per-entry overhead QPACK adds to the octet lengths of name and value (RFC 9204 §3.2.1). */
    public static final int ENTRY_OVERHEAD = 32;

    /**
     * Creates a field.
     *
     * @param name the field name, one char per octet
     * @param value the field value, one char per octet
     * @param sensitive whether the field is sent as a never-indexed literal
     */
    public HeaderField {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(value, "value");
    }

    /**
     * Creates a field that may enter a compression context.
     *
     * @param name the field name, one char per octet
     * @param value the field value, one char per octet
     */
    public HeaderField(String name, String value) {
        this(name, value, false);
    }

    /**
     * The size QPACK and SETTINGS_MAX_FIELD_SECTION_SIZE count for this field: name + value + 32.
     *
     * @return the size in octets
     */
    public int size() {
        return name.length() + value.length() + ENTRY_OVERHEAD;
    }

    @Override
    public String toString() {
        return name + ": " + value + (sensitive ? " (never indexed)" : "");
    }
}
