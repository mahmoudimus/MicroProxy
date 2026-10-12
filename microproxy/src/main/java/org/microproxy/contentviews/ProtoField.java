package org.microproxy.contentviews;

import java.util.Objects;

/**
 * One field of a decoded protobuf message, as it appeared on the wire. A repeated field that was
 * not packed appears once per value.
 *
 * @param number the field number (1 to 2<sup>29</sup>-1)
 * @param value the value
 * @param declared the field's declaration in the schema the message was decoded with, or {@code
 *     null} for a field the schema does not know (or that did not match its declared type) and for
 *     messages decoded without a schema
 */
public record ProtoField(int number, ProtoValue value, ProtoSchema.Field declared) {

    /**
     * Checks the field number and value.
     *
     * @param number the field number (1 to 2<sup>29</sup>-1)
     * @param value the value
     * @param declared the field's declaration, or {@code null}
     * @throws IllegalArgumentException if the field number is out of range
     */
    public ProtoField {
        if (number < 1 || number > Protobuf.MAX_FIELD_NUMBER) {
            throw new IllegalArgumentException("field number out of range: " + number);
        }
        Objects.requireNonNull(value, "value");
    }

    /**
     * A field without a declaration.
     *
     * @param number the field number (1 to 2<sup>29</sup>-1)
     * @param value the value
     */
    public ProtoField(int number, ProtoValue value) {
        this(number, value, null);
    }

    /** {@return the declared name of the field, or {@code null} without a declaration} */
    public String name() {
        return declared == null ? null : declared.name();
    }
}
