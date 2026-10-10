package org.microproxy.contentviews;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A decoded protobuf message: its fields in the order they appeared on the wire. Build one by
 * hand to encode it ({@link Protobuf#encode(ProtoMessage)}), or get one from {@link
 * Protobuf#decode(byte[])}.
 *
 * @param fields the fields, in wire order
 * @param type the schema type the message was decoded as, or {@code null} without a schema
 */
public record ProtoMessage(List<ProtoField> fields, ProtoSchema.MessageType type) {

    /**
     * Copies the field list.
     *
     * @param fields the fields, in wire order
     * @param type the schema type, or {@code null}
     */
    public ProtoMessage {
        fields = List.copyOf(fields);
    }

    /**
     * A message without a schema type.
     *
     * @param fields the fields, in wire order
     */
    public ProtoMessage(List<ProtoField> fields) {
        this(fields, null);
    }

    /**
     * The values of field {@code number}, in wire order (the elements of a packed field count one
     * by one).
     *
     * @param number the field number
     * @return the values, possibly none
     */
    public List<ProtoValue> values(int number) {
        List<ProtoValue> out = new ArrayList<>();
        for (ProtoField f : fields) {
            if (f.number() != number) continue;
            if (f.value() instanceof ProtoValue.Packed p) out.addAll(p.elements());
            else out.add(f.value());
        }
        return out;
    }

    /**
     * The first value of field {@code number}.
     *
     * @param number the field number
     * @return the value, or empty when the field is absent
     */
    public Optional<ProtoValue> first(int number) {
        List<ProtoValue> values = values(number);
        return values.isEmpty() ? Optional.empty() : Optional.of(values.getFirst());
    }

    /**
     * The message as plain Java values, as scripts see it: see {@link Protobuf#toPlain}.
     *
     * @return a mutable map from field numbers (or declared names) to values
     */
    public Map<Object, Object> toPlain() {
        return Protobuf.toPlain(this);
    }

    /**
     * The message as readable YAML-like text with field numbers (or declared names), as {@link
     * Protobuf#render(byte[])} shows it.
     *
     * @return the text
     */
    public String render() {
        return ProtoText.render(this);
    }

    @Override
    public String toString() {
        return render();
    }
}
