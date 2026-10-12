/*
 * Encoding plain values without a schema follows mitmproxy_rs
 * (https://github.com/mitmproxy/mitmproxy_rs), mitmproxy-contentviews/src/protobuf/reencode.rs
 * (add_field and int_value): integers are varints, strings and bytes length-delimited, mappings
 * nested messages, sequences repeated fields. Copyright (c) 2022, Fabio Valentini and Maximilian
 * Hils. Licensed under the MIT License; see META-INF/LICENSE-mitmproxy_rs.txt.
 */
package org.microproxy.contentviews;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/** Writes {@link ProtoMessage}s and plain values ({@link Protobuf#toPlain}) in the wire format. */
final class ProtoEncoder {

    /** Deeper plain values are refused, which also stops a map that contains itself. */
    static final int MAX_DEPTH = 100;

    private static final BigInteger MIN = BigInteger.valueOf(Long.MIN_VALUE);
    private static final BigInteger MAX_UNSIGNED = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

    private final ProtoSchema schema;

    ProtoEncoder(ProtoSchema schema) {
        this.schema = schema;
    }

    // ---------------------------------------------------------------------------------------
    // ProtoMessage
    // ---------------------------------------------------------------------------------------

    static byte[] encode(ProtoMessage message) {
        ProtoWire.Writer w = new ProtoWire.Writer();
        write(w, message);
        return w.toByteArray();
    }

    private static void write(ProtoWire.Writer w, ProtoMessage message) {
        for (ProtoField f : message.fields()) write(w, f.number(), f.value());
    }

    static void write(ProtoWire.Writer w, int number, ProtoValue value) {
        if (value instanceof ProtoValue.Group g) {
            w.tag(number, ProtoValue.WIRE_START_GROUP);
            write(w, g.message());
            w.tag(number, ProtoValue.WIRE_END_GROUP);
            return;
        }
        w.tag(number, value.wireType());
        switch (value) {
            case ProtoValue.Varint v -> w.varint(v.value());
            case ProtoValue.Fixed32 f -> w.fixed32(f.bits());
            case ProtoValue.Fixed64 f -> w.fixed64(f.bits());
            case ProtoValue.Text t -> w.lengthDelimited(t.utf8());
            case ProtoValue.Bytes b -> w.lengthDelimited(b.data());
            case ProtoValue.Message m -> w.lengthDelimited(encode(m.message()));
            case ProtoValue.Packed p -> {
                ProtoWire.Writer packed = new ProtoWire.Writer();
                for (ProtoValue e : p.elements()) {
                    switch (e) {
                        case ProtoValue.Varint v -> packed.varint(v.value());
                        case ProtoValue.Fixed32 f -> packed.fixed32(f.bits());
                        case ProtoValue.Fixed64 f -> packed.fixed64(f.bits());
                        default -> throw new IllegalStateException("not packable: " + e);
                    }
                }
                w.lengthDelimited(packed.toByteArray());
            }
            case ProtoValue.Group g -> throw new IllegalStateException("unreachable");
        }
    }

    // ---------------------------------------------------------------------------------------
    // Plain values
    // ---------------------------------------------------------------------------------------

    byte[] encodePlain(Map<?, ?> fields, ProtoSchema.MessageType type, int depth) {
        if (depth > MAX_DEPTH) throw new IllegalArgumentException("message nested more than " + MAX_DEPTH + " deep");
        ProtoWire.Writer w = new ProtoWire.Writer();
        writePlain(w, fields, type, depth);
        return w.toByteArray();
    }

    private void writePlain(ProtoWire.Writer w, Map<?, ?> fields, ProtoSchema.MessageType type, int depth) {
        for (Map.Entry<?, ?> e : fields.entrySet()) {
            Object key = e.getKey();
            ProtoSchema.Field declared;
            int number;
            if (key instanceof String name && type != null && type.field(name) != null) {
                declared = type.field(name);
                number = declared.number();
            } else {
                number = fieldNumber(key, type);
                declared = type == null ? null : type.field(number);
            }
            if (declared != null) declared(w, type, declared, e.getValue(), depth);
            else undeclared(w, number, e.getValue(), depth, true);
        }
    }

    private static int fieldNumber(Object key, ProtoSchema.MessageType type) {
        long n;
        if (key instanceof Number number && !(key instanceof Double || key instanceof Float)) {
            n = number instanceof BigInteger b ? (b.bitLength() < 32 ? b.longValue() : -1) : number.longValue();
        } else if (key instanceof String s && !s.isEmpty() && s.chars().allMatch(Character::isDigit) && s.length() < 11) {
            n = Long.parseLong(s);
        } else if (key instanceof String s) {
            throw new IllegalArgumentException("unknown field " + s + (type == null ? " (field names need a schema)"
                    : " in " + type.fullName()));
        } else {
            throw new IllegalArgumentException("field keys are numbers or names, not " + describe(key));
        }
        if (n < 1 || n > Protobuf.MAX_FIELD_NUMBER) throw new IllegalArgumentException("field number out of range: " + n);
        return (int) n;
    }

    /** A value of a field without a declaration, typed by its Java type. */
    private void undeclared(ProtoWire.Writer w, int number, Object value, int depth, boolean listAllowed) {
        switch (value) {
            case null -> {}
            case List<?> list when listAllowed -> {
                for (Object item : list) undeclared(w, number, item, depth, false);
            }
            case ProtoValue v -> write(w, number, v);
            case ProtoMessage m -> write(w, number, new ProtoValue.Message(m));
            case Boolean b -> write(w, number, new ProtoValue.Varint(b ? 1 : 0));
            case Double d -> write(w, number, new ProtoValue.Fixed64(Double.doubleToRawLongBits(d)));
            case Float f -> write(w, number, new ProtoValue.Fixed32(Float.floatToRawIntBits(f)));
            case Number n -> write(w, number, new ProtoValue.Varint(toLong(n, number)));
            case String s -> write(w, number, new ProtoValue.Text(s));
            case byte[] b -> write(w, number, new ProtoValue.Bytes(b));
            case Map<?, ?> m -> {
                w.tag(number, ProtoValue.WIRE_LEN);
                w.lengthDelimited(encodePlain(m, null, depth + 1));
            }
            default -> throw new IllegalArgumentException("field " + number + ": cannot encode " + describe(value));
        }
    }

    /** A value of a declared field, as its declared type. */
    private void declared(ProtoWire.Writer w, ProtoSchema.MessageType type, ProtoSchema.Field f, Object value, int depth) {
        if (value == null) return;
        if (value instanceof Map<?, ?> map && f.repeated() && f.type() == ProtoSchema.Type.MESSAGE) {
            ProtoSchema.MessageType entry = schema.message(f.typeName()).orElse(null);
            if (entry != null && entry.mapEntry()) {
                for (Map.Entry<?, ?> e : map.entrySet()) {
                    java.util.LinkedHashMap<Object, Object> fields = new java.util.LinkedHashMap<>();
                    fields.put(1, e.getKey());
                    fields.put(2, e.getValue());
                    w.tag(f.number(), ProtoValue.WIRE_LEN);
                    w.lengthDelimited(encodePlain(fields, entry, depth + 1));
                }
                return;
            }
        }
        if (value instanceof List<?> list) {
            if (f.packed()) {
                ProtoWire.Writer packed = new ProtoWire.Writer();
                for (Object item : list) {
                    if (item == null) continue;
                    switch (scalar(type, f, item)) {
                        case ProtoValue.Varint v -> packed.varint(v.value());
                        case ProtoValue.Fixed32 x -> packed.fixed32(x.bits());
                        case ProtoValue.Fixed64 x -> packed.fixed64(x.bits());
                        default -> throw new IllegalStateException("not packable");
                    }
                }
                if (!list.isEmpty()) {
                    w.tag(f.number(), ProtoValue.WIRE_LEN);
                    w.lengthDelimited(packed.toByteArray());
                }
                return;
            }
            for (Object item : list) {
                if (item instanceof List<?>) throw new IllegalArgumentException(f.name() + ": a list inside a list");
                declared(w, type, f, item, depth);
            }
            return;
        }
        if (value instanceof ProtoValue v) {
            write(w, f.number(), v);
            return;
        }
        switch (f.type()) {
            case STRING -> write(w, f.number(), value instanceof byte[] b ? new ProtoValue.Bytes(b)
                    : new ProtoValue.Text(expect(String.class, value, f)));
            case BYTES -> {
                if (value instanceof Map<?, ?> m) {
                    // Any.value, or bytes holding a message.
                    w.tag(f.number(), ProtoValue.WIRE_LEN);
                    w.lengthDelimited(encodePlain(m, null, depth + 1));
                } else {
                    write(w, f.number(), value instanceof String s ? new ProtoValue.Bytes(s.getBytes(StandardCharsets.UTF_8))
                            : new ProtoValue.Bytes(expect(byte[].class, value, f)));
                }
            }
            case MESSAGE -> {
                if (value instanceof ProtoMessage m) {
                    write(w, f.number(), new ProtoValue.Message(m));
                } else {
                    w.tag(f.number(), ProtoValue.WIRE_LEN);
                    w.lengthDelimited(encodePlain(expect(Map.class, value, f),
                            schema.message(f.typeName()).orElse(null), depth + 1));
                }
            }
            case GROUP -> {
                w.tag(f.number(), ProtoValue.WIRE_START_GROUP);
                if (depth >= MAX_DEPTH) throw new IllegalArgumentException("message nested more than " + MAX_DEPTH + " deep");
                writePlain(w, expect(Map.class, value, f), schema.message(f.typeName()).orElse(null), depth + 1);
                w.tag(f.number(), ProtoValue.WIRE_END_GROUP);
            }
            default -> write(w, f.number(), scalar(type, f, value));
        }
    }

    /** A scalar value of a declared numeric, bool or enum field as its wire value. */
    private static ProtoValue scalar(ProtoSchema.MessageType type, ProtoSchema.Field f, Object value) {
        if (value instanceof ProtoValue v && v.wireType() == f.type().wireType()) return v;
        return switch (f.type()) {
            case BOOL -> new ProtoValue.Varint(value instanceof Boolean b ? (b ? 1 : 0) : toLong(number(value, f), f.number()));
            case ENUM -> {
                if (value instanceof String name) {
                    Integer n = type.enumType(f.number()).flatMap(e -> e.number(name)).orElseThrow(
                            () -> new IllegalArgumentException(f.name() + ": unknown enum value " + name));
                    yield new ProtoValue.Varint(n);
                }
                yield new ProtoValue.Varint((int) toLong(number(value, f), f.number()));
            }
            case SINT32 -> new ProtoValue.Varint(Integer.toUnsignedLong(
                    Protobuf.zigzagEncode32((int) toLong(number(value, f), f.number()))));
            case SINT64 -> new ProtoValue.Varint(Protobuf.zigzagEncode(toLong(number(value, f), f.number())));
            case INT32 -> new ProtoValue.Varint((int) toLong(number(value, f), f.number()));
            case UINT32 -> new ProtoValue.Varint(toLong(number(value, f), f.number()) & 0xffffffffL);
            case FLOAT -> new ProtoValue.Fixed32(Float.floatToRawIntBits(number(value, f).floatValue()));
            case DOUBLE -> new ProtoValue.Fixed64(Double.doubleToRawLongBits(number(value, f).doubleValue()));
            case FIXED32, SFIXED32 -> new ProtoValue.Fixed32((int) toLong(number(value, f), f.number()));
            case FIXED64, SFIXED64 -> new ProtoValue.Fixed64(toLong(number(value, f), f.number()));
            case INT64, UINT64 -> new ProtoValue.Varint(toLong(number(value, f), f.number()));
            default -> throw new IllegalArgumentException(f.name() + ": cannot encode " + describe(value)
                    + " as " + f.type().name().toLowerCase(java.util.Locale.ROOT));
        };
    }

    private static Number number(Object value, ProtoSchema.Field f) {
        if (value instanceof Number n) return n;
        if (value instanceof Boolean b) return b ? 1 : 0;
        throw new IllegalArgumentException(f.name() + ": expected a number, not " + describe(value));
    }

    /** An integer as the 64 bits of a varint: signed values and unsigned ones up to 2^64-1. */
    private static long toLong(Number n, int field) {
        if (n instanceof BigInteger b) {
            if (b.compareTo(MIN) < 0 || b.compareTo(MAX_UNSIGNED) > 0) {
                throw new IllegalArgumentException("field " + field + ": " + b + " does not fit in 64 bits");
            }
            return b.longValue();
        }
        if (n instanceof Double || n instanceof Float) {
            double d = n.doubleValue();
            if (d != Math.rint(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("field " + field + ": " + d + " is not an integer");
            }
        }
        return n.longValue();
    }

    private static <T> T expect(Class<T> type, Object value, ProtoSchema.Field f) {
        if (type.isInstance(value)) return type.cast(value);
        throw new IllegalArgumentException(f.name() + ": expected " + f.type().name().toLowerCase(java.util.Locale.ROOT)
                + " value, not " + describe(value));
    }

    private static String describe(Object value) {
        return value == null ? "null" : value.getClass().getSimpleName();
    }
}
