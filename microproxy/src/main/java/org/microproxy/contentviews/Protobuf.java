package org.microproxy.contentviews;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Decodes and encodes protobuf messages without generated code, and usually without a schema:
 *
 * <pre>{@code
 * ProtoMessage m = Protobuf.decode(bytes);          // fields by number, types guessed
 * String yaml = m.render();                          // "1: 150  # !sint: 75\n2: hello\n"
 * Map<Object, Object> plain = m.toPlain();           // {1=150, 2=hello}
 * plain.put(2, "goodbye");
 * byte[] changed = Protobuf.encode(plain);
 * }</pre>
 *
 * <p>Without a schema, varints, fixed-width values and groups are what the wire says; whether a
 * length-delimited value is text, a nested message or bytes is guessed, as mitmproxy guesses it
 * (see {@link ProtoValue}). With a {@link ProtoSchema}, declared fields are read as declared, with
 * names, and the rest is guessed.
 *
 * <p>Decoding never throws anything but {@link DecodeException} for bad input, whatever the bytes:
 * nesting is bounded ({@value #DEFAULT_MAX_DEPTH} levels; deeper length-delimited values stay
 * bytes), lengths are checked against the input, and nothing is allocated before it is known to
 * fit. Encoding a decoded message gives back the same bytes, except where the input used
 * non-minimal varints at the top level (nested messages are only recognized with minimal ones).
 * Plain values ({@link #toPlain}) re-encode to the same bytes when each field's occurrences were
 * together on the wire, as encoders write them.
 */
public final class Protobuf {

    /** The largest field number protobuf allows, 2<sup>29</sup>-1. */
    public static final int MAX_FIELD_NUMBER = (1 << 29) - 1;

    /** How deep messages and groups may nest before length-delimited values are left as bytes. */
    public static final int DEFAULT_MAX_DEPTH = 64;

    private static final BigInteger TWO_64 = BigInteger.ONE.shiftLeft(64);

    private Protobuf() {}

    /**
     * Decodes a message without a schema.
     *
     * @param data the serialized message
     * @return the message, with every field keyed by number
     * @throws DecodeException if {@code data} is not a protobuf message
     */
    public static ProtoMessage decode(byte[] data) throws DecodeException {
        return decode(data, null, (String) null);
    }

    /**
     * Decodes a message as {@code messageType} of {@code schema}; fields the type does not
     * declare, or whose values do not match their declared type, are decoded without it.
     *
     * @param data the serialized message
     * @param schema the schema, or {@code null} to decode without one
     * @param messageType the full name of the message's type, or {@code null} to decode without one
     * @return the message
     * @throws DecodeException if {@code data} is not a protobuf message
     * @throws IllegalArgumentException if the schema has no type {@code messageType}
     */
    public static ProtoMessage decode(byte[] data, ProtoSchema schema, String messageType) throws DecodeException {
        Objects.requireNonNull(data, "data");
        ProtoSchema s = schema != null ? schema : ProtoSchema.empty();
        ProtoSchema.MessageType type = null;
        if (messageType != null) {
            type = s.message(messageType).orElseThrow(
                    () -> new IllegalArgumentException("no message type " + messageType + " in the schema"));
        }
        return new ProtoDecoder(s, DEFAULT_MAX_DEPTH).decode(data, type);
    }

    /**
     * Decodes a message without a schema and renders it as YAML with field numbers; see {@link
     * ProtoMessage#render()}.
     *
     * @param data the serialized message
     * @return the text, or {@code {}  # empty protobuf message} for no bytes
     * @throws DecodeException if {@code data} is not a protobuf message
     */
    public static String render(byte[] data) throws DecodeException {
        return decode(data).render();
    }

    /**
     * Encodes a message, field by field in its order.
     *
     * @param message the message
     * @return the serialized message
     */
    public static byte[] encode(ProtoMessage message) {
        return ProtoEncoder.encode(message);
    }

    /**
     * Encodes plain values, as {@link #toPlain} makes them, without a schema. Keys are field
     * numbers (integers, or strings of digits). Values:
     *
     * <ul>
     *   <li>integers ({@code Integer}, {@code Long}, {@code BigInteger} up to 2<sup>64</sup>-1) and
     *       booleans: varints; negative numbers take ten bytes, as {@code int32} and {@code int64}
     *       do;
     *   <li>{@code String}: UTF-8; {@code byte[]}: bytes; {@code Map}: a nested message;
     *   <li>{@code List}: a repeated field, one occurrence per element (not packed);
     *   <li>{@code Double}: a {@code fixed64} double; {@code Float}: a {@code fixed32} float;
     *   <li>a {@link ProtoValue} (such as {@link ProtoValue.Fixed32} or {@link ProtoValue.Group}):
     *       as it is; {@code null}: nothing.
     * </ul>
     *
     * @param fields the fields
     * @return the serialized message
     * @throws IllegalArgumentException if a key or value cannot be encoded
     */
    public static byte[] encode(Map<?, ?> fields) {
        return new ProtoEncoder(ProtoSchema.empty()).encodePlain(fields, null, 0);
    }

    /**
     * Encodes plain values as {@code messageType}: keys may be field names, and values are
     * encoded as their fields are declared (enum values may be names, {@code sint} fields are
     * zigzag-encoded, packed fields packed, map fields from maps). Undeclared fields are encoded
     * as {@link #encode(Map)} does.
     *
     * @param fields the fields
     * @param schema the schema
     * @param messageType the full name of the message's type
     * @return the serialized message
     * @throws IllegalArgumentException if the schema has no such type, or a key or value cannot
     *     be encoded
     */
    public static byte[] encode(Map<?, ?> fields, ProtoSchema schema, String messageType) {
        ProtoSchema.MessageType type = schema.message(messageType).orElseThrow(
                () -> new IllegalArgumentException("no message type " + messageType + " in the schema"));
        return new ProtoEncoder(schema).encodePlain(fields, type, 0);
    }

    /**
     * A message as plain Java values, for scripts and quick edits. Keys are field numbers ({@code
     * Integer}), or names for declared fields; a field that occurs more than once, or is declared
     * repeated, is a {@code List}. Values:
     *
     * <ul>
     *   <li>without a declaration: varints as {@code Long} (negative when the top bit is set),
     *       text as {@code String}, bytes as {@code byte[]}, nested messages as {@code Map}; fixed-width
     *       values and groups stay {@link ProtoValue.Fixed32}, {@link ProtoValue.Fixed64} and {@link
     *       ProtoValue.Group}, so that they encode back as they were;
     *   <li>with one, as declared: {@code Long} (or {@code BigInteger} for {@code uint64} and
     *       {@code fixed64} values above {@code Long.MAX_VALUE}), {@code Boolean}, {@code Double}
     *       for {@code float} and {@code double}, enum value names (or numbers, when unknown),
     *       {@code String}, {@code byte[]}, and {@code Map}s for messages, groups and map fields.
     * </ul>
     *
     * @param message the message
     * @return a mutable, ordered map
     */
    public static Map<Object, Object> toPlain(ProtoMessage message) {
        Map<Object, Object> out = new LinkedHashMap<>();
        for (ProtoField f : message.fields()) {
            ProtoSchema.Field declared = f.declared();
            Object key = declared != null ? declared.name() : (Object) f.number();
            if (declared != null && declared.repeated() && f.value() instanceof ProtoValue.Message m
                    && m.message().type() != null && m.message().type().mapEntry()) {
                @SuppressWarnings("unchecked")
                Map<Object, Object> map = (Map<Object, Object>) out.computeIfAbsent(key, k -> new LinkedHashMap<>());
                Map<Object, Object> entry = toPlain(m.message());
                map.put(entry.get("key"), entry.get("value"));
                continue;
            }
            List<Object> values = new ArrayList<>();
            if (f.value() instanceof ProtoValue.Packed p) {
                for (ProtoValue e : p.elements()) values.add(plain(e, message.type(), declared));
            } else {
                values.add(plain(f.value(), message.type(), declared));
            }
            boolean repeated = declared != null && declared.repeated() || f.value() instanceof ProtoValue.Packed;
            Object existing = out.get(key);
            if (existing instanceof RepeatedList list) {
                list.addAll(values);
            } else if (existing != null || repeated || values.size() > 1) {
                RepeatedList list = new RepeatedList();
                if (existing != null) list.add(existing);
                list.addAll(values);
                out.put(key, list);
            } else {
                out.put(key, values.getFirst());
            }
        }
        // Plain lists, so that callers can tell nothing apart.
        out.replaceAll((k, v) -> v instanceof RepeatedList list ? new ArrayList<>(list) : v);
        return out;
    }

    /** Marks the lists toPlain made, as opposed to values that are lists. */
    private static final class RepeatedList extends ArrayList<Object> {
        private static final long serialVersionUID = 1L;
    }

    private static Object plain(ProtoValue value, ProtoSchema.MessageType type, ProtoSchema.Field declared) {
        if (declared != null) {
            Object typed = typed(value, type, declared);
            if (typed != null) return typed;
        }
        return switch (value) {
            case ProtoValue.Varint v -> v.value();
            case ProtoValue.Text t -> t.text();
            case ProtoValue.Bytes b -> b.data().clone();
            case ProtoValue.Message m -> toPlain(m.message());
            case ProtoValue.Fixed32 f -> f;
            case ProtoValue.Fixed64 f -> f;
            case ProtoValue.Group g -> declared != null ? toPlain(g.message()) : g;
            case ProtoValue.Packed p -> {
                List<Object> out = new ArrayList<>();
                for (ProtoValue e : p.elements()) out.add(plain(e, type, declared));
                yield out;
            }
        };
    }

    private static Object typed(ProtoValue value, ProtoSchema.MessageType type, ProtoSchema.Field declared) {
        if (value instanceof ProtoValue.Varint v) {
            long x = v.value();
            return switch (declared.type()) {
                case INT32 -> (long) (int) x;
                case UINT32 -> x & 0xffffffffL;
                case UINT64 -> unsigned(x);
                case SINT32 -> (long) zigzagDecode32((int) x);
                case SINT64 -> zigzagDecode(x);
                case BOOL -> x != 0;
                case ENUM -> {
                    String name = type == null ? null
                            : type.enumType(declared.number()).map(e -> e.values().get((int) x)).orElse(null);
                    yield name != null ? name : (Object) (long) (int) x;
                }
                case INT64 -> x;
                default -> null;
            };
        }
        if (value instanceof ProtoValue.Fixed32 f) {
            return switch (declared.type()) {
                case FIXED32 -> f.unsigned();
                case SFIXED32 -> (long) f.bits();
                case FLOAT -> (double) f.asFloat();
                default -> null;
            };
        }
        if (value instanceof ProtoValue.Fixed64 f) {
            return switch (declared.type()) {
                case FIXED64 -> unsigned(f.bits());
                case SFIXED64 -> f.bits();
                case DOUBLE -> f.asDouble();
                default -> null;
            };
        }
        return null;
    }

    private static Object unsigned(long x) {
        return x >= 0 ? (Object) x : BigInteger.valueOf(x).add(TWO_64);
    }

    /**
     * Zigzag-encodes a signed 64-bit value, as {@code sint64} fields are: 0, -1, 1, -2 become 0, 1,
     * 2, 3.
     *
     * @param n the signed value
     * @return the encoded value
     */
    public static long zigzagEncode(long n) {
        return (n << 1) ^ (n >> 63);
    }

    /**
     * Decodes a zigzag-encoded 64-bit value: 0, 1, 2, 3 become 0, -1, 1, -2.
     *
     * @param n the encoded value
     * @return the signed value
     */
    public static long zigzagDecode(long n) {
        return (n >>> 1) ^ -(n & 1);
    }

    /**
     * Zigzag-encodes a signed 32-bit value, as {@code sint32} fields are.
     *
     * @param n the signed value
     * @return the encoded value, as 32 unsigned bits
     */
    public static int zigzagEncode32(int n) {
        return (n << 1) ^ (n >> 31);
    }

    /**
     * Decodes a zigzag-encoded 32-bit value.
     *
     * @param n the encoded value
     * @return the signed value
     */
    public static int zigzagDecode32(int n) {
        return (n >>> 1) ^ -(n & 1);
    }

    /**
     * Reads bytes as packed varints, as a packed repeated integer field holds them.
     *
     * @param data the field's bytes
     * @return the values, as 64-bit varint values
     * @throws DecodeException if the bytes are not a sequence of varints
     */
    public static List<Long> unpackVarints(byte[] data) throws DecodeException {
        List<Long> out = new ArrayList<>();
        for (ProtoValue v : ProtoWire.unpack(data, 0, data.length, ProtoValue.WIRE_VARINT)) {
            out.add(((ProtoValue.Varint) v).value());
        }
        return out;
    }

    /**
     * Packs integers as varints, as a packed repeated integer field holds them (negative numbers
     * take ten bytes, as for {@code int32} and {@code int64}).
     *
     * @param values the values
     * @return the field's bytes
     */
    public static byte[] packVarints(List<? extends Number> values) {
        ProtoWire.Writer w = new ProtoWire.Writer();
        for (Number n : values) {
            w.varint(n instanceof BigInteger b ? b.longValue() : n.longValue());
        }
        return w.toByteArray();
    }
}
