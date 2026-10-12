/*
 * Ported from mitmproxy_rs (https://github.com/mitmproxy/mitmproxy_rs),
 * mitmproxy-contentviews/src/protobuf/proto_to_yaml.rs and yaml_to_pretty.rs: the YAML layout,
 * the !binary, !fixed32 and !fixed64 tags, and the choice of a number's representations
 * (NumReprs). Copyright (c) 2022, Fabio Valentini and Maximilian Hils. Licensed under the MIT
 * License; see META-INF/LICENSE-mitmproxy_rs.txt.
 */
package org.microproxy.contentviews;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Renders a {@link ProtoMessage} as YAML, as mitmproxy's protobuf view does:
 *
 * <pre>
 * 1: 150  # !sint: 75
 * 2: hello
 * 3: !fixed32 3.14159  # u32: 1078530000
 * 5:
 *   1: 42  # !sint: 21
 * 6: !binary 038e029ea705  # packed: [3, 270, 86942]
 * </pre>
 *
 * <p>Fields are keyed by number, or by name when a schema declares them, and sorted by number; a
 * field that occurs more than once (or is declared repeated) is a sequence. A number without a
 * declared type is shown in its shortest representation, with the others as a comment: a varint
 * as unsigned, signed (when the top bit is set) or zigzag ({@code !sint}); fixed-width values as
 * unsigned, signed and floating point. Bytes that read as packed varints say so in a comment.
 */
final class ProtoText {

    private static final HexFormat HEX = HexFormat.of();

    private ProtoText() {}

    static String render(ProtoMessage message) {
        if (message.fields().isEmpty()) return "{}  # empty protobuf message";
        return Yaml.emit(mapping(message));
    }

    static Yaml.Mapping mapping(ProtoMessage message) {
        // Sorted by number; declared and undeclared occurrences of one number are kept apart.
        Map<Integer, List<ProtoField>> declared = new TreeMap<>();
        Map<Integer, List<ProtoField>> undeclared = new TreeMap<>();
        for (ProtoField f : message.fields()) {
            (f.declared() != null ? declared : undeclared).computeIfAbsent(f.number(), k -> new ArrayList<>()).add(f);
        }
        Yaml.Mapping out = new Yaml.Mapping();
        List<Integer> numbers = new ArrayList<>(declared.keySet());
        for (Integer n : undeclared.keySet()) if (!numbers.contains(n)) numbers.add(n);
        numbers.sort(null);
        for (int n : numbers) {
            List<ProtoField> named = declared.get(n);
            if (named != null) out.entries().add(entry(message.type(), named.getFirst().declared(), named));
            List<ProtoField> numbered = undeclared.get(n);
            if (numbered != null) out.entries().add(entry(null, null, numbered));
        }
        return out;
    }

    private static Yaml.Entry entry(ProtoSchema.MessageType type, ProtoSchema.Field declared, List<ProtoField> fields) {
        String key = declared != null ? Yaml.string(declared.name()) : String.valueOf(fields.getFirst().number());
        List<Yaml.Node> values = new ArrayList<>();
        for (ProtoField f : fields) {
            if (f.value() instanceof ProtoValue.Packed p) {
                for (ProtoValue e : p.elements()) values.add(value(e, type, declared));
            } else {
                values.add(value(f.value(), type, declared));
            }
        }
        if (declared != null && declared.repeated() && isMap(fields)) return new Yaml.Entry(key, map(fields));
        boolean sequence = values.size() > 1 || declared != null && declared.repeated();
        return new Yaml.Entry(key, sequence ? new Yaml.Sequence(values) : values.getFirst());
    }

    /** Whether the fields are the entries of a map field. */
    private static boolean isMap(List<ProtoField> fields) {
        for (ProtoField f : fields) {
            if (!(f.value() instanceof ProtoValue.Message m) || m.message().type() == null
                    || !m.message().type().mapEntry()) {
                return false;
            }
        }
        return true;
    }

    /** A map field's entries as one mapping from keys to values. */
    private static Yaml.Node map(List<ProtoField> fields) {
        Yaml.Mapping out = new Yaml.Mapping();
        for (ProtoField f : fields) {
            ProtoMessage entry = ((ProtoValue.Message) f.value()).message();
            Yaml.Node key = new Yaml.Scalar("''");
            Yaml.Node value = new Yaml.Mapping();
            for (ProtoField ef : entry.fields()) {
                Yaml.Node v = value(ef.value(), entry.type(), ef.declared());
                if (ef.number() == 1) key = v;
                else if (ef.number() == 2) value = v;
            }
            out.put(key instanceof Yaml.Scalar s ? s.text() : "? complex key", value);
        }
        return out;
    }

    /** One value; with a declaration, as its declared type. */
    static Yaml.Node value(ProtoValue value, ProtoSchema.MessageType type, ProtoSchema.Field declared) {
        if (declared != null) {
            Yaml.Node typed = typed(value, type, declared);
            if (typed != null) return typed;
        }
        return switch (value) {
            case ProtoValue.Varint v -> varint(v.value());
            case ProtoValue.Fixed32 f -> fixed32(f.bits());
            case ProtoValue.Fixed64 f -> fixed64(f.bits());
            case ProtoValue.Text t -> new Yaml.Scalar(Yaml.string(t.text()));
            case ProtoValue.Bytes b -> new Yaml.Scalar("!binary " + Yaml.string(HEX.formatHex(b.data())),
                    declared == null ? packedComment(b.data()) : null);
            case ProtoValue.Message m -> nested(m.message(), null);
            case ProtoValue.Group g -> nested(g.message(), "!group");
            case ProtoValue.Packed p -> {
                List<Yaml.Node> items = new ArrayList<>();
                for (ProtoValue e : p.elements()) items.add(value(e, null, null));
                yield new Yaml.Sequence(items);
            }
        };
    }

    private static Yaml.Node nested(ProtoMessage m, String tag) {
        Yaml.Mapping mapping = mapping(m);
        return tag == null ? mapping : new Yaml.Mapping(tag, mapping.entries());
    }

    /** A value read as its declared type, or {@code null} if the value does not have that type's wire form. */
    private static Yaml.Node typed(ProtoValue value, ProtoSchema.MessageType type, ProtoSchema.Field declared) {
        return switch (declared.type()) {
            case INT32 -> value instanceof ProtoValue.Varint v ? number(String.valueOf((int) v.value())) : null;
            case INT64 -> value instanceof ProtoValue.Varint v ? number(String.valueOf(v.value())) : null;
            case UINT32 -> value instanceof ProtoValue.Varint v ? number(String.valueOf(v.value() & 0xffffffffL)) : null;
            case UINT64 -> value instanceof ProtoValue.Varint v ? number(v.unsigned()) : null;
            case SINT32 -> value instanceof ProtoValue.Varint v ? number(String.valueOf(Protobuf.zigzagDecode32((int) v.value()))) : null;
            case SINT64 -> value instanceof ProtoValue.Varint v ? number(String.valueOf(v.zigzag())) : null;
            case BOOL -> value instanceof ProtoValue.Varint v
                    ? new Yaml.Scalar(v.value() != 0 ? "true" : "false",
                            v.value() != 0 && v.value() != 1 ? "varint " + v.unsigned() : null)
                    : null;
            case ENUM -> value instanceof ProtoValue.Varint v ? enumValue(v, type, declared) : null;
            case FIXED32 -> value instanceof ProtoValue.Fixed32 f ? number(String.valueOf(f.unsigned())) : null;
            case SFIXED32 -> value instanceof ProtoValue.Fixed32 f ? number(String.valueOf(f.bits())) : null;
            case FLOAT -> value instanceof ProtoValue.Fixed32 f ? number(formatFloat(f.asFloat())) : null;
            case FIXED64 -> value instanceof ProtoValue.Fixed64 f ? number(f.unsigned()) : null;
            case SFIXED64 -> value instanceof ProtoValue.Fixed64 f ? number(String.valueOf(f.bits())) : null;
            case DOUBLE -> value instanceof ProtoValue.Fixed64 f ? number(formatDouble(f.asDouble())) : null;
            case STRING, BYTES, MESSAGE, GROUP -> null;
        };
    }

    private static Yaml.Node number(String text) {
        return new Yaml.Scalar(text);
    }

    private static Yaml.Node enumValue(ProtoValue.Varint v, ProtoSchema.MessageType type, ProtoSchema.Field declared) {
        int number = (int) v.value();
        String name = type == null ? null
                : type.enumType(declared.number()).map(e -> e.values().get(number)).orElse(null);
        return name != null ? new Yaml.Scalar(Yaml.string(name)) : new Yaml.Scalar(String.valueOf(number));
    }

    // ---------------------------------------------------------------------------------------
    // Numbers of unknown type (yaml_to_pretty.rs)
    // ---------------------------------------------------------------------------------------

    /** The representations of a number: the shortest is the value, the others a comment. */
    private static final class Reprs {
        private final List<String[]> reprs = new ArrayList<>(3);

        Reprs add(String type, String value) {
            reprs.add(new String[] {type, value});
            return this;
        }

        Yaml.Scalar scalar(String tag) {
            // By type name first, so that !sint is never the main representation; then the shortest.
            String[] main = reprs.getFirst();
            for (String[] r : reprs) {
                if (r[0].length() < main[0].length()
                        || r[0].length() == main[0].length() && r[1].length() < main[1].length()) {
                    main = r;
                }
            }
            List<String> rest = new ArrayList<>();
            for (String[] r : reprs) if (!r[0].equals(main[0])) rest.add(r[0] + ": " + r[1]);
            return new Yaml.Scalar(tag == null ? main[1] : tag + " " + main[1],
                    rest.isEmpty() ? null : String.join(", ", rest));
        }
    }

    static Yaml.Scalar varint(long value) {
        Reprs r = new Reprs().add("u64", Long.toUnsignedString(value));
        if (value < 0) {
            // Probably a negative int32 or int64; it could be zigzag, but that is unlikely.
            r.add("i64", String.valueOf(value));
        } else {
            r.add("!sint", String.valueOf(Protobuf.zigzagDecode(value)));
        }
        return r.scalar(null);
    }

    static Yaml.Scalar fixed32(int bits) {
        Reprs r = new Reprs().add("u32", Integer.toUnsignedString(bits));
        float f = Float.intBitsToFloat(bits);
        if (!Float.isNaN(f) && Math.abs(f) > 0.0000001) r.add("f32", formatFloat(f));
        if (bits < 0) r.add("i32", String.valueOf(bits));
        return r.scalar("!fixed32");
    }

    static Yaml.Scalar fixed64(long bits) {
        Reprs r = new Reprs().add("u64", Long.toUnsignedString(bits));
        double d = Double.longBitsToDouble(bits);
        if (!Double.isNaN(d) && Math.abs(d) > 0.0000001) r.add("f64", formatDouble(d));
        if (bits < 0) r.add("i64", String.valueOf(bits));
        return r.scalar("!fixed64");
    }

    /** The shortest decimal that reads back as {@code f}, with a fraction so it reads back as a float. */
    static String formatFloat(float f) {
        if (Float.isNaN(f)) return ".nan";
        if (Float.isInfinite(f)) return f > 0 ? ".inf" : "-.inf";
        return plainDecimal(Float.toString(f));
    }

    static String formatDouble(double d) {
        if (Double.isNaN(d)) return ".nan";
        if (Double.isInfinite(d)) return d > 0 ? ".inf" : "-.inf";
        return plainDecimal(Double.toString(d));
    }

    private static String plainDecimal(String javaText) {
        BigDecimal decimal = new BigDecimal(javaText);
        String s = decimal.signum() == 0 ? (javaText.startsWith("-") ? "-0" : "0")
                : decimal.stripTrailingZeros().toPlainString();
        return s.contains(".") ? s : s + ".0";
    }

    /**
     * A comment for bytes that read as two or more packed varints, each a 32-bit value or a
     * negative 64-bit one, minimally encoded; or {@code null}.
     */
    static String packedComment(byte[] data) {
        List<Long> values = packedVarints(data);
        if (values == null || values.size() < 2) return null;
        StringBuilder sb = new StringBuilder("packed: [");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(values.get(i));
        }
        return sb.append(']').toString();
    }

    private static List<Long> packedVarints(byte[] data) {
        List<Long> out = new ArrayList<>();
        int pos = 0;
        while (pos < data.length) {
            long value = 0;
            int i = 0;
            while (true) {
                if (pos >= data.length || i == 10) return null;
                int b = data[pos++] & 0xff;
                value |= (long) (b & 0x7f) << (7 * i);
                if (b < 0x80) {
                    if (i > 0 && b == 0) return null;
                    break;
                }
                i++;
            }
            boolean int32 = i < 5 && value >>> 32 == 0;
            boolean negative64 = i == 9 && value < 0;
            if (!int32 && !negative64) return null;
            out.add(value);
        }
        return out;
    }
}
