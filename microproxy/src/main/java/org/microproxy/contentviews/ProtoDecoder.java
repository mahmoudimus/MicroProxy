/*
 * The type guessing for fields without a schema is ported from mitmproxy_rs
 * (https://github.com/mitmproxy/mitmproxy_rs), mitmproxy-contentviews/src/protobuf/raw_to_proto.rs
 * (guess_field_type and create_descriptor_proto). Copyright (c) 2022, Fabio Valentini and
 * Maximilian Hils. Licensed under the MIT License; see META-INF/LICENSE-mitmproxy_rs.txt.
 */
package org.microproxy.contentviews;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Turns wire fields into a {@link ProtoMessage}. Fields a schema declares are read as declared;
 * the length-delimited values of other fields are guessed as mitmproxy does, per field number
 * over all of the field's values:
 *
 * <ol>
 *   <li>text, when every value is UTF-8 without control characters other than whitespace (mitmproxy
 *       accepts only ASCII here; this also accepts other printable characters);
 *   <li>else a nested message, when every value parses as one: minimal varints only, field numbers
 *       in range, each field number with a single wire type, within the depth limit;
 *   <li>else bytes.
 * </ol>
 */
final class ProtoDecoder {

    private static final String ANY = "google.protobuf.Any";

    private final ProtoSchema schema;
    private final int maxDepth;

    ProtoDecoder(ProtoSchema schema, int maxDepth) {
        this.schema = schema;
        this.maxDepth = maxDepth;
    }

    ProtoMessage decode(byte[] data, ProtoSchema.MessageType type) throws DecodeException {
        return interpret(ProtoWire.read(data, 0, data.length, false, maxDepth), type, 0);
    }

    /** What the length-delimited values of one undeclared field number were taken for. */
    private enum Kind { TEXT, MESSAGE, BYTES }

    private ProtoMessage interpret(List<ProtoWire.Raw> raws, ProtoSchema.MessageType type, int depth) {
        ProtoField[] fields = new ProtoField[raws.size()];
        ProtoSchema.MessageType anyType = type != null && type.fullName().equals(ANY) ? anyType(raws) : null;
        // Declared fields first; the undeclared length-delimited values are then guessed per number.
        Map<Integer, List<ProtoWire.Raw>> undeclared = new LinkedHashMap<>();
        for (int i = 0; i < fields.length; i++) {
            ProtoWire.Raw raw = raws.get(i);
            ProtoSchema.Field declared = type == null ? null : type.field(raw.number());
            if (declared != null) fields[i] = declared(raw, declared, type, anyType, depth);
            if (fields[i] == null && raw.wireType() == ProtoValue.WIRE_LEN) {
                undeclared.computeIfAbsent(raw.number(), k -> new ArrayList<>()).add(raw);
            }
        }
        Map<ProtoWire.Raw, Object> guessed = new IdentityHashMap<>();
        Map<Integer, Kind> kinds = new HashMap<>();
        for (Map.Entry<Integer, List<ProtoWire.Raw>> e : undeclared.entrySet()) {
            kinds.put(e.getKey(), guess(e.getValue(), depth, guessed));
        }
        for (int i = 0; i < fields.length; i++) {
            if (fields[i] != null) continue;
            ProtoWire.Raw raw = raws.get(i);
            fields[i] = new ProtoField(raw.number(), undeclared(raw, kinds.get(raw.number()), guessed, depth));
        }
        return new ProtoMessage(List.of(fields), type);
    }

    private ProtoValue undeclared(ProtoWire.Raw raw, Kind kind, Map<ProtoWire.Raw, Object> guessed, int depth) {
        return switch (raw.wireType()) {
            case ProtoValue.WIRE_VARINT -> new ProtoValue.Varint(raw.bits());
            case ProtoValue.WIRE_FIXED32 -> new ProtoValue.Fixed32((int) raw.bits());
            case ProtoValue.WIRE_FIXED64 -> new ProtoValue.Fixed64(raw.bits());
            case ProtoValue.WIRE_START_GROUP -> new ProtoValue.Group(interpret(raw.group(), null, depth + 1));
            default -> switch (kind) {
                case TEXT -> new ProtoValue.Text((String) guessed.get(raw));
                case MESSAGE -> {
                    @SuppressWarnings("unchecked")
                    List<ProtoWire.Raw> nested = (List<ProtoWire.Raw>) guessed.get(raw);
                    yield new ProtoValue.Message(interpret(nested, null, depth + 1));
                }
                case BYTES -> new ProtoValue.Bytes(raw.bytes());
            };
        };
    }

    /** Guesses what the values of one field are, keeping each value's text or fields in {@code guessed}. */
    private Kind guess(List<ProtoWire.Raw> values, int depth, Map<ProtoWire.Raw, Object> guessed) {
        Map<ProtoWire.Raw, Object> found = new IdentityHashMap<>();
        boolean text = true;
        for (ProtoWire.Raw v : values) {
            String s = text(v);
            if (s == null) {
                text = false;
                break;
            }
            found.put(v, s);
        }
        if (text) {
            guessed.putAll(found);
            return Kind.TEXT;
        }
        if (depth < maxDepth) {
            found.clear();
            for (ProtoWire.Raw v : values) {
                List<ProtoWire.Raw> fields = nested(v, depth);
                if (fields == null) return Kind.BYTES;
                found.put(v, fields);
            }
            guessed.putAll(found);
            return Kind.MESSAGE;
        }
        return Kind.BYTES;
    }

    /** The fields of {@code raw} read as a nested message, or {@code null} if it does not look like one. */
    private List<ProtoWire.Raw> nested(ProtoWire.Raw raw, int depth) {
        List<ProtoWire.Raw> fields;
        try {
            fields = ProtoWire.read(raw.data(), raw.offset(), raw.offset() + raw.length(), true, maxDepth - depth - 1);
        } catch (DecodeException e) {
            return null;
        }
        return consistent(fields) ? fields : null;
    }

    /** Whether each field number has one wire type, as in any message a real encoder wrote. */
    private static boolean consistent(List<ProtoWire.Raw> fields) {
        Map<Integer, Integer> wireTypes = new HashMap<>();
        for (ProtoWire.Raw f : fields) {
            Integer before = wireTypes.putIfAbsent(f.number(), f.wireType());
            if (before != null && before != f.wireType()) return false;
            if (f.group() != null && !consistent(f.group())) return false;
        }
        return true;
    }

    /** The value as text, or {@code null} if it is not UTF-8 or has control characters. */
    static String text(ProtoWire.Raw raw) {
        return text(raw.data(), raw.offset(), raw.length());
    }

    static String text(byte[] data, int offset, int length) {
        String s = utf8(data, offset, length);
        if (s == null) return null;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean whitespace = c == '\t' || c == '\n' || c == '\r' || c == '\f';
            if (!whitespace && (c < 0x20 || c == 0x7f || c >= 0x80 && c < 0xa0)) return null;
        }
        return s;
    }

    // ---------------------------------------------------------------------------------------
    // Declared fields
    // ---------------------------------------------------------------------------------------

    /** {@code raw} read as {@code declared} says, or {@code null} when it does not fit. */
    private ProtoField declared(ProtoWire.Raw raw, ProtoSchema.Field declared, ProtoSchema.MessageType type,
            ProtoSchema.MessageType anyType, int depth) {
        ProtoSchema.Type t = declared.type();
        int n = raw.number();
        if (raw.wireType() == ProtoValue.WIRE_LEN && t.packable() && declared.repeated()) {
            try {
                List<ProtoValue> elements = ProtoWire.unpack(raw.data(), raw.offset(), raw.offset() + raw.length(),
                        t.wireType());
                return new ProtoField(n, new ProtoValue.Packed(elements), declared);
            } catch (DecodeException e) {
                return null;
            }
        }
        if (raw.wireType() != t.wireType()) return null;
        return switch (t) {
            case STRING -> {
                String s = utf8(raw);
                yield s == null ? null : new ProtoField(n, new ProtoValue.Text(s), declared);
            }
            case BYTES -> {
                if (type.fullName().equals(ANY) && n == 2) {
                    // Any.value is a message of the type its type_url names.
                    ProtoMessage m = anyType != null ? message(raw, anyType, depth) : null;
                    if (m == null && depth < maxDepth) {
                        List<ProtoWire.Raw> fields = nested(raw, depth);
                        if (fields != null) m = interpret(fields, null, depth + 1);
                    }
                    if (m != null) yield new ProtoField(n, new ProtoValue.Message(m), declared);
                }
                yield new ProtoField(n, new ProtoValue.Bytes(raw.bytes()), declared);
            }
            case MESSAGE -> {
                ProtoSchema.MessageType nested = schema.message(declared.typeName()).orElse(null);
                ProtoMessage m = nested == null ? null : message(raw, nested, depth);
                yield m == null ? null : new ProtoField(n, new ProtoValue.Message(m), declared);
            }
            case GROUP -> {
                ProtoSchema.MessageType nested = schema.message(declared.typeName()).orElse(null);
                yield new ProtoField(n, new ProtoValue.Group(interpret(raw.group(), nested, depth + 1)), declared);
            }
            case DOUBLE, FIXED64, SFIXED64 -> new ProtoField(n, new ProtoValue.Fixed64(raw.bits()), declared);
            case FLOAT, FIXED32, SFIXED32 -> new ProtoField(n, new ProtoValue.Fixed32((int) raw.bits()), declared);
            default -> new ProtoField(n, new ProtoValue.Varint(raw.bits()), declared);
        };
    }

    /** {@code raw} decoded as a message of {@code type}, or {@code null} if it is not one. */
    private ProtoMessage message(ProtoWire.Raw raw, ProtoSchema.MessageType type, int depth) {
        if (depth >= maxDepth) return null;
        try {
            List<ProtoWire.Raw> fields =
                    ProtoWire.read(raw.data(), raw.offset(), raw.offset() + raw.length(), false, maxDepth - depth - 1);
            return interpret(fields, type, depth + 1);
        } catch (DecodeException e) {
            return null;
        }
    }

    /** The type an {@code Any}'s {@code type_url} names, if the schema has it. */
    private ProtoSchema.MessageType anyType(List<ProtoWire.Raw> raws) {
        for (ProtoWire.Raw raw : raws) {
            if (raw.number() == 1 && raw.wireType() == ProtoValue.WIRE_LEN) {
                String url = utf8(raw);
                if (url == null) return null;
                return schema.message(url.substring(url.lastIndexOf('/') + 1)).orElse(null);
            }
        }
        return null;
    }

    private static String utf8(ProtoWire.Raw raw) {
        return utf8(raw.data(), raw.offset(), raw.length());
    }

    /** Strictly decoded UTF-8, or {@code null} if the bytes are not UTF-8. */
    static String utf8(byte[] data, int offset, int length) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(data, offset, length))
                    .toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }
}
