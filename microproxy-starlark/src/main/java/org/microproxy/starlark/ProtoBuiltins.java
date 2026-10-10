package org.microproxy.starlark;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.microproxy.contentviews.DecodeException;
import org.microproxy.contentviews.Grpc;
import org.microproxy.contentviews.ProtoMessage;
import org.microproxy.contentviews.ProtoSchema;
import org.microproxy.contentviews.ProtoValue;
import org.microproxy.contentviews.Protobuf;
import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.ParamType;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.NoneType;
import org.microproxy.thirdparty.starlark.eval.Sequence;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkFloat;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkList;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;

/**
 * The {@code protobuf} and {@code grpc} modules: protobuf messages as plain dicts keyed by field
 * number (or by name, with a schema), and gRPC's message framing. They are built on {@link
 * Protobuf} and {@link Grpc}. A script's schema, if any ({@link ScriptedProxy.Builder#protoSchema}),
 * is in its threads (see {@link StarlarkScript}).
 */
final class ProtoBuiltins {

    private ProtoBuiltins() {}

    private static final int MAX_DEPTH = 100;

    /** The script's schema, or the well-known types only. */
    private static ProtoSchema schema(StarlarkThread thread) {
        ProtoSchema schema = thread.getThreadLocal(ProtoSchema.class);
        return schema != null ? schema : ProtoSchema.empty();
    }

    private static String type(Object type) {
        return type == Starlark.NONE ? null : (String) type;
    }

    private static byte[] bytes(Object data, String what) throws EvalException {
        if (data instanceof StarlarkBytes b) return b.toByteArray();
        throw Starlark.errorf("%s must be bytes, not %s", what, Starlark.type(data));
    }

    // ---------------------------------------------------------------------------------------
    // Values between Java and Starlark
    // ---------------------------------------------------------------------------------------

    /** Plain Java values ({@link Protobuf#toPlain}) as Starlark values. */
    static Object toStarlark(Object v, Mutability mu) {
        return switch (v) {
            case Map<?, ?> map -> {
                Map<Object, Object> out = new LinkedHashMap<>();
                for (Map.Entry<?, ?> e : map.entrySet()) out.put(toStarlark(e.getKey(), mu), toStarlark(e.getValue(), mu));
                yield Dict.copyOf(mu, out);
            }
            case List<?> list -> {
                List<Object> out = new ArrayList<>(list.size());
                for (Object o : list) out.add(toStarlark(o, mu));
                yield StarlarkList.copyOf(mu, out);
            }
            case Integer i -> StarlarkInt.of(i);
            case Long l -> StarlarkInt.of(l);
            case BigInteger b -> StarlarkInt.of(b);
            case Double d -> StarlarkFloat.of(d);
            case byte[] b -> StarlarkBytes.of(null, b);
            case ProtoValue.Fixed32 f -> new ProtoFixed(f);
            case ProtoValue.Fixed64 f -> new ProtoFixed(f);
            case ProtoValue.Group g -> {
                @SuppressWarnings("unchecked")
                Dict<Object, Object> fields = (Dict<Object, Object>) toStarlark(g.message().toPlain(), mu);
                yield new ProtoGroup(fields);
            }
            case null -> Starlark.NONE;
            default -> v;
        };
    }

    /** Starlark values as plain Java values for {@link Protobuf#encode(Map)}. */
    static Object toJava(Object v, int depth) throws EvalException {
        if (depth > MAX_DEPTH) throw Starlark.errorf("value nested more than %d deep", MAX_DEPTH);
        return switch (v) {
            case Dict<?, ?> dict -> {
                Map<Object, Object> out = new LinkedHashMap<>();
                for (Map.Entry<?, ?> e : dict.entrySet()) out.put(toJava(e.getKey(), depth + 1), toJava(e.getValue(), depth + 1));
                yield out;
            }
            case StarlarkBytes b -> b.toByteArray();
            case Sequence<?> seq -> {
                List<Object> out = new ArrayList<>(seq.size());
                for (Object o : seq) out.add(toJava(o, depth + 1));
                yield out;
            }
            case StarlarkInt i -> {
                BigInteger b = i.toBigInteger();
                yield b.bitLength() < 64 ? (Object) b.longValue() : b;
            }
            case StarlarkFloat f -> f.toDouble();
            case String s -> s;
            case Boolean b -> b;
            case NoneType none -> null;
            case ProtoFixed f -> f.value();
            case ProtoGroup g -> {
                try {
                    @SuppressWarnings("unchecked")
                    Map<Object, Object> fields = (Map<Object, Object>) toJava(g.fields(), depth + 1);
                    yield new ProtoValue.Group(Protobuf.decode(Protobuf.encode(fields)));
                } catch (DecodeException | IllegalArgumentException e) {
                    throw Starlark.errorf("protobuf.group: %s", e.getMessage());
                }
            }
            default -> throw Starlark.errorf("cannot encode %s as protobuf", Starlark.type(v));
        };
    }

    private static byte[] encode(Object fields, Object type, StarlarkThread thread) throws EvalException {
        if (!(fields instanceof Dict<?, ?>)) {
            throw Starlark.errorf("protobuf messages are dicts, not %s", Starlark.type(fields));
        }
        Map<?, ?> plain = (Map<?, ?>) toJava(fields, 0);
        try {
            return type == Starlark.NONE ? Protobuf.encode(plain) : Protobuf.encode(plain, schema(thread), (String) type);
        } catch (IllegalArgumentException e) {
            throw Starlark.errorf("protobuf.encode: %s", e.getMessage());
        }
    }

    private static Object decode(byte[] data, Object type, StarlarkThread thread) throws EvalException {
        try {
            ProtoMessage m = Protobuf.decode(data, schema(thread), type(type));
            return toStarlark(m.toPlain(), thread.mutability());
        } catch (DecodeException | IllegalArgumentException e) {
            throw Starlark.errorf("protobuf.decode: %s", e.getMessage());
        }
    }

    // ---------------------------------------------------------------------------------------
    // protobuf
    // ---------------------------------------------------------------------------------------

    @StarlarkBuiltin(name = "protobuf", doc = "Protobuf messages as dicts keyed by field number.")
    public static final class ProtobufModule implements StarlarkValue {

        private static final String TYPE_DOC = "the message type's full name, from the script's schema (None: none)";

        @StarlarkMethod(name = "decode", useStarlarkThread = true,
                doc = "Decodes a message into a dict keyed by field number (or name, with a type): varints are ints, "
                        + "text str, other bytes bytes, nested messages dicts, repeated fields lists, fixed-width "
                        + "values ProtoFixed and groups ProtoGroup.",
                parameters = {
                    @Param(name = "data", doc = "the serialized message"),
                    @Param(name = "type", named = true, defaultValue = "None", doc = TYPE_DOC,
                            allowedTypes = {@ParamType(type = String.class), @ParamType(type = NoneType.class)}),
                })
        public Object decode(Object data, Object type, StarlarkThread thread) throws EvalException {
            return ProtoBuiltins.decode(bytes(data, "data"), type, thread);
        }

        @StarlarkMethod(name = "encode", useStarlarkThread = true,
                doc = "Encodes a dict as decode makes them: ints are varints (negative ones ten bytes), str and bytes "
                        + "length-delimited, dicts nested messages, lists repeated fields, floats doubles.",
                parameters = {
                    @Param(name = "fields", doc = "the message's fields"),
                    @Param(name = "type", named = true, defaultValue = "None", doc = TYPE_DOC,
                            allowedTypes = {@ParamType(type = String.class), @ParamType(type = NoneType.class)}),
                })
        public StarlarkBytes encode(Object fields, Object type, StarlarkThread thread) throws EvalException {
            return StarlarkBytes.of(null, ProtoBuiltins.encode(fields, type, thread));
        }

        @StarlarkMethod(name = "render", useStarlarkThread = true,
                doc = "The message as YAML with field numbers, as the protobuf content view shows it.",
                parameters = {
                    @Param(name = "data", doc = "the serialized message"),
                    @Param(name = "type", named = true, defaultValue = "None", doc = TYPE_DOC,
                            allowedTypes = {@ParamType(type = String.class), @ParamType(type = NoneType.class)}),
                })
        public String render(Object data, Object type, StarlarkThread thread) throws EvalException {
            try {
                return Protobuf.decode(bytes(data, "data"), schema(thread), type(type)).render();
            } catch (DecodeException | IllegalArgumentException e) {
                throw Starlark.errorf("protobuf.render: %s", e.getMessage());
            }
        }

        @StarlarkMethod(name = "fixed32", doc = "A fixed32 value: an int (signed or unsigned) or a float.",
                parameters = {@Param(name = "value")})
        public ProtoFixed fixed32(Object value) throws EvalException {
            if (value instanceof StarlarkFloat f) {
                return new ProtoFixed(new ProtoValue.Fixed32(Float.floatToRawIntBits((float) f.toDouble())));
            }
            long v = integer(value, "fixed32", -(1L << 31), (1L << 32) - 1);
            return new ProtoFixed(new ProtoValue.Fixed32((int) v));
        }

        @StarlarkMethod(name = "fixed64", doc = "A fixed64 value: an int (signed or unsigned) or a float.",
                parameters = {@Param(name = "value")})
        public ProtoFixed fixed64(Object value) throws EvalException {
            if (value instanceof StarlarkFloat f) {
                return new ProtoFixed(new ProtoValue.Fixed64(Double.doubleToRawLongBits(f.toDouble())));
            }
            if (!(value instanceof StarlarkInt i)) throw Starlark.errorf("fixed64 needs an int or float");
            BigInteger b = i.toBigInteger();
            if (b.bitLength() > 64 || b.signum() < 0 && b.bitLength() > 63) {
                throw Starlark.errorf("fixed64: %s does not fit in 64 bits", b);
            }
            return new ProtoFixed(new ProtoValue.Fixed64(b.longValue()));
        }

        @StarlarkMethod(name = "group", doc = "A group with these fields (proto2's wire types 3 and 4).",
                parameters = {@Param(name = "fields", allowedTypes = {@ParamType(type = Dict.class)})})
        public ProtoGroup group(Dict<?, ?> fields) {
            @SuppressWarnings("unchecked")
            Dict<Object, Object> f = (Dict<Object, Object>) fields;
            return new ProtoGroup(f);
        }

        @StarlarkMethod(name = "zigzag_decode", doc = "Reads a varint as sint32/sint64 do: 0, 1, 2, 3 become 0, -1, 1, -2.",
                parameters = {@Param(name = "n")})
        public StarlarkInt zigzagDecode(StarlarkInt n) throws EvalException {
            return StarlarkInt.of(Protobuf.zigzagDecode(varint(n)));
        }

        @StarlarkMethod(name = "zigzag_encode", doc = "Encodes a signed int as sint32/sint64 do: 0, -1, 1, -2 become 0, 1, 2, 3.",
                parameters = {@Param(name = "n")})
        public StarlarkInt zigzagEncode(StarlarkInt n) throws EvalException {
            long v = integer(n, "zigzag_encode", Long.MIN_VALUE, Long.MAX_VALUE);
            return StarlarkInt.of(new BigInteger(Long.toUnsignedString(Protobuf.zigzagEncode(v))));
        }

        @StarlarkMethod(name = "unpack", doc = "Reads bytes as packed varints, as a packed repeated integer field holds them.",
                parameters = {@Param(name = "data")}, useStarlarkThread = true)
        public StarlarkList<StarlarkInt> unpack(Object data, StarlarkThread thread) throws EvalException {
            try {
                List<StarlarkInt> out = new ArrayList<>();
                for (long v : Protobuf.unpackVarints(bytes(data, "data"))) out.add(StarlarkInt.of(v));
                return StarlarkList.copyOf(thread.mutability(), out);
            } catch (DecodeException e) {
                throw Starlark.errorf("protobuf.unpack: %s", e.getMessage());
            }
        }

        @StarlarkMethod(name = "pack", doc = "Packs ints as varints, as a packed repeated integer field holds them.",
                parameters = {@Param(name = "values", allowedTypes = {@ParamType(type = Sequence.class)})})
        public StarlarkBytes pack(Sequence<?> values) throws EvalException {
            List<Long> out = new ArrayList<>();
            for (Object v : values) {
                if (!(v instanceof StarlarkInt i)) throw Starlark.errorf("pack takes ints, not %s", Starlark.type(v));
                out.add(varint(i));
            }
            return StarlarkBytes.of(null, Protobuf.packVarints(out));
        }

        /** An int as a varint's 64 bits: signed, or unsigned up to 2^64-1. */
        private static long varint(StarlarkInt n) throws EvalException {
            BigInteger b = n.toBigInteger();
            if (b.bitLength() > 64 || b.signum() < 0 && b.bitLength() > 63) {
                throw Starlark.errorf("%s does not fit in 64 bits", b);
            }
            return b.longValue();
        }

        private static long integer(Object value, String what, long min, long max) throws EvalException {
            if (!(value instanceof StarlarkInt i)) throw Starlark.errorf("%s needs an int, not %s", what, Starlark.type(value));
            BigInteger b = i.toBigInteger();
            if (b.compareTo(BigInteger.valueOf(min)) < 0 || b.compareTo(BigInteger.valueOf(max)) > 0) {
                throw Starlark.errorf("%s: %s is out of range", what, b);
            }
            return b.longValue();
        }
    }

    // ---------------------------------------------------------------------------------------
    // grpc
    // ---------------------------------------------------------------------------------------

    @StarlarkBuiltin(name = "grpc", doc = "gRPC message framing and status details.")
    public static final class GrpcModule implements StarlarkValue {

        private static final String ENCODING_DOC = "the grpc-encoding header (gzip, deflate, identity; None: none)";

        @StarlarkMethod(name = "messages", useStarlarkThread = true,
                doc = "Splits a gRPC body into its messages (bytes), decompressing compressed ones.",
                parameters = {
                    @Param(name = "body"),
                    @Param(name = "encoding", named = true, defaultValue = "None", doc = ENCODING_DOC,
                            allowedTypes = {@ParamType(type = String.class), @ParamType(type = NoneType.class)}),
                })
        public StarlarkList<StarlarkBytes> messages(Object body, Object encoding, StarlarkThread thread)
                throws EvalException {
            try {
                List<StarlarkBytes> out = new ArrayList<>();
                for (byte[] m : Grpc.messages(bytes(body, "body"), type(encoding))) out.add(StarlarkBytes.of(null, m));
                return StarlarkList.copyOf(thread.mutability(), out);
            } catch (DecodeException e) {
                throw Starlark.errorf("grpc.messages: %s", e.getMessage());
            }
        }

        @StarlarkMethod(name = "frame",
                doc = "Frames messages (bytes) into a gRPC body, compressing each when an encoding is given.",
                parameters = {
                    @Param(name = "messages", allowedTypes = {@ParamType(type = Sequence.class)}),
                    @Param(name = "encoding", named = true, defaultValue = "None", doc = ENCODING_DOC,
                            allowedTypes = {@ParamType(type = String.class), @ParamType(type = NoneType.class)}),
                })
        public StarlarkBytes frame(Sequence<?> messages, Object encoding) throws EvalException {
            List<byte[]> out = new ArrayList<>();
            for (Object m : messages) out.add(bytes(m, "a message"));
            try {
                return StarlarkBytes.of(null, Grpc.join(out, type(encoding)));
            } catch (IllegalArgumentException e) {
                throw Starlark.errorf("grpc.frame: %s", e.getMessage());
            }
        }

        @StarlarkMethod(name = "decode", useStarlarkThread = true,
                doc = "grpc.messages, then protobuf.decode of each: a list of dicts.",
                parameters = {
                    @Param(name = "body"),
                    @Param(name = "encoding", named = true, defaultValue = "None", doc = ENCODING_DOC,
                            allowedTypes = {@ParamType(type = String.class), @ParamType(type = NoneType.class)}),
                    @Param(name = "type", named = true, defaultValue = "None",
                            allowedTypes = {@ParamType(type = String.class), @ParamType(type = NoneType.class)}),
                })
        public StarlarkList<Object> decode(Object body, Object encoding, Object type, StarlarkThread thread)
                throws EvalException {
            List<Object> out = new ArrayList<>();
            for (StarlarkBytes m : messages(body, encoding, thread)) out.add(ProtoBuiltins.decode(m.toByteArray(), type, thread));
            return StarlarkList.copyOf(thread.mutability(), out);
        }

        @StarlarkMethod(name = "encode", useStarlarkThread = true,
                doc = "protobuf.encode of each dict, then grpc.frame: a gRPC body.",
                parameters = {
                    @Param(name = "messages", allowedTypes = {@ParamType(type = Sequence.class)}),
                    @Param(name = "encoding", named = true, defaultValue = "None", doc = ENCODING_DOC,
                            allowedTypes = {@ParamType(type = String.class), @ParamType(type = NoneType.class)}),
                    @Param(name = "type", named = true, defaultValue = "None",
                            allowedTypes = {@ParamType(type = String.class), @ParamType(type = NoneType.class)}),
                })
        public StarlarkBytes encode(Sequence<?> messages, Object encoding, Object type, StarlarkThread thread)
                throws EvalException {
            List<byte[]> out = new ArrayList<>();
            for (Object m : messages) out.add(ProtoBuiltins.encode(m, type, thread));
            try {
                return StarlarkBytes.of(null, Grpc.join(out, type(encoding)));
            } catch (IllegalArgumentException e) {
                throw Starlark.errorf("grpc.encode: %s", e.getMessage());
            }
        }

        @StarlarkMethod(name = "status", useStarlarkThread = true,
                doc = "Decodes grpc-status-details-bin (its base64 text, or the decoded bytes) into a dict: code, name, "
                        + "message, and details, a list of dicts with type_url and value (bytes).",
                parameters = {@Param(name = "details")})
        public Dict<String, Object> status(Object details, StarlarkThread thread) throws EvalException {
            Grpc.Status status;
            try {
                status = details instanceof String s ? Grpc.statusFromTrailer(s) : Grpc.status(bytes(details, "details"));
            } catch (DecodeException e) {
                throw Starlark.errorf("grpc.status: %s", e.getMessage());
            }
            List<Object> list = new ArrayList<>();
            for (Grpc.Detail d : status.details()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("type_url", d.typeUrl());
                m.put("value", StarlarkBytes.of(null, d.value()));
                list.add(Dict.copyOf(thread.mutability(), m));
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("code", StarlarkInt.of(status.code()));
            out.put("name", status.codeName() == null ? Starlark.NONE : status.codeName());
            out.put("message", status.message());
            out.put("details", StarlarkList.copyOf(thread.mutability(), list));
            return Dict.copyOf(thread.mutability(), out);
        }

        @StarlarkMethod(name = "status_details",
                doc = "The grpc-status-details-bin value for a status: base64 of a google.rpc.Status.",
                parameters = {
                    @Param(name = "code"),
                    @Param(name = "message", defaultValue = "''"),
                    @Param(name = "details", named = true, defaultValue = "[]",
                            doc = "dicts with type_url (str) and value (bytes, or a dict to encode)"),
                },
                useStarlarkThread = true)
        public String statusDetails(StarlarkInt code, String message, Object details, StarlarkThread thread)
                throws EvalException {
            List<Grpc.Detail> list = new ArrayList<>();
            for (Object d : Starlark.toIterable(details)) {
                if (!(d instanceof Dict<?, ?> dict) || !(dict.get("type_url") instanceof String url)) {
                    throw Starlark.errorf("details are dicts with type_url and value");
                }
                Object value = dict.get("value");
                byte[] bytes = value instanceof Dict<?, ?> ? ProtoBuiltins.encode(value, Starlark.NONE, thread)
                        : bytes(value, "value");
                list.add(new Grpc.Detail(url, bytes));
            }
            return new Grpc.Status(code.toInt("code"), message, list).toTrailer();
        }

        @StarlarkMethod(name = "code_name", allowReturnNones = true,
                doc = "The name of a status code (3 is INVALID_ARGUMENT), or None.",
                parameters = {@Param(name = "code")})
        public Object codeName(StarlarkInt code) throws EvalException {
            String name = Grpc.codeName(code.toInt("code"));
            return name == null ? Starlark.NONE : name;
        }
    }
}
