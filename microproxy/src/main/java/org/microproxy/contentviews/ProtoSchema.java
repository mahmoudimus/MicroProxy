package org.microproxy.contentviews;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Protobuf type definitions, read from a {@code FileDescriptorSet} (what {@code protoc
 * --descriptor_set_out=types.desc --include_imports} writes), so that messages decode with field
 * names, enum names and declared types instead of guesses, and gRPC calls decode with their
 * method's input and output types:
 *
 * <pre>{@code
 * ProtoSchema schema = ProtoSchema.load(Path.of("types.desc"));
 * ProtoMessage m = Protobuf.decode(body, schema, "example.Order");
 * ContentViews views = ContentViews.defaults().withSchema(schema);
 * }</pre>
 *
 * <p>The descriptor set is parsed with this package's own protobuf decoder; no protobuf library
 * is involved. Every schema also knows a few well-known types, which gRPC error details use:
 * {@code google.protobuf.Any} and {@code Duration}, {@code google.rpc.Status} and the standard
 * error details ({@code ErrorInfo}, {@code RetryInfo}, {@code BadRequest}, ...). Definitions in
 * the descriptor set take precedence over them. Extensions, options other than {@code packed} and
 * {@code map_entry}, and default values are ignored.
 */
public final class ProtoSchema {

    /** The types a field can be declared with, as numbered in {@code descriptor.proto}. */
    public enum Type {
        /** {@code double}: fixed64 on the wire. */
        DOUBLE,
        /** {@code float}: fixed32 on the wire. */
        FLOAT,
        /** {@code int64}: varint. */
        INT64,
        /** {@code uint64}: varint. */
        UINT64,
        /** {@code int32}: varint (negative values take ten bytes). */
        INT32,
        /** {@code fixed64}. */
        FIXED64,
        /** {@code fixed32}. */
        FIXED32,
        /** {@code bool}: varint. */
        BOOL,
        /** {@code string}: length-delimited UTF-8. */
        STRING,
        /** A proto2 group. */
        GROUP,
        /** A nested message: length-delimited. */
        MESSAGE,
        /** {@code bytes}: length-delimited. */
        BYTES,
        /** {@code uint32}: varint. */
        UINT32,
        /** An enum: varint. */
        ENUM,
        /** {@code sfixed32}. */
        SFIXED32,
        /** {@code sfixed64}. */
        SFIXED64,
        /** {@code sint32}: zigzag varint. */
        SINT32,
        /** {@code sint64}: zigzag varint. */
        SINT64;

        /** {@return the type's number in {@code FieldDescriptorProto.Type}} */
        public int number() {
            return ordinal() + 1;
        }

        /**
         * The type with {@code number} in {@code FieldDescriptorProto.Type}.
         *
         * @param number the type number, 1 to 18
         * @return the type, or empty for an unknown number
         */
        public static Optional<Type> of(int number) {
            Type[] all = values();
            return number >= 1 && number <= all.length ? Optional.of(all[number - 1]) : Optional.empty();
        }

        /** {@return the wire type values of this type are encoded with (unpacked)} */
        public int wireType() {
            return switch (this) {
                case DOUBLE, FIXED64, SFIXED64 -> ProtoValue.WIRE_FIXED64;
                case FLOAT, FIXED32, SFIXED32 -> ProtoValue.WIRE_FIXED32;
                case STRING, MESSAGE, BYTES -> ProtoValue.WIRE_LEN;
                case GROUP -> ProtoValue.WIRE_START_GROUP;
                default -> ProtoValue.WIRE_VARINT;
            };
        }

        /** {@return whether repeated fields of this type can be packed} */
        public boolean packable() {
            return wireType() != ProtoValue.WIRE_LEN && this != GROUP;
        }
    }

    /**
     * A field of a message type.
     *
     * @param name the field's name
     * @param number the field number
     * @param type the declared type
     * @param repeated whether the field is repeated (or a map)
     * @param typeName the full name of the message or enum type (without a leading dot) for
     *     {@link Type#MESSAGE}, {@link Type#GROUP} and {@link Type#ENUM}; otherwise {@code null}
     * @param packed whether repeated values are encoded packed
     */
    public record Field(String name, int number, Type type, boolean repeated, String typeName, boolean packed) {
        /**
         * Checks the field.
         *
         * @param name the field's name
         * @param number the field number
         * @param type the declared type
         * @param repeated whether the field is repeated
         * @param typeName the referenced type's full name, or {@code null}
         * @param packed whether repeated values are packed
         */
        public Field {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(type, "type");
        }
    }

    /** A message type: its full name and fields. */
    public static final class MessageType {
        private final String fullName;
        private final List<Field> fields;
        private final boolean mapEntry;
        private final Map<Integer, Field> byNumber = new LinkedHashMap<>();
        private final Map<String, Field> byName = new LinkedHashMap<>();
        private final Map<Integer, EnumType> enums;

        MessageType(String fullName, List<Field> fields, boolean mapEntry, Map<Integer, EnumType> enums) {
            this.fullName = fullName;
            this.fields = List.copyOf(fields);
            this.mapEntry = mapEntry;
            this.enums = Map.copyOf(enums);
            for (Field f : this.fields) {
                byNumber.putIfAbsent(f.number(), f);
                byName.putIfAbsent(f.name(), f);
            }
        }

        /** {@return the full name, such as {@code example.Order.Item}} */
        public String fullName() {
            return fullName;
        }

        /** {@return the fields, in declaration order} */
        public List<Field> fields() {
            return fields;
        }

        /**
         * The field with {@code number}.
         *
         * @param number the field number
         * @return the field, or {@code null} if the type declares none
         */
        public Field field(int number) {
            return byNumber.get(number);
        }

        /**
         * The field named {@code name}.
         *
         * @param name the field name
         * @return the field, or {@code null} if the type declares none
         */
        public Field field(String name) {
            return byName.get(name);
        }

        /**
         * The enum type of an enum field.
         *
         * @param number the field number
         * @return the enum type, or empty if the field is not an enum or its type is unknown
         */
        public Optional<EnumType> enumType(int number) {
            return Optional.ofNullable(enums.get(number));
        }

        /** {@return whether this is the entry type of a map field ({@code key} = 1, {@code value} = 2)} */
        public boolean mapEntry() {
            return mapEntry;
        }

        @Override
        public String toString() {
            return "MessageType[" + fullName + "]";
        }
    }

    /**
     * An enum type.
     *
     * @param fullName the full name
     * @param values the value names by number (the first name of aliased numbers)
     */
    public record EnumType(String fullName, Map<Integer, String> values) {
        /**
         * Copies the values.
         *
         * @param fullName the full name
         * @param values the value names by number
         */
        public EnumType {
            values = Collections.unmodifiableMap(new LinkedHashMap<>(values));
        }

        /**
         * The number of the value named {@code name}.
         *
         * @param name a value name
         * @return its number, or empty if there is no such value
         */
        public Optional<Integer> number(String name) {
            for (Map.Entry<Integer, String> e : values.entrySet()) {
                if (e.getValue().equals(name)) return Optional.of(e.getKey());
            }
            return Optional.empty();
        }
    }

    /**
     * An RPC method of a service.
     *
     * @param service the service's full name, such as {@code example.Shop}
     * @param name the method's name
     * @param inputType the request message type's full name
     * @param outputType the response message type's full name
     * @param clientStreaming whether the client sends a stream of messages
     * @param serverStreaming whether the server sends a stream of messages
     */
    public record Method(String service, String name, String inputType, String outputType,
            boolean clientStreaming, boolean serverStreaming) {

        /** {@return the gRPC request path, {@code /<service>/<method>}} */
        public String path() {
            return "/" + service + "/" + name;
        }
    }

    private static final ProtoSchema WELL_KNOWN = wellKnown();

    private final Map<String, MessageType> messages;
    private final Map<String, EnumType> enums;
    private final Map<String, Method> methods;

    private ProtoSchema(Map<String, MessageType> messages, Map<String, EnumType> enums, Map<String, Method> methods) {
        this.messages = Collections.unmodifiableMap(messages);
        this.enums = Collections.unmodifiableMap(enums);
        this.methods = Collections.unmodifiableMap(methods);
    }

    /** {@return a schema with only the well-known types} */
    public static ProtoSchema empty() {
        return WELL_KNOWN;
    }

    /**
     * Reads a {@code FileDescriptorSet} file, as {@code protoc --descriptor_set_out} writes it.
     *
     * @param file the descriptor set
     * @return the schema
     * @throws IOException if the file cannot be read, or is not a valid descriptor set
     */
    public static ProtoSchema load(Path file) throws IOException {
        try {
            return parse(Files.readAllBytes(file));
        } catch (DecodeException e) {
            throw new IOException(file + ": " + e.getMessage(), e);
        }
    }

    /**
     * Parses a serialized {@code FileDescriptorSet}.
     *
     * @param fileDescriptorSet the descriptor set's bytes
     * @return the schema, which also knows the well-known types
     * @throws DecodeException if the bytes are not a valid descriptor set
     */
    public static ProtoSchema parse(byte[] fileDescriptorSet) throws DecodeException {
        Parser parser = new Parser();
        for (ProtoWire.Raw file : ProtoWire.read(fileDescriptorSet, 0, fileDescriptorSet.length, false, 0)) {
            if (file.number() == 1 && file.wireType() == ProtoValue.WIRE_LEN) parser.file(sub(file));
        }
        return WELL_KNOWN.merge(parser.build());
    }

    /**
     * This schema with the definitions of {@code other} added; where both define a name, {@code
     * other}'s definition wins.
     *
     * @param other the schema to add
     * @return the combined schema
     */
    public ProtoSchema merge(ProtoSchema other) {
        Map<String, MessageType> m = new LinkedHashMap<>(messages);
        m.putAll(other.messages);
        Map<String, EnumType> e = new LinkedHashMap<>(enums);
        e.putAll(other.enums);
        Map<String, Method> s = new LinkedHashMap<>(methods);
        s.putAll(other.methods);
        return new ProtoSchema(m, e, s);
    }

    /**
     * The message type named {@code fullName}.
     *
     * @param fullName the full name, with or without a leading dot
     * @return the type, or empty if the schema has none
     */
    public Optional<MessageType> message(String fullName) {
        return Optional.ofNullable(fullName == null ? null : messages.get(strip(fullName)));
    }

    /**
     * The enum type named {@code fullName}.
     *
     * @param fullName the full name, with or without a leading dot
     * @return the type, or empty if the schema has none
     */
    public Optional<EnumType> enumType(String fullName) {
        return Optional.ofNullable(fullName == null ? null : enums.get(strip(fullName)));
    }

    /**
     * The RPC method a gRPC request path names.
     *
     * @param path the request path, {@code /<package>.<Service>/<Method>}
     * @return the method, or empty if the schema has none
     */
    public Optional<Method> method(String path) {
        if (path == null) return Optional.empty();
        int q = path.indexOf('?');
        String p = q >= 0 ? path.substring(0, q) : path;
        return Optional.ofNullable(methods.get(p.startsWith("/") ? p : "/" + p));
    }

    /**
     * The message type of a gRPC call's requests or responses.
     *
     * @param path the request path, {@code /<package>.<Service>/<Method>}
     * @param request whether the messages are requests (the method's input type) or responses
     * @return the type, or empty if the schema does not know the method or its types
     */
    public Optional<MessageType> messageFor(String path, boolean request) {
        return method(path).flatMap(m -> message(request ? m.inputType() : m.outputType()));
    }

    /** {@return the message types, by full name} */
    public Map<String, MessageType> messages() {
        return messages;
    }

    /** {@return the enum types, by full name} */
    public Map<String, EnumType> enums() {
        return enums;
    }

    /** {@return the RPC methods, by request path} */
    public Collection<Method> methods() {
        return methods.values();
    }

    @Override
    public String toString() {
        return "ProtoSchema[" + messages.size() + " messages, " + enums.size() + " enums, "
                + methods.size() + " methods]";
    }

    private static String strip(String name) {
        return name.startsWith(".") ? name.substring(1) : name;
    }

    // ---------------------------------------------------------------------------------------
    // Reading descriptor.proto messages
    // ---------------------------------------------------------------------------------------

    private static List<ProtoWire.Raw> sub(ProtoWire.Raw raw) throws DecodeException {
        return ProtoWire.read(raw.data(), raw.offset(), raw.offset() + raw.length(), false, 0);
    }

    private static String string(ProtoWire.Raw raw) {
        return new String(raw.data(), raw.offset(), raw.length(), StandardCharsets.UTF_8);
    }

    /** The last string in field {@code number}, or {@code fallback}. */
    private static String string(List<ProtoWire.Raw> fields, int number, String fallback) {
        String value = fallback;
        for (ProtoWire.Raw f : fields) {
            if (f.number() == number && f.wireType() == ProtoValue.WIRE_LEN) value = string(f);
        }
        return value;
    }

    /** The last varint in field {@code number}, or {@code fallback}. */
    private static long varint(List<ProtoWire.Raw> fields, int number, long fallback) {
        long value = fallback;
        for (ProtoWire.Raw f : fields) {
            if (f.number() == number && f.wireType() == ProtoValue.WIRE_VARINT) value = f.bits();
        }
        return value;
    }

    private static List<List<ProtoWire.Raw>> messages(List<ProtoWire.Raw> fields, int number) throws DecodeException {
        List<List<ProtoWire.Raw>> out = new ArrayList<>();
        for (ProtoWire.Raw f : fields) {
            if (f.number() == number && f.wireType() == ProtoValue.WIRE_LEN) out.add(sub(f));
        }
        return out;
    }

    /** A field before its type name is resolved. */
    private record PendingField(String scope, String name, int number, int type, boolean repeated, String typeName,
            Boolean packedOption, boolean proto3) {}

    private record PendingMessage(String fullName, List<PendingField> fields, boolean mapEntry) {}

    /** Collects the definitions of a descriptor set's files, then resolves type names. */
    private static final class Parser {
        private final List<PendingMessage> messages = new ArrayList<>();
        private final Map<String, EnumType> enums = new LinkedHashMap<>();
        private final Map<String, Method> methods = new LinkedHashMap<>();
        private final List<String[]> pendingMethods = new ArrayList<>();

        void file(List<ProtoWire.Raw> file) throws DecodeException {
            String pkg = string(file, 2, "");
            String syntax = string(file, 12, "proto2");
            boolean packedByDefault = !syntax.equals("proto2");
            for (List<ProtoWire.Raw> m : messages(file, 4)) message(pkg, m, packedByDefault);
            for (List<ProtoWire.Raw> e : messages(file, 5)) enumType(pkg, e);
            for (List<ProtoWire.Raw> s : messages(file, 6)) {
                String service = qualify(pkg, string(s, 1, ""));
                for (List<ProtoWire.Raw> m : messages(s, 2)) {
                    pendingMethods.add(new String[] {
                        service, string(m, 1, ""), pkg, string(m, 2, ""), string(m, 3, ""),
                        String.valueOf(varint(m, 5, 0) != 0), String.valueOf(varint(m, 6, 0) != 0)});
                }
            }
        }

        private void message(String scope, List<ProtoWire.Raw> m, boolean packedByDefault) throws DecodeException {
            String fullName = qualify(scope, string(m, 1, ""));
            List<PendingField> fields = new ArrayList<>();
            for (List<ProtoWire.Raw> f : messages(m, 2)) {
                Boolean packed = null;
                for (List<ProtoWire.Raw> options : messages(f, 8)) {
                    for (ProtoWire.Raw o : options) {
                        if (o.number() == 2 && o.wireType() == ProtoValue.WIRE_VARINT) packed = o.bits() != 0;
                    }
                }
                fields.add(new PendingField(fullName, string(f, 1, ""), (int) varint(f, 3, 0), (int) varint(f, 5, 0),
                        varint(f, 4, 1) == 3, string(f, 6, null), packed, packedByDefault));
            }
            boolean mapEntry = false;
            for (List<ProtoWire.Raw> options : messages(m, 7)) mapEntry |= varint(options, 7, 0) != 0;
            messages.add(new PendingMessage(fullName, fields, mapEntry));
            for (List<ProtoWire.Raw> nested : messages(m, 3)) message(fullName, nested, packedByDefault);
            for (List<ProtoWire.Raw> e : messages(m, 4)) enumType(fullName, e);
        }

        private void enumType(String scope, List<ProtoWire.Raw> e) throws DecodeException {
            String fullName = qualify(scope, string(e, 1, ""));
            Map<Integer, String> values = new LinkedHashMap<>();
            for (List<ProtoWire.Raw> v : messages(e, 2)) values.putIfAbsent((int) varint(v, 2, 0), string(v, 1, ""));
            enums.put(fullName, new EnumType(fullName, values));
        }

        ProtoSchema build() {
            Map<String, PendingMessage> byName = new LinkedHashMap<>();
            for (PendingMessage m : messages) byName.put(m.fullName(), m);
            Map<String, MessageType> types = new LinkedHashMap<>();
            for (PendingMessage m : messages) {
                List<Field> fields = new ArrayList<>();
                Map<Integer, EnumType> enumTypes = new LinkedHashMap<>();
                for (PendingField f : m.fields()) {
                    String typeName = null;
                    Type type = Type.of(f.type()).orElse(null);
                    if (f.typeName() != null && !f.typeName().isEmpty()) {
                        typeName = resolve(f.scope(), f.typeName(), byName.keySet(), enums.keySet());
                        if (type == null) {
                            // Unresolved descriptors leave the type out; the name says what it is.
                            type = enums.containsKey(typeName) ? Type.ENUM : Type.MESSAGE;
                        }
                    }
                    if (type == null || f.number() < 1 || f.number() > Protobuf.MAX_FIELD_NUMBER) continue;
                    boolean packed = f.repeated() && type.packable()
                            && (f.packedOption() != null ? f.packedOption() : f.proto3());
                    fields.add(new Field(f.name(), f.number(), type, f.repeated(), typeName, packed));
                    if (type == Type.ENUM && enums.containsKey(typeName)) enumTypes.put(f.number(), enums.get(typeName));
                }
                types.put(m.fullName(), new MessageType(m.fullName(), fields, m.mapEntry(), enumTypes));
            }
            for (String[] pm : pendingMethods) {
                Method method = new Method(pm[0], pm[1],
                        resolve(pm[2], pm[3], byName.keySet(), enums.keySet()),
                        resolve(pm[2], pm[4], byName.keySet(), enums.keySet()),
                        Boolean.parseBoolean(pm[5]), Boolean.parseBoolean(pm[6]));
                methods.put(method.path(), method);
            }
            return new ProtoSchema(types, enums, methods);
        }
    }

    private static String qualify(String scope, String name) {
        return scope.isEmpty() ? name : scope + "." + name;
    }

    /**
     * Resolves a type name as protoc does: a name with a leading dot is fully qualified; others
     * are looked up from the innermost enclosing scope outwards.
     */
    private static String resolve(String scope, String name, Collection<String> messages, Collection<String> enums) {
        if (name.startsWith(".")) return name.substring(1);
        String s = scope;
        while (true) {
            String candidate = qualify(s, name);
            if (messages.contains(candidate) || enums.contains(candidate) || WELL_KNOWN != null
                    && (WELL_KNOWN.messages.containsKey(candidate) || WELL_KNOWN.enums.containsKey(candidate))) {
                return candidate;
            }
            if (s.isEmpty()) return name;
            int dot = s.lastIndexOf('.');
            s = dot < 0 ? "" : s.substring(0, dot);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Well-known types
    // ---------------------------------------------------------------------------------------

    private static ProtoSchema wellKnown() {
        Map<String, MessageType> types = new LinkedHashMap<>();
        define(types, "google.protobuf.Any", false, "string type_url = 1; bytes value = 2");
        define(types, "google.protobuf.Duration", false, "int64 seconds = 1; int32 nanos = 2");
        define(types, "google.protobuf.Timestamp", false, "int64 seconds = 1; int32 nanos = 2");
        define(types, "google.rpc.Status", false,
                "int32 code = 1; string message = 2; repeated google.protobuf.Any details = 3");
        define(types, "google.rpc.ErrorInfo", false,
                "string reason = 1; string domain = 2; repeated google.rpc.ErrorInfo.MetadataEntry metadata = 3");
        define(types, "google.rpc.ErrorInfo.MetadataEntry", true, "string key = 1; string value = 2");
        define(types, "google.rpc.RetryInfo", false, "google.protobuf.Duration retry_delay = 1");
        define(types, "google.rpc.DebugInfo", false, "repeated string stack_entries = 1; string detail = 2");
        define(types, "google.rpc.QuotaFailure", false, "repeated google.rpc.QuotaFailure.Violation violations = 1");
        define(types, "google.rpc.QuotaFailure.Violation", false, "string subject = 1; string description = 2");
        define(types, "google.rpc.PreconditionFailure", false,
                "repeated google.rpc.PreconditionFailure.Violation violations = 1");
        define(types, "google.rpc.PreconditionFailure.Violation", false,
                "string type = 1; string subject = 2; string description = 3");
        define(types, "google.rpc.BadRequest", false,
                "repeated google.rpc.BadRequest.FieldViolation field_violations = 1");
        define(types, "google.rpc.BadRequest.FieldViolation", false,
                "string field = 1; string description = 2; string reason = 3;"
                        + " google.rpc.LocalizedMessage localized_message = 4");
        define(types, "google.rpc.RequestInfo", false, "string request_id = 1; string serving_data = 2");
        define(types, "google.rpc.ResourceInfo", false,
                "string resource_type = 1; string resource_name = 2; string owner = 3; string description = 4");
        define(types, "google.rpc.Help", false, "repeated google.rpc.Help.Link links = 1");
        define(types, "google.rpc.Help.Link", false, "string description = 1; string url = 2");
        define(types, "google.rpc.LocalizedMessage", false, "string locale = 1; string message = 2");
        return new ProtoSchema(types, new LinkedHashMap<>(), new LinkedHashMap<>());
    }

    /** Defines a message from {@code [repeated] <type> <name> = <number>} declarations. */
    private static void define(Map<String, MessageType> types, String fullName, boolean mapEntry, String declarations) {
        List<Field> fields = new ArrayList<>();
        for (String declaration : declarations.split(";")) {
            String[] words = declaration.strip().split("\\s+");
            boolean repeated = words[0].equals("repeated");
            int i = repeated ? 1 : 0;
            String typeWord = words[i];
            Type type;
            String typeName = null;
            try {
                type = Type.valueOf(typeWord.toUpperCase(java.util.Locale.ROOT));
            } catch (IllegalArgumentException e) {
                type = Type.MESSAGE;
                typeName = typeWord;
            }
            fields.add(new Field(words[i + 1], Integer.parseInt(words[i + 3]), type, repeated, typeName, false));
        }
        types.put(fullName, new MessageType(fullName, fields, mapEntry, Map.of()));
    }
}
