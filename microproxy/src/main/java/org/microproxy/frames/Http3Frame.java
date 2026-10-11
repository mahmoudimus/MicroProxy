package org.microproxy.frames;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * An HTTP/3 frame (RFC 9114 section 7.2) as a {@link FrameInterceptor} sees it, decoded, with
 * header sections as field lists ({@link Field}) decoded through QPACK. HTTP/3 frames carry no
 * stream id or flags: the QUIC stream they travel on says which stream, and its end ends the
 * message; {@link FrameContext#streamId()} names the stream.
 *
 * <p>The proxy does not terminate QUIC, so it never sees live HTTP/3 traffic: these frames come
 * from an {@link Http3FramePipeline}, which runs an interceptor over the bytes of HTTP/3 streams.
 * Records are immutable apart from their byte arrays, which are not copied; edit a frame with its
 * {@code with...} methods.
 */
public sealed interface Http3Frame extends HttpFrame
        permits Http3Frame.Data,
                Http3Frame.Headers,
                Http3Frame.CancelPush,
                Http3Frame.Settings,
                Http3Frame.PushPromise,
                Http3Frame.GoAway,
                Http3Frame.MaxPushId,
                Http3Frame.Unknown {

    /** The type code of DATA. */
    long TYPE_DATA = 0x00;
    /** The type code of HEADERS. */
    long TYPE_HEADERS = 0x01;
    /** The type code of CANCEL_PUSH. */
    long TYPE_CANCEL_PUSH = 0x03;
    /** The type code of SETTINGS. */
    long TYPE_SETTINGS = 0x04;
    /** The type code of PUSH_PROMISE. */
    long TYPE_PUSH_PROMISE = 0x05;
    /** The type code of GOAWAY. */
    long TYPE_GOAWAY = 0x07;
    /** The type code of MAX_PUSH_ID. */
    long TYPE_MAX_PUSH_ID = 0x0d;

    /** SETTINGS_QPACK_MAX_TABLE_CAPACITY (RFC 9204). */
    long SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01;
    /** SETTINGS_MAX_FIELD_SECTION_SIZE. */
    long SETTINGS_MAX_FIELD_SECTION_SIZE = 0x06;
    /** SETTINGS_QPACK_BLOCKED_STREAMS (RFC 9204). */
    long SETTINGS_QPACK_BLOCKED_STREAMS = 0x07;
    /** SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220). */
    long SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08;
    /** SETTINGS_H3_DATAGRAM (RFC 9297). */
    long SETTINGS_H3_DATAGRAM = 0x33;

    /** The largest variable-length integer, 2^62-1. */
    long MAX_VARINT = (1L << 62) - 1;

    @Override
    default FrameProtocol protocol() {
        return FrameProtocol.HTTP_3;
    }

    /**
     * A DATA frame to inject.
     *
     * @param data the content
     * @return the frame
     */
    static Data data(byte[] data) {
        return new Data(data);
    }

    /**
     * A HEADERS frame to inject.
     *
     * @param fields the field section, pseudo-headers first
     * @return the frame
     */
    static Headers headers(List<Field> fields) {
        return new Headers(fields);
    }

    /**
     * A frame of an extension type to inject; peers ignore types they do not know.
     *
     * @param type the type code, not one HTTP/3 defines or reserves for HTTP/2
     * @param payload the payload
     * @return the frame
     */
    static Unknown unknown(long type, byte[] payload) {
        return new Unknown(type, payload);
    }

    /**
     * The name of a setting without its {@code SETTINGS_} prefix, or its hexadecimal identifier for
     * another one.
     *
     * @param id the setting identifier
     * @return a name such as {@code QPACK_MAX_TABLE_CAPACITY}, or {@code 0x...}
     */
    static String settingName(long id) {
        if (id == SETTINGS_QPACK_MAX_TABLE_CAPACITY) return "QPACK_MAX_TABLE_CAPACITY";
        if (id == SETTINGS_MAX_FIELD_SECTION_SIZE) return "MAX_FIELD_SECTION_SIZE";
        if (id == SETTINGS_QPACK_BLOCKED_STREAMS) return "QPACK_BLOCKED_STREAMS";
        if (id == SETTINGS_ENABLE_CONNECT_PROTOCOL) return "ENABLE_CONNECT_PROTOCOL";
        if (id == SETTINGS_H3_DATAGRAM) return "H3_DATAGRAM";
        return "0x" + Long.toHexString(id);
    }

    /**
     * The identifier of a setting named as {@link #settingName(long)} names it (a {@code SETTINGS_}
     * prefix is allowed), or written as a number.
     *
     * @param name the setting's name or number
     * @return the identifier
     * @throws IllegalArgumentException for a name that is neither
     */
    static long settingId(String name) {
        String n = name.startsWith("SETTINGS_") ? name.substring("SETTINGS_".length()) : name;
        switch (n) {
            case "QPACK_MAX_TABLE_CAPACITY" -> {
                return SETTINGS_QPACK_MAX_TABLE_CAPACITY;
            }
            case "MAX_FIELD_SECTION_SIZE" -> {
                return SETTINGS_MAX_FIELD_SECTION_SIZE;
            }
            case "QPACK_BLOCKED_STREAMS" -> {
                return SETTINGS_QPACK_BLOCKED_STREAMS;
            }
            case "ENABLE_CONNECT_PROTOCOL" -> {
                return SETTINGS_ENABLE_CONNECT_PROTOCOL;
            }
            case "H3_DATAGRAM" -> {
                return SETTINGS_H3_DATAGRAM;
            }
            default -> {
                try {
                    long id = n.startsWith("0x") || n.startsWith("0X") ? Long.parseLong(n.substring(2), 16) : Long.parseLong(n);
                    if (id >= 0 && id <= MAX_VARINT) return id;
                } catch (NumberFormatException e) {
                    // reported below
                }
                throw new IllegalArgumentException("unknown HTTP/3 setting " + name);
            }
        }
    }

    private static void checkVarInt(long value, String what) {
        if (value < 0 || value > MAX_VARINT) throw new IllegalArgumentException(what + " out of range 0 to 2^62-1: " + value);
    }

    /**
     * DATA (section 7.2.1).
     *
     * @param data the content, not copied
     */
    record Data(byte[] data) implements Http3Frame {
        /**
         * Creates DATA.
         *
         * @param data the content, not copied
         */
        public Data {
            Objects.requireNonNull(data, "data");
        }

        @Override
        public String typeName() {
            return "DATA";
        }

        @Override
        public long typeCode() {
            return TYPE_DATA;
        }

        /**
         * The content as UTF-8 text (malformed sequences replaced).
         *
         * @return the decoded content
         */
        public String text() {
            return new String(data, StandardCharsets.UTF_8);
        }

        /**
         * This frame with other content.
         *
         * @param newData the new content
         * @return a copy with it
         */
        public Data withData(byte[] newData) {
            return new Data(newData);
        }

        /**
         * This frame with {@code text}, encoded as UTF-8, as its content.
         *
         * @param text the new content
         * @return a copy with the text
         */
        public Data withText(String text) {
            return new Data(text.getBytes(StandardCharsets.UTF_8));
        }

        /** Compares the content, not the array's identity. */
        @Override
        public boolean equals(Object o) {
            return o instanceof Data d && Arrays.equals(d.data, data);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(data);
        }

        @Override
        public String toString() {
            return "DATA[" + data.length + " bytes]";
        }
    }

    /**
     * HEADERS (section 7.2.2), with its field section decoded.
     *
     * @param fields the field section, pseudo-headers first
     */
    record Headers(List<Field> fields) implements Http3Frame {
        /**
         * Creates HEADERS.
         *
         * @param fields the field section, copied
         */
        public Headers {
            fields = List.copyOf(fields);
        }

        @Override
        public String typeName() {
            return "HEADERS";
        }

        @Override
        public long typeCode() {
            return TYPE_HEADERS;
        }

        /**
         * The first value of a field.
         *
         * @param name the field name, lower case
         * @return the value, or null if there is no such field
         */
        public String get(String name) {
            return Fields.get(fields, name);
        }

        /**
         * This frame with another field section.
         *
         * @param newFields the new fields
         * @return a copy with them
         */
        public Headers withFields(List<Field> newFields) {
            return new Headers(newFields);
        }

        /**
         * This frame with {@code name} set to {@code value}, as {@link
         * Http2Frame.Headers#withHeader(String, String)} does it.
         *
         * @param name the field name, lower case
         * @param value the value
         * @return a copy with the field set
         */
        public Headers withHeader(String name, String value) {
            return new Headers(Fields.set(fields, name, value));
        }

        /**
         * This frame without the fields named {@code name}.
         *
         * @param name the field name, lower case
         * @return a copy without them
         */
        public Headers withoutHeader(String name) {
            return new Headers(Fields.remove(fields, name));
        }
    }

    /**
     * CANCEL_PUSH (section 7.2.3), on the control stream.
     *
     * @param pushId the push
     */
    record CancelPush(long pushId) implements Http3Frame {
        /**
         * Creates CANCEL_PUSH.
         *
         * @param pushId the push, 0 to 2^62-1
         */
        public CancelPush {
            checkVarInt(pushId, "push ID");
        }

        @Override
        public String typeName() {
            return "CANCEL_PUSH";
        }

        @Override
        public long typeCode() {
            return TYPE_CANCEL_PUSH;
        }
    }

    /**
     * SETTINGS (section 7.2.4), the first frame of the control stream.
     *
     * @param values setting identifiers and their values
     */
    record Settings(Map<Long, Long> values) implements Http3Frame {
        /**
         * Creates SETTINGS.
         *
         * @param values setting identifiers and values, each 0 to 2^62-1, copied
         */
        public Settings {
            for (Map.Entry<Long, Long> e : values.entrySet()) {
                checkVarInt(Objects.requireNonNull(e.getKey(), "setting id"), "setting identifier");
                checkVarInt(Objects.requireNonNull(e.getValue(), "setting value"), "setting value");
            }
            values = Collections.unmodifiableMap(new LinkedHashMap<>(values));
        }

        @Override
        public String typeName() {
            return "SETTINGS";
        }

        @Override
        public long typeCode() {
            return TYPE_SETTINGS;
        }

        /**
         * A setting's value in this frame.
         *
         * @param id the setting identifier
         * @return the value, or null if the frame does not carry it
         */
        public Long get(long id) {
            return values.get(id);
        }

        /**
         * This frame with one setting set.
         *
         * @param id the setting identifier
         * @param value the value
         * @return a copy with the setting
         */
        public Settings withValue(long id, long value) {
            Map<Long, Long> m = new LinkedHashMap<>(values);
            m.put(id, value);
            return new Settings(m);
        }

        /**
         * This frame without one setting.
         *
         * @param id the setting identifier
         * @return a copy without it
         */
        public Settings withoutValue(long id) {
            Map<Long, Long> m = new LinkedHashMap<>(values);
            m.remove(id);
            return new Settings(m);
        }

        /**
         * This frame with other settings.
         *
         * @param newValues the settings
         * @return a copy with them
         */
        public Settings withValues(Map<Long, Long> newValues) {
            return new Settings(newValues);
        }
    }

    /**
     * PUSH_PROMISE (section 7.2.5), from a server on a request stream.
     *
     * @param pushId the push it promises
     * @param fields the promised request's field section
     */
    record PushPromise(long pushId, List<Field> fields) implements Http3Frame {
        /**
         * Creates PUSH_PROMISE.
         *
         * @param pushId the push, 0 to 2^62-1
         * @param fields the field section, copied
         */
        public PushPromise {
            checkVarInt(pushId, "push ID");
            fields = List.copyOf(fields);
        }

        @Override
        public String typeName() {
            return "PUSH_PROMISE";
        }

        @Override
        public long typeCode() {
            return TYPE_PUSH_PROMISE;
        }
    }

    /**
     * GOAWAY (section 7.2.6), on the control stream: from a server, the first client-initiated
     * request stream it will not process; from a client, a push id.
     *
     * @param id the stream or push id
     */
    record GoAway(long id) implements Http3Frame {
        /**
         * Creates GOAWAY.
         *
         * @param id the stream or push id, 0 to 2^62-1
         */
        public GoAway {
            checkVarInt(id, "GOAWAY identifier");
        }

        @Override
        public String typeName() {
            return "GOAWAY";
        }

        @Override
        public long typeCode() {
            return TYPE_GOAWAY;
        }
    }

    /**
     * MAX_PUSH_ID (section 7.2.7), from a client on the control stream.
     *
     * @param pushId the largest push id the server may use
     */
    record MaxPushId(long pushId) implements Http3Frame {
        /**
         * Creates MAX_PUSH_ID.
         *
         * @param pushId the push id, 0 to 2^62-1
         */
        public MaxPushId {
            checkVarInt(pushId, "push ID");
        }

        @Override
        public String typeName() {
            return "MAX_PUSH_ID";
        }

        @Override
        public long typeCode() {
            return TYPE_MAX_PUSH_ID;
        }
    }

    /**
     * A frame of an extension or reserved type, such as a grease frame (type {@code 0x1f * N +
     * 0x21}) or PRIORITY_UPDATE (RFC 9218).
     *
     * @param type the type code
     * @param payload the payload, not copied
     */
    record Unknown(long type, byte[] payload) implements Http3Frame {
        /**
         * Creates an extension frame.
         *
         * @param type the type code: 0 to 2^62-1, not a type HTTP/3 defines (0x00, 0x01, 0x03, 0x04,
         *     0x05, 0x07, 0x0d) or forbids as HTTP/2's (0x02, 0x06, 0x08, 0x09)
         * @param payload the payload, not copied
         */
        public Unknown {
            checkVarInt(type, "frame type");
            if (type <= 0x09 || type == TYPE_MAX_PUSH_ID) {
                throw new IllegalArgumentException("not an extension frame type: 0x" + Long.toHexString(type));
            }
            Objects.requireNonNull(payload, "payload");
        }

        @Override
        public String typeName() {
            return "UNKNOWN";
        }

        @Override
        public long typeCode() {
            return type;
        }

        /**
         * Whether the type is reserved for greasing ({@code 0x1f * N + 0x21}).
         *
         * @return whether the frame is grease
         */
        public boolean isReserved() {
            return type >= 0x21 && (type - 0x21) % 0x1f == 0;
        }

        /**
         * This frame with another payload.
         *
         * @param newPayload the new payload
         * @return a copy with it
         */
        public Unknown withPayload(byte[] newPayload) {
            return new Unknown(type, newPayload);
        }

        /** Compares the payload's content, not the array's identity. */
        @Override
        public boolean equals(Object o) {
            return o instanceof Unknown u && u.type == type && Arrays.equals(u.payload, payload);
        }

        @Override
        public int hashCode() {
            return Objects.hash(type, Arrays.hashCode(payload));
        }

        @Override
        public String toString() {
            return "UNKNOWN[type 0x" + Long.toHexString(type) + ", "
                    + HexFormat.of().formatHex(payload, 0, Math.min(payload.length, 16)) + (payload.length > 16 ? "...]" : "]");
        }
    }
}
