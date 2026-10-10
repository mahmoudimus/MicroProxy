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
 * An HTTP/2 frame (RFC 9113 section 6) as a {@link FrameInterceptor} sees it: decoded, with header
 * blocks as field lists ({@link Field}). CONTINUATION frames are folded into the HEADERS they
 * continue, padding is gone, and HPACK is the proxy's business: a header block is decoded once,
 * when it arrives, and encoded once, when it is sent, so edits never put the compression state of
 * either side out of step.
 *
 * <p>Records are immutable apart from their byte arrays, which are not copied. Edit a frame with its
 * {@code with...} methods and return the copy; build frames to inject with {@link #data}, {@link
 * #headers} and {@link #unknown}. Which edits the proxy accepts is described in {@link
 * FrameInterceptor}.
 */
public sealed interface Http2Frame extends HttpFrame
        permits Http2Frame.Data,
                Http2Frame.Headers,
                Http2Frame.Priority,
                Http2Frame.RstStream,
                Http2Frame.Settings,
                Http2Frame.PushPromise,
                Http2Frame.Ping,
                Http2Frame.GoAway,
                Http2Frame.WindowUpdate,
                Http2Frame.Unknown {

    /** The type code of DATA. */
    int TYPE_DATA = 0x0;
    /** The type code of HEADERS. */
    int TYPE_HEADERS = 0x1;
    /** The type code of PRIORITY. */
    int TYPE_PRIORITY = 0x2;
    /** The type code of RST_STREAM. */
    int TYPE_RST_STREAM = 0x3;
    /** The type code of SETTINGS. */
    int TYPE_SETTINGS = 0x4;
    /** The type code of PUSH_PROMISE. */
    int TYPE_PUSH_PROMISE = 0x5;
    /** The type code of PING. */
    int TYPE_PING = 0x6;
    /** The type code of GOAWAY. */
    int TYPE_GOAWAY = 0x7;
    /** The type code of WINDOW_UPDATE. */
    int TYPE_WINDOW_UPDATE = 0x8;
    /** The type code of CONTINUATION, which interceptors never see (it is folded into HEADERS). */
    int TYPE_CONTINUATION = 0x9;

    /** SETTINGS_HEADER_TABLE_SIZE. */
    int SETTINGS_HEADER_TABLE_SIZE = 0x1;
    /** SETTINGS_ENABLE_PUSH. */
    int SETTINGS_ENABLE_PUSH = 0x2;
    /** SETTINGS_MAX_CONCURRENT_STREAMS. */
    int SETTINGS_MAX_CONCURRENT_STREAMS = 0x3;
    /** SETTINGS_INITIAL_WINDOW_SIZE. */
    int SETTINGS_INITIAL_WINDOW_SIZE = 0x4;
    /** SETTINGS_MAX_FRAME_SIZE. */
    int SETTINGS_MAX_FRAME_SIZE = 0x5;
    /** SETTINGS_MAX_HEADER_LIST_SIZE. */
    int SETTINGS_MAX_HEADER_LIST_SIZE = 0x6;
    /** SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441). */
    int SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x8;

    /** The names of the error codes (RFC 9113 section 7), indexed by code. */
    List<String> ERROR_NAMES = List.of("NO_ERROR", "PROTOCOL_ERROR", "INTERNAL_ERROR", "FLOW_CONTROL_ERROR",
            "SETTINGS_TIMEOUT", "STREAM_CLOSED", "FRAME_SIZE_ERROR", "REFUSED_STREAM", "CANCEL", "COMPRESSION_ERROR",
            "CONNECT_ERROR", "ENHANCE_YOUR_CALM", "INADEQUATE_SECURITY", "HTTP_1_1_REQUIRED");

    /** The names of the settings this API names, indexed by identifier ({@code null} for none). */
    List<String> SETTING_NAMES = Collections.unmodifiableList(Arrays.asList(null, "HEADER_TABLE_SIZE", "ENABLE_PUSH",
            "MAX_CONCURRENT_STREAMS", "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE", "MAX_HEADER_LIST_SIZE", null,
            "ENABLE_CONNECT_PROTOCOL"));

    /**
     * The stream the frame belongs to, or 0 for the connection.
     *
     * @return the stream identifier
     */
    int streamId();

    @Override
    default FrameProtocol protocol() {
        return FrameProtocol.HTTP_2;
    }

    /**
     * A DATA frame to inject.
     *
     * @param streamId the stream
     * @param data the content
     * @param endStream whether it ends the stream
     * @return the frame
     */
    static Data data(int streamId, byte[] data, boolean endStream) {
        return new Data(streamId, data, endStream);
    }

    /**
     * A HEADERS frame to inject.
     *
     * @param streamId the stream
     * @param fields the header block, pseudo-headers first
     * @param endStream whether it ends the stream
     * @return the frame
     */
    static Headers headers(int streamId, List<Field> fields, boolean endStream) {
        return new Headers(streamId, fields, endStream);
    }

    /**
     * A frame of an extension type to inject; peers ignore types they do not know.
     *
     * @param type the type code, 10 to 255
     * @param flags the flags, 0 to 255
     * @param streamId the stream, or 0 for the connection
     * @param payload the payload
     * @return the frame
     */
    static Unknown unknown(int type, int flags, int streamId, byte[] payload) {
        return new Unknown(type, flags, streamId, payload);
    }

    /**
     * The name of an error code, or its hexadecimal value for an unknown one.
     *
     * @param code the unsigned 32-bit error code
     * @return a name such as {@code PROTOCOL_ERROR}, or {@code 0x...}
     */
    static String errorName(long code) {
        return code >= 0 && code < ERROR_NAMES.size() ? ERROR_NAMES.get((int) code) : "0x" + Long.toHexString(code);
    }

    /**
     * The name of a setting without its {@code SETTINGS_} prefix, or its hexadecimal identifier for
     * an extension one.
     *
     * @param id the setting identifier
     * @return a name such as {@code MAX_FRAME_SIZE}, or {@code 0x...}
     */
    static String settingName(int id) {
        String name = id >= 0 && id < SETTING_NAMES.size() ? SETTING_NAMES.get(id) : null;
        return name != null ? name : "0x" + Integer.toHexString(id);
    }

    /**
     * The identifier of a setting named as {@link #settingName(int)} names it (a {@code SETTINGS_}
     * prefix is allowed), or written as a number ({@code 0x10}, {@code 16}).
     *
     * @param name the setting's name or number
     * @return the identifier
     * @throws IllegalArgumentException for a name that is neither
     */
    static int settingId(String name) {
        String n = name.startsWith("SETTINGS_") ? name.substring("SETTINGS_".length()) : name;
        int i = SETTING_NAMES.indexOf(n);
        if (i > 0) return i;
        try {
            long id = n.startsWith("0x") || n.startsWith("0X") ? Long.parseLong(n.substring(2), 16) : Long.parseLong(n);
            if (id >= 0 && id <= 0xffff) return (int) id;
        } catch (NumberFormatException e) {
            // reported below
        }
        throw new IllegalArgumentException("unknown HTTP/2 setting " + name);
    }

    private static void requireStream(int streamId, String what) {
        if (streamId <= 0) throw new IllegalArgumentException(what + " needs a stream id from 1 to 2^31-1, got " + streamId);
    }

    private static void checkErrorCode(long code) {
        if (code < 0 || code > 0xffffffffL) throw new IllegalArgumentException("error code out of range: " + code);
    }

    /**
     * DATA (section 6.1). Interceptors see DATA frames of at most 16 KiB; padding is not shown (it
     * is counted for flow control, and the proxy never sends any).
     *
     * @param streamId the stream
     * @param data the content, not copied
     * @param endStream whether the frame ends the stream
     */
    record Data(int streamId, byte[] data, boolean endStream) implements Http2Frame {
        /**
         * Creates DATA.
         *
         * @param streamId the stream, 1 or more
         * @param data the content, not copied
         * @param endStream whether the frame ends the stream
         */
        public Data {
            requireStream(streamId, "DATA");
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
         * @return a copy with {@code newData}
         */
        public Data withData(byte[] newData) {
            return new Data(streamId, newData, endStream);
        }

        /**
         * This frame with {@code text}, encoded as UTF-8, as its content.
         *
         * @param text the new content
         * @return a copy with the text
         */
        public Data withText(String text) {
            return withData(text.getBytes(StandardCharsets.UTF_8));
        }

        /**
         * This frame with END_STREAM set or not (see {@link FrameInterceptor} for who decides).
         *
         * @param end whether the frame ends the stream
         * @return a copy with the flag
         */
        public Data withEndStream(boolean end) {
            return new Data(streamId, data, end);
        }

        /** Compares the content, not the array's identity. */
        @Override
        public boolean equals(Object o) {
            return o instanceof Data d && d.streamId == streamId && d.endStream == endStream && Arrays.equals(d.data, data);
        }

        @Override
        public int hashCode() {
            return Objects.hash(streamId, endStream, Arrays.hashCode(data));
        }

        @Override
        public String toString() {
            return "DATA[stream " + streamId + ", " + data.length + " bytes" + (endStream ? ", END_STREAM" : "") + "]";
        }
    }

    /**
     * HEADERS (section 6.2), with its whole decoded header block. The deprecated priority signal a
     * client may put in HEADERS is not shown.
     *
     * @param streamId the stream
     * @param fields the header block, pseudo-headers first
     * @param endStream whether the frame ends the stream
     */
    record Headers(int streamId, List<Field> fields, boolean endStream) implements Http2Frame {
        /**
         * Creates HEADERS.
         *
         * @param streamId the stream, 1 or more
         * @param fields the header block, copied
         * @param endStream whether the frame ends the stream
         */
        public Headers {
            requireStream(streamId, "HEADERS");
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
         * This frame with another header block.
         *
         * @param newFields the new header block
         * @return a copy with the fields
         */
        public Headers withFields(List<Field> newFields) {
            return new Headers(streamId, newFields, endStream);
        }

        /**
         * This frame with {@code name} set to {@code value}: the first field of that name gets the
         * value and later ones are removed; without one, the field is added (a pseudo-header after
         * the other pseudo-headers, a regular field at the end).
         *
         * @param name the field name, lower case
         * @param value the value
         * @return a copy with the field set
         */
        public Headers withHeader(String name, String value) {
            return withFields(Fields.set(fields, name, value));
        }

        /**
         * This frame without the fields named {@code name}.
         *
         * @param name the field name, lower case
         * @return a copy without them
         */
        public Headers withoutHeader(String name) {
            return withFields(Fields.remove(fields, name));
        }

        /**
         * This frame with END_STREAM set or not (see {@link FrameInterceptor} for who decides).
         *
         * @param end whether the frame ends the stream
         * @return a copy with the flag
         */
        public Headers withEndStream(boolean end) {
            return new Headers(streamId, fields, end);
        }
    }

    /**
     * PRIORITY (section 6.3), deprecated by RFC 9113; the proxy ignores it and never sends one.
     *
     * @param streamId the stream
     * @param streamDependency the stream it depends on, or 0
     * @param exclusive whether the dependency is exclusive
     * @param weight the weight, 1 to 256
     */
    record Priority(int streamId, int streamDependency, boolean exclusive, int weight) implements Http2Frame {
        /**
         * Creates PRIORITY.
         *
         * @param streamId the stream, 1 or more
         * @param streamDependency the stream it depends on, 0 or more
         * @param exclusive whether the dependency is exclusive
         * @param weight the weight, 1 to 256
         */
        public Priority {
            requireStream(streamId, "PRIORITY");
            if (streamDependency < 0) throw new IllegalArgumentException("bad stream dependency " + streamDependency);
            if (weight < 1 || weight > 256) throw new IllegalArgumentException("weight must be 1 to 256, got " + weight);
        }

        @Override
        public String typeName() {
            return "PRIORITY";
        }

        @Override
        public long typeCode() {
            return TYPE_PRIORITY;
        }
    }

    /**
     * RST_STREAM (section 6.4).
     *
     * @param streamId the stream
     * @param errorCode the unsigned 32-bit error code
     */
    record RstStream(int streamId, long errorCode) implements Http2Frame {
        /**
         * Creates RST_STREAM.
         *
         * @param streamId the stream, 1 or more
         * @param errorCode the error code, 0 to 2^32-1
         */
        public RstStream {
            requireStream(streamId, "RST_STREAM");
            checkErrorCode(errorCode);
        }

        @Override
        public String typeName() {
            return "RST_STREAM";
        }

        @Override
        public long typeCode() {
            return TYPE_RST_STREAM;
        }

        /**
         * The error code's name ({@link Http2Frame#errorName(long)}).
         *
         * @return the name
         */
        public String errorName() {
            return Http2Frame.errorName(errorCode);
        }

        /**
         * This frame with another error code.
         *
         * @param code the new error code
         * @return a copy with the code
         */
        public RstStream withErrorCode(long code) {
            return new RstStream(streamId, code);
        }
    }

    /**
     * SETTINGS (section 6.5): the identifiers and values the frame carries, in order. An
     * acknowledgement carries none.
     *
     * @param ack whether this acknowledges the peer's SETTINGS
     * @param values setting identifiers and their unsigned 32-bit values
     */
    record Settings(boolean ack, Map<Integer, Long> values) implements Http2Frame {
        /**
         * Creates SETTINGS.
         *
         * @param ack whether this acknowledges the peer's SETTINGS
         * @param values setting identifiers (0 to 65535) and values (0 to 2^32-1), copied; empty for an ACK
         */
        public Settings {
            for (Map.Entry<Integer, Long> e : values.entrySet()) {
                int id = Objects.requireNonNull(e.getKey(), "setting id");
                long v = Objects.requireNonNull(e.getValue(), "setting value");
                if (id < 0 || id > 0xffff) throw new IllegalArgumentException("setting id out of range: " + id);
                if (v < 0 || v > 0xffffffffL) throw new IllegalArgumentException("setting value out of range: " + v);
            }
            if (ack && !values.isEmpty()) throw new IllegalArgumentException("a SETTINGS ACK carries no values");
            values = Collections.unmodifiableMap(new LinkedHashMap<>(values));
        }

        @Override
        public int streamId() {
            return 0;
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
        public Long get(int id) {
            return values.get(id);
        }

        /**
         * This frame with one setting set.
         *
         * @param id the setting identifier
         * @param value the value
         * @return a copy with the setting
         */
        public Settings withValue(int id, long value) {
            Map<Integer, Long> m = new LinkedHashMap<>(values);
            m.put(id, value);
            return new Settings(ack, m);
        }

        /**
         * This frame without one setting.
         *
         * @param id the setting identifier
         * @return a copy without it
         */
        public Settings withoutValue(int id) {
            Map<Integer, Long> m = new LinkedHashMap<>(values);
            m.remove(id);
            return new Settings(ack, m);
        }

        /**
         * This frame with other settings.
         *
         * @param newValues the settings
         * @return a copy with them
         */
        public Settings withValues(Map<Integer, Long> newValues) {
            return new Settings(ack, newValues);
        }
    }

    /**
     * PUSH_PROMISE (section 6.6). The proxy disables server push, so this record exists for
     * completeness: interceptors are never shown one.
     *
     * @param streamId the stream the promise is made on
     * @param promisedStreamId the stream it reserves
     * @param fields the promised request's header block
     */
    record PushPromise(int streamId, int promisedStreamId, List<Field> fields) implements Http2Frame {
        /**
         * Creates PUSH_PROMISE.
         *
         * @param streamId the stream, 1 or more
         * @param promisedStreamId the promised stream, 1 or more
         * @param fields the header block, copied
         */
        public PushPromise {
            requireStream(streamId, "PUSH_PROMISE");
            requireStream(promisedStreamId, "PUSH_PROMISE promised stream");
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
     * PING (section 6.7); its 8 opaque octets as a big-endian long.
     *
     * @param ack whether this answers a PING
     * @param opaqueData the opaque data
     */
    record Ping(boolean ack, long opaqueData) implements Http2Frame {
        @Override
        public int streamId() {
            return 0;
        }

        @Override
        public String typeName() {
            return "PING";
        }

        @Override
        public long typeCode() {
            return TYPE_PING;
        }
    }

    /**
     * GOAWAY (section 6.8).
     *
     * @param lastStreamId the last stream the sender might have processed
     * @param errorCode the unsigned 32-bit error code
     * @param debugData the diagnostic data, not copied
     */
    record GoAway(int lastStreamId, long errorCode, byte[] debugData) implements Http2Frame {
        /**
         * Creates GOAWAY.
         *
         * @param lastStreamId the last stream the sender might have processed, 0 or more
         * @param errorCode the error code, 0 to 2^32-1
         * @param debugData the diagnostic data, not copied
         */
        public GoAway {
            if (lastStreamId < 0) throw new IllegalArgumentException("bad last stream id " + lastStreamId);
            checkErrorCode(errorCode);
            Objects.requireNonNull(debugData, "debugData");
        }

        @Override
        public int streamId() {
            return 0;
        }

        @Override
        public String typeName() {
            return "GOAWAY";
        }

        @Override
        public long typeCode() {
            return TYPE_GOAWAY;
        }

        /**
         * The error code's name ({@link Http2Frame#errorName(long)}).
         *
         * @return the name
         */
        public String errorName() {
            return Http2Frame.errorName(errorCode);
        }

        /**
         * The debug data as text (malformed UTF-8 replaced).
         *
         * @return the decoded debug data
         */
        public String debugText() {
            return new String(debugData, StandardCharsets.UTF_8);
        }

        /**
         * This frame with another error code.
         *
         * @param code the new error code
         * @return a copy with the code
         */
        public GoAway withErrorCode(long code) {
            return new GoAway(lastStreamId, code, debugData);
        }

        /**
         * This frame with other debug data.
         *
         * @param data the new debug data
         * @return a copy with it
         */
        public GoAway withDebugData(byte[] data) {
            return new GoAway(lastStreamId, errorCode, data);
        }

        /** Compares the debug data's content, not the array's identity. */
        @Override
        public boolean equals(Object o) {
            return o instanceof GoAway g && g.lastStreamId == lastStreamId && g.errorCode == errorCode
                    && Arrays.equals(g.debugData, debugData);
        }

        @Override
        public int hashCode() {
            return Objects.hash(lastStreamId, errorCode, Arrays.hashCode(debugData));
        }

        @Override
        public String toString() {
            return "GOAWAY[last stream " + lastStreamId + ", " + errorName() + ", " + debugData.length + " bytes of debug data]";
        }
    }

    /**
     * WINDOW_UPDATE (section 6.9), for a stream or the connection (stream 0).
     *
     * @param streamId the stream, or 0 for the connection
     * @param increment the credit, 1 to 2^31-1
     */
    record WindowUpdate(int streamId, int increment) implements Http2Frame {
        /**
         * Creates WINDOW_UPDATE.
         *
         * @param streamId the stream, or 0
         * @param increment the credit, 1 to 2^31-1
         */
        public WindowUpdate {
            if (streamId < 0) throw new IllegalArgumentException("bad stream id " + streamId);
            if (increment <= 0) throw new IllegalArgumentException("window increment must be 1 to 2^31-1, got " + increment);
        }

        @Override
        public String typeName() {
            return "WINDOW_UPDATE";
        }

        @Override
        public long typeCode() {
            return TYPE_WINDOW_UPDATE;
        }
    }

    /**
     * A frame of an extension type (section 5.5), such as ALTSVC (10) or PRIORITY_UPDATE (16).
     *
     * @param type the type code, 10 to 255
     * @param flags the flags, 0 to 255
     * @param streamId the stream, or 0 for the connection
     * @param payload the payload, not copied
     */
    record Unknown(int type, int flags, int streamId, byte[] payload) implements Http2Frame {
        /**
         * Creates an extension frame.
         *
         * @param type the type code, 10 to 255
         * @param flags the flags, 0 to 255
         * @param streamId the stream, or 0
         * @param payload the payload, not copied
         */
        public Unknown {
            if (type <= TYPE_CONTINUATION || type > 0xff) throw new IllegalArgumentException("not an extension frame type: " + type);
            if (flags < 0 || flags > 0xff) throw new IllegalArgumentException("bad flags " + flags);
            if (streamId < 0) throw new IllegalArgumentException("bad stream id " + streamId);
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
         * This frame with another payload.
         *
         * @param newPayload the new payload
         * @return a copy with it
         */
        public Unknown withPayload(byte[] newPayload) {
            return new Unknown(type, flags, streamId, newPayload);
        }

        /** Compares the payload's content, not the array's identity. */
        @Override
        public boolean equals(Object o) {
            return o instanceof Unknown u && u.type == type && u.flags == flags && u.streamId == streamId
                    && Arrays.equals(u.payload, payload);
        }

        @Override
        public int hashCode() {
            return Objects.hash(type, flags, streamId, Arrays.hashCode(payload));
        }

        @Override
        public String toString() {
            return "UNKNOWN[type 0x" + Integer.toHexString(type) + ", stream " + streamId + ", "
                    + HexFormat.of().formatHex(payload, 0, Math.min(payload.length, 16)) + (payload.length > 16 ? "...]" : "]");
        }
    }
}

