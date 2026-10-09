package io.github.mahmoudimus.http3;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The SETTINGS parameters of one endpoint (RFC 9114 §7.2.4). Immutable; the constructor and
 * {@link Builder#build()} reject values the protocol does not allow with
 * {@link IllegalArgumentException}, and {@link #fromFrame(Http3Frame.Settings)} rejects a peer's
 * invalid values with the {@link Http3Exception} the protocol requires.
 *
 * <p>Unlike HTTP/2, each endpoint sends SETTINGS exactly once, as the first frame of its control
 * stream, and nothing acknowledges it. {@link #DEFAULT} holds the initial values, which apply until
 * the peer's SETTINGS arrive.
 *
 * @param qpackMaxTableCapacity SETTINGS_QPACK_MAX_TABLE_CAPACITY (RFC 9204 §5): the largest QPACK
 *     dynamic table the sender's decoder accepts; 0 means static-table-only QPACK
 * @param maxFieldSectionSize SETTINGS_MAX_FIELD_SECTION_SIZE: the largest field section the sender
 *     accepts, counting name + value + 32 per field, or {@link #UNLIMITED}
 * @param qpackBlockedStreams SETTINGS_QPACK_BLOCKED_STREAMS (RFC 9204 §5): how many streams may be
 *     blocked on dynamic table updates at once
 * @param enableConnectProtocol SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220): the sender accepts
 *     extended CONNECT requests (with {@code :protocol})
 * @param h3Datagram SETTINGS_H3_DATAGRAM (RFC 9297): the sender accepts HTTP Datagrams
 * @param extensions settings with any other identifier (extensions, and the reserved 0x1f * N +
 *     0x21 used for greasing) in the order received; they have no effect here and are kept so they
 *     can be relayed
 */
public record Http3Settings(
        long qpackMaxTableCapacity,
        long maxFieldSectionSize,
        long qpackBlockedStreams,
        boolean enableConnectProtocol,
        boolean h3Datagram,
        Map<Long, Long> extensions) {

    public static final long QPACK_MAX_TABLE_CAPACITY = 0x01;
    public static final long MAX_FIELD_SECTION_SIZE = 0x06;
    public static final long QPACK_BLOCKED_STREAMS = 0x07;
    public static final long ENABLE_CONNECT_PROTOCOL = 0x08;
    public static final long H3_DATAGRAM = 0x33;

    /** No limit: the initial value of MAX_FIELD_SECTION_SIZE. */
    public static final long UNLIMITED = Long.MAX_VALUE;

    /** The initial values, in force until the peer's SETTINGS frame arrives. */
    public static final Http3Settings DEFAULT = new Http3Settings(0, UNLIMITED, 0, false, false, Map.of());

    public Http3Settings {
        checkValue(qpackMaxTableCapacity, "qpackMaxTableCapacity");
        if (maxFieldSectionSize != UNLIMITED) checkValue(maxFieldSectionSize, "maxFieldSectionSize");
        checkValue(qpackBlockedStreams, "qpackBlockedStreams");
        Objects.requireNonNull(extensions, "extensions");
        for (Map.Entry<Long, Long> e : extensions.entrySet()) {
            long id = e.getKey();
            checkValue(id, "setting identifier");
            checkValue(e.getValue(), "setting value");
            if (isDefined(id) || isHttp2Reserved(id)) {
                throw new IllegalArgumentException("not an extension setting: 0x" + Long.toHexString(id));
            }
        }
        extensions = Collections.unmodifiableMap(new LinkedHashMap<>(extensions));
    }

    public static Builder builder() {
        return new Builder(DEFAULT);
    }

    public Builder toBuilder() {
        return new Builder(this);
    }

    /**
     * Whether {@code id} is an HTTP/2 setting with no HTTP/3 counterpart (0x00, 0x02, 0x03, 0x04 and
     * 0x05), which must not be sent; receiving one is a connection error H3_SETTINGS_ERROR
     * (RFC 9114 §7.2.4.1).
     */
    public static boolean isHttp2Reserved(long id) {
        return id == 0x00 || id == 0x02 || id == 0x03 || id == 0x04 || id == 0x05;
    }

    /** Whether {@code id} is one of the settings this class has a component for. */
    public static boolean isDefined(long id) {
        return id == QPACK_MAX_TABLE_CAPACITY || id == MAX_FIELD_SECTION_SIZE || id == QPACK_BLOCKED_STREAMS
                || id == ENABLE_CONNECT_PROTOCOL || id == H3_DATAGRAM;
    }

    /**
     * Checks one received setting. Unknown identifiers are accepted, since they must be ignored.
     *
     * @throws Http3Exception a connection error H3_SETTINGS_ERROR for an HTTP/2-only identifier, or
     *     for ENABLE_CONNECT_PROTOCOL or H3_DATAGRAM other than 0 or 1
     */
    public static void validate(long id, long value) throws Http3Exception {
        if (isHttp2Reserved(id)) {
            throw settingsError("HTTP/2 setting 0x" + Long.toHexString(id) + " is reserved in HTTP/3");
        }
        if ((id == ENABLE_CONNECT_PROTOCOL || id == H3_DATAGRAM) && value != 0 && value != 1) {
            String name = id == H3_DATAGRAM ? "SETTINGS_H3_DATAGRAM" : "SETTINGS_ENABLE_CONNECT_PROTOCOL";
            throw settingsError(name + " must be 0 or 1, got " + value);
        }
    }

    /** The settings a peer's SETTINGS frame establishes: its values on top of the defaults. */
    public static Http3Settings fromFrame(Http3Frame.Settings frame) throws Http3Exception {
        Builder b = builder();
        for (Map.Entry<Long, Long> e : frame.values().entrySet()) {
            long id = e.getKey();
            long v = e.getValue();
            validate(id, v);
            if (id == QPACK_MAX_TABLE_CAPACITY) b.qpackMaxTableCapacity = v;
            else if (id == MAX_FIELD_SECTION_SIZE) b.maxFieldSectionSize = v;
            else if (id == QPACK_BLOCKED_STREAMS) b.qpackBlockedStreams = v;
            else if (id == ENABLE_CONNECT_PROTOCOL) b.enableConnectProtocol = v == 1;
            else if (id == H3_DATAGRAM) b.h3Datagram = v == 1;
            else b.extensions.put(id, v);
        }
        return b.build();
    }

    /**
     * The values that differ from the defaults, in identifier order, followed by the extensions:
     * what the SETTINGS frame must carry.
     */
    public Map<Long, Long> values() {
        Map<Long, Long> m = new LinkedHashMap<>();
        if (qpackMaxTableCapacity != DEFAULT.qpackMaxTableCapacity) m.put(QPACK_MAX_TABLE_CAPACITY, qpackMaxTableCapacity);
        if (maxFieldSectionSize != DEFAULT.maxFieldSectionSize) m.put(MAX_FIELD_SECTION_SIZE, maxFieldSectionSize);
        if (qpackBlockedStreams != DEFAULT.qpackBlockedStreams) m.put(QPACK_BLOCKED_STREAMS, qpackBlockedStreams);
        if (enableConnectProtocol) m.put(ENABLE_CONNECT_PROTOCOL, 1L);
        if (h3Datagram) m.put(H3_DATAGRAM, 1L);
        m.putAll(extensions);
        return m;
    }

    /** A SETTINGS frame carrying {@link #values()}. */
    public Http3Frame.Settings toFrame() {
        return new Http3Frame.Settings(values());
    }

    private static Http3Exception settingsError(String message) {
        return Http3Exception.connectionError(Http3ErrorCode.H3_SETTINGS_ERROR, message);
    }

    private static void checkValue(long v, String what) {
        if (v < 0 || v > QuicVarInt.MAX_VALUE) throw new IllegalArgumentException(what + " out of range 0 to 2^62-1: " + v);
    }

    /** Builds {@link Http3Settings}, starting from the defaults. */
    public static final class Builder {
        private long qpackMaxTableCapacity;
        private long maxFieldSectionSize;
        private long qpackBlockedStreams;
        private boolean enableConnectProtocol;
        private boolean h3Datagram;
        private final Map<Long, Long> extensions;

        private Builder(Http3Settings s) {
            qpackMaxTableCapacity = s.qpackMaxTableCapacity;
            maxFieldSectionSize = s.maxFieldSectionSize;
            qpackBlockedStreams = s.qpackBlockedStreams;
            enableConnectProtocol = s.enableConnectProtocol;
            h3Datagram = s.h3Datagram;
            extensions = new LinkedHashMap<>(s.extensions);
        }

        public Builder qpackMaxTableCapacity(long v) {
            qpackMaxTableCapacity = v;
            return this;
        }

        public Builder maxFieldSectionSize(long v) {
            maxFieldSectionSize = v;
            return this;
        }

        public Builder qpackBlockedStreams(long v) {
            qpackBlockedStreams = v;
            return this;
        }

        public Builder enableConnectProtocol(boolean v) {
            enableConnectProtocol = v;
            return this;
        }

        public Builder h3Datagram(boolean v) {
            h3Datagram = v;
            return this;
        }

        /** Adds an extension or reserved setting, sent after the defined ones. */
        public Builder extension(long id, long value) {
            extensions.put(id, value);
            return this;
        }

        /** Adds the reserved (greasing) setting 0x1f * n + 0x21 with the given value. */
        public Builder grease(long n, long value) {
            return extension(Http3FrameType.reserved(n), value);
        }

        public Http3Settings build() {
            return new Http3Settings(
                    qpackMaxTableCapacity, maxFieldSectionSize, qpackBlockedStreams, enableConnectProtocol, h3Datagram, extensions);
        }
    }
}
