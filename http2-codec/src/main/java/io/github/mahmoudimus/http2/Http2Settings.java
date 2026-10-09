package io.github.mahmoudimus.http2;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The SETTINGS parameters of one endpoint (RFC 9113 §6.5.2). Immutable; the constructor and
 * {@link Builder#build()} reject values the protocol does not allow with
 * {@link IllegalArgumentException}, and {@link #apply(Frame.Settings)} rejects a peer's invalid
 * values with the {@link Http2Exception} the protocol requires.
 *
 * <p>{@link #DEFAULT} holds the protocol's initial values, which are in force for each direction
 * until a SETTINGS frame changes them. {@link #UNLIMITED} stands for "no limit", the initial value
 * of {@code maxConcurrentStreams} and {@code maxHeaderListSize}.
 *
 * @param headerTableSize SETTINGS_HEADER_TABLE_SIZE: the largest HPACK dynamic table the sender of
 *     these settings lets its peer's encoder use, 0 to 2^32-1
 * @param enablePush SETTINGS_ENABLE_PUSH
 * @param maxConcurrentStreams SETTINGS_MAX_CONCURRENT_STREAMS, 0 to 2^32-1 or {@link #UNLIMITED}
 * @param initialWindowSize SETTINGS_INITIAL_WINDOW_SIZE, 0 to 2^31-1
 * @param maxFrameSize SETTINGS_MAX_FRAME_SIZE, 2^14 to 2^24-1
 * @param maxHeaderListSize SETTINGS_MAX_HEADER_LIST_SIZE, 0 to 2^32-1 or {@link #UNLIMITED}
 * @param enableConnectProtocol SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441)
 */
public record Http2Settings(
        long headerTableSize,
        boolean enablePush,
        long maxConcurrentStreams,
        int initialWindowSize,
        int maxFrameSize,
        long maxHeaderListSize,
        boolean enableConnectProtocol) {

    public static final int HEADER_TABLE_SIZE = 0x1;
    public static final int ENABLE_PUSH = 0x2;
    public static final int MAX_CONCURRENT_STREAMS = 0x3;
    public static final int INITIAL_WINDOW_SIZE = 0x4;
    public static final int MAX_FRAME_SIZE = 0x5;
    public static final int MAX_HEADER_LIST_SIZE = 0x6;
    /** RFC 8441: extended CONNECT (including WebSockets). */
    public static final int ENABLE_CONNECT_PROTOCOL = 0x8;

    /** Source-compatible constructor for the original HTTP/2 settings. */
    public Http2Settings(long headerTableSize, boolean enablePush, long maxConcurrentStreams,
            int initialWindowSize, int maxFrameSize, long maxHeaderListSize) {
        this(headerTableSize, enablePush, maxConcurrentStreams, initialWindowSize, maxFrameSize, maxHeaderListSize, false);
    }

    /** No limit: the initial value of MAX_CONCURRENT_STREAMS and MAX_HEADER_LIST_SIZE. */
    public static final long UNLIMITED = Long.MAX_VALUE;

    public static final int DEFAULT_HEADER_TABLE_SIZE = 4096;
    public static final int DEFAULT_INITIAL_WINDOW_SIZE = 65_535;
    public static final int DEFAULT_MAX_FRAME_SIZE = 1 << 14;
    /** The largest SETTINGS_MAX_FRAME_SIZE allowed, 2^24 - 1. */
    public static final int MAX_MAX_FRAME_SIZE = (1 << 24) - 1;
    /** The largest flow-control window and SETTINGS_INITIAL_WINDOW_SIZE, 2^31 - 1. */
    public static final int MAX_WINDOW_SIZE = Integer.MAX_VALUE;

    private static final long MAX_U32 = 0xffffffffL;

    /** The protocol's initial values. */
    public static final Http2Settings DEFAULT = new Http2Settings(
            DEFAULT_HEADER_TABLE_SIZE, true, UNLIMITED, DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_FRAME_SIZE, UNLIMITED);

    public Http2Settings {
        if (headerTableSize < 0 || headerTableSize > MAX_U32) {
            throw new IllegalArgumentException("headerTableSize out of range: " + headerTableSize);
        }
        if ((maxConcurrentStreams < 0 || maxConcurrentStreams > MAX_U32) && maxConcurrentStreams != UNLIMITED) {
            throw new IllegalArgumentException("maxConcurrentStreams out of range: " + maxConcurrentStreams);
        }
        if (initialWindowSize < 0) {
            throw new IllegalArgumentException("initialWindowSize out of range: " + initialWindowSize);
        }
        if (maxFrameSize < DEFAULT_MAX_FRAME_SIZE || maxFrameSize > MAX_MAX_FRAME_SIZE) {
            throw new IllegalArgumentException("maxFrameSize must be 2^14 to 2^24-1, got " + maxFrameSize);
        }
        if ((maxHeaderListSize < 0 || maxHeaderListSize > MAX_U32) && maxHeaderListSize != UNLIMITED) {
            throw new IllegalArgumentException("maxHeaderListSize out of range: " + maxHeaderListSize);
        }
    }

    public static Builder builder() {
        return new Builder(DEFAULT);
    }

    public Builder toBuilder() {
        return new Builder(this);
    }

    /**
     * Checks one received setting (RFC 9113 §6.5.2). Unknown identifiers are accepted, since they
     * must be ignored.
     *
     * @throws Http2Exception a connection error: PROTOCOL_ERROR for a bad ENABLE_PUSH or
     *     MAX_FRAME_SIZE, FLOW_CONTROL_ERROR for an INITIAL_WINDOW_SIZE above 2^31-1
     */
    public static void validate(int id, long value) throws Http2Exception {
        switch (id) {
            case ENABLE_PUSH, ENABLE_CONNECT_PROTOCOL -> {
                if (value != 0 && value != 1) {
                    throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, "boolean setting " + id + " must be 0 or 1, got " + value);
                }
            }
            case INITIAL_WINDOW_SIZE -> {
                if (value > MAX_WINDOW_SIZE) {
                    throw Http2Exception.connectionError(
                            ErrorCode.FLOW_CONTROL_ERROR, "SETTINGS_INITIAL_WINDOW_SIZE above 2^31-1: " + value);
                }
            }
            case MAX_FRAME_SIZE -> {
                if (value < DEFAULT_MAX_FRAME_SIZE || value > MAX_MAX_FRAME_SIZE) {
                    throw Http2Exception.connectionError(
                            ErrorCode.PROTOCOL_ERROR, "SETTINGS_MAX_FRAME_SIZE must be 2^14 to 2^24-1, got " + value);
                }
            }
            default -> {
                // HEADER_TABLE_SIZE, MAX_CONCURRENT_STREAMS and MAX_HEADER_LIST_SIZE take any
                // 32-bit value; unknown settings are ignored.
            }
        }
    }

    /**
     * These settings updated by a peer's SETTINGS frame, values processed in order and unknown
     * identifiers ignored. An ACK changes nothing.
     */
    public Http2Settings apply(Frame.Settings frame) throws Http2Exception {
        if (frame.ack()) return this;
        Builder b = toBuilder();
        for (Map.Entry<Integer, Long> e : frame.values().entrySet()) {
            int id = e.getKey();
            long v = e.getValue();
            validate(id, v);
            switch (id) {
                case HEADER_TABLE_SIZE -> b.headerTableSize = v;
                case ENABLE_PUSH -> b.enablePush = v == 1;
                case MAX_CONCURRENT_STREAMS -> b.maxConcurrentStreams = v;
                case INITIAL_WINDOW_SIZE -> b.initialWindowSize = (int) v;
                case MAX_FRAME_SIZE -> b.maxFrameSize = (int) v;
                case MAX_HEADER_LIST_SIZE -> b.maxHeaderListSize = v;
                case ENABLE_CONNECT_PROTOCOL -> {
                    if (b.enableConnectProtocol && v == 0) {
                        throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR,
                                "SETTINGS_ENABLE_CONNECT_PROTOCOL cannot be disabled once enabled");
                    }
                    b.enableConnectProtocol = v == 1;
                }
                default -> {}
            }
        }
        return b.build();
    }

    /**
     * The values that differ from the protocol's initial ones, in identifier order: what a SETTINGS
     * frame must carry to establish these settings on a new connection.
     */
    public Map<Integer, Long> changedValues() {
        Map<Integer, Long> m = new LinkedHashMap<>();
        if (headerTableSize != DEFAULT.headerTableSize) m.put(HEADER_TABLE_SIZE, headerTableSize);
        if (enablePush != DEFAULT.enablePush) m.put(ENABLE_PUSH, enablePush ? 1L : 0L);
        if (maxConcurrentStreams != DEFAULT.maxConcurrentStreams) m.put(MAX_CONCURRENT_STREAMS, maxConcurrentStreams);
        if (initialWindowSize != DEFAULT.initialWindowSize) m.put(INITIAL_WINDOW_SIZE, (long) initialWindowSize);
        if (maxFrameSize != DEFAULT.maxFrameSize) m.put(MAX_FRAME_SIZE, (long) maxFrameSize);
        if (maxHeaderListSize != DEFAULT.maxHeaderListSize) m.put(MAX_HEADER_LIST_SIZE, maxHeaderListSize);
        if (enableConnectProtocol) m.put(ENABLE_CONNECT_PROTOCOL, 1L);
        return m;
    }

    /** A SETTINGS frame carrying {@link #changedValues()}. */
    public Frame.Settings toFrame() {
        return new Frame.Settings(false, changedValues());
    }

    /** Builds {@link Http2Settings}, starting from the protocol's initial values. */
    public static final class Builder {
        private long headerTableSize;
        private boolean enablePush;
        private long maxConcurrentStreams;
        private int initialWindowSize;
        private int maxFrameSize;
        private long maxHeaderListSize;
        private boolean enableConnectProtocol;

        private Builder(Http2Settings s) {
            headerTableSize = s.headerTableSize;
            enablePush = s.enablePush;
            maxConcurrentStreams = s.maxConcurrentStreams;
            initialWindowSize = s.initialWindowSize;
            maxFrameSize = s.maxFrameSize;
            maxHeaderListSize = s.maxHeaderListSize;
            enableConnectProtocol = s.enableConnectProtocol;
        }

        public Builder headerTableSize(long v) {
            headerTableSize = v;
            return this;
        }

        public Builder enablePush(boolean v) {
            enablePush = v;
            return this;
        }

        public Builder maxConcurrentStreams(long v) {
            maxConcurrentStreams = v;
            return this;
        }

        public Builder initialWindowSize(int v) {
            initialWindowSize = v;
            return this;
        }

        public Builder maxFrameSize(int v) {
            maxFrameSize = v;
            return this;
        }

        public Builder maxHeaderListSize(long v) {
            maxHeaderListSize = v;
            return this;
        }

        public Builder enableConnectProtocol(boolean v) {
            enableConnectProtocol = v;
            return this;
        }

        public Http2Settings build() {
            return new Http2Settings(
                    headerTableSize, enablePush, maxConcurrentStreams, initialWindowSize, maxFrameSize, maxHeaderListSize,
                    enableConnectProtocol);
        }
    }
}
