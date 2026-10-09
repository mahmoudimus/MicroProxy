package io.github.mahmoudimus.http2;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * One HTTP/2 frame (RFC 9113 §6). Instances are immutable apart from their byte arrays, which are
 * not copied: whoever creates a frame hands its arrays over.
 *
 * <p>The constructors check only what any frame of the type must satisfy (ranges, required stream
 * 0 or non-0), throwing {@link IllegalArgumentException}; rules about what the peer is allowed to
 * send are checked by {@link FrameReader} and raised as {@link Http2Exception}.
 *
 * <p>{@code padding} on DATA, HEADERS and PUSH_PROMISE is the number of octets that padding adds to
 * the frame, counting the Pad Length octet: 0 means the PADDED flag is clear, and {@code n > 0}
 * means a Pad Length of {@code n - 1}. It counts toward flow control for DATA.
 */
public sealed interface Frame
        permits Frame.Data,
                Frame.Headers,
                Frame.Priority,
                Frame.RstStream,
                Frame.Settings,
                Frame.PushPromise,
                Frame.Ping,
                Frame.GoAway,
                Frame.WindowUpdate,
                Frame.Continuation,
                Frame.Unknown {

    /** The largest stream identifier, 2^31 - 1. */
    int MAX_STREAM_ID = Integer.MAX_VALUE;

    /** The stream this frame belongs to, or 0 for the connection. */
    int streamId();

    /** The frame type code, one of the {@link FrameType} constants (or any value for {@link Unknown}). */
    int type();

    /** DATA (§6.1): part of a stream's content. */
    record Data(int streamId, byte[] data, boolean endStream, int padding) implements Frame {
        public Data {
            requireStream(streamId, "DATA");
            Objects.requireNonNull(data, "data");
            checkPadding(padding);
        }

        public Data(int streamId, byte[] data, boolean endStream) {
            this(streamId, data, endStream, 0);
        }

        @Override
        public int type() {
            return FrameType.DATA;
        }

        /** The bytes this frame counts against flow-control windows: data plus padding. */
        public int flowControlledLength() {
            return data.length + padding;
        }
    }

    /**
     * HEADERS (§6.2). Frames returned by {@link FrameReader} always carry the complete field block,
     * already joined with its CONTINUATION frames, so {@code endHeaders} is true. The (deprecated)
     * priority signal is parsed into {@code priority}, which is null when absent; it has no other
     * effect.
     */
    record Headers(int streamId, byte[] fieldBlock, boolean endStream, boolean endHeaders, PrioritySpec priority, int padding)
            implements Frame {
        public Headers {
            requireStream(streamId, "HEADERS");
            Objects.requireNonNull(fieldBlock, "fieldBlock");
            checkPadding(padding);
        }

        /** A complete, unpadded field block without priority. */
        public Headers(int streamId, byte[] fieldBlock, boolean endStream) {
            this(streamId, fieldBlock, endStream, true, null, 0);
        }

        @Override
        public int type() {
            return FrameType.HEADERS;
        }
    }

    /**
     * The RFC 7540 priority signal carried by PRIORITY frames and HEADERS frames with the PRIORITY
     * flag. RFC 9113 deprecates it; this codec parses it so the frame can be validated, and nothing
     * acts on it.
     *
     * @param weight 1 to 256 (the wire value plus one)
     */
    record PrioritySpec(int streamDependency, boolean exclusive, int weight) {
        public PrioritySpec {
            if (streamDependency < 0) throw new IllegalArgumentException("bad stream dependency " + streamDependency);
            if (weight < 1 || weight > 256) throw new IllegalArgumentException("weight must be 1-256, got " + weight);
        }
    }

    /** PRIORITY (§6.3): parsed and otherwise ignored. */
    record Priority(int streamId, PrioritySpec spec) implements Frame {
        public Priority {
            requireStream(streamId, "PRIORITY");
            Objects.requireNonNull(spec, "spec");
        }

        @Override
        public int type() {
            return FrameType.PRIORITY;
        }
    }

    /** RST_STREAM (§6.4). {@code errorCode} is the raw wire value; see {@link #error()}. */
    record RstStream(int streamId, int errorCode) implements Frame {
        public RstStream {
            requireStream(streamId, "RST_STREAM");
        }

        public RstStream(int streamId, ErrorCode error) {
            this(streamId, error.code());
        }

        @Override
        public int type() {
            return FrameType.RST_STREAM;
        }

        public ErrorCode error() {
            return ErrorCode.forCode(errorCode);
        }
    }

    /**
     * SETTINGS (§6.5). {@code values} maps setting identifiers to their (unsigned 32-bit) values in
     * the order they first appeared; a repeated identifier keeps its last value, which is what
     * processing them in order would give. Unknown identifiers are kept so callers can see them,
     * and must be ignored. An ACK has no values.
     */
    record Settings(boolean ack, Map<Integer, Long> values) implements Frame {
        public Settings {
            Objects.requireNonNull(values, "values");
            if (ack && !values.isEmpty()) throw new IllegalArgumentException("a SETTINGS ACK carries no values");
            for (Map.Entry<Integer, Long> e : values.entrySet()) {
                int id = e.getKey();
                long v = e.getValue();
                if (id < 0 || id > 0xffff) throw new IllegalArgumentException("setting id out of range: " + id);
                if (v < 0 || v > 0xffffffffL) throw new IllegalArgumentException("setting value out of range: " + v);
            }
            values = Collections.unmodifiableMap(new LinkedHashMap<>(values));
        }

        /** The acknowledgement of a peer's SETTINGS. */
        public static Settings acknowledgement() {
            return new Settings(true, Map.of());
        }

        @Override
        public int streamId() {
            return 0;
        }

        @Override
        public int type() {
            return FrameType.SETTINGS;
        }
    }

    /**
     * PUSH_PROMISE (§6.6), with its complete field block. A server never accepts one, and a client
     * that sent {@code SETTINGS_ENABLE_PUSH = 0} must treat one as a connection error of type
     * PROTOCOL_ERROR (§8.4). The reader still returns it, with the field block (which must be
     * decoded to keep HPACK state in step if the connection is to continue), and leaves the decision
     * to the caller.
     */
    record PushPromise(int streamId, int promisedStreamId, byte[] fieldBlock, boolean endHeaders, int padding)
            implements Frame {
        public PushPromise {
            requireStream(streamId, "PUSH_PROMISE");
            requireStream(promisedStreamId, "PUSH_PROMISE promised stream");
            Objects.requireNonNull(fieldBlock, "fieldBlock");
            checkPadding(padding);
        }

        @Override
        public int type() {
            return FrameType.PUSH_PROMISE;
        }
    }

    /** PING (§6.7). The 8 opaque octets are carried as a big-endian long. */
    record Ping(boolean ack, long opaqueData) implements Frame {
        @Override
        public int streamId() {
            return 0;
        }

        @Override
        public int type() {
            return FrameType.PING;
        }
    }

    /** GOAWAY (§6.8). {@code errorCode} is the raw wire value; see {@link #error()}. */
    record GoAway(int lastStreamId, int errorCode, byte[] debugData) implements Frame {
        public GoAway {
            if (lastStreamId < 0) throw new IllegalArgumentException("bad last stream id " + lastStreamId);
            Objects.requireNonNull(debugData, "debugData");
        }

        public GoAway(int lastStreamId, ErrorCode error, byte[] debugData) {
            this(lastStreamId, error.code(), debugData);
        }

        @Override
        public int streamId() {
            return 0;
        }

        @Override
        public int type() {
            return FrameType.GOAWAY;
        }

        public ErrorCode error() {
            return ErrorCode.forCode(errorCode);
        }
    }

    /** WINDOW_UPDATE (§6.9) for a stream, or for the connection when {@code streamId} is 0. */
    record WindowUpdate(int streamId, int increment) implements Frame {
        public WindowUpdate {
            if (streamId < 0) throw new IllegalArgumentException("bad stream id " + streamId);
            if (increment <= 0) throw new IllegalArgumentException("window increment must be 1 to 2^31-1, got " + increment);
        }

        @Override
        public int type() {
            return FrameType.WINDOW_UPDATE;
        }
    }

    /**
     * CONTINUATION (§6.10). Only written: {@link FrameReader} joins CONTINUATION frames into the
     * HEADERS or PUSH_PROMISE they continue, and never returns one.
     */
    record Continuation(int streamId, byte[] fieldBlock, boolean endHeaders) implements Frame {
        public Continuation {
            requireStream(streamId, "CONTINUATION");
            Objects.requireNonNull(fieldBlock, "fieldBlock");
        }

        @Override
        public int type() {
            return FrameType.CONTINUATION;
        }
    }

    /**
     * A frame of a type this codec does not know (an extension). The reader discards these unless
     * {@link FrameReader#setDeliverUnknownFrames(boolean)} asks for them; either way they must not
     * change any state (§5.5).
     */
    record Unknown(int type, int flags, int streamId, byte[] payload) implements Frame {
        public Unknown {
            if (type <= FrameType.CONTINUATION || type > 0xff) {
                throw new IllegalArgumentException("not an extension frame type: " + type);
            }
            if (flags < 0 || flags > 0xff) throw new IllegalArgumentException("bad flags " + flags);
            if (streamId < 0) throw new IllegalArgumentException("bad stream id " + streamId);
            Objects.requireNonNull(payload, "payload");
        }
    }

    private static void requireStream(int streamId, String what) {
        if (streamId <= 0) throw new IllegalArgumentException(what + " needs a stream id from 1 to 2^31-1, got " + streamId);
    }

    private static void checkPadding(int padding) {
        if (padding < 0 || padding > 256) throw new IllegalArgumentException("padding must be 0 to 256 octets, got " + padding);
    }
}
