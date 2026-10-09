package io.github.mahmoudimus.http3;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * One HTTP/3 frame (RFC 9114 §7.2). Instances are immutable apart from their byte arrays, which are
 * not copied: whoever creates a frame hands its arrays over.
 *
 * <p>Unlike HTTP/2 frames, HTTP/3 frames carry no stream identifier and no flags: the QUIC stream
 * they arrive on gives the stream, and the end of a message is the end of that stream.
 *
 * <p>The constructors check only what any frame of the type must satisfy (value ranges),
 * throwing {@link IllegalArgumentException}; rules about what the peer is allowed to send are
 * checked by {@link Http3FrameReader} and {@link Http3StreamValidator} and raised as
 * {@link Http3Exception}.
 */
public sealed interface Http3Frame
        permits Http3Frame.Data,
                Http3Frame.Headers,
                Http3Frame.CancelPush,
                Http3Frame.Settings,
                Http3Frame.PushPromise,
                Http3Frame.GoAway,
                Http3Frame.MaxPushId,
                Http3Frame.Unknown {

    /** The frame type code: one of the {@link Http3FrameType} constants, or any other for {@link Unknown}. */
    long type();

    /** DATA (§7.2.1): part of a message's content. */
    record Data(byte[] data) implements Http3Frame {
        public Data {
            Objects.requireNonNull(data, "data");
        }

        @Override
        public long type() {
            return Http3FrameType.DATA;
        }
    }

    /** HEADERS (§7.2.2): a QPACK-encoded field section, decoded with {@link QpackDecoder}. */
    record Headers(byte[] fieldSection) implements Http3Frame {
        public Headers {
            Objects.requireNonNull(fieldSection, "fieldSection");
        }

        @Override
        public long type() {
            return Http3FrameType.HEADERS;
        }
    }

    /** CANCEL_PUSH (§7.2.3), on the control stream. */
    record CancelPush(long pushId) implements Http3Frame {
        public CancelPush {
            checkVarInt(pushId, "push ID");
        }

        @Override
        public long type() {
            return Http3FrameType.CANCEL_PUSH;
        }
    }

    /**
     * SETTINGS (§7.2.4), the first frame on each control stream and sent once. {@code values} maps
     * setting identifiers to their values in the order they appeared; unknown and reserved
     * identifiers are kept so that callers can see and relay them, and must otherwise be ignored.
     * See {@link Http3Settings} for the defined ones.
     */
    record Settings(Map<Long, Long> values) implements Http3Frame {
        public Settings {
            Objects.requireNonNull(values, "values");
            for (Map.Entry<Long, Long> e : values.entrySet()) {
                checkVarInt(e.getKey(), "setting identifier");
                checkVarInt(e.getValue(), "setting value");
            }
            values = Collections.unmodifiableMap(new LinkedHashMap<>(values));
        }

        @Override
        public long type() {
            return Http3FrameType.SETTINGS;
        }
    }

    /** PUSH_PROMISE (§7.2.5): a promised request's QPACK-encoded field section, on a request stream. */
    record PushPromise(long pushId, byte[] fieldSection) implements Http3Frame {
        public PushPromise {
            checkVarInt(pushId, "push ID");
            Objects.requireNonNull(fieldSection, "fieldSection");
        }

        @Override
        public long type() {
            return Http3FrameType.PUSH_PROMISE;
        }
    }

    /**
     * GOAWAY (§7.2.6), on the control stream. {@code id} is a client-initiated bidirectional stream
     * ID when the server sends it, and a push ID when the client does.
     */
    record GoAway(long id) implements Http3Frame {
        public GoAway {
            checkVarInt(id, "GOAWAY identifier");
        }

        @Override
        public long type() {
            return Http3FrameType.GOAWAY;
        }
    }

    /** MAX_PUSH_ID (§7.2.7), sent by a client on the control stream. */
    record MaxPushId(long pushId) implements Http3Frame {
        public MaxPushId {
            checkVarInt(pushId, "push ID");
        }

        @Override
        public long type() {
            return Http3FrameType.MAX_PUSH_ID;
        }
    }

    /**
     * A frame of any other type: an extension, or a reserved type (0x1f * N + 0x21) used for
     * greasing. Kept whole so that it can be inspected, edited and relayed; a receiver must not
     * act on types it does not understand (§9). The HTTP/2-only types are never unknown frames:
     * receiving one is an error.
     */
    record Unknown(long type, byte[] payload) implements Http3Frame {
        public Unknown {
            checkVarInt(type, "frame type");
            if (Http3FrameType.isKnown(type) || Http3FrameType.isHttp2Only(type)) {
                throw new IllegalArgumentException("not an extension frame type: " + Http3FrameType.name(type));
            }
            Objects.requireNonNull(payload, "payload");
        }

        /** Whether this is a reserved (greasing) frame type. */
        public boolean isReserved() {
            return Http3FrameType.isReserved(type);
        }
    }

    private static void checkVarInt(long value, String what) {
        if (value < 0 || value > QuicVarInt.MAX_VALUE) {
            throw new IllegalArgumentException(what + " out of range 0 to 2^62-1: " + value);
        }
    }
}
