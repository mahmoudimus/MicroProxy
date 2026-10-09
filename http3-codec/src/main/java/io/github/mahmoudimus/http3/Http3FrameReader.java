package io.github.mahmoudimus.http3;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Reads HTTP/3 frames from one QUIC stream's bytes, one call per frame, validating everything that
 * can be checked from a frame on its own (RFC 9114 §7). Meant to be driven by one (virtual) thread
 * per stream; it buffers nothing itself, so give it a {@link java.io.BufferedInputStream} or
 * similar. Not thread-safe.
 *
 * <pre>{@code
 * Http3FrameReader reader = new Http3FrameReader(requestStreamInput);
 * Http3StreamValidator validator = Http3StreamValidator.forRequestStream(streamId, Role.SERVER);
 * for (Http3Frame frame; (frame = reader.readFrame()) != null; ) {
 *     validator.onFrame(frame);
 *     switch (frame) {
 *         case Http3Frame.Headers h -> fields = qpack.decode(streamId, h.fieldSection());
 *         case Http3Frame.Data d -> body.write(d.data());
 *         default -> {}
 *     }
 * }
 * validator.onEndOfStream();
 * }</pre>
 *
 * <p>What it enforces:
 *
 * <ul>
 *   <li>A payload of at most {@link #setMaxFramePayloadSize(int)} bytes (default 64 KiB), checked
 *       before anything is allocated; a longer one is a connection error H3_EXCESSIVE_LOAD. DATA
 *       is the exception: HTTP/3 gives DATA frame boundaries no meaning, so a longer DATA frame is
 *       returned as consecutive {@link Http3Frame.Data} pieces of at most that size, and memory per
 *       frame stays bounded by the limit either way.
 *   <li>Payloads that hold exactly their fields (CANCEL_PUSH, GOAWAY, MAX_PUSH_ID, SETTINGS,
 *       PUSH_PROMISE), and frames cut short by the end of the stream: connection error
 *       H3_FRAME_ERROR.
 *   <li>The HTTP/2 frame types that HTTP/3 forbids (0x02, 0x06, 0x08, 0x09): connection error
 *       H3_FRAME_UNEXPECTED.
 *   <li>SETTINGS: no identifier twice, none of the HTTP/2-only identifiers, and valid values for
 *       the defined ones (connection error H3_SETTINGS_ERROR).
 * </ul>
 *
 * <p>Frames of unknown and reserved types are returned as {@link Http3Frame.Unknown}, so they can
 * be relayed, unless {@link #setDeliverUnknownFrames(boolean)} turns that off; then they are
 * skipped without allocating their payload. Which frames may appear on which stream, and in what
 * order, is {@link Http3StreamValidator}'s job.
 *
 * <p>Every error is a connection error, and the reader must not be used after one.
 */
public final class Http3FrameReader {

    /** The default limit on a frame payload, 64 KiB. */
    public static final int DEFAULT_MAX_FRAME_PAYLOAD_SIZE = 64 * 1024;

    private final InputStream in;
    private int maxFramePayloadSize = DEFAULT_MAX_FRAME_PAYLOAD_SIZE;
    private boolean deliverUnknownFrames = true;
    // What is left of a DATA frame longer than the limit, returned in pieces.
    private long dataRemaining;

    public Http3FrameReader(InputStream in) {
        this.in = Objects.requireNonNull(in, "in");
    }

    /** A reader over the remaining bytes of a buffer, which it consumes. */
    public static Http3FrameReader of(ByteBuffer buf) {
        return new Http3FrameReader(new ByteBufferInputStream(buf));
    }

    /** The largest payload accepted (and the largest piece a long DATA frame is returned in). */
    public void setMaxFramePayloadSize(int maxFramePayloadSize) {
        if (maxFramePayloadSize < 1 || maxFramePayloadSize > Integer.MAX_VALUE - 8) {
            throw new IllegalArgumentException("max frame payload size must be 1 to 2^31-9, got " + maxFramePayloadSize);
        }
        this.maxFramePayloadSize = maxFramePayloadSize;
    }

    public int maxFramePayloadSize() {
        return maxFramePayloadSize;
    }

    /** Return frames of unknown and reserved types as {@link Http3Frame.Unknown} (the default) or skip them. */
    public void setDeliverUnknownFrames(boolean deliverUnknownFrames) {
        this.deliverUnknownFrames = deliverUnknownFrames;
    }

    /**
     * Reads the stream type that starts every unidirectional stream (RFC 9114 §6.2); see
     * {@link Http3StreamType}. Call it once, before the first {@link #readFrame()}.
     *
     * @return the type, or -1 if the stream ended before all of it arrived (which a receiver must
     *     tolerate)
     */
    public long readStreamType() throws IOException {
        return Http3StreamType.read(in);
    }

    /**
     * Reads the next frame.
     *
     * @return the frame, or null if the stream ended cleanly between frames
     * @throws Http3Exception if the frame breaks the protocol or a limit, or the stream ends inside it
     */
    public Http3Frame readFrame() throws IOException {
        while (true) {
            if (dataRemaining > 0) return dataPiece();
            long type = readVarInt(true);
            if (type < 0) return null;
            if (Http3FrameType.isHttp2Only(type)) {
                throw Http3Exception.connectionError(Http3ErrorCode.H3_FRAME_UNEXPECTED,
                        "frame type 0x" + Long.toHexString(type) + " is HTTP/2-only and forbidden in HTTP/3");
            }
            long length = readVarInt(false);
            if (type == Http3FrameType.DATA) {
                dataRemaining = length;
                if (length == 0) return new Http3Frame.Data(new byte[0]);
                return dataPiece();
            }
            if (!Http3FrameType.isKnown(type) && !deliverUnknownFrames) {
                skip(length);
                continue;
            }
            if (length > maxFramePayloadSize) {
                throw Http3Exception.connectionError(Http3ErrorCode.H3_EXCESSIVE_LOAD,
                        Http3FrameType.name(type) + " frame of " + length + " bytes exceeds the limit of " + maxFramePayloadSize);
            }
            return parsePayload(type, readFully((int) length));
        }
    }

    /**
     * Parses one whole frame at the buffer's position, for callers that collect a stream's bytes in
     * a buffer. The limit applies to every frame type here, DATA included; read long DATA frames
     * with a reader over a stream instead.
     *
     * @return the frame, with the position moved past it; or null, with the position unchanged, if
     *     the buffer holds only part of it
     * @throws Http3Exception as {@link #readFrame()}, and H3_EXCESSIVE_LOAD for a DATA frame longer
     *     than {@code maxFramePayloadSize}
     */
    public static Http3Frame parse(ByteBuffer buf, int maxFramePayloadSize) throws Http3Exception {
        int start = buf.position();
        long type = QuicVarInt.read(buf);
        if (type < 0) return null;
        if (Http3FrameType.isHttp2Only(type)) {
            throw Http3Exception.connectionError(Http3ErrorCode.H3_FRAME_UNEXPECTED,
                    "frame type 0x" + Long.toHexString(type) + " is HTTP/2-only and forbidden in HTTP/3");
        }
        long length = QuicVarInt.read(buf);
        if (length < 0) {
            buf.position(start);
            return null;
        }
        if (length > maxFramePayloadSize) {
            throw Http3Exception.connectionError(Http3ErrorCode.H3_EXCESSIVE_LOAD,
                    Http3FrameType.name(type) + " frame of " + length + " bytes exceeds the limit of " + maxFramePayloadSize);
        }
        if (buf.remaining() < length) {
            buf.position(start);
            return null;
        }
        byte[] payload = new byte[(int) length];
        buf.get(payload);
        if (type == Http3FrameType.DATA) return new Http3Frame.Data(payload);
        return parsePayload(type, payload);
    }

    /** Parses the payload of a frame whose type is not HTTP/2-only. */
    static Http3Frame parsePayload(long type, byte[] payload) throws Http3Exception {
        if (type == Http3FrameType.DATA) return new Http3Frame.Data(payload);
        if (type == Http3FrameType.HEADERS) return new Http3Frame.Headers(payload);
        if (type == Http3FrameType.CANCEL_PUSH) return new Http3Frame.CancelPush(singleVarInt(type, payload));
        if (type == Http3FrameType.SETTINGS) return new Http3Frame.Settings(settings(payload));
        if (type == Http3FrameType.PUSH_PROMISE) {
            long pushId = QuicVarInt.read(payload, 0, payload.length);
            if (pushId < 0) throw frameError("PUSH_PROMISE frame too short for its push ID");
            int n = QuicVarInt.lengthOf(payload[0]);
            return new Http3Frame.PushPromise(pushId, Arrays.copyOfRange(payload, n, payload.length));
        }
        if (type == Http3FrameType.GOAWAY) return new Http3Frame.GoAway(singleVarInt(type, payload));
        if (type == Http3FrameType.MAX_PUSH_ID) return new Http3Frame.MaxPushId(singleVarInt(type, payload));
        return new Http3Frame.Unknown(type, payload);
    }

    private static long singleVarInt(long type, byte[] payload) throws Http3Exception {
        long v = QuicVarInt.read(payload, 0, payload.length);
        if (v < 0 || QuicVarInt.lengthOf(payload[0]) != payload.length) {
            throw frameError(Http3FrameType.name(type) + " frame payload of " + payload.length
                    + " bytes does not hold exactly one variable-length integer");
        }
        return v;
    }

    private static Map<Long, Long> settings(byte[] payload) throws Http3Exception {
        Map<Long, Long> values = new LinkedHashMap<>();
        int pos = 0;
        while (pos < payload.length) {
            long id = QuicVarInt.read(payload, pos, payload.length);
            if (id < 0) throw frameError("SETTINGS frame ends inside a setting identifier");
            pos += QuicVarInt.lengthOf(payload[pos]);
            long value = QuicVarInt.read(payload, pos, payload.length);
            if (value < 0) throw frameError("SETTINGS frame ends inside the value of setting 0x" + Long.toHexString(id));
            pos += QuicVarInt.lengthOf(payload[pos]);
            Http3Settings.validate(id, value);
            if (values.putIfAbsent(id, value) != null) {
                throw Http3Exception.connectionError(Http3ErrorCode.H3_SETTINGS_ERROR,
                        "setting 0x" + Long.toHexString(id) + " appears more than once");
            }
        }
        return values;
    }

    private Http3Frame dataPiece() throws IOException {
        int n = (int) Math.min(dataRemaining, maxFramePayloadSize);
        byte[] data = readFully(n);
        dataRemaining -= n;
        return new Http3Frame.Data(data);
    }

    /** A variable-length integer; -1 at a clean end of stream before its first byte, if allowed. */
    private long readVarInt(boolean atFrameStart) throws IOException {
        int first = in.read();
        if (first < 0) {
            if (atFrameStart) return -1;
            throw truncated();
        }
        int n = QuicVarInt.lengthOf(first);
        long v = first & 0x3f;
        for (int i = 1; i < n; i++) {
            int b = in.read();
            if (b < 0) throw truncated();
            v = (v << 8) | b;
        }
        return v;
    }

    private byte[] readFully(int n) throws IOException {
        byte[] b = in.readNBytes(n);
        if (b.length < n) throw truncated();
        return b;
    }

    private void skip(long n) throws IOException {
        while (n > 0) {
            long chunk = Math.min(n, 8192);
            byte[] ignored = in.readNBytes((int) chunk);
            if (ignored.length < chunk) throw truncated();
            n -= chunk;
        }
    }

    private static Http3Exception truncated() {
        return frameError("stream ended inside a frame");
    }

    private static Http3Exception frameError(String message) {
        return Http3Exception.connectionError(Http3ErrorCode.H3_FRAME_ERROR, message);
    }

    /** Reads a ByteBuffer's remaining bytes, consuming them. */
    private static final class ByteBufferInputStream extends InputStream {
        private final ByteBuffer buf;

        ByteBufferInputStream(ByteBuffer buf) {
            this.buf = Objects.requireNonNull(buf, "buf");
        }

        @Override
        public int read() {
            return buf.hasRemaining() ? buf.get() & 0xff : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            Objects.checkFromIndexSize(off, len, b.length);
            if (len == 0) return 0;
            if (!buf.hasRemaining()) return -1;
            int n = Math.min(len, buf.remaining());
            buf.get(b, off, n);
            return n;
        }

        @Override
        public int available() {
            return buf.remaining();
        }
    }
}
