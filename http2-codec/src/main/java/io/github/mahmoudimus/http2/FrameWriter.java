package io.github.mahmoudimus.http2;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;
import java.util.Objects;

/**
 * Writes HTTP/2 frames to a blocking stream. Each call builds its frames in memory and hands them
 * to the stream in one {@code write}, so frames from different threads never interleave as long
 * as callers serialize their calls (this class does no locking; hold a lock, or give one thread
 * the job of writing). Nothing is flushed until {@link #flush()}.
 *
 * <p>Arguments that would produce a frame the protocol forbids, including a payload larger than
 * the peer's {@link #setMaxFrameSize(int) SETTINGS_MAX_FRAME_SIZE}, are rejected with
 * {@link IllegalArgumentException} before anything is written. {@link #writeHeaders} and
 * {@link #writePushPromise} split long field blocks into CONTINUATION frames; DATA is never split,
 * because how much may be sent is a flow-control decision for the caller.
 */
public final class FrameWriter {

    private static final byte[] EMPTY = new byte[0];

    private final OutputStream out;
    private int maxFrameSize = Http2Settings.DEFAULT_MAX_FRAME_SIZE;

    public FrameWriter(OutputStream out) {
        this.out = Objects.requireNonNull(out, "out");
    }

    /** The largest payload the peer accepts: its SETTINGS_MAX_FRAME_SIZE (16384 until it says otherwise). */
    public void setMaxFrameSize(int maxFrameSize) {
        if (maxFrameSize < Http2Settings.DEFAULT_MAX_FRAME_SIZE || maxFrameSize > Http2Settings.MAX_MAX_FRAME_SIZE) {
            throw new IllegalArgumentException("max frame size must be 2^14 to 2^24-1, got " + maxFrameSize);
        }
        this.maxFrameSize = maxFrameSize;
    }

    public int maxFrameSize() {
        return maxFrameSize;
    }

    /** Writes the client connection preface; a client then sends its SETTINGS. */
    public void writeClientPreface() throws IOException {
        out.write(FrameReader.CLIENT_PREFACE_BYTES);
    }

    /**
     * Writes one frame exactly as given. A HEADERS or PUSH_PROMISE without END_HEADERS must be
     * followed by its CONTINUATION frames, with nothing in between.
     */
    public void writeFrame(Frame frame) throws IOException {
        out.write(encode(frame));
    }

    /** One DATA frame, unpadded. */
    public void writeData(int streamId, byte[] data, int offset, int length, boolean endStream) throws IOException {
        Objects.checkFromIndexSize(offset, length, data.length);
        checkStream(streamId);
        checkLength(length);
        byte[] f = new byte[FrameType.FRAME_HEADER_LENGTH + length];
        header(f, 0, length, FrameType.DATA, endStream ? FrameType.FLAG_END_STREAM : 0, streamId);
        System.arraycopy(data, offset, f, FrameType.FRAME_HEADER_LENGTH, length);
        out.write(f);
    }

    /** A complete field block: one HEADERS frame, followed by CONTINUATION frames if it is too long for one. */
    public void writeHeaders(int streamId, byte[] fieldBlock, boolean endStream) throws IOException {
        checkStream(streamId);
        writeFieldBlock(FrameType.HEADERS, endStream ? FrameType.FLAG_END_STREAM : 0, streamId, EMPTY, fieldBlock);
    }

    /** A complete PUSH_PROMISE field block, with CONTINUATION frames as needed. */
    public void writePushPromise(int streamId, int promisedStreamId, byte[] fieldBlock) throws IOException {
        checkStream(streamId);
        checkStream(promisedStreamId);
        byte[] prefix = new byte[4];
        putInt(prefix, 0, promisedStreamId);
        writeFieldBlock(FrameType.PUSH_PROMISE, 0, streamId, prefix, fieldBlock);
    }

    public void writeSettings(Http2Settings settings) throws IOException {
        writeFrame(settings.toFrame());
    }

    public void writeSettings(Map<Integer, Long> values) throws IOException {
        writeFrame(new Frame.Settings(false, values));
    }

    public void writeSettingsAck() throws IOException {
        writeFrame(Frame.Settings.acknowledgement());
    }

    public void writePing(boolean ack, long opaqueData) throws IOException {
        writeFrame(new Frame.Ping(ack, opaqueData));
    }

    public void writeGoAway(int lastStreamId, ErrorCode error, byte[] debugData) throws IOException {
        writeFrame(new Frame.GoAway(lastStreamId, error, debugData == null ? EMPTY : debugData));
    }

    public void writeRstStream(int streamId, ErrorCode error) throws IOException {
        writeFrame(new Frame.RstStream(streamId, error));
    }

    public void writeWindowUpdate(int streamId, int increment) throws IOException {
        writeFrame(new Frame.WindowUpdate(streamId, increment));
    }

    public void flush() throws IOException {
        out.flush();
    }

    private void writeFieldBlock(int type, int flags, int streamId, byte[] prefix, byte[] block) throws IOException {
        int first = Math.min(block.length, maxFrameSize - prefix.length);
        int rest = block.length - first;
        int continuations = rest == 0 ? 0 : (rest + maxFrameSize - 1) / maxFrameSize;
        long total = (long) FrameType.FRAME_HEADER_LENGTH * (1 + continuations) + prefix.length + block.length;
        if (total > Integer.MAX_VALUE - 8) throw new IllegalArgumentException("field block too large");
        byte[] f = new byte[(int) total];
        int pos = 0;
        header(f, pos, prefix.length + first, type, flags | (continuations == 0 ? FrameType.FLAG_END_HEADERS : 0), streamId);
        pos += FrameType.FRAME_HEADER_LENGTH;
        System.arraycopy(prefix, 0, f, pos, prefix.length);
        pos += prefix.length;
        System.arraycopy(block, 0, f, pos, first);
        pos += first;
        int src = first;
        for (int i = 0; i < continuations; i++) {
            int n = Math.min(maxFrameSize, block.length - src);
            boolean last = i == continuations - 1;
            header(f, pos, n, FrameType.CONTINUATION, last ? FrameType.FLAG_END_HEADERS : 0, streamId);
            pos += FrameType.FRAME_HEADER_LENGTH;
            System.arraycopy(block, src, f, pos, n);
            pos += n;
            src += n;
        }
        out.write(f);
    }

    /** The bytes of one frame, header included. */
    byte[] encode(Frame frame) {
        return switch (frame) {
            case Frame.Data d -> padded(FrameType.DATA, flag(d.endStream(), FrameType.FLAG_END_STREAM), d.streamId(), d.padding(),
                    EMPTY, d.data());
            case Frame.Headers h -> {
                byte[] prefix = EMPTY;
                int flags = flag(h.endStream(), FrameType.FLAG_END_STREAM) | flag(h.endHeaders(), FrameType.FLAG_END_HEADERS);
                if (h.priority() != null) {
                    prefix = prioritySpec(h.priority());
                    flags |= FrameType.FLAG_PRIORITY;
                }
                yield padded(FrameType.HEADERS, flags, h.streamId(), h.padding(), prefix, h.fieldBlock());
            }
            case Frame.Priority p -> frame(FrameType.PRIORITY, 0, p.streamId(), prioritySpec(p.spec()));
            case Frame.RstStream r -> frame(FrameType.RST_STREAM, 0, r.streamId(), int32(r.errorCode()));
            case Frame.Settings s -> {
                byte[] payload = new byte[s.values().size() * 6];
                int pos = 0;
                for (Map.Entry<Integer, Long> e : s.values().entrySet()) {
                    try {
                        Http2Settings.validate(e.getKey(), e.getValue());
                    } catch (Http2Exception x) {
                        throw new IllegalArgumentException("invalid setting: " + x.getMessage(), x);
                    }
                    payload[pos]= (byte) (e.getKey() >>> 8);
                    payload[pos + 1] = (byte) e.getKey().intValue();
                    putInt(payload, pos + 2, (int) e.getValue().longValue());
                    pos += 6;
                }
                yield frame(FrameType.SETTINGS, flag(s.ack(), FrameType.FLAG_ACK), 0, payload);
            }
            case Frame.PushPromise p -> padded(FrameType.PUSH_PROMISE, flag(p.endHeaders(), FrameType.FLAG_END_HEADERS),
                    p.streamId(), p.padding(), int32(p.promisedStreamId()), p.fieldBlock());
            case Frame.Ping p -> {
                byte[] payload = new byte[8];
                putInt(payload, 0, (int) (p.opaqueData() >>> 32));
                putInt(payload, 4, (int) p.opaqueData());
                yield frame(FrameType.PING, flag(p.ack(), FrameType.FLAG_ACK), 0, payload);
            }
            case Frame.GoAway g -> {
                byte[] payload = new byte[8 + g.debugData().length];
                putInt(payload, 0, g.lastStreamId());
                putInt(payload, 4, g.errorCode());
                System.arraycopy(g.debugData(), 0, payload, 8, g.debugData().length);
                yield frame(FrameType.GOAWAY, 0, 0, payload);
            }
            case Frame.WindowUpdate w -> frame(FrameType.WINDOW_UPDATE, 0, w.streamId(), int32(w.increment()));
            case Frame.Continuation c -> frame(FrameType.CONTINUATION, flag(c.endHeaders(), FrameType.FLAG_END_HEADERS),
                    c.streamId(), c.fieldBlock());
            case Frame.Unknown u -> frame(u.type(), u.flags(), u.streamId(), u.payload());
        };
    }

    private byte[] padded(int type, int flags, int streamId, int padding, byte[] prefix, byte[] body) {
        long length = (long) padding + prefix.length + body.length;
        checkLength(length);
        byte[] f = new byte[FrameType.FRAME_HEADER_LENGTH + (int) length];
        header(f, 0, (int) length, type, flags | (padding > 0 ? FrameType.FLAG_PADDED : 0), streamId);
        int pos = FrameType.FRAME_HEADER_LENGTH;
        if (padding > 0) f[pos++] = (byte) (padding - 1);
        System.arraycopy(prefix, 0, f, pos, prefix.length);
        pos += prefix.length;
        System.arraycopy(body, 0, f, pos, body.length);
        // The padding octets stay zero, as required.
        return f;
    }

    private byte[] frame(int type, int flags, int streamId, byte[] payload) {
        checkLength(payload.length);
        byte[] f = new byte[FrameType.FRAME_HEADER_LENGTH + payload.length];
        header(f, 0, payload.length, type, flags, streamId);
        System.arraycopy(payload, 0, f, FrameType.FRAME_HEADER_LENGTH, payload.length);
        return f;
    }

    private void checkLength(long length) {
        if (length > maxFrameSize) {
            throw new IllegalArgumentException("frame payload of " + length + " bytes exceeds the peer's SETTINGS_MAX_FRAME_SIZE " + maxFrameSize);
        }
    }

    private static void checkStream(int streamId) {
        if (streamId <= 0) throw new IllegalArgumentException("stream id must be 1 to 2^31-1, got " + streamId);
    }

    private static void header(byte[] f, int pos, int length, int type, int flags, int streamId) {
        f[pos] = (byte) (length >>> 16);
        f[pos + 1] = (byte) (length >>> 8);
        f[pos + 2] = (byte) length;
        f[pos + 3] = (byte) type;
        f[pos + 4] = (byte) flags;
        putInt(f, pos + 5, streamId & 0x7fffffff);
    }

    private static byte[] prioritySpec(Frame.PrioritySpec spec) {
        byte[] b = new byte[5];
        putInt(b, 0, spec.streamDependency() | (spec.exclusive() ? 0x80000000 : 0));
        b[4] = (byte) (spec.weight() - 1);
        return b;
    }

    private static int flag(boolean set, int flag) {
        return set ? flag : 0;
    }

    private static byte[] int32(int v) {
        byte[] b = new byte[4];
        putInt(b, 0, v);
        return b;
    }

    private static void putInt(byte[] b, int off, int v) {
        b[off] = (byte) (v >>> 24);
        b[off + 1] = (byte) (v >>> 16);
        b[off + 2] = (byte) (v >>> 8);
        b[off + 3] = (byte) v;
    }
}
