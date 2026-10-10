package io.github.mahmoudimus.http3;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Objects;

/**
 * Writes HTTP/3 frames to one QUIC stream. Each call builds its frame in memory and hands it to the
 * stream in one {@code write}. A QUIC stream has a single writer, so there is no locking; if
 * several threads share one stream, they must serialize their calls. Nothing is flushed until
 * {@link #flush()}.
 *
 * <p>Arguments that would produce a frame the protocol forbids (an HTTP/2-only setting, say) are
 * rejected with {@link IllegalArgumentException} before anything is written. The static
 * {@link #encode(Http3Frame)} methods give the bytes of a frame without a stream.
 */
public final class Http3FrameWriter {

    private final OutputStream out;

    /**
     * A writer for one stream.
     *
     * @param out the stream's bytes; give it a buffered stream and flush it as needed
     */
    public Http3FrameWriter(OutputStream out) {
        this.out = Objects.requireNonNull(out, "out");
    }

    /**
     * Writes the stream type that must start a unidirectional stream; see {@link Http3StreamType}.
     *
     * @param streamType the stream type
     * @throws IOException if writing fails
     */
    public void writeStreamType(long streamType) throws IOException {
        out.write(QuicVarInt.encode(streamType));
    }

    /**
     * Writes one frame exactly as given.
     *
     * @param frame the frame
     * @throws IOException if writing fails
     */
    public void writeFrame(Http3Frame frame) throws IOException {
        out.write(encode(frame));
    }

    /**
     * One DATA frame.
     *
     * @param data the content
     * @param offset where it starts in {@code data}
     * @param length how many bytes
     * @throws IOException if writing fails
     */
    public void writeData(byte[] data, int offset, int length) throws IOException {
        Objects.checkFromIndexSize(offset, length, data.length);
        int header = QuicVarInt.length(Http3FrameType.DATA) + QuicVarInt.length(length);
        byte[] f = new byte[header + length];
        int pos = QuicVarInt.write(Http3FrameType.DATA, f, 0);
        pos = QuicVarInt.write(length, f, pos);
        System.arraycopy(data, offset, f, pos, length);
        out.write(f);
    }

    /**
     * One DATA frame with all of {@code data}.
     *
     * @param data the content
     * @throws IOException if writing fails
     */
    public void writeData(byte[] data) throws IOException {
        writeData(data, 0, data.length);
    }

    /**
     * A HEADERS frame carrying an encoded field section from {@link QpackEncoder}.
     *
     * @param fieldSection the encoded field section
     * @throws IOException if writing fails
     */
    public void writeHeaders(byte[] fieldSection) throws IOException {
        writeFrame(new Http3Frame.Headers(fieldSection));
    }

    /**
     * A SETTINGS frame.
     *
     * @param settings the settings
     * @throws IOException if writing fails
     */
    public void writeSettings(Http3Settings settings) throws IOException {
        writeFrame(settings.toFrame());
    }

    /**
     * A PUSH_PROMISE frame.
     *
     * @param pushId the push it promises
     * @param fieldSection the encoded field section of the promised request
     * @throws IOException if writing fails
     */
    public void writePushPromise(long pushId, byte[] fieldSection) throws IOException {
        writeFrame(new Http3Frame.PushPromise(pushId, fieldSection));
    }

    /**
     * A CANCEL_PUSH frame.
     *
     * @param pushId the push to cancel
     * @throws IOException if writing fails
     */
    public void writeCancelPush(long pushId) throws IOException {
        writeFrame(new Http3Frame.CancelPush(pushId));
    }

    /**
     * A GOAWAY frame.
     *
     * @param id the stream or push id
     * @throws IOException if writing fails
     */
    public void writeGoAway(long id) throws IOException {
        writeFrame(new Http3Frame.GoAway(id));
    }

    /**
     * A MAX_PUSH_ID frame.
     *
     * @param pushId the largest push id the server may use
     * @throws IOException if writing fails
     */
    public void writeMaxPushId(long pushId) throws IOException {
        writeFrame(new Http3Frame.MaxPushId(pushId));
    }

    /**
     * Flushes the stream.
     *
     * @throws IOException if flushing fails
     */
    public void flush() throws IOException {
        out.flush();
    }

    /**
     * The bytes of one frame.
     *
     * @param frame the frame
     * @return its type, length and payload
     */
    public static byte[] encode(Http3Frame frame) {
        byte[] payload = payload(frame);
        long type = frame.type();
        byte[] f = new byte[QuicVarInt.length(type) + QuicVarInt.length(payload.length) + payload.length];
        int pos = QuicVarInt.write(type, f, 0);
        pos = QuicVarInt.write(payload.length, f, pos);
        System.arraycopy(payload, 0, f, pos, payload.length);
        return f;
    }

    /**
     * Puts the bytes of one frame at the buffer's position.
     *
     * @param frame the frame
     * @param buf where to put it
     * @throws BufferOverflowException if it does not fit; nothing is written then
     */
    public static void encode(Http3Frame frame, ByteBuffer buf) {
        byte[] f = encode(frame);
        if (buf.remaining() < f.length) throw new BufferOverflowException();
        buf.put(f);
    }

    /** The payload of a frame, without its type and length. */
    static byte[] payload(Http3Frame frame) {
        return switch (frame) {
            case Http3Frame.Data d -> d.data();
            case Http3Frame.Headers h -> h.fieldSection();
            case Http3Frame.CancelPush c -> QuicVarInt.encode(c.pushId());
            case Http3Frame.Settings s -> settingsPayload(s.values());
            case Http3Frame.PushPromise p -> {
                byte[] id = QuicVarInt.encode(p.pushId());
                byte[] b = new byte[id.length + p.fieldSection().length];
                System.arraycopy(id, 0, b, 0, id.length);
                System.arraycopy(p.fieldSection(), 0, b, id.length, p.fieldSection().length);
                yield b;
            }
            case Http3Frame.GoAway g -> QuicVarInt.encode(g.id());
            case Http3Frame.MaxPushId m -> QuicVarInt.encode(m.pushId());
            case Http3Frame.Unknown u -> u.payload();
        };
    }

    private static byte[] settingsPayload(Map<Long, Long> values) {
        int length = 0;
        for (Map.Entry<Long, Long> e : values.entrySet()) {
            try {
                Http3Settings.validate(e.getKey(), e.getValue());
            } catch (Http3Exception x) {
                throw new IllegalArgumentException("invalid setting: " + x.getMessage(), x);
            }
            length += QuicVarInt.length(e.getKey()) + QuicVarInt.length(e.getValue());
        }
        byte[] b = new byte[length];
        int pos = 0;
        for (Map.Entry<Long, Long> e : values.entrySet()) {
            pos = QuicVarInt.write(e.getKey(), b, pos);
            pos = QuicVarInt.write(e.getValue(), b, pos);
        }
        return b;
    }
}
