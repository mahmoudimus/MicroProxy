package io.github.mahmoudimus.http2;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Reads HTTP/2 frames from a blocking stream, one call per frame, validating everything that can
 * be checked from a frame on its own (RFC 9113 §4, §6). Meant to be driven by one (virtual)
 * thread per connection; it buffers nothing itself, so give it a {@link java.io.BufferedInputStream}
 * or similar. Not thread-safe.
 *
 * <pre>{@code
 * FrameReader reader = new FrameReader(new BufferedInputStream(socket.getInputStream()));
 * reader.readClientPreface();                  // server side
 * for (Frame frame; (frame = reader.readFrame()) != null; ) {
 *     switch (frame) {
 *         case Frame.Headers h -> handle(h.streamId(), hpack.decode(h.streamId(), h.fieldBlock()));
 *         case Frame.Data d -> ...
 *         default -> ...
 *     }
 * }
 * }</pre>
 *
 * <p>What it enforces:
 *
 * <ul>
 *   <li>The length of every frame against {@link #setMaxFrameSize(int) SETTINGS_MAX_FRAME_SIZE}
 *       (connection error FRAME_SIZE_ERROR), before reading or allocating its payload. Memory per
 *       frame is bounded by that size, and per field block by {@link #setMaxHeaderBlockSize(int)}.
 *   <li>Fixed lengths (PRIORITY, RST_STREAM, SETTINGS, PING, GOAWAY, WINDOW_UPDATE), padding that
 *       does not fit in the payload, frames on the wrong kind of stream (stream 0 or not), a zero
 *       WINDOW_UPDATE increment, and invalid SETTINGS values.
 *   <li>Field blocks: HEADERS and PUSH_PROMISE without END_HEADERS are joined with the CONTINUATION
 *       frames that follow into one frame; any other frame in between, a CONTINUATION for another
 *       stream or one without a preceding HEADERS is a connection error PROTOCOL_ERROR. A block
 *       longer than {@link #setMaxHeaderBlockSize(int)} or split into more than
 *       {@link #setMaxContinuationFrames(int)} CONTINUATION frames is a connection error
 *       ENHANCE_YOUR_CALM (the CONTINUATION flood).
 *   <li>Frames of unknown types are skipped (§5.5), without allocating their payload.
 * </ul>
 *
 * <p>Stream states, stream-id ordering and parity, SETTINGS acknowledgement and flow control are the
 * caller's business. After an {@link Http2Exception} that is a connection error the reader is
 * unusable; after a stream error the offending frame has been consumed and reading can go on.
 */
public final class FrameReader {

    /** The client connection preface (RFC 9113 §3.4). */
    public static final String CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    static final byte[] CLIENT_PREFACE_BYTES = CLIENT_PREFACE.getBytes(StandardCharsets.US_ASCII);

    /** The default limit on a field block's encoded size, 64 KiB. */
    public static final int DEFAULT_MAX_HEADER_BLOCK_SIZE = 64 * 1024;

    /** The default limit on CONTINUATION frames per field block. */
    public static final int DEFAULT_MAX_CONTINUATION_FRAMES = 128;

    private final InputStream in;
    private final byte[] header = new byte[FrameType.FRAME_HEADER_LENGTH];
    private int maxFrameSize = Http2Settings.DEFAULT_MAX_FRAME_SIZE;
    private int maxHeaderBlockSize = DEFAULT_MAX_HEADER_BLOCK_SIZE;
    private int maxContinuationFrames = DEFAULT_MAX_CONTINUATION_FRAMES;
    private boolean deliverUnknownFrames;

    // The frame header just read.
    private int length;
    private int type;
    private int flags;
    private int streamId;

    public FrameReader(InputStream in) {
        this.in = Objects.requireNonNull(in, "in");
    }

    /**
     * The largest frame payload accepted: the SETTINGS_MAX_FRAME_SIZE this endpoint advertised
     * (16384 until the peer acknowledges a larger one).
     */
    public void setMaxFrameSize(int maxFrameSize) {
        if (maxFrameSize < Http2Settings.DEFAULT_MAX_FRAME_SIZE || maxFrameSize > Http2Settings.MAX_MAX_FRAME_SIZE) {
            throw new IllegalArgumentException("max frame size must be 2^14 to 2^24-1, got " + maxFrameSize);
        }
        this.maxFrameSize = maxFrameSize;
    }

    public int maxFrameSize() {
        return maxFrameSize;
    }

    /** The largest encoded field block (HEADERS or PUSH_PROMISE plus CONTINUATION payloads) accepted. */
    public void setMaxHeaderBlockSize(int maxHeaderBlockSize) {
        if (maxHeaderBlockSize < 0) throw new IllegalArgumentException("negative limit");
        this.maxHeaderBlockSize = maxHeaderBlockSize;
    }

    public int maxHeaderBlockSize() {
        return maxHeaderBlockSize;
    }

    /** The most CONTINUATION frames accepted in one field block. */
    public void setMaxContinuationFrames(int maxContinuationFrames) {
        if (maxContinuationFrames < 0) throw new IllegalArgumentException("negative limit");
        this.maxContinuationFrames = maxContinuationFrames;
    }

    /** Return frames of unknown types as {@link Frame.Unknown} instead of skipping them. */
    public void setDeliverUnknownFrames(boolean deliverUnknownFrames) {
        this.deliverUnknownFrames = deliverUnknownFrames;
    }

    /**
     * Reads and checks the client connection preface, failing at the first wrong byte so that,
     * say, an HTTP/1.1 request is rejected without waiting for 24 bytes.
     *
     * @throws Http2Exception a connection error PROTOCOL_ERROR if the bytes differ
     * @throws EOFException if the stream ends first
     */
    public void readClientPreface() throws IOException {
        for (int i = 0; i < CLIENT_PREFACE_BYTES.length; i++) {
            int b = in.read();
            if (b < 0) throw new EOFException("connection closed in the client preface");
            if (b != (CLIENT_PREFACE_BYTES[i] & 0xff)) {
                throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, "invalid connection preface");
            }
        }
    }

    /**
     * Reads the next frame.
     *
     * @return the frame, or null if the stream ended cleanly between frames
     * @throws Http2Exception if the frame breaks the protocol or a limit
     * @throws EOFException if the stream ends inside a frame or a field block
     */
    public Frame readFrame() throws IOException {
        while (true) {
            if (!readHeader(false)) return null;
            Frame frame = readPayload();
            if (frame != null) return frame;
        }
    }

    private Frame readPayload() throws IOException {
        if (length > maxFrameSize) {
            throw Http2Exception.connectionError(ErrorCode.FRAME_SIZE_ERROR,
                    FrameType.name(type) + " frame of " + length + " bytes exceeds SETTINGS_MAX_FRAME_SIZE " + maxFrameSize);
        }
        return switch (type) {
            case FrameType.DATA -> readData();
            case FrameType.HEADERS -> readHeaders();
            case FrameType.PRIORITY -> readPriority();
            case FrameType.RST_STREAM -> readRstStream();
            case FrameType.SETTINGS -> readSettings();
            case FrameType.PUSH_PROMISE -> readPushPromise();
            case FrameType.PING -> readPing();
            case FrameType.GOAWAY -> readGoAway();
            case FrameType.WINDOW_UPDATE -> readWindowUpdate();
            case FrameType.CONTINUATION -> throw protocolError("CONTINUATION without a preceding HEADERS or PUSH_PROMISE");
            default -> readUnknown();
        };
    }

    private Frame readData() throws IOException {
        requireStream();
        byte[] payload = readFully(length);
        int padding = padding(payload, 0);
        byte[] data = padding == 0 ? payload : Arrays.copyOfRange(payload, 1, payload.length - (padding - 1));
        return new Frame.Data(streamId, data, (flags & FrameType.FLAG_END_STREAM) != 0, padding);
    }

    private Frame readHeaders() throws IOException {
        requireStream();
        int id = streamId;
        int frameFlags = flags;
        byte[] payload = readFully(length);
        boolean hasPriority = (frameFlags & FrameType.FLAG_PRIORITY) != 0;
        int padding = padding(payload, hasPriority ? 5 : 0);
        int start = padding > 0 ? 1 : 0;
        Frame.PrioritySpec priority = null;
        if (hasPriority) {
            priority = prioritySpec(payload, start);
            start += 5;
        }
        int end = payload.length - (padding > 0 ? padding - 1 : 0);
        byte[] block = fieldBlock(id, payload, start, end, (frameFlags & FrameType.FLAG_END_HEADERS) != 0);
        return new Frame.Headers(id, block, (frameFlags & FrameType.FLAG_END_STREAM) != 0, true, priority, padding);
    }

    private Frame readPriority() throws IOException {
        requireStream();
        byte[] payload = readFully(length);
        if (payload.length != 5) {
            throw Http2Exception.streamError(streamId, ErrorCode.FRAME_SIZE_ERROR, "PRIORITY frame of " + payload.length + " bytes");
        }
        Frame.PrioritySpec spec = prioritySpec(payload, 0);
        if (spec.streamDependency() == streamId) {
            throw Http2Exception.streamError(streamId, ErrorCode.PROTOCOL_ERROR, "stream depends on itself");
        }
        return new Frame.Priority(streamId, spec);
    }

    private Frame readRstStream() throws IOException {
        requireStream();
        if (length != 4) throw frameSizeError("RST_STREAM frame of " + length + " bytes");
        byte[] payload = readFully(4);
        return new Frame.RstStream(streamId, int32(payload, 0));
    }

    private Frame readSettings() throws IOException {
        requireConnection();
        boolean ack = (flags & FrameType.FLAG_ACK) != 0;
        if (ack && length != 0) throw frameSizeError("SETTINGS ACK with a payload");
        if (length % 6 != 0) throw frameSizeError("SETTINGS frame of " + length + " bytes is not a multiple of 6");
        byte[] payload = readFully(length);
        Map<Integer, Long> values = new LinkedHashMap<>();
        for (int i = 0; i < payload.length; i += 6) {
            int id = ((payload[i] & 0xff) << 8) | (payload[i + 1] & 0xff);
            long value = int32(payload, i + 2) & 0xffffffffL;
            Http2Settings.validate(id, value);
            values.remove(id); // a repeated setting takes the position of its last occurrence
            values.put(id, value);
        }
        return new Frame.Settings(ack, values);
    }

    private Frame readPushPromise() throws IOException {
        requireStream();
        int id = streamId;
        int frameFlags = flags;
        byte[] payload = readFully(length);
        int padding = padding(payload, 4);
        int start = padding > 0 ? 1 : 0;
        int promised = int32(payload, start) & 0x7fffffff;
        if (promised == 0) throw protocolError("PUSH_PROMISE promising stream 0");
        int end = payload.length - (padding > 0 ? padding - 1 : 0);
        byte[] block = fieldBlock(id, payload, start + 4, end, (frameFlags & FrameType.FLAG_END_HEADERS) != 0);
        return new Frame.PushPromise(id, promised, block, true, padding);
    }

    private Frame readPing() throws IOException {
        requireConnection();
        if (length != 8) throw frameSizeError("PING frame of " + length + " bytes");
        byte[] payload = readFully(8);
        long data = ((long) int32(payload, 0) << 32) | (int32(payload, 4) & 0xffffffffL);
        return new Frame.Ping((flags & FrameType.FLAG_ACK) != 0, data);
    }

    private Frame readGoAway() throws IOException {
        requireConnection();
        if (length < 8) throw frameSizeError("GOAWAY frame of " + length + " bytes");
        byte[] payload = readFully(length);
        int lastStreamId = int32(payload, 0) & 0x7fffffff;
        int errorCode = int32(payload, 4);
        return new Frame.GoAway(lastStreamId, errorCode, Arrays.copyOfRange(payload, 8, payload.length));
    }

    private Frame readWindowUpdate() throws IOException {
        if (length != 4) throw frameSizeError("WINDOW_UPDATE frame of " + length + " bytes");
        byte[] payload = readFully(4);
        int increment = int32(payload, 0) & 0x7fffffff;
        if (increment == 0) {
            if (streamId == 0) throw protocolError("WINDOW_UPDATE with an increment of 0");
            throw Http2Exception.streamError(streamId, ErrorCode.PROTOCOL_ERROR, "WINDOW_UPDATE with an increment of 0");
        }
        return new Frame.WindowUpdate(streamId, increment);
    }

    private Frame readUnknown() throws IOException {
        if (deliverUnknownFrames) {
            return new Frame.Unknown(type, flags, streamId, readFully(length));
        }
        in.skipNBytes(length);
        return null;
    }

    /**
     * The padding of a PADDED frame, as {@link Frame} counts it (0 when not padded), checking that
     * it fits in the payload after {@code fixed} more bytes of fields.
     */
    private int padding(byte[] payload, int fixed) throws Http2Exception {
        if ((flags & FrameType.FLAG_PADDED) == 0) {
            if (payload.length < fixed) throw frameSizeError(FrameType.name(type) + " frame too short: " + payload.length + " bytes");
            return 0;
        }
        if (payload.length < 1 + fixed) {
            throw frameSizeError(FrameType.name(type) + " frame too short for its padding: " + payload.length + " bytes");
        }
        int padLength = payload[0] & 0xff;
        if (padLength > payload.length - 1 - fixed) {
            throw protocolError(FrameType.name(type) + " padding of " + padLength + " bytes exceeds the payload");
        }
        return padLength + 1;
    }

    private static Frame.PrioritySpec prioritySpec(byte[] payload, int offset) {
        int word = int32(payload, offset);
        return new Frame.PrioritySpec(word & 0x7fffffff, word < 0, (payload[offset + 4] & 0xff) + 1);
    }

    /** Joins a field block's first fragment with the CONTINUATION frames that follow it. */
    private byte[] fieldBlock(int id, byte[] payload, int start, int end, boolean endHeaders) throws IOException {
        int size = end - start;
        if (size > maxHeaderBlockSize) throw headerBlockTooLarge(id, size);
        byte[] block = Arrays.copyOfRange(payload, start, end);
        int continuations = 0;
        while (!endHeaders) {
            if (!readHeader(true)) throw new EOFException("connection closed inside a field block");
            if (type != FrameType.CONTINUATION) {
                throw protocolError(FrameType.name(type) + " frame inside the field block of stream " + id);
            }
            if (streamId != id) {
                throw protocolError("CONTINUATION for stream " + streamId + " inside the field block of stream " + id);
            }
            if (length > maxFrameSize) {
                throw Http2Exception.connectionError(ErrorCode.FRAME_SIZE_ERROR,
                        "CONTINUATION frame of " + length + " bytes exceeds SETTINGS_MAX_FRAME_SIZE " + maxFrameSize);
            }
            if (++continuations > maxContinuationFrames) {
                throw Http2Exception.connectionError(ErrorCode.ENHANCE_YOUR_CALM,
                        "field block of stream " + id + " is split into more than " + maxContinuationFrames + " CONTINUATION frames");
            }
            if ((long) size + length > maxHeaderBlockSize) throw headerBlockTooLarge(id, (long) size + length);
            if (size + length > block.length) {
                block = Arrays.copyOf(block, Math.min(maxHeaderBlockSize, Math.max(size + length, block.length * 2)));
            }
            readFully(block, size, length);
            size += length;
            endHeaders = (flags & FrameType.FLAG_END_HEADERS) != 0;
        }
        return size == block.length ? block : Arrays.copyOf(block, size);
    }

    private Http2Exception headerBlockTooLarge(int id, long size) {
        return Http2Exception.connectionError(ErrorCode.ENHANCE_YOUR_CALM,
                "field block of stream " + id + " exceeds " + maxHeaderBlockSize + " bytes (at least " + size + ")");
    }

    /** Reads a frame header; false at a clean end of stream (before its first byte) if allowed. */
    private boolean readHeader(boolean inBlock) throws IOException {
        int n = in.readNBytes(header, 0, header.length);
        if (n == 0 && !inBlock) return false;
        if (n < header.length) throw new EOFException("connection closed inside a frame header");
        length = ((header[0] & 0xff) << 16) | ((header[1] & 0xff) << 8) | (header[2] & 0xff);
        type = header[3] & 0xff;
        flags = header[4] & 0xff;
        streamId = int32(header, 5) & 0x7fffffff; // the reserved bit is ignored
        return true;
    }

    private byte[] readFully(int n) throws IOException {
        byte[] b = new byte[n];
        readFully(b, 0, n);
        return b;
    }

    private void readFully(byte[] b, int off, int n) throws IOException {
        if (in.readNBytes(b, off, n) < n) {
            throw new EOFException("connection closed inside a " + FrameType.name(type) + " frame");
        }
    }

    private void requireStream() throws Http2Exception {
        if (streamId == 0) throw protocolError(FrameType.name(type) + " frame on stream 0");
    }

    private void requireConnection() throws Http2Exception {
        if (streamId != 0) throw protocolError(FrameType.name(type) + " frame on stream " + streamId);
    }

    private static Http2Exception protocolError(String message) {
        return Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, message);
    }

    private static Http2Exception frameSizeError(String message) {
        return Http2Exception.connectionError(ErrorCode.FRAME_SIZE_ERROR, message);
    }

    static int int32(byte[] b, int off) {
        return ((b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16) | ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff);
    }
}
