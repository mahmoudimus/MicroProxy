package org.microproxy.impl;

import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3ErrorCode;
import io.github.mahmoudimus.http3.Http3FrameWriter;
import io.github.mahmoudimus.quic.QuicStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.SocketException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.IntConsumer;
import org.microproxy.FlowContext;
import org.microproxy.frames.Http3Frame;

/**
 * The sending side of one HTTP/3 request stream: a request to a server ({@link
 * Http3UpstreamStream}), or the response to a client ({@link Http3StreamChannel}). Header sections
 * are encoded through the connection's QPACK encoder ({@link Http3Endpoint#encodeFields}), bodies
 * written as DATA frames, and the end of the message is the end of the stream (its FIN). Writes
 * wait for QUIC's flow control and send window.
 *
 * <p>With a frame interceptor, each frame is shown to it before it is written (DATA in pieces of
 * at most {@link #MAX_DATA_FRAME} bytes), and what comes back is written in its place: QUIC's flow
 * control then counts what is actually sent.
 */
final class Http3MessageWriter {

    /** The largest DATA frame shown to an interceptor. */
    static final int MAX_DATA_FRAME = 16 * 1024;

    private final Http3Endpoint endpoint;
    private final QuicStream stream;
    final long id;
    /** The frames are a response's rather than a request's. */
    private final boolean response;
    private final OutputStream out;
    private final Http3FrameWriter writer;
    /** Serializes writing, and ending the stream from another thread. */
    private final ReentrantLock lock = new ReentrantLock();
    private final Http3Frames.State[] state = {Http3Frames.State.HEADERS};
    /** The message has ended (FIN) or the stream was reset: nothing more is written. */
    private volatile boolean ended;

    /** The exchange the stream carries, for the interceptor. */
    volatile FlowContext flow;

    Http3MessageWriter(Http3Endpoint endpoint, QuicStream stream, boolean response, IntConsumer onBytes) {
        this.endpoint = endpoint;
        this.stream = stream;
        this.id = stream.id();
        this.response = response;
        OutputStream os = stream.getOutputStream();
        this.out = onBytes == null ? os : CountingStreams.counting(os, onBytes);
        this.writer = new Http3FrameWriter(out);
    }

    /** Whether the message has ended, or the stream was reset. */
    boolean ended() {
        return ended;
    }

    /** Writes a header section (the head, an interim response's, or trailers), ending the stream after it if {@code end}. */
    void headers(List<HeaderField> fields, boolean end) throws IOException {
        lock.lock();
        try {
            checkOpen();
            if (endpoint.frames == null) {
                writer.writeHeaders(endpoint.encodeFields(id, fields));
            } else {
                Http3Frame.Headers h = new Http3Frame.Headers(Http3Frames.fields(fields));
                write(endpoint.frames.onStream(h, endpoint.sentDirection(), endpoint.frameOrigin(), id, flow, state, response));
            }
            if (end) finish();
        } finally {
            lock.unlock();
        }
    }

    /** Writes body bytes as DATA, ending the stream after them if {@code end}. */
    void data(byte[] data, int off, int len, boolean end) throws IOException {
        lock.lock();
        try {
            checkOpen();
            if (endpoint.frames == null) {
                if (len > 0) writer.writeData(data, off, len);
            } else {
                for (int at = off; at < off + len; at += MAX_DATA_FRAME) {
                    byte[] piece = Arrays.copyOfRange(data, at, Math.min(off + len, at + MAX_DATA_FRAME));
                    write(endpoint.frames.onStream(new Http3Frame.Data(piece), endpoint.sentDirection(),
                            endpoint.frameOrigin(), id, flow, state, response));
                }
            }
            if (end) finish();
        } finally {
            lock.unlock();
        }
    }

    /** Ends the message (the stream's FIN), unless it has ended. */
    void end() throws IOException {
        lock.lock();
        try {
            if (!ended) finish();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Ends the message from another thread, while a write may be in progress: with the FIN if no
     * write is, else by resetting the stream with {@code code}.
     */
    void endOrReset(Http3ErrorCode code) {
        if (!lock.tryLock()) {
            reset(code);
            return;
        }
        try {
            if (!ended) finish();
        } catch (IOException e) {
            reset(code);
        } finally {
            lock.unlock();
        }
    }

    /** Abandons the message (RESET_STREAM with {@code code}), unless it has ended. */
    void reset(Http3ErrorCode code) {
        if (ended) return;
        ended = true;
        try {
            stream.reset(code.code());
        } catch (IOException | RuntimeException e) {
            // finished or reset already, or the connection is gone
        }
    }

    void flush() throws IOException {
        writer.flush();
    }

    /** Writes what the interceptor returned, in order; holds lock. */
    private void write(List<Http3Frame> frames) throws IOException {
        for (Http3Frame f : frames) {
            switch (f) {
                case Http3Frame.Headers h -> writer.writeHeaders(endpoint.encodeFields(id, Http3Frames.codecFields(h.fields())));
                case Http3Frame.Data d -> writer.writeData(d.data());
                case Http3Frame.Unknown u -> writer.writeFrame(new io.github.mahmoudimus.http3.Http3Frame.Unknown(u.type(), u.payload()));
                default -> throw new IllegalStateException(f.typeName() + " on a request stream");
            }
        }
    }

    private void checkOpen() throws IOException {
        if (ended) throw new SocketException("stream " + id + "'s output has ended");
    }

    /** Sends the FIN; holds lock. */
    private void finish() throws IOException {
        ended = true;
        out.close();
    }
}
