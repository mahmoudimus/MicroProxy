package org.microproxy.impl;

import io.github.mahmoudimus.http2.ErrorCode;
import io.github.mahmoudimus.http2.FlowController;
import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.FrameWriter;
import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.HpackEncoder;
import io.github.mahmoudimus.http2.Http2Exception;
import io.github.mahmoudimus.http2.Http2Settings;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.FlowContext;
import org.microproxy.Http2Options;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.Http2Frame;

/**
 * What the proxy's two kinds of HTTP/2 connection share: {@link Http2Connection}, which serves a
 * client, and {@link Http2UpstreamConnection}, which talks to an origin server. Both read frames on
 * a thread of their own and write them from the threads of their streams' exchanges.
 *
 * <ul>
 *   <li>{@link #writeLock} serializes writing: the frame writer, the HPACK encoder (a header block
 *       is encoded and written under one hold, so blocks reach the peer in encoding order) and the
 *       socket.
 *   <li>{@link #stateLock} guards the flow-control windows, the peer's settings and each side's
 *       streams. It is never held while writing. Stream threads wait on its conditions, the
 *       connection's {@link #windowOpened} among them.
 *   <li>Response or request DATA waits until the stream and the connection both have send window,
 *       in frames of at most 16 KiB (or the peer's SETTINGS_MAX_FRAME_SIZE if smaller), so the
 *       streams of a connection take turns.
 *   <li>SETTINGS from the peer are applied (and acknowledged), PINGs answered.
 *   <li>With a {@link org.microproxy.frames.FrameInterceptor}, {@link #frames} shows it every frame
 *       written here before it is encoded (DATA in pieces of at most 16 KiB, before waiting for
 *       window, so DATA is debited at its size after interception), and the subclasses show it every
 *       frame they read, after decoding. Without one, {@link #frames} is null and nothing changes.
 * </ul>
 */
abstract class Http2Endpoint {

    /** The largest DATA frame sent, whatever the peer allows, so streams take turns. */
    static final int MAX_DATA_FRAME = 16_384;
    static final byte[] EMPTY = new byte[0];

    /** Runs every connection's checks; they only read fields and start threads, so one thread serves all. */
    static final ScheduledExecutorService TIMERS = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "microproxy-h2-timer");
        t.setDaemon(true);
        return t;
    });

    final DefaultHttpProxyServer server;
    final String logPrefix;
    final Http2Options options;

    // Guarded by writeLock.
    final ReentrantLock writeLock = new ReentrantLock();
    FrameWriter writer;
    HpackEncoder encoder;
    boolean writesFailed;
    /** When the write in progress started (System.nanoTime, never 0), or 0: for stall detection. */
    volatile long writeStartedNanos;

    // Guarded by stateLock.
    final ReentrantLock stateLock = new ReentrantLock();
    /** Signalled whenever send window may have opened, or a stream or the connection ended. */
    final Condition windowOpened = stateLock.newCondition();
    final FlowController flow;
    Http2Settings peerSettings = Http2Settings.DEFAULT;

    volatile boolean closed;

    /** The frame interceptor's side of this connection, or null without one: frames then go straight through. */
    final Http2Frames frames;

    /** One stream, as far as the code shared by both kinds of connection is concerned. */
    abstract static class Stream {
        /** The stream's id; for a stream to a server, 0 until its HEADERS are written. */
        int id;
        /** Guarded by stateLock: reset (by either side) or abandoned; waits and writes fail with {@link #failure()}. */
        boolean reset;
        volatile IOException resetCause;
        /** No more frames may be written for the stream (RST_STREAM sent or received). Written under writeLock or stateLock. */
        volatile boolean rstWritten;

        /** What waits and writes fail with once the stream is reset. */
        abstract IOException failure();
    }

    @FunctionalInterface
    interface FrameWrite {
        void run() throws IOException;
    }

    Http2Endpoint(DefaultHttpProxyServer server, String logPrefix, FlowController flow) {
        this.server = server;
        this.logPrefix = logPrefix;
        this.options = server.http2Options;
        this.flow = flow;
        this.frames = server.frameInterceptor == null ? null : new Http2Frames(server.frameInterceptor, this);
    }

    /** Who is at the other end, for messages: {@code client} or {@code server}. */
    abstract String peer();

    /** A write failed: the connection is unusable. Called with no lock held. */
    abstract void writeFailed();

    /** Called under {@link #writeLock} after each write for stream {@code s} (null: the connection). */
    void written(Stream s) {}

    // ---------------------------------------------------------------------------------------
    // What the frame interceptor is told (only called when there is one)
    // ---------------------------------------------------------------------------------------

    /** The direction of frames read here: from the client, or from the server. */
    abstract FrameDirection receivedDirection();

    /** The direction of frames written here. */
    abstract FrameDirection sentDirection();

    /** The exchange stream {@code s} carries, or null. */
    abstract FlowContext flowOf(Stream s);

    /** The exchange stream {@code streamId} carries, or null (0, or a stream not open). Takes stateLock. */
    abstract FlowContext flowOf(int streamId);

    /** The client connection's id for frames that belong to no exchange, or -1. */
    abstract long frameConnectionId();

    /** The client's address for frames that belong to no exchange, or null. */
    abstract InetSocketAddress frameClientAddress();

    /** The server's {@code host:port}, or null on the client side. */
    abstract String frameServer();

    /** The interceptor's verdict on a frame read here; {@link #frames} must not be null. */
    final List<Http2Frame> received(Http2Frame frame) {
        return frames.intercept(frame, receivedDirection(), flowOf(frame.streamId()));
    }

    /** The interceptor's verdict on a frame about to be written for {@code s} (null: none); {@link #frames} must not be null. */
    final List<Http2Frame> sent(Stream s, Http2Frame frame) {
        return frames.intercept(frame, sentDirection(), s != null ? flowOf(s) : flowOf(frame.streamId()));
    }

    /**
     * Why the peer's SETTINGS {@code original}, edited to {@code edited}, would make the proxy less
     * strict towards the peer than the original (or are invalid), or null if they would not.
     * Called on the reading thread, which alone changes {@link #peerSettings}.
     */
    final String stricterSettings(Map<Integer, Long> original, Map<Integer, Long> edited) {
        Http2Settings current;
        stateLock.lock();
        try {
            current = peerSettings;
        } finally {
            stateLock.unlock();
        }
        Http2Settings before;
        Http2Settings after;
        try {
            before = current.apply(new Frame.Settings(false, original));
        } catch (Http2Exception e) {
            return "the peer's SETTINGS are invalid themselves";
        }
        try {
            after = current.apply(new Frame.Settings(false, edited));
        } catch (Http2Exception e) {
            return "invalid SETTINGS: " + e.getMessage();
        }
        if (after.headerTableSize() > before.headerTableSize()) return "a larger HEADER_TABLE_SIZE than the peer's";
        if (after.maxConcurrentStreams() > before.maxConcurrentStreams()) return "a larger MAX_CONCURRENT_STREAMS than the peer's";
        if (after.initialWindowSize() > before.initialWindowSize()) return "a larger INITIAL_WINDOW_SIZE than the peer's";
        if (after.maxFrameSize() > before.maxFrameSize()) return "a larger MAX_FRAME_SIZE than the peer's";
        if (after.maxHeaderListSize() > before.maxHeaderListSize()) return "a larger MAX_HEADER_LIST_SIZE than the peer's";
        if (after.enablePush() && !before.enablePush()) return "ENABLE_PUSH turned on";
        if (after.enableConnectProtocol() && !before.enableConnectProtocol()) return "ENABLE_CONNECT_PROTOCOL turned on";
        return null;
    }

    /** Writes intercepted frames other than DATA: HEADERS are encoded here. Holds {@link #writeLock}. */
    final void writeFrames(List<Http2Frame> out) throws IOException {
        for (Http2Frame f : out) {
            if (f instanceof Http2Frame.Headers h) {
                writer.writeHeaders(h.streamId(), encoder.encode(Http2Frames.codecFields(h.fields())), h.endStream());
            } else {
                writer.writeFrame(Http2Frames.toCodec(f));
            }
        }
    }

    /** Writes through {@code out} from now on. */
    final void startWriting(OutputStream out) {
        writeLock.lock();
        try {
            writer = new FrameWriter(out);
            encoder = new HpackEncoder();
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Runs {@code action} with the writer to itself, then flushes if asked. Fails if stream {@code
     * s} (if given) was reset, so nothing more is written for it.
     */
    final void write(Stream s, FrameWrite action, boolean flush) throws IOException {
        boolean failed = false;
        writeLock.lock();
        try {
            if (writesFailed || closed) throw new IOException("HTTP/2 connection closed");
            if (s != null && s.rstWritten) throw s.failure();
            writeStartedNanos = nanoTime();
            try {
                action.run();
                if (flush) writer.flush();
            } catch (IOException e) {
                writesFailed = true;
                failed = true;
                throw e;
            } finally {
                writeStartedNanos = 0;
                written(s);
            }
        } finally {
            writeLock.unlock();
            if (failed) writeFailed();
        }
    }

    /** Writes a header block for stream {@code s}. */
    final void writeHeaders(Stream s, List<HeaderField> fields, boolean endStream) throws IOException {
        if (frames == null) {
            write(s, () -> writer.writeHeaders(s.id, encoder.encode(fields), endStream), true);
            return;
        }
        List<Http2Frame> out = sent(s, new Http2Frame.Headers(s.id, Http2Frames.fields(fields), endStream));
        write(s, () -> writeFrames(out), true);
    }

    /**
     * Writes data for stream {@code s} as DATA frames, waiting for send window as needed (the
     * stream's thread blocks until the peer opens it). With a frame interceptor, the data is shown
     * to it in pieces of at most {@link #MAX_DATA_FRAME} first, and what it returns is sent.
     */
    final void writeData(Stream s, byte[] data, int off, int len, boolean endStream, boolean flush) throws IOException {
        if (frames == null) {
            writeDataFrames(s, data, off, len, endStream, flush);
            return;
        }
        do {
            int n = Math.min(len, MAX_DATA_FRAME);
            boolean end = endStream && n == len;
            Http2Frame.Data piece = new Http2Frame.Data(s.id, Arrays.copyOfRange(data, off, off + n), end);
            for (Http2Frame f : sent(s, piece)) {
                if (f instanceof Http2Frame.Data d) {
                    // An empty DATA frame that does not end the stream says nothing: not sent.
                    if (d.data().length > 0 || d.endStream()) writeDataFrames(s, d.data(), 0, d.data().length, d.endStream(), flush);
                } else {
                    write(s, () -> writeFrames(List.of(f)), flush || f instanceof Http2Frame.Headers);
                }
            }
            off += n;
            len -= n;
        } while (len > 0);
    }

    /** {@link #writeData} without interception. */
    private void writeDataFrames(Stream s, byte[] data, int off, int len, boolean endStream, boolean flush) throws IOException {
        do {
            int n = reserveSendWindow(s, len);
            boolean end = endStream && n == len;
            int at = off;
            write(s, () -> writer.writeData(s.id, data, at, n, end), flush || end || n < len);
            off += n;
            len -= n;
        } while (len > 0);
    }

    /** Waits until {@code s} may send some of {@code len} bytes and debits the windows for them. */
    private int reserveSendWindow(Stream s, int len) throws IOException {
        if (len == 0) return 0;
        int idle = server.idleTimeoutMillis();
        long remaining = idle > 0 ? TimeUnit.MILLISECONDS.toNanos(idle) : Long.MAX_VALUE;
        stateLock.lock();
        try {
            while (true) {
                if (s.reset) throw s.failure();
                if (closed) throw new IOException("HTTP/2 connection closed");
                int n = Math.min(len, Math.min(flow.sendable(s.id), Math.min(peerSettings.maxFrameSize(), MAX_DATA_FRAME)));
                if (n > 0) {
                    flow.onDataSent(s.id, n);
                    return n;
                }
                if (remaining <= 0) {
                    throw new SocketTimeoutException("the " + peer() + " opened no flow-control window for " + idle + " ms");
                }
                remaining = windowOpened.awaitNanos(remaining);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted waiting for flow-control window");
        } finally {
            stateLock.unlock();
        }
    }

    final void flush() throws IOException {
        write(null, () -> {}, true);
    }

    /** Writes RST_STREAM for stream {@code id} (once for {@code s}, if given); failures only mark the writer failed. */
    final void writeReset(Stream s, int id, ErrorCode code) {
        List<Http2Frame> out = frames == null || s != null && s.rstWritten ? null
                : sent(s, new Http2Frame.RstStream(id, code.code() & 0xffffffffL));
        writeLock.lock();
        try {
            if (s != null) {
                if (s.rstWritten) return;
                s.rstWritten = true;
            }
            if (writesFailed || closed) return;
            writeStartedNanos = nanoTime();
            try {
                if (out == null) {
                    writer.writeRstStream(id, code);
                } else {
                    writeFrames(out);
                }
                writer.flush();
            } catch (IOException e) {
                writesFailed = true;
            } finally {
                writeStartedNanos = 0;
                written(s);
            }
        } finally {
            writeLock.unlock();
        }
    }

    /** Returns receive window to the peer: WINDOW_UPDATE for a stream and for the connection. */
    final void sendWindowUpdates(int streamId, int streamCredit, int connectionCredit) throws IOException {
        if (streamCredit <= 0 && connectionCredit <= 0) return;
        if (frames != null) {
            // Read-only: the interceptor sees them, and they are sent as they are.
            if (streamCredit > 0) sent(null, new Http2Frame.WindowUpdate(streamId, streamCredit));
            if (connectionCredit > 0) sent(null, new Http2Frame.WindowUpdate(0, connectionCredit));
        }
        write(null, () -> {
            if (streamCredit > 0) writer.writeWindowUpdate(streamId, streamCredit);
            if (connectionCredit > 0) writer.writeWindowUpdate(0, connectionCredit);
        }, true);
    }

    /**
     * Applies the peer's SETTINGS (a new initial window shifts every stream's send window) and
     * acknowledges them.
     *
     * @return the peer's settings now in force
     */
    final Http2Settings applySettings(Frame.Settings settings) throws IOException {
        Http2Settings next;
        stateLock.lock();
        try {
            next = peerSettings.apply(settings);
            if (next.initialWindowSize() != peerSettings.initialWindowSize()) {
                flow.onPeerInitialWindowSize(next.initialWindowSize());
            }
            peerSettings = next;
            windowOpened.signalAll();
        } finally {
            stateLock.unlock();
        }
        if (frames != null) sent(null, new Http2Frame.Settings(true, Map.of()));
        write(null, () -> {
            writer.setMaxFrameSize(next.maxFrameSize());
            encoder.setMaxHeaderTableSize(next.headerTableSize());
            writer.writeSettingsAck();
        }, true);
        return next;
    }

    /**
     * Writes the start of the connection: the client preface (towards a server), {@code ours} as
     * SETTINGS, and a WINDOW_UPDATE that grows the connection's receive window, if {@code
     * connectionIncrement} is positive.
     */
    final void writePreface(boolean clientPreface, Http2Settings ours, int connectionIncrement) throws IOException {
        List<Http2Frame> settings = null;
        if (frames != null) {
            settings = sent(null, new Http2Frame.Settings(false, ours.changedValues()));
            if (connectionIncrement > 0) sent(null, new Http2Frame.WindowUpdate(0, connectionIncrement));
        }
        List<Http2Frame> out = settings;
        write(null, () -> {
            if (clientPreface) writer.writeClientPreface();
            if (out == null) {
                writer.writeSettings(ours);
            } else {
                writeFrames(out);
            }
            if (connectionIncrement > 0) writer.writeWindowUpdate(0, connectionIncrement);
        }, true);
    }

    /** Answers a PING. */
    final void answerPing(Frame.Ping ping) throws IOException {
        if (!ping.ack()) {
            if (frames != null) sent(null, new Http2Frame.Ping(true, ping.opaqueData()));
            write(null, () -> writer.writePing(true, ping.opaqueData()), true);
        }
    }

    /** Writes GOAWAY; a failure only means the connection is going anyway. */
    final void writeGoAway(int lastStreamId, ErrorCode code, String debug) {
        byte[] debugData = debug == null || debug.isEmpty() ? EMPTY
                : debug.substring(0, Math.min(debug.length(), 200)).getBytes(StandardCharsets.US_ASCII);
        List<Http2Frame> out = frames == null ? null
                : sent(null, new Http2Frame.GoAway(lastStreamId, code.code() & 0xffffffffL, debugData));
        try {
            write(null, () -> {
                if (out == null) {
                    writer.writeGoAway(lastStreamId, code, debugData);
                } else {
                    writeFrames(out);
                }
            }, true);
        } catch (IOException e) {
            // closing anyway
        }
    }

    /** {@link System#nanoTime()}, never 0 (which means "none"). */
    static long nanoTime() {
        long t = System.nanoTime();
        return t == 0 ? 1 : t;
    }
}
