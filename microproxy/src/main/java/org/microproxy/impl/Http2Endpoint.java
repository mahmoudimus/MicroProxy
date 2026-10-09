package org.microproxy.impl;

import io.github.mahmoudimus.http2.ErrorCode;
import io.github.mahmoudimus.http2.FlowController;
import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.FrameWriter;
import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.HpackEncoder;
import io.github.mahmoudimus.http2.Http2Settings;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.Http2Options;

/**
 * What the proxy's HTTP/2 connections share, whichever end of them the proxy is: frames are read on
 * a thread of their own and written from the threads of the streams' exchanges.
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
    }

    /** Who is at the other end, for messages: {@code client} or {@code server}. */
    abstract String peer();

    /** A write failed: the connection is unusable. Called with no lock held. */
    abstract void writeFailed();

    /** Called under {@link #writeLock} after each write for stream {@code s} (null: the connection). */
    void written(Stream s) {}

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
        write(s, () -> writer.writeHeaders(s.id, encoder.encode(fields), endStream), true);
    }

    /**
     * Writes data for stream {@code s} as DATA frames, waiting for send window as needed (the
     * stream's thread blocks until the peer opens it).
     */
    final void writeData(Stream s, byte[] data, int off, int len, boolean endStream, boolean flush) throws IOException {
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
        writeLock.lock();
        try {
            if (s != null) {
                if (s.rstWritten) return;
                s.rstWritten = true;
            }
            if (writesFailed || closed) return;
            writeStartedNanos = nanoTime();
            try {
                writer.writeRstStream(id, code);
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
        write(null, () -> {
            writer.setMaxFrameSize(next.maxFrameSize());
            encoder.setMaxHeaderTableSize(next.headerTableSize());
            writer.writeSettingsAck();
        }, true);
        return next;
    }

    /** Answers a PING. */
    final void answerPing(Frame.Ping ping) throws IOException {
        if (!ping.ack()) {
            write(null, () -> writer.writePing(true, ping.opaqueData()), true);
        }
    }

    /** Writes GOAWAY; a failure only means the connection is going anyway. */
    final void writeGoAway(int lastStreamId, ErrorCode code, String debug) {
        byte[] debugData = debug == null || debug.isEmpty() ? EMPTY
                : debug.substring(0, Math.min(debug.length(), 200)).getBytes(StandardCharsets.US_ASCII);
        try {
            write(null, () -> writer.writeGoAway(lastStreamId, code, debugData), true);
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
