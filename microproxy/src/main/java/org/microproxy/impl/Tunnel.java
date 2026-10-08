package org.microproxy.impl;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.System.Logger.Level;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLSocket;
import org.microproxy.http.WebSocketFrame;

/**
 * Relays bytes in both directions between two sockets until both directions finish, using one
 * extra virtual thread. End-of-stream on one side is propagated as a half-close to the other.
 * With an idle timeout, the tunnel closes only when neither direction has moved data for that
 * long.
 *
 * <p>For upgraded WebSocket connections the relay can parse frames and report each one to an
 * observer before forwarding it unchanged.
 */
final class Tunnel {

    private static final System.Logger LOG = System.getLogger(Tunnel.class.getName());

    /** Receives each relayed WebSocket frame. */
    @FunctionalInterface
    interface FrameObserver {
        void frame(WebSocketFrame frame, boolean fromClient);
    }

    /** Thrown when both directions have been idle for the idle timeout. */
    private static final class IdleTimeout extends IOException {
        IdleTimeout() {
            super("tunnel idle");
        }
    }

    private Tunnel() {}

    /** Relays raw bytes. */
    static void relay(
            Socket clientSocket, InputStream clientIn, OutputStream clientOut,
            Socket serverSocket, InputStream serverIn, OutputStream serverOut,
            Duration idleTimeout, String name, BufferPool pool) {
        relay(clientSocket, clientIn, clientOut, serverSocket, serverIn, serverOut, idleTimeout, name, null, 0, pool);
    }

    /**
     * Relays bytes, parsing WebSocket frames when {@code observer} is non-null.
     *
     * @param maxFrameBuffer frames with larger payloads are streamed and reported as truncated
     */
    static void relay(
            Socket clientSocket, InputStream clientIn, OutputStream clientOut,
            Socket serverSocket, InputStream serverIn, OutputStream serverOut,
            Duration idleTimeout, String name, FrameObserver observer, int maxFrameBuffer, BufferPool pool) {
        AtomicLong lastActivity = new AtomicLong(System.nanoTime());
        long idleNanos = idleTimeout == null ? 0 : idleTimeout.toNanos();
        Runnable closeAll = () -> {
            Tls.closeQuietly(clientSocket);
            Tls.closeQuietly(serverSocket);
        };
        Direction up = new Direction(clientIn, serverOut, serverSocket, lastActivity, idleNanos, true, pool);
        Direction down = new Direction(serverIn, clientOut, clientSocket, lastActivity, idleNanos, false, pool);
        Thread upstream = Thread.ofVirtual().name(name + "-up").start(
                () -> run(up, observer, maxFrameBuffer, closeAll));
        run(down, observer, maxFrameBuffer, closeAll);
        try {
            upstream.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            closeAll.run();
        }
    }

    private static void run(Direction d, FrameObserver observer, int maxFrameBuffer, Runnable closeAll) {
        try {
            if (observer == null) {
                d.copyAll();
            } else {
                pumpFrames(d, observer, maxFrameBuffer);
            }
            d.halfClose();
        } catch (IOException e) {
            closeAll.run();
        }
    }

    /** Parses and forwards frames until end-of-stream at a frame boundary. */
    private static void pumpFrames(Direction d, FrameObserver observer, int maxFrameBuffer) throws IOException {
        byte[] head = new byte[14];
        while (true) {
            if (!d.readFully(head, 0, 2, true)) {
                return;
            }
            int length7 = head[1] & 0x7f;
            int pos = 2;
            long length;
            if (length7 == 126) {
                d.readFully(head, pos, 2, false);
                length = ((head[2] & 0xffL) << 8) | (head[3] & 0xffL);
                pos += 2;
            } else if (length7 == 127) {
                d.readFully(head, pos, 8, false);
                length = 0;
                for (int i = 0; i < 8; i++) {
                    length = (length << 8) | (head[pos + i] & 0xffL);
                }
                pos += 8;
                if (length < 0) {
                    // Not valid WebSocket framing: stop interpreting, keep relaying bytes.
                    LOG.log(Level.DEBUG, "invalid WebSocket frame length; relaying raw bytes");
                    d.write(head, 0, pos);
                    d.copyAll();
                    return;
                }
            } else {
                length = length7;
            }
            if ((head[1] & 0x80) != 0) {
                d.readFully(head, pos, 4, false);
                pos += 4;
            }
            byte[] header = Arrays.copyOf(head, pos);
            if (length <= maxFrameBuffer) {
                byte[] payload = new byte[(int) length];
                d.readFully(payload, 0, payload.length, false);
                notify(observer, new WebSocketFrame(header, payload, length), d.fromClient);
                d.write(header, 0, header.length);
                d.write(payload, 0, payload.length);
                d.flush();
            } else {
                notify(observer, new WebSocketFrame(header, null, length), d.fromClient);
                d.write(header, 0, header.length);
                d.copy(length);
                d.flush();
            }
        }
    }

    private static void notify(FrameObserver observer, WebSocketFrame frame, boolean fromClient) {
        try {
            observer.frame(frame, fromClient);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "WebSocket frame observer threw", e);
        }
    }

    /** One direction of the tunnel. */
    private static final class Direction {
        final InputStream in;
        final OutputStream out;
        final Socket destination;
        final AtomicLong lastActivity;
        final long idleNanos;
        final boolean fromClient;
        final BufferPool pool;

        Direction(InputStream in, OutputStream out, Socket destination, AtomicLong lastActivity,
                long idleNanos, boolean fromClient, BufferPool pool) {
            this.pool = pool;
            this.in = in;
            this.out = out;
            this.destination = destination;
            this.lastActivity = lastActivity;
            this.idleNanos = idleNanos;
            this.fromClient = fromClient;
        }

        /** Reads up to {@code len} bytes, tolerating timeouts while the other direction is active. */
        int read(byte[] b, int off, int len) throws IOException {
            while (true) {
                try {
                    int n = in.read(b, off, len);
                    if (n > 0) lastActivity.set(System.nanoTime());
                    return n;
                } catch (SocketTimeoutException e) {
                    if (idleNanos <= 0 || System.nanoTime() - lastActivity.get() >= idleNanos) {
                        throw new IdleTimeout();
                    }
                }
            }
        }

        /**
         * Reads exactly {@code len} bytes.
         *
         * @return false if the stream ended before the first byte and {@code eofAllowed}
         */
        boolean readFully(byte[] b, int off, int len, boolean eofAllowed) throws IOException {
            int done = 0;
            while (done < len) {
                int n = read(b, off + done, len - done);
                if (n < 0) {
                    if (done == 0 && eofAllowed) return false;
                    throw new EOFException("stream ended mid-frame");
                }
                done += n;
            }
            return true;
        }

        void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
        }

        void flush() throws IOException {
            out.flush();
        }

        /** Reads one byte, tolerating timeouts while the other direction is active. */
        int readByte() throws IOException {
            while (true) {
                try {
                    int b = in.read();
                    if (b >= 0) lastActivity.set(System.nanoTime());
                    return b;
                } catch (SocketTimeoutException e) {
                    if (idleNanos <= 0 || System.nanoTime() - lastActivity.get() >= idleNanos) {
                        throw new IdleTimeout();
                    }
                }
            }
        }

        /**
         * Copies until end-of-stream. A buffer is held only while data keeps arriving; before
         * blocking on a quiet peer it goes back to the pool and the wait is for a single byte.
         */
        void copyAll() throws IOException {
            byte[] buf = null;
            try {
                while (true) {
                    int n;
                    if (buf == null) {
                        int first = readByte();
                        if (first < 0) return;
                        buf = pool.take();
                        buf[0] = (byte) first;
                        n = 1;
                        int available = in.available();
                        if (available > 0) {
                            int more = read(buf, 1, Math.min(available, buf.length - 1));
                            if (more > 0) n += more;
                        }
                    } else {
                        n = read(buf, 0, buf.length);
                        if (n < 0) return;
                    }
                    out.write(buf, 0, n);
                    out.flush();
                    if (in.available() <= 0) {
                        pool.give(buf);
                        buf = null;
                    }
                }
            } finally {
                pool.give(buf);
            }
        }

        /** Copies exactly {@code remaining} bytes. */
        void copy(long remaining) throws IOException {
            byte[] buf = pool.take();
            try {
                while (remaining > 0) {
                    int n = read(buf, 0, (int) Math.min(buf.length, remaining));
                    if (n < 0) throw new EOFException("stream ended mid-frame");
                    out.write(buf, 0, n);
                    out.flush();
                    remaining -= n;
                }
            } finally {
                pool.give(buf);
            }
        }

        void halfClose() {
            try {
                out.flush();
                if (destination instanceof SSLSocket) {
                    // TLS half-close support varies by peer; closing is the safe choice.
                    destination.close();
                } else if (!destination.isClosed() && !destination.isOutputShutdown()) {
                    destination.shutdownOutput();
                }
            } catch (IOException | UnsupportedOperationException e) {
                Tls.closeQuietly(destination);
            }
        }
    }
}
