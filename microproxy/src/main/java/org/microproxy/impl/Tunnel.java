package org.microproxy.impl;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLSocket;
import org.microproxy.ResponseFlag;

/**
 * Relays bytes in both directions between two sockets until both directions finish, using one
 * extra virtual thread. End-of-stream on one side is propagated as a half-close to the other.
 * With an idle timeout, the tunnel closes only when neither direction has moved data for that
 * long.
 *
 * <p>For upgraded WebSocket connections a {@link WebSocketRelay} can parse frames and pass them,
 * and whole messages, to hooks that may forward, replace or drop them. For raw tunnels the relay
 * can pass the bytes of each read through a {@link TcpSession} instead; without either, bytes are
 * copied through pooled buffers.
 */
final class Tunnel {

    @FunctionalInterface
    interface HalfClose {
        void close() throws IOException;
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
            Duration idleTimeout, String name, String logPrefix, BufferPool pool) {
        relay(clientSocket, clientIn, clientOut, serverSocket, serverIn, serverOut, idleTimeout, name, logPrefix,
                null, null, pool);
    }

    /**
     * Relays bytes, parsing WebSocket frames when {@code webSocket} is non-null, or passing them
     * through {@code tcp} when that is.
     *
     * @param logPrefix starts each log line, naming the client connection
     * @param webSocket the frame relay for an upgraded WebSocket connection, or null for raw bytes
     * @param tcp the TCP hooks for a raw tunnel, or null
     */
    static void relay(
            Socket clientSocket, InputStream clientIn, OutputStream clientOut,
            Socket serverSocket, InputStream serverIn, OutputStream serverOut,
            Duration idleTimeout, String name, String logPrefix, WebSocketRelay webSocket, TcpSession tcp,
            BufferPool pool) {
        Runnable closeAll = () -> {
            Tls.closeQuietly(clientSocket);
            Tls.closeQuietly(serverSocket);
        };
        relay(clientIn, clientOut, () -> halfClose(clientSocket), serverIn, serverOut, () -> halfClose(serverSocket),
                closeAll, idleTimeout, name, logPrefix, webSocket, tcp, pool, null);
    }

    /**
     * The same relay, frame hooks and TCP hooks for sockets and multiplexed streams.
     *
     * @param webSocket the frame relay for an upgraded WebSocket connection, or null
     * @param tcp sees the bytes of each read, or null (never together with {@code webSocket})
     * @param counted counts the bytes read from the client (received) and from the server (sent
     *     on to the client), and an idle timeout, for the access log; or null
     */
    static void relay(InputStream clientIn, OutputStream clientOut, HalfClose clientEnd,
            InputStream serverIn, OutputStream serverOut, HalfClose serverEnd, Runnable closeAll,
            Duration idleTimeout, String name, String logPrefix, WebSocketRelay webSocket, TcpSession tcp,
            BufferPool pool, ClientFlowContext counted) {
        AtomicLong lastActivity = new AtomicLong(System.nanoTime());
        long idleNanos = idleTimeout == null ? 0 : idleTimeout.toNanos();
        Direction up = new Direction(clientIn, serverOut, serverEnd, lastActivity, idleNanos, true, pool, logPrefix);
        Direction down = new Direction(serverIn, clientOut, clientEnd, lastActivity, idleNanos, false, pool, logPrefix);
        up.counted = counted;
        down.counted = counted;
        if (webSocket != null) webSocket.attach(up, down);
        if (tcp != null) tcp.start(up.sink(), down.sink(), closeAll);
        Thread upstream = null;
        try {
            upstream = Thread.ofVirtual().name(name + "-up").start(() -> run(up, webSocket, tcp, closeAll));
            run(down, webSocket, tcp, closeAll);
            try {
                upstream.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        } finally {
            closeAll.run();
            if (tcp != null) tcp.finish();
            if (webSocket != null && upstream != null && !upstream.isAlive()) webSocket.end();
        }
    }

    static void halfClose(Socket destination) throws IOException {
        if (destination instanceof SSLSocket) {
            // Keep the existing TLS relay behavior; TLS peers differ in half-close support.
            destination.close();
        } else if (!destination.isClosed() && !destination.isOutputShutdown()) {
            destination.shutdownOutput();
        }
    }

    private static void run(Direction d, WebSocketRelay webSocket, TcpSession tcp, Runnable closeAll) {
        try {
            if (tcp != null) {
                pumpTcp(d, tcp);
                tcp.endOfStream(d.fromClient);
                return;
            }
            if (webSocket == null) {
                d.copyAll();
            } else {
                webSocket.pump(d);
            }
            d.halfClose();
        } catch (IOException | UnsupportedOperationException e) {
            if (e instanceof IdleTimeout && d.counted != null) {
                d.counted.addResponseFlag(ResponseFlag.STREAM_IDLE_TIMEOUT);
                d.counted.defaultResponseCodeDetails("stream_idle_timeout");
            }
            if (tcp != null) tcp.failed(d.fromClient, e instanceof IOException io ? io : new IOException(e));
            closeAll.run();
        }
    }

    /**
     * Hands the bytes of each read to {@code tcp} until end-of-stream. As {@link
     * Direction#copyAll}, it holds no buffer while waiting for a quiet peer; each message gets an
     * array of its own, as the interceptor may keep it.
     */
    private static void pumpTcp(Direction d, TcpSession tcp) throws IOException {
        while (true) {
            int first = d.readByte();
            if (first < 0) return;
            byte[] buf = d.pool.take();
            byte[] data;
            try {
                buf[0] = (byte) first;
                int n = 1;
                // Everything that arrived with it, without waiting for more. (A read with input
                // available returns what is there; some streams report only that there is some.)
                while (n < buf.length && d.in.available() > 0) {
                    int more = d.read(buf, n, buf.length - n);
                    if (more <= 0) break;
                    n += more;
                }
                data = Arrays.copyOf(buf, n);
            } finally {
                d.pool.give(buf);
            }
            tcp.message(d.fromClient, data);
        }
    }

    /** One direction of the tunnel. */
    static final class Direction {
        final InputStream in;
        final OutputStream out;
        final HalfClose destination;
        final AtomicLong lastActivity;
        final long idleNanos;
        final boolean fromClient;
        final BufferPool pool;
        final String logPrefix;
        /** Counts this direction's bytes for the access log, or null. */
        ClientFlowContext counted;

        Direction(InputStream in, OutputStream out, HalfClose destination, AtomicLong lastActivity,
                long idleNanos, boolean fromClient, BufferPool pool, String logPrefix) {
            this.pool = pool;
            this.logPrefix = logPrefix;
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
                    if (n > 0) {
                        lastActivity.set(System.nanoTime());
                        count(n);
                    }
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

        private void count(int n) {
            ClientFlowContext flow = counted;
            if (flow == null) return;
            if (fromClient) {
                flow.addBytesReceived(n);
            } else {
                flow.addBytesSent(n);
            }
        }

        void flush() throws IOException {
            out.flush();
        }

        /** Reads one byte, tolerating timeouts while the other direction is active. */
        int readByte() throws IOException {
            while (true) {
                try {
                    int b = in.read();
                    if (b >= 0) {
                        lastActivity.set(System.nanoTime());
                        count(1);
                    }
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

        /** Reads and discards exactly {@code remaining} bytes. */
        void skip(long remaining) throws IOException {
            byte[] buf = pool.take();
            try {
                while (remaining > 0) {
                    int n = read(buf, 0, (int) Math.min(buf.length, remaining));
                    if (n < 0) throw new EOFException("stream ended mid-frame");
                    remaining -= n;
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

        void halfClose() throws IOException {
            out.flush();
            destination.close();
        }

        /** Where a {@link TcpSession} writes this direction's bytes. */
        TcpSession.Sink sink() {
            return new TcpSession.Sink() {
                @Override
                public void write(byte[] data) throws IOException {
                    out.write(data, 0, data.length);
                    out.flush();
                }

                @Override
                public void end() throws IOException {
                    halfClose();
                }
            };
        }
    }
}
