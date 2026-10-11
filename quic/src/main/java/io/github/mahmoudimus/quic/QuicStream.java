package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.Connection;
import io.github.mahmoudimus.quic.connection.Dir;
import io.github.mahmoudimus.quic.connection.StreamException;
import io.github.mahmoudimus.quic.connection.StreamId;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * One QUIC stream of a {@link QuicConnection}, with blocking {@link InputStream} and {@link
 * OutputStream} views. A bidirectional stream has both; a unidirectional stream has only the side
 * its direction allows: output on the side that opened it, input on the other.
 *
 * <ul>
 *   <li>The output stream copies what is written and blocks while flow control or the send window
 *       hold data back; {@code close()} sends the FIN.
 *   <li>The input stream blocks until data arrives and returns -1 after the FIN; it throws a {@link
 *       QuicStreamException} if the peer reset the stream.
 *   <li>{@link #reset(long)} abandons sending (RESET_STREAM); {@link #stopSending(long)} asks the
 *       peer to stop (STOP_SENDING); writes then fail with a {@link QuicStreamException}.
 * </ul>
 *
 * <p>The views are safe to use from different threads, though one reader and one writer at a time
 * is the sensible pattern.
 */
public final class QuicStream implements Closeable {

    private final QuicConnection connection;
    private final ConnectionDriver driver;
    private final Connection conn;
    private final StreamId id;
    private final boolean local;
    private final Input input;
    private final Output output;

    QuicStream(QuicConnection connection, StreamId id, boolean local) {
        this.connection = connection;
        this.driver = connection.driver();
        this.conn = connection.connection();
        this.id = id;
        this.local = local;
        boolean bidi = id.dir() == Dir.BI;
        this.input = bidi || !local ? new Input() : null;
        this.output = bidi || local ? new Output() : null;
    }

    /**
     * The stream ID (RFC 9000 section 2.1).
     *
     * @return the ID
     */
    public long id() {
        return id.value();
    }

    /**
     * Whether the stream is bidirectional.
     *
     * @return true for a bidirectional stream
     */
    public boolean isBidirectional() {
        return id.dir() == Dir.BI;
    }

    /**
     * Server: whether any of the stream's data arrived in 0-RTT packets. Such data may be a replay
     * of an earlier connection's (RFC 8446 section 8); act on it only if that is safe, or wait for
     * {@link QuicConnection#awaitHandshake(java.time.Duration) the handshake}.
     *
     * @return true if the peer sent part of the stream as early data
     */
    public boolean receivedEarlyData() {
        return connection.withLock(() -> conn.receivedEarlyData(id));
    }

    /**
     * Whether this side opened the stream.
     *
     * @return true for a locally opened stream
     */
    public boolean isLocal() {
        return local;
    }

    /**
     * The connection.
     *
     * @return the connection
     */
    public QuicConnection connection() {
        return connection;
    }

    /**
     * The stream's data from the peer.
     *
     * @return the input stream
     * @throws IllegalStateException for a unidirectional stream this side opened
     */
    public InputStream getInputStream() {
        if (input == null) {
            throw new IllegalStateException("send-only stream " + id);
        }
        return input;
    }

    /**
     * The stream's data to the peer.
     *
     * @return the output stream; closing it sends the FIN
     * @throws IllegalStateException for a unidirectional stream the peer opened
     */
    public OutputStream getOutputStream() {
        if (output == null) {
            throw new IllegalStateException("receive-only stream " + id);
        }
        return output;
    }

    /**
     * Abandons sending (RESET_STREAM): unsent and unacknowledged data is discarded.
     *
     * @param errorCode the application error code
     * @throws IOException if the connection is gone or the stream was already reset or finished
     *     and acknowledged
     */
    public void reset(long errorCode) throws IOException {
        if (output == null) {
            throw new IllegalStateException("receive-only stream " + id);
        }
        driver.lock.lock();
        try {
            connection.checkOpen();
            output.closed = true;
            conn.resetStream(id, errorCode);
        } catch (StreamException e) {
            throw new IOException("cannot reset " + id + ": " + e.getMessage());
        } finally {
            driver.lock.unlock();
        }
        driver.wake();
    }

    /**
     * Asks the peer to stop sending (STOP_SENDING); data not yet read is discarded.
     *
     * @param errorCode the application error code
     * @throws IOException if the connection is gone or the stream is already finished
     */
    public void stopSending(long errorCode) throws IOException {
        if (input == null) {
            throw new IllegalStateException("send-only stream " + id);
        }
        driver.lock.lock();
        try {
            connection.checkOpen();
            input.stopped = true;
            conn.stopSending(id, errorCode);
        } catch (StreamException e) {
            throw new IOException("cannot stop " + id + ": " + e.getMessage());
        } finally {
            driver.lock.unlock();
        }
        driver.wake();
    }

    /**
     * Closes both directions: sends the FIN if the output is open, and STOP_SENDING (code 0) if the
     * input was not read to its end.
     *
     * @throws IOException if the connection is gone
     */
    @Override
    public void close() throws IOException {
        if (output != null) {
            output.close();
        }
        if (input != null) {
            input.close();
        }
    }

    @Override
    public String toString() {
        return "QuicStream[" + id + "]";
    }

    private final class Input extends InputStream {
        boolean eof;
        boolean stopped;
        QuicStreamException reset;

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            Objects.checkFromIndexSize(off, len, b.length);
            if (len == 0) {
                return 0;
            }
            int n;
            driver.lock.lock();
            try {
                while (true) {
                    if (eof) {
                        return -1;
                    }
                    if (reset != null) {
                        throw new QuicStreamException(reset.kind(), reset.errorCode());
                    }
                    if (stopped) {
                        throw new IOException("stream " + id + " was stopped");
                    }
                    try {
                        n = conn.read(id, ByteBuffer.wrap(b, off, len));
                    } catch (StreamException e) {
                        switch (e.kind()) {
                            case BLOCKED -> {
                                connection.checkOpen();
                                connection.await();
                                continue;
                            }
                            case RESET -> {
                                reset = new QuicStreamException(QuicStreamException.Kind.RESET, e.errorCode());
                                throw reset;
                            }
                            default -> {
                                connection.checkOpen();
                                throw new IOException("stream " + id + ": " + e.getMessage());
                            }
                        }
                    }
                    if (n < 0) {
                        eof = true;
                        conn.releaseRead(id);
                        return -1;
                    }
                    break;
                }
            } finally {
                driver.lock.unlock();
            }
            driver.wake(); // reading may have earned the peer more credit
            return n;
        }

        @Override
        public void close() throws IOException {
            driver.lock.lock();
            try {
                if (eof || stopped || reset != null || driver.lostReason() != null) {
                    return;
                }
                stopped = true;
                try {
                    conn.stopSending(id, 0);
                } catch (StreamException e) {
                    return; // already finished or reset
                }
            } finally {
                driver.lock.unlock();
            }
            driver.wake();
        }
    }

    private final class Output extends OutputStream {
        boolean closed;

        @Override
        public void write(int b) throws IOException {
            write(new byte[] {(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            Objects.checkFromIndexSize(off, len, b.length);
            ByteBuffer data = ByteBuffer.wrap(b, off, len);
            while (data.hasRemaining()) {
                driver.lock.lock();
                try {
                    while (true) {
                        if (closed) {
                            throw new IOException("stream " + id + " output is closed");
                        }
                        connection.checkOpen();
                        try {
                            conn.write(id, data);
                            break;
                        } catch (StreamException e) {
                            switch (e.kind()) {
                                case BLOCKED -> connection.await();
                                case STOPPED -> throw new QuicStreamException(QuicStreamException.Kind.STOPPED,
                                        e.errorCode());
                                default -> {
                                    connection.checkOpen();
                                    throw new IOException("stream " + id + ": " + e.getMessage());
                                }
                            }
                        }
                    }
                } finally {
                    driver.lock.unlock();
                }
                driver.wake();
            }
        }

        @Override
        public void close() throws IOException {
            driver.lock.lock();
            try {
                if (closed) {
                    return;
                }
                closed = true;
                connection.checkOpen();
                try {
                    conn.finish(id);
                } catch (StreamException e) {
                    if (e.kind() == StreamException.Kind.STOPPED) {
                        throw new QuicStreamException(QuicStreamException.Kind.STOPPED, e.errorCode());
                    }
                    // already finished or reset
                }
            } finally {
                driver.lock.unlock();
            }
            driver.wake();
        }
    }
}
