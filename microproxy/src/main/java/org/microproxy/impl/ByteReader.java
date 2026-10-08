package org.microproxy.impl;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.simd.Simd;

/**
 * A buffered reader over a blocking {@link InputStream} with bounded line reading. Unlike {@link
 * java.io.BufferedInputStream}, it can hand back the bytes it has buffered but not yet consumed,
 * which is needed when a connection switches from HTTP to a tunnel or to TLS.
 *
 * <p>The buffer is borrowed from a {@link BufferPool} when bytes arrive and given back once
 * consumed ({@link #release()}), and {@link #awaitNext()} waits for an idle peer without holding
 * one, so idle connections cost almost no memory.
 */
final class ByteReader {

    private final InputStream in;
    private final BufferPool pool;
    private byte[] buf;
    private int pos;
    private int limit;

    ByteReader(InputStream in, BufferPool pool) {
        this.in = in;
        this.pool = pool;
    }

    /** A reader with its own (unshared) buffers of {@code bufferSize} bytes. */
    ByteReader(InputStream in, int bufferSize) {
        this(in, new BufferPool(bufferSize, 1));
    }

    /** Reads at most {@code len} bytes, blocking until at least one is available; -1 at EOF. */
    int read(byte[] b, int off, int len) throws IOException {
        if (len == 0) return 0;
        if (pos < limit) {
            int n = Math.min(len, limit - pos);
            System.arraycopy(buf, pos, b, off, n);
            pos += n;
            return n;
        }
        if (len >= pool.size()) {
            release();
            return in.read(b, off, len);
        }
        if (!fill()) return -1;
        return read(b, off, len);
    }

    /** Reads one byte; with nothing buffered it blocks on the stream without holding a buffer. */
    int read() throws IOException {
        if (pos < limit) return buf[pos++] & 0xff;
        release();
        return in.read();
    }

    /**
     * Waits for the next bytes from a peer that may stay idle for a long time, without holding a
     * buffer while blocked: a single byte is read first, then a buffer is borrowed for the rest.
     * Returns immediately if bytes are already buffered.
     */
    void awaitNext() throws IOException {
        if (pos < limit) return;
        release();
        int first = in.read();
        if (first < 0) return;
        buf = pool.take();
        buf[0] = (byte) first;
        pos = 0;
        limit = 1;
        int available = in.available();
        if (available > 0) {
            int n = in.read(buf, 1, Math.min(available, buf.length - 1));
            if (n > 0) limit += n;
        }
    }

    /** Gives the buffer back to the pool if everything in it has been consumed. */
    void release() {
        if (buf != null && pos >= limit) {
            pool.give(buf);
            buf = null;
            pos = 0;
            limit = 0;
        }
    }

    void readFully(byte[] b, int off, int len) throws IOException {
        while (len > 0) {
            int n = read(b, off, len);
            if (n < 0) throw new EOFException("connection closed mid-message");
            off += n;
            len -= n;
        }
    }

    /**
     * Reads a line terminated by LF (an optional preceding CR is dropped), decoded as ISO-8859-1.
     *
     * @return the line, or {@code null} if the stream ended before any byte was read
     * @throws HttpParseException if the line exceeds {@code maxLength} bytes
     */
    String readLine(int maxLength, HttpResponseStatus tooLongStatus) throws IOException {
        StringBuilder sb = null;
        int length = 0;
        while (true) {
            if (pos >= limit && !fill()) {
                if (sb == null && length == 0) return null;
                throw new EOFException("connection closed mid-line");
            }
            int start = pos;
            int end = Simd.indexOf(buf, pos, limit, (byte) '\n');
            if (end >= 0) {
                pos = end + 1;
                length += end - start;
                if (length > maxLength + 1) {
                    throw new HttpParseException(tooLongStatus, "line too long");
                }
                if (sb == null) {
                    // The common case: the whole line is buffered; make one string without the CR.
                    int stop = end > start && buf[end - 1] == '\r' ? end - 1 : end;
                    return new String(buf, start, stop - start, StandardCharsets.ISO_8859_1);
                }
                String line = sb.append(new String(buf, start, end - start, StandardCharsets.ISO_8859_1)).toString();
                return line.endsWith("\r") ? line.substring(0, line.length() - 1) : line;
            }
            pos = limit;
            length += pos - start;
            if (length > maxLength + 1) {
                throw new HttpParseException(tooLongStatus, "line too long");
            }
            if (sb == null) sb = new StringBuilder(Math.min(maxLength, 256));
            sb.append(new String(buf, start, pos - start, StandardCharsets.ISO_8859_1));
        }
    }

    /**
     * Blocks until data (or end-of-stream) is available, without consuming anything. A socket read
     * timeout makes this return false and leaves the stream intact, so it can be used to wait a
     * bounded time for a peer before deciding what to do.
     */
    boolean awaitData() throws IOException {
        if (pos < limit) return true;
        try {
            fill();
            return true;
        } catch (SocketTimeoutException e) {
            return false;
        }
    }

    /** Number of bytes buffered and not yet consumed. */
    int buffered() {
        return limit - pos;
    }

    /** Removes and returns the buffered, unconsumed bytes. */
    byte[] drainBuffered() {
        if (buf == null) return new byte[0];
        byte[] out = Arrays.copyOfRange(buf, pos, limit);
        pos = limit;
        release();
        return out;
    }

    /** A view that reads buffered bytes first, then the underlying stream. */
    InputStream asInputStream() {
        return new InputStream() {
            @Override
            public int read() throws IOException {
                return ByteReader.this.read();
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                return ByteReader.this.read(b, off, len);
            }

            @Override
            public int available() throws IOException {
                return buffered() > 0 ? buffered() : in.available();
            }

            @Override
            public void close() throws IOException {
                in.close();
            }
        };
    }

    private boolean fill() throws IOException {
        if (buf == null) buf = pool.take();
        pos = 0;
        limit = 0;
        int n = in.read(buf, 0, buf.length);
        if (n <= 0) return false;
        limit = n;
        return true;
    }
}
