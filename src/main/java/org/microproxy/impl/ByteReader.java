package org.microproxy.impl;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.microproxy.http.HttpResponseStatus;

/**
 * A buffered reader over a blocking {@link InputStream} with bounded line reading. Unlike {@link
 * java.io.BufferedInputStream}, it can hand back the bytes it has buffered but not yet consumed,
 * which is needed when a connection switches from HTTP to a tunnel or to TLS.
 */
final class ByteReader {

    private final InputStream in;
    private final byte[] buf;
    private int pos;
    private int limit;

    ByteReader(InputStream in, int bufferSize) {
        this.in = in;
        this.buf = new byte[bufferSize];
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
        if (len >= buf.length) {
            return in.read(b, off, len);
        }
        if (!fill()) return -1;
        return read(b, off, len);
    }

    int read() throws IOException {
        if (pos >= limit && !fill()) return -1;
        return buf[pos++] & 0xff;
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
            while (pos < limit) {
                if (buf[pos] == '\n') {
                    int end = pos;
                    pos++;
                    String part = new String(buf, start, end - start, StandardCharsets.ISO_8859_1);
                    length += end - start;
                    if (length > maxLength + 1) {
                        throw new HttpParseException(tooLongStatus, "line too long");
                    }
                    String line = sb == null ? part : sb.append(part).toString();
                    return line.endsWith("\r") ? line.substring(0, line.length() - 1) : line;
                }
                pos++;
            }
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
        } catch (java.net.SocketTimeoutException e) {
            return false;
        }
    }

    /** Number of bytes buffered and not yet consumed. */
    int buffered() {
        return limit - pos;
    }

    /** Removes and returns the buffered, unconsumed bytes. */
    byte[] drainBuffered() {
        byte[] out = Arrays.copyOfRange(buf, pos, limit);
        pos = limit;
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
        pos = 0;
        limit = 0;
        int n = in.read(buf, 0, buf.length);
        if (n <= 0) return false;
        limit = n;
        return true;
    }
}
