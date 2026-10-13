package org.microproxy.loadtest.client;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * One keep-alive HTTP/1.1 connection from the load generator to the proxy, sending absolute-form
 * requests as a forward-proxy client does. Written for the harness: a minimal blocking client that
 * validates every response by status and body length (Content-Length, chunked, or to the end of
 * the connection).
 */
public final class HttpConn implements Closeable {

    private static final byte[] UPLOAD = new byte[64 * 1024];

    static {
        for (int i = 0; i < UPLOAD.length; i++) UPLOAD[i] = (byte) ('A' + i % 26);
    }

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private boolean usable = true;
    // Allocated on the first body read, so an idle held connection (the ramp holds tens of
    // thousands) keeps only the small buffered stream, not a 64 KB transfer buffer.
    private byte[] buf;

    private HttpConn(Socket socket) throws IOException {
        this.socket = socket;
        // A small per-connection buffer: the ramp holds many idle connections, and the bodies are
        // drained through the larger lazy buffer below.
        this.in = new BufferedInputStream(socket.getInputStream(), 4 * 1024);
        this.out = socket.getOutputStream();
    }

    private byte[] buf() {
        if (buf == null) buf = new byte[64 * 1024];
        return buf;
    }

    /** What to send and what to expect back. */
    public record Target(byte[] head, long uploadBytes, int expectStatus, long expectLength, String url) {

        /**
         * A request for {@code url} (absolute, http), expecting {@code expectStatus} and
         * {@code expectLength} body bytes (-1: any). With {@code uploadBytes} > 0 it is a POST of
         * that many bytes.
         */
        public static Target of(String url, int expectStatus, long expectLength, long uploadBytes) {
            URI u = URI.create(url);
            String host = u.getHost() + (u.getPort() > 0 ? ":" + u.getPort() : "");
            String method = uploadBytes > 0 ? "POST" : "GET";
            String head = method + " " + url + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: microproxy-loadtest\r\n"
                    + (uploadBytes > 0 ? "Content-Type: application/octet-stream\r\nContent-Length: " + uploadBytes + "\r\n" : "")
                    + "\r\n";
            return new Target(head.getBytes(StandardCharsets.US_ASCII), uploadBytes, expectStatus, expectLength, url);
        }
    }

    /** How an exchange ended. */
    public record Result(Outcome outcome, int status, long bodyBytes, String detail) {}

    /**
     * Connects to the proxy at {@code proxy}, from {@code source} (null: any), with the given
     * timeouts; {@code rcvBuf} > 0 sets a small receive buffer (for slow readers).
     */
    public static HttpConn open(InetSocketAddress proxy, InetAddress source, int connectTimeoutMs, int readTimeoutMs,
            int rcvBuf) throws IOException {
        Socket s = new Socket();
        try {
            if (rcvBuf > 0) s.setReceiveBufferSize(rcvBuf);
            s.setTcpNoDelay(true);
            if (source != null) s.bind(new InetSocketAddress(source, 0));
            s.connect(proxy, connectTimeoutMs);
            s.setSoTimeout(readTimeoutMs);
            return new HttpConn(s);
        } catch (IOException | RuntimeException e) {
            try {
                s.close();
            } catch (IOException ignored) {
                // Already failed.
            }
            throw e;
        }
    }

    /** The socket, for attacks that write by hand. */
    public Socket socket() {
        return socket;
    }

    /** The buffered input. */
    public InputStream input() {
        return in;
    }

    /** Whether the connection can carry another request. */
    public boolean usable() {
        return usable && !socket.isClosed();
    }

    /** Sends {@code t} and reads the whole response. */
    public Result exchange(Target t) {
        return exchange(t, 0, Long.MAX_VALUE);
    }

    /**
     * Sends {@code t} and reads the response, reading the body at {@code readRate} bytes a second
     * (0: as fast as possible) until {@code deadlineNanos}. Any failure leaves the connection
     * unusable.
     */
    public Result exchange(Target t, long readRate, long deadlineNanos) {
        boolean inBody = false;
        try {
            out.write(t.head());
            if (t.uploadBytes() > 0) {
                long left = t.uploadBytes();
                while (left > 0) {
                    int c = (int) Math.min(left, UPLOAD.length);
                    out.write(UPLOAD, 0, c);
                    left -= c;
                }
            }
            out.flush();
            String status = readLine(true);
            String[] f = status.split(" ", 3);
            if (f.length < 2 || !f[0].startsWith("HTTP/")) {
                usable = false;
                return new Result(Outcome.IO_ERROR, -1, 0, "bad status line: " + status);
            }
            int code = Integer.parseInt(f[1]);
            boolean http10 = f[0].equals("HTTP/1.0");
            long length = -1;
            boolean chunked = false;
            boolean close = http10;
            while (true) {
                String h = readLine(false);
                if (h.isEmpty()) break;
                int colon = h.indexOf(':');
                if (colon < 0) continue;
                String name = h.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                String value = h.substring(colon + 1).trim().toLowerCase(Locale.ROOT);
                switch (name) {
                    case "content-length" -> length = Long.parseLong(value);
                    case "transfer-encoding" -> chunked = value.contains("chunked");
                    case "connection", "proxy-connection" -> {
                        if (value.contains("close")) close = true;
                        else if (value.contains("keep-alive")) close = false;
                    }
                    default -> {
                        // Ignored.
                    }
                }
            }
            inBody = true;
            long body;
            if (code == 204 || code == 304 || (code >= 100 && code < 200)) {
                body = 0;
            } else if (chunked) {
                body = readChunked(readRate, deadlineNanos);
            } else if (length >= 0) {
                body = skip(length, readRate, deadlineNanos);
                if (body < length) {
                    usable = false;
                    return new Result(Outcome.TRUNCATED, code, body, "stopped at the deadline");
                }
            } else {
                body = skip(Long.MAX_VALUE, readRate, deadlineNanos);
                close = true;
            }
            if (close) usable = false;
            if (code != t.expectStatus()) return new Result(Outcome.BAD_STATUS, code, body, null);
            if (t.expectLength() >= 0 && body != t.expectLength()) {
                return new Result(Outcome.BAD_LENGTH, code, body, "expected " + t.expectLength());
            }
            return new Result(Outcome.OK, code, body, null);
        } catch (IOException e) {
            usable = false;
            return new Result(Outcome.of(e, false, inBody), -1, 0, String.valueOf(e.getMessage()));
        } catch (RuntimeException e) {
            usable = false;
            return new Result(Outcome.IO_ERROR, -1, 0, e.toString());
        }
    }

    private long readChunked(long readRate, long deadlineNanos) throws IOException {
        long total = 0;
        while (true) {
            String size = readLine(false);
            int semi = size.indexOf(';');
            long n = Long.parseLong((semi < 0 ? size : size.substring(0, semi)).trim(), 16);
            if (n == 0) {
                while (!readLine(false).isEmpty()) {
                    // Trailers.
                }
                return total;
            }
            long got = skip(n, readRate, deadlineNanos);
            total += got;
            if (got < n) throw new EOFException("deadline inside a chunk");
            readLine(false);
        }
    }

    /** Reads and discards up to {@code n} bytes; at end of stream returns fewer only when n is unbounded. */
    private long skip(long n, long readRate, long deadlineNanos) throws IOException {
        long total = 0;
        long start = System.nanoTime();
        byte[] buf = buf();
        int chunk = readRate > 0 ? (int) Math.max(256, Math.min(buf.length, readRate / 4)) : buf.length;
        while (total < n) {
            if (System.nanoTime() > deadlineNanos) return total;
            int r = in.read(buf, 0, (int) Math.min(chunk, n - total));
            if (r < 0) {
                if (n == Long.MAX_VALUE) return total;
                throw new EOFException("connection closed after " + total + " body bytes");
            }
            total += r;
            if (readRate > 0) {
                long due = start + total * 1_000_000_000L / readRate;
                long wait = Math.min(due, deadlineNanos) - System.nanoTime();
                if (wait > 0) {
                    try {
                        Thread.sleep(wait / 1_000_000, (int) (wait % 1_000_000));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return total;
                    }
                }
            }
        }
        return total;
    }

    private String readLine(boolean first) throws IOException {
        StringBuilder b = new StringBuilder(64);
        while (true) {
            int c = in.read();
            if (c < 0) {
                if (first && b.length() == 0) throw new EOFException("closed before a response");
                throw new EOFException("closed inside the response head");
            }
            if (c == '\n') return b.toString();
            if (c != '\r') b.append((char) c);
            if (b.length() > 64 * 1024) throw new IOException("response line too long");
        }
    }

    @Override
    public void close() {
        usable = false;
        try {
            socket.close();
        } catch (IOException e) {
            // Already closed.
        }
    }
}
