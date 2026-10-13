package org.microproxy.bench;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

/**
 * The origin server every benchmark talks to through either proxy: a minimal blocking HTTP/1.1
 * server on its own pool of platform threads, one per connection, that serves fixed responses.
 * It shares no code with either proxy (no MicroProxy internals, no Netty), so neither proxy is
 * favoured by it.
 *
 * <p>It answers every request with {@code 200}, a {@code Content-Length} and keep-alive, unless the
 * request asked for {@code Connection: close}:
 *
 * <ul>
 *   <li>{@code GET /b/<n>}: a body of {@code n} bytes. Responses are prebuilt once per size, so
 *       serving one is a single write (or a header and slices of one shared array, for large ones).
 *   <li>any request with a body ({@code Content-Length} or chunked): the body is read and
 *       discarded, and the answer is an empty body with {@code X-Received: <bytes read>}.
 * </ul>
 *
 * <p>A request carrying {@link #ECHO_TRIGGER} gets {@link #ECHO_HEADER} in its response, so the
 * filter benchmark can check that a proxy's filter added the request header.
 *
 * <p>The same server listens on a plain socket ({@link #plainAddress()}) and, when given a TLS
 * context, on a TLS socket ({@link #tlsAddress()}) for the MITM benchmarks.
 */
public final class Origin implements Closeable {

    /** The request header whose presence the origin reports back ({@link #ECHO_HEADER}). */
    public static final String ECHO_TRIGGER = "X-Bench-Req";

    /** The response header the origin adds when the request carried {@link #ECHO_TRIGGER}. */
    public static final String ECHO_HEADER = "X-Bench-Echo";

    /** Large bodies are written from this one shared array, a slice at a time. */
    private static final int SLICE = 64 * 1024;

    /** Bodies up to this size are prebuilt into the same array as their head: a single write. */
    private static final int PREBUILT_LIMIT = 256 * 1024;

    private static final byte[] FILLER = filler(SLICE);
    private static final byte[] CONTENT_LENGTH = lower("content-length:");
    private static final byte[] TRANSFER_ENCODING = lower("transfer-encoding:");
    private static final byte[] CONNECTION = lower("connection:");
    private static final byte[] ECHO_TRIGGER_BYTES = lower(ECHO_TRIGGER + ":");
    private static final byte[] CLOSE = lower("close");
    private static final byte[] CHUNKED = lower("chunked");

    private final ServerSocket plain;
    private final ServerSocket tls;
    private final ExecutorService workers;
    private final Set<Socket> open = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<Long, byte[]> prebuilt = new ConcurrentHashMap<>();
    private volatile boolean closed;

    private Origin(ServerSocket plain, ServerSocket tls) {
        this.plain = plain;
        this.tls = tls;
        AtomicInteger ids = new AtomicInteger();
        // Platform threads, one per connection, with small stacks: thousands of idle keep-alive
        // connections from the concurrency benchmark must fit.
        this.workers = new ThreadPoolExecutor(0, Integer.MAX_VALUE, 30, TimeUnit.SECONDS, new SynchronousQueue<>(),
                r -> {
                    Thread t = new Thread(null, r, "origin-" + ids.incrementAndGet(), 256 * 1024);
                    t.setDaemon(true);
                    return t;
                });
    }

    /**
     * Starts an origin on loopback, on ephemeral ports.
     *
     * @param tlsContext the context of the TLS listener, or {@code null} for none
     * @return the running origin
     * @throws IOException if a listener cannot be bound
     */
    public static Origin start(SSLContext tlsContext) throws IOException {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        ServerSocket plain = new ServerSocket(0, 4096, loopback);
        ServerSocket tls = null;
        if (tlsContext != null) {
            SSLServerSocket s = (SSLServerSocket) tlsContext.getServerSocketFactory().createServerSocket(0, 4096, loopback);
            s.setEnabledProtocols(new String[] {"TLSv1.3"});
            tls = s;
        }
        Origin origin = new Origin(plain, tls);
        origin.acceptOn(plain);
        if (tls != null) origin.acceptOn(tls);
        return origin;
    }

    /** {@return the address of the plain HTTP listener} */
    public InetSocketAddress plainAddress() {
        return (InetSocketAddress) plain.getLocalSocketAddress();
    }

    /** {@return the address of the TLS listener, or {@code null} without one} */
    public InetSocketAddress tlsAddress() {
        return tls == null ? null : (InetSocketAddress) tls.getLocalSocketAddress();
    }

    /** {@return how many connections the origin has open now} */
    public int openConnections() {
        return open.size();
    }

    private void acceptOn(ServerSocket listener) {
        Thread acceptor = new Thread(() -> {
            while (!closed) {
                Socket s;
                try {
                    s = listener.accept();
                } catch (IOException e) {
                    return;
                }
                try {
                    workers.execute(() -> serve(s));
                } catch (RuntimeException e) {
                    closeQuietly(s);
                }
            }
        }, "origin-accept-" + listener.getLocalPort());
        acceptor.setDaemon(true);
        acceptor.start();
    }

    private void serve(Socket socket) {
        open.add(socket);
        try (socket) {
            socket.setTcpNoDelay(true);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            RequestReader reader = new RequestReader(in);
            while (!closed) {
                if (!reader.readHead()) return;
                long received = reader.skipBody();
                byte[] head;
                long bodyLength;
                if (received >= 0) {
                    head = uploadHead(received, reader.close, reader.echo);
                    bodyLength = 0;
                } else {
                    bodyLength = reader.sizeFromPath();
                    if (bodyLength < 0) {
                        out.write(NOT_FOUND);
                        return;
                    }
                    head = null;
                }
                if (head != null) {
                    out.write(head);
                } else if (bodyLength <= PREBUILT_LIMIT) {
                    out.write(prebuiltResponse(bodyLength, reader.close, reader.echo));
                } else {
                    out.write(responseHead(bodyLength, reader.close, reader.echo));
                    for (long left = bodyLength; left > 0; ) {
                        int n = (int) Math.min(left, SLICE);
                        out.write(FILLER, 0, n);
                        left -= n;
                    }
                }
                out.flush();
                if (reader.close) return;
            }
        } catch (IOException | RuntimeException e) {
            // the peer went away, or the origin is closing
        } finally {
            open.remove(socket);
        }
    }

    private static final byte[] NOT_FOUND =
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);

    private byte[] prebuiltResponse(long size, boolean close, boolean echo) {
        long key = (size << 2) | (close ? 2 : 0) | (echo ? 1 : 0);
        byte[] cached = prebuilt.get(key);
        if (cached != null) return cached;
        byte[] head = responseHead(size, close, echo);
        byte[] full = Arrays.copyOf(head, head.length + (int) size);
        for (int i = head.length; i < full.length; i++) full[i] = FILLER[(i - head.length) % FILLER.length];
        prebuilt.putIfAbsent(key, full);
        return full;
    }

    private static byte[] responseHead(long size, boolean close, boolean echo) {
        return ("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " + size + "\r\n"
                + (echo ? ECHO_HEADER + ": 1\r\n" : "")
                + (close ? "Connection: close\r\n" : "")
                + "\r\n").getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] uploadHead(long received, boolean close, boolean echo) {
        return ("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Received: " + received + "\r\n"
                + (echo ? ECHO_HEADER + ": 1\r\n" : "")
                + (close ? "Connection: close\r\n" : "")
                + "\r\n").getBytes(StandardCharsets.ISO_8859_1);
    }

    @Override
    public void close() {
        closed = true;
        closeQuietly(plain);
        if (tls != null) closeQuietly(tls);
        for (Socket s : open) closeQuietly(s);
        workers.shutdownNow();
    }

    private static void closeQuietly(Closeable c) {
        try {
            c.close();
        } catch (IOException ignored) {
            // closing anyway
        }
    }

    private static byte[] filler(int size) {
        byte[] b = new byte[size];
        for (int i = 0; i < size; i++) b[i] = (byte) ('a' + i % 26);
        return b;
    }

    private static byte[] lower(String s) {
        return s.toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.ISO_8859_1);
    }

    /** Reads request heads and bodies from one connection, without allocating per request. */
    private static final class RequestReader {
        private final InputStream in;
        private final byte[] buf = new byte[16 * 1024];
        private int pos;
        private int limit;

        // The current request's head: [headStart, headEnd) holds it, CRLF CRLF included.
        private int headStart;
        private int headEnd;
        private long contentLength;
        private boolean chunked;
        boolean close;
        boolean echo;

        RequestReader(InputStream in) {
            this.in = in;
        }

        /** Reads the next request's head; false on a clean end of the connection. */
        boolean readHead() throws IOException {
            if (pos == limit) {
                pos = 0;
                limit = 0;
            } else if (pos > buf.length / 2) {
                System.arraycopy(buf, pos, buf, 0, limit - pos);
                limit -= pos;
                pos = 0;
            }
            int scanFrom = pos;
            while (true) {
                int end = indexOfHeadEnd(buf, scanFrom, limit);
                if (end >= 0) {
                    headStart = pos;
                    headEnd = end;
                    pos = end;
                    parseHead();
                    return true;
                }
                scanFrom = Math.max(pos, limit - 3);
                if (limit == buf.length) {
                    if (pos == 0) throw new IOException("request head too large");
                    System.arraycopy(buf, pos, buf, 0, limit - pos);
                    limit -= pos;
                    scanFrom -= pos;
                    pos = 0;
                }
                int n = in.read(buf, limit, buf.length - limit);
                if (n < 0) {
                    if (limit == pos) return false;
                    throw new EOFException("connection closed inside a request head");
                }
                limit += n;
            }
        }

        private void parseHead() {
            contentLength = -1;
            chunked = false;
            close = false;
            echo = false;
            int line = nextLine(headStart);
            while (line < headEnd - 2) {
                int eol = nextLine(line);
                int valueEnd = eol - 2;
                if (startsWithIgnoreCase(line, CONTENT_LENGTH)) {
                    contentLength = parseLong(line + CONTENT_LENGTH.length, valueEnd);
                } else if (startsWithIgnoreCase(line, TRANSFER_ENCODING)) {
                    chunked = containsIgnoreCase(line + TRANSFER_ENCODING.length, valueEnd, CHUNKED);
                } else if (startsWithIgnoreCase(line, CONNECTION)) {
                    close = containsIgnoreCase(line + CONNECTION.length, valueEnd, CLOSE);
                } else if (startsWithIgnoreCase(line, ECHO_TRIGGER_BYTES)) {
                    echo = true;
                }
                line = eol;
            }
        }

        /** The body size a {@code GET /b/<n>} asks for, or -1 for any other target. */
        long sizeFromPath() {
            int sp = headStart;
            while (sp < headEnd && buf[sp] != ' ') sp++;
            int i = sp + 1;
            // An absolute-form target (from a proxy that kept it) is reduced to its path.
            if (i < headEnd && buf[i] != '/') {
                int scheme = i;
                while (scheme + 2 < headEnd
                        && !(buf[scheme] == ':' && buf[scheme + 1] == '/' && buf[scheme + 2] == '/')) {
                    scheme++;
                }
                i = scheme + 3;
                while (i < headEnd && buf[i] != '/' && buf[i] != ' ') i++;
            }
            if (i + 3 >= headEnd || buf[i] != '/' || buf[i + 1] != 'b' || buf[i + 2] != '/') return -1;
            i += 3;
            long n = 0;
            int digits = 0;
            while (i < headEnd && buf[i] >= '0' && buf[i] <= '9') {
                n = n * 10 + (buf[i++] - '0');
                digits++;
            }
            return digits == 0 ? -1 : n;
        }

        /** Reads and discards the request's body: its length, or -1 when it has none. */
        long skipBody() throws IOException {
            if (chunked) return skipChunked();
            if (contentLength <= 0) return contentLength == 0 ? 0 : -1;
            long left = contentLength;
            int buffered = Math.min(limit - pos, (int) Math.min(left, Integer.MAX_VALUE));
            pos += buffered;
            left -= buffered;
            while (left > 0) {
                int n = in.read(buf, 0, (int) Math.min(buf.length, left));
                if (n < 0) throw new EOFException("connection closed inside a request body");
                left -= n;
            }
            if (pos == limit) {
                pos = 0;
                limit = 0;
            }
            return contentLength;
        }

        private long skipChunked() throws IOException {
            long total = 0;
            while (true) {
                long size = readChunkSize();
                if (size == 0) {
                    // Trailers, up to the empty line.
                    while (readLineLength() > 0) {
                        // skip
                    }
                    return total;
                }
                for (long left = size; left > 0; ) {
                    if (pos == limit) fill();
                    int n = (int) Math.min(left, limit - pos);
                    pos += n;
                    left -= n;
                }
                total += size;
                readLineLength();
            }
        }

        private long readChunkSize() throws IOException {
            long size = 0;
            boolean inExtension = false;
            while (true) {
                if (pos == limit) fill();
                byte b = buf[pos++];
                if (b == '\n') return size;
                if (b == '\r' || inExtension) continue;
                if (b == ';') {
                    inExtension = true;
                    continue;
                }
                int digit = Character.digit(b, 16);
                if (digit < 0) throw new IOException("bad chunk size");
                size = size * 16 + digit;
            }
        }

        private int readLineLength() throws IOException {
            int length = 0;
            while (true) {
                if (pos == limit) fill();
                byte b = buf[pos++];
                if (b == '\n') return length;
                if (b != '\r') length++;
            }
        }

        private void fill() throws IOException {
            pos = 0;
            limit = 0;
            int n = in.read(buf, 0, buf.length);
            if (n < 0) throw new EOFException("connection closed inside a request body");
            limit = n;
        }

        private int nextLine(int from) {
            for (int i = from; i < headEnd - 1; i++) {
                if (buf[i] == '\r' && buf[i + 1] == '\n') return i + 2;
            }
            return headEnd;
        }

        private boolean startsWithIgnoreCase(int at, byte[] lowerPrefix) {
            if (at + lowerPrefix.length > headEnd) return false;
            for (int i = 0; i < lowerPrefix.length; i++) {
                if (toLower(buf[at + i]) != lowerPrefix[i]) return false;
            }
            return true;
        }

        private boolean containsIgnoreCase(int from, int to, byte[] lowerNeedle) {
            outer:
            for (int i = from; i + lowerNeedle.length <= to; i++) {
                for (int j = 0; j < lowerNeedle.length; j++) {
                    if (toLower(buf[i + j]) != lowerNeedle[j]) continue outer;
                }
                return true;
            }
            return false;
        }

        private long parseLong(int from, int to) {
            long n = 0;
            for (int i = from; i < to; i++) {
                byte b = buf[i];
                if (b >= '0' && b <= '9') n = n * 10 + (b - '0');
            }
            return n;
        }
    }

    static byte toLower(byte b) {
        return b >= 'A' && b <= 'Z' ? (byte) (b + 32) : b;
    }

    /** The index just past the first CRLF CRLF in {@code buf[from, limit)}, or -1. */
    static int indexOfHeadEnd(byte[] buf, int from, int limit) {
        for (int i = from; i + 3 < limit; i++) {
            if (buf[i + 3] == '\n' && buf[i + 2] == '\r' && buf[i + 1] == '\n' && buf[i] == '\r') return i + 4;
        }
        return -1;
    }
}
