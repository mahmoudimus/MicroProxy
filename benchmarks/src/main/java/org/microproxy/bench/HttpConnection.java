package org.microproxy.bench;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/**
 * The benchmark client's side of one connection: a raw {@link Socket} speaking HTTP/1.1, with
 * requests built once up front and responses read up to their {@code Content-Length} and thrown
 * away. It allocates nothing per request after the first, so the client weighs as little as
 * possible, and the same for both proxies (the JDK's {@code HttpClient} would dominate the
 * measurements).
 *
 * <p>Every response is checked, so a broken proxy cannot post fast numbers: its status, its
 * {@code Content-Length} (a response without one fails), and optionally that it carries given
 * header fields. A check that fails throws {@link IllegalStateException}, which fails the benchmark.
 *
 * <p>Not thread-safe: one thread uses a connection at a time.
 */
public final class HttpConnection implements Closeable {

    private static final byte[] CONTENT_LENGTH = "content-length:".getBytes(StandardCharsets.ISO_8859_1);

    private Socket socket;
    private InputStream in;
    private OutputStream out;
    private final byte[] buf = new byte[16 * 1024];
    private int pos;
    private int limit;

    private HttpConnection(Socket socket) throws IOException {
        use(socket);
    }

    /**
     * Opens a connection to {@code address} (a proxy, or the origin itself).
     *
     * @param address where to connect
     * @return the open connection
     * @throws IOException if the connection fails
     */
    public static HttpConnection open(InetSocketAddress address) throws IOException {
        Socket socket = new Socket();
        try {
            socket.setTcpNoDelay(true);
            socket.connect(address, 10_000);
            socket.setSoTimeout(60_000);
            return new HttpConnection(socket);
        } catch (IOException | RuntimeException e) {
            socket.close();
            throw e;
        }
    }

    private void use(Socket s) throws IOException {
        this.socket = s;
        this.in = s.getInputStream();
        this.out = s.getOutputStream();
    }

    /**
     * Sends {@code CONNECT authority} and waits for the proxy's {@code 200}: the connection is a
     * tunnel to {@code authority} afterwards.
     *
     * @param authority the {@code host:port} to tunnel to
     * @throws IOException if the connection fails
     * @throws IllegalStateException if the proxy does not answer {@code 200}
     */
    public void connectTunnel(String authority) throws IOException {
        out.write(("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
        int headEnd = readHead();
        int status = status();
        if (status != 200) throw new IllegalStateException("CONNECT " + authority + " answered " + status);
        // A 200 to CONNECT has no body, whatever its headers say.
        pos = headEnd;
    }

    /**
     * Starts TLS on this connection (inside a tunnel, for an intercepted session), as a client
     * trusting {@code context}'s anchors and checking the certificate is for {@code host}, and
     * completes the handshake.
     *
     * @param context the client TLS context
     * @param host the server name to send and verify
     * @param port the server port
     * @throws IOException if the handshake fails
     */
    public void startTls(SSLContext context, String host, int port) throws IOException {
        if (pos != limit) throw new IllegalStateException("bytes left before the TLS handshake");
        SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(socket, host, port, true);
        tls.setUseClientMode(true);
        SSLParameters parameters = tls.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        tls.setSSLParameters(parameters);
        tls.startHandshake();
        use(tls);
    }

    /**
     * Writes a prebuilt request.
     *
     * @param request the request's bytes
     * @throws IOException if the write fails
     */
    public void send(byte[] request) throws IOException {
        out.write(request);
        out.flush();
    }

    /**
     * Writes a prebuilt request head followed by {@code bodyLength} bytes of {@code body}, sent
     * {@code body.length} at a time (the same array again and again for a large upload).
     *
     * @param head the request's head, ending with CRLF CRLF
     * @param body the bytes the body is made of
     * @param bodyLength the body's length, the {@code Content-Length} in {@code head}
     * @throws IOException if the write fails
     */
    public void send(byte[] head, byte[] body, long bodyLength) throws IOException {
        out.write(head);
        for (long left = bodyLength; left > 0; ) {
            int n = (int) Math.min(left, body.length);
            out.write(body, 0, n);
            left -= n;
        }
        out.flush();
    }

    /**
     * Reads one response, checks it and discards its body.
     *
     * @param expectedStatus the status the response must have
     * @param expectedLength the {@code Content-Length} it must have
     * @param requiredHeaders lower-case {@code name:} prefixes of header fields it must carry
     * @return the body's length
     * @throws IOException if the connection fails or ends early
     * @throws IllegalStateException if the response is not the one expected
     */
    public long readResponse(int expectedStatus, long expectedLength, byte[]... requiredHeaders) throws IOException {
        int headEnd = readHead();
        int status = status();
        long length = -1;
        int found = 0;
        int line = nextLine(pos, headEnd);
        while (line < headEnd - 2) {
            int eol = nextLine(line, headEnd);
            if (startsWithIgnoreCase(line, headEnd, CONTENT_LENGTH)) {
                length = parseLong(line + CONTENT_LENGTH.length, eol - 2);
            } else {
                for (byte[] required : requiredHeaders) {
                    if (startsWithIgnoreCase(line, headEnd, required)) found++;
                }
            }
            line = eol;
        }
        if (status != expectedStatus || length != expectedLength || found < requiredHeaders.length) {
            String head = new String(buf, pos, headEnd - pos, StandardCharsets.ISO_8859_1);
            throw new IllegalStateException("expected " + expectedStatus + " with Content-Length " + expectedLength
                    + (requiredHeaders.length > 0 ? " and " + requiredHeaders.length + " required header(s)" : "")
                    + ", got:\n" + head);
        }
        pos = headEnd;
        skip(length);
        return length;
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }

    /** Reads until the buffer holds a whole head starting at {@code pos}; returns its end. */
    private int readHead() throws IOException {
        if (pos == limit) {
            pos = 0;
            limit = 0;
        } else if (pos > 0) {
            System.arraycopy(buf, pos, buf, 0, limit - pos);
            limit -= pos;
            pos = 0;
        }
        int scanFrom = 0;
        while (true) {
            int end = Origin.indexOfHeadEnd(buf, scanFrom, limit);
            if (end >= 0) return end;
            scanFrom = Math.max(0, limit - 3);
            if (limit == buf.length) throw new IllegalStateException("response head too large");
            int n = in.read(buf, limit, buf.length - limit);
            if (n < 0) throw new EOFException("connection closed before a response head");
            limit += n;
        }
    }

    private int status() {
        // "HTTP/1.1 200 ..."
        if (limit - pos < 12 || buf[pos] != 'H') throw new IllegalStateException("not an HTTP response: "
                + new String(buf, pos, Math.min(limit - pos, 64), StandardCharsets.ISO_8859_1));
        return (buf[pos + 9] - '0') * 100 + (buf[pos + 10] - '0') * 10 + (buf[pos + 11] - '0');
    }

    private void skip(long length) throws IOException {
        long left = length;
        int buffered = (int) Math.min(left, limit - pos);
        pos += buffered;
        left -= buffered;
        if (left > 0) {
            // The rest of the body is read over the buffer, never past it.
            pos = 0;
            limit = 0;
            while (left > 0) {
                int n = in.read(buf, 0, (int) Math.min(buf.length, left));
                if (n < 0) throw new EOFException("connection closed inside a response body, " + left + " bytes short");
                left -= n;
            }
        }
    }

    private int nextLine(int from, int headEnd) {
        for (int i = from; i < headEnd - 1; i++) {
            if (buf[i] == '\r' && buf[i + 1] == '\n') return i + 2;
        }
        return headEnd;
    }

    private boolean startsWithIgnoreCase(int at, int headEnd, byte[] lowerPrefix) {
        if (at + lowerPrefix.length > headEnd) return false;
        for (int i = 0; i < lowerPrefix.length; i++) {
            if (Origin.toLower(buf[at + i]) != lowerPrefix[i]) return false;
        }
        return true;
    }

    private long parseLong(int from, int to) {
        long n = 0;
        for (int i = from; i < to; i++) {
            byte b = buf[i];
            if (b >= '0' && b <= '9') n = n * 10 + (b - '0');
        }
        return n;
    }

    /**
     * A header field name as {@link #readResponse} looks for it: lower case, with its colon.
     *
     * @param name the field name
     * @return the prefix to pass to {@link #readResponse}
     */
    public static byte[] headerPrefix(String name) {
        return (name.toLowerCase(Locale.ROOT) + ":").getBytes(StandardCharsets.ISO_8859_1);
    }

    /**
     * A whole header field as {@link #readResponse} looks for it: lower-case name, a space, the
     * value (compared exactly, so it should hold no letters) and the end of the line.
     *
     * @param name the field name
     * @param value the field value
     * @return the prefix to pass to {@link #readResponse}
     */
    public static byte[] headerLine(String name, String value) {
        return (name.toLowerCase(Locale.ROOT) + ": " + value + "\r").getBytes(StandardCharsets.ISO_8859_1);
    }

    /**
     * A {@code GET} for a body of {@code size} bytes from the origin: in absolute form for a
     * proxy, or in origin form inside a tunnel.
     *
     * @param origin the origin's address
     * @param size the body size to ask for
     * @param absolute whether to address a proxy (absolute form) rather than the origin itself
     * @param close whether to ask for {@code Connection: close}
     * @param extraHeaders more header lines, each ending with CRLF, or the empty string
     * @return the request's bytes
     */
    public static byte[] get(InetSocketAddress origin, long size, boolean absolute, boolean close, String extraHeaders) {
        String authority = authority(origin);
        String target = (absolute ? "http://" + authority : "") + "/b/" + size;
        return ("GET " + target + " HTTP/1.1\r\nHost: " + authority + "\r\n"
                + (close ? "Connection: close\r\n" : "") + extraHeaders + "\r\n").getBytes(StandardCharsets.ISO_8859_1);
    }

    /**
     * The head of a {@code POST} of {@code size} bytes to the origin, through a proxy.
     *
     * @param origin the origin's address
     * @param size the body's length
     * @return the request head's bytes
     */
    public static byte[] postHead(InetSocketAddress origin, long size) {
        String authority = authority(origin);
        return ("POST http://" + authority + "/upload HTTP/1.1\r\nHost: " + authority
                + "\r\nContent-Type: application/octet-stream\r\nContent-Length: " + size + "\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1);
    }

    /**
     * {@return {@code host:port} of {@code address}, by its literal IP address}
     *
     * @param address the address
     */
    public static String authority(InetSocketAddress address) {
        return address.getAddress().getHostAddress() + ":" + address.getPort();
    }
}
