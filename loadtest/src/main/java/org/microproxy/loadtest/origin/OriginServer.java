package org.microproxy.loadtest.origin;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.microproxy.loadtest.Json;
import org.microproxy.loadtest.proc.ManagedProcess;

/**
 * The origin: a small HTTP/1.1 server on blocking sockets and virtual threads, written for the
 * harness alone (it shares no code with either proxy). It listens on one port of several loopback
 * addresses (so that a proxy's upstream connections can exceed one address's ephemeral ports) and
 * serves:
 *
 * <ul>
 *   <li>{@code GET /bytes/<n>}: {@code n} bytes with a Content-Length;
 *   <li>{@code GET /chunked/<n>}: {@code n} bytes, chunked;
 *   <li>{@code GET /delay/<ms>/<n>}: the same after {@code ms} milliseconds;
 *   <li>{@code GET /stall/<n>?after=<k>}: the headers and {@code k} bytes, then nothing;
 *   <li>{@code GET /reset/<n>?after=<k>}: the headers and {@code k} bytes, then a TCP reset;
 *   <li>{@code POST|PUT /upload}: reads the body and answers with its length, also in
 *       {@code X-Received};
 *   <li>{@code GET /__stats}: the origin's and its fault relays' connection counts, as JSON.
 * </ul>
 *
 * <p>It also starts the {@link FaultRelay}s given with {@code --relay name:kind[:param=value...]}.
 * Once listening it prints one protocol line with its port and the relays' ports.
 */
public final class OriginServer {

    private static final byte[] PATTERN = new byte[64 * 1024];

    static {
        for (int i = 0; i < PATTERN.length; i++) PATTERN[i] = (byte) ('a' + i % 26);
    }

    private final AtomicLong open = new AtomicLong();
    private final AtomicLong accepted = new AtomicLong();
    private final AtomicLong requests = new AtomicLong();
    private final List<FaultRelay> relays = new ArrayList<>();
    private final List<ServerSocket> listeners = new ArrayList<>();

    /** Runs the origin: {@code origin --addresses a,b --port p --relay ...}. */
    public static void main(String[] args) throws Exception {
        List<String> addresses = List.of("127.0.0.1");
        int port = 0;
        List<String> relaySpecs = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--addresses" -> addresses = List.of(args[++i].split(","));
                case "--port" -> port = Integer.parseInt(args[++i]);
                case "--relay" -> relaySpecs.add(args[++i]);
                default -> throw new IllegalArgumentException("unknown origin option " + args[i]);
            }
        }
        OriginServer server = new OriginServer();
        int bound = server.listen(addresses, port);
        Map<String, Object> relayPorts = new LinkedHashMap<>();
        for (String spec : relaySpecs) {
            FaultRelay relay = FaultRelay.parse(spec, new InetSocketAddress(addresses.get(0), bound));
            server.relays.add(relay);
            relayPorts.put(relay.name(), relay.start());
        }
        Map<String, Object> ready = Json.obj("ready", true, "port", bound, "addresses", addresses, "relays", relayPorts,
                "pid", ProcessHandle.current().pid());
        System.out.println(ManagedProcess.PROTOCOL_PREFIX + Json.write(ready));
        System.out.flush();
        Thread.currentThread().join();
    }

    /** Listens on {@code port} (0 for any) of every address; returns the port. */
    public int listen(List<String> addresses, int port) throws IOException {
        int p = port;
        for (String address : addresses) {
            ServerSocket ss = new ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress(InetAddress.getByName(address), p), 4096);
            p = ss.getLocalPort();
            listeners.add(ss);
            Thread.ofPlatform().daemon().name("origin-accept-" + address).start(() -> acceptLoop(ss));
        }
        return p;
    }

    private void acceptLoop(ServerSocket ss) {
        while (!ss.isClosed()) {
            try {
                Socket s = ss.accept();
                accepted.incrementAndGet();
                open.incrementAndGet();
                Thread.ofVirtual().start(() -> serve(s));
            } catch (IOException e) {
                if (ss.isClosed()) return;
                // Out of descriptors, for instance: back off briefly.
                try {
                    Thread.sleep(10);
                } catch (InterruptedException ie) {
                    return;
                }
            }
        }
    }

    private void serve(Socket s) {
        try (s) {
            s.setTcpNoDelay(true);
            InputStream in = new BufferedInputStream(s.getInputStream(), 16 * 1024);
            OutputStream out = new BufferedOutputStream(s.getOutputStream(), 64 * 1024);
            while (true) {
                Request req = Request.read(in);
                if (req == null) return;
                requests.incrementAndGet();
                if (!handle(req, in, out, s)) return;
            }
        } catch (IOException | RuntimeException e) {
            // The client went away, or a fault mode ended the connection.
        } finally {
            open.decrementAndGet();
        }
    }

    /** Answers one request; false to close the connection. */
    private boolean handle(Request req, InputStream in, OutputStream out, Socket s) throws IOException {
        String path = req.path;
        String[] parts = path.split("/");
        boolean close = req.close;
        if ((req.method.equals("POST") || req.method.equals("PUT")) && path.equals("/upload")) {
            long n = req.readBody(in);
            byte[] body = Long.toString(n).getBytes(StandardCharsets.US_ASCII);
            head(out, 200, body.length, close, "X-Received: " + n + "\r\n");
            out.write(body);
            out.flush();
            return !close;
        }
        req.readBody(in);
        if (path.equals("/__stats")) {
            byte[] body = Json.write(stats()).getBytes(StandardCharsets.UTF_8);
            head(out, 200, body.length, close, "Content-Type: application/json\r\n");
            out.write(body);
            out.flush();
            return !close;
        }
        try {
            switch (parts.length > 1 ? parts[1] : "") {
                case "bytes" -> {
                    long n = Long.parseLong(parts[2]);
                    head(out, 200, n, close, "");
                    body(out, n);
                    out.flush();
                    return !close;
                }
                case "chunked" -> {
                    long n = Long.parseLong(parts[2]);
                    out.write(("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n"
                            + (close ? "Connection: close\r\n" : "") + "\r\n").getBytes(StandardCharsets.US_ASCII));
                    long left = n;
                    while (left > 0) {
                        int c = (int) Math.min(left, 8192);
                        out.write((Integer.toHexString(c) + "\r\n").getBytes(StandardCharsets.US_ASCII));
                        out.write(PATTERN, 0, c);
                        out.write('\r');
                        out.write('\n');
                        left -= c;
                    }
                    out.write("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                    return !close;
                }
                case "delay" -> {
                    sleep(Long.parseLong(parts[2]));
                    long n = Long.parseLong(parts[3]);
                    head(out, 200, n, close, "");
                    body(out, n);
                    out.flush();
                    return !close;
                }
                case "stall" -> {
                    long n = Long.parseLong(parts[2]);
                    long after = req.queryLong("after", 0);
                    head(out, 200, n, close, "");
                    body(out, Math.min(after, n));
                    out.flush();
                    // Hold the connection until the peer closes it (or an hour passes).
                    s.setSoTimeout(1000);
                    long deadline = System.nanoTime() + 3600L * 1_000_000_000L;
                    while (System.nanoTime() < deadline) {
                        try {
                            if (in.read() < 0) return false;
                        } catch (SocketTimeoutException e) {
                            // Keep stalling.
                        }
                    }
                    return false;
                }
                case "reset" -> {
                    long n = Long.parseLong(parts[2]);
                    long after = req.queryLong("after", 0);
                    head(out, 200, n, close, "");
                    body(out, Math.min(after, n));
                    out.flush();
                    s.setSoLinger(true, 0);
                    return false;
                }
                default -> {
                    byte[] body = "not found\n".getBytes(StandardCharsets.US_ASCII);
                    head(out, 404, body.length, close, "");
                    out.write(body);
                    out.flush();
                    return !close;
                }
            }
        } catch (NumberFormatException | ArrayIndexOutOfBoundsException e) {
            byte[] body = "bad request\n".getBytes(StandardCharsets.US_ASCII);
            head(out, 400, body.length, true, "");
            out.write(body);
            out.flush();
            return false;
        }
    }

    private Map<String, Object> stats() {
        Map<String, Object> r = new LinkedHashMap<>();
        for (FaultRelay relay : relays) r.put(relay.name(), relay.stats());
        return Json.obj("open", open.get(), "accepted", accepted.get(), "requests", requests.get(), "relays", r);
    }

    private static void head(OutputStream out, int status, long length, boolean close, String extra) throws IOException {
        String reason = switch (status) {
            case 200 -> "OK";
            case 404 -> "Not Found";
            default -> "Bad Request";
        };
        out.write(("HTTP/1.1 " + status + " " + reason + "\r\nContent-Length: " + length
                + "\r\nContent-Type: application/octet-stream\r\n" + (close ? "Connection: close\r\n" : "") + extra + "\r\n")
                .getBytes(StandardCharsets.US_ASCII));
    }

    private static void body(OutputStream out, long n) throws IOException {
        long left = n;
        while (left > 0) {
            int c = (int) Math.min(left, PATTERN.length);
            out.write(PATTERN, 0, c);
            left -= c;
        }
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** A parsed request head. */
    static final class Request {
        String method;
        String path;
        String query = "";
        long contentLength = 0;
        boolean chunked;
        boolean close;

        /** Reads a request head; null at a clean end of stream. */
        static Request read(InputStream in) throws IOException {
            String line = readLine(in, true);
            if (line == null) return null;
            while (line.isEmpty()) {
                line = readLine(in, true);
                if (line == null) return null;
            }
            Request r = new Request();
            String[] f = line.split(" ");
            if (f.length < 3) throw new IOException("bad request line: " + line);
            r.method = f[0];
            String target = f[1];
            if (target.startsWith("http://") || target.startsWith("https://")) {
                int slash = target.indexOf('/', target.indexOf("//") + 2);
                target = slash < 0 ? "/" : target.substring(slash);
            }
            int q = target.indexOf('?');
            r.path = q < 0 ? target : target.substring(0, q);
            if (q >= 0) r.query = target.substring(q + 1);
            r.close = f[2].equals("HTTP/1.0");
            int total = 0;
            while (true) {
                String h = readLine(in, false);
                if (h.isEmpty()) break;
                total += h.length();
                if (total > 64 * 1024) throw new IOException("headers too large");
                int colon = h.indexOf(':');
                if (colon < 0) continue;
                String name = h.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                String value = h.substring(colon + 1).trim();
                switch (name) {
                    case "content-length" -> r.contentLength = Long.parseLong(value);
                    case "transfer-encoding" -> r.chunked = value.toLowerCase(Locale.ROOT).contains("chunked");
                    case "connection" -> {
                        String v = value.toLowerCase(Locale.ROOT);
                        if (v.contains("close")) r.close = true;
                        else if (v.contains("keep-alive")) r.close = false;
                    }
                    default -> {
                        // Ignored.
                    }
                }
            }
            return r;
        }

        long queryLong(String key, long def) {
            for (String kv : query.split("&")) {
                int eq = kv.indexOf('=');
                if (eq > 0 && kv.substring(0, eq).equals(key)) return Long.parseLong(kv.substring(eq + 1));
            }
            return def;
        }

        /** Reads and discards the body; returns its length. */
        long readBody(InputStream in) throws IOException {
            byte[] buf = new byte[64 * 1024];
            if (chunked) {
                long total = 0;
                while (true) {
                    String size = readLine(in, false);
                    int semi = size.indexOf(';');
                    long n = Long.parseLong((semi < 0 ? size : size.substring(0, semi)).trim(), 16);
                    if (n == 0) {
                        while (!readLine(in, false).isEmpty()) {
                            // Trailers.
                        }
                        return total;
                    }
                    skip(in, n, buf);
                    total += n;
                    readLine(in, false);
                }
            }
            skip(in, contentLength, buf);
            return contentLength;
        }

        private static void skip(InputStream in, long n, byte[] buf) throws IOException {
            long left = n;
            while (left > 0) {
                int r = in.read(buf, 0, (int) Math.min(buf.length, left));
                if (r < 0) throw new EOFException();
                left -= r;
            }
        }

        private static String readLine(InputStream in, boolean eofOk) throws IOException {
            StringBuilder b = new StringBuilder();
            while (true) {
                int c = in.read();
                if (c < 0) {
                    if (eofOk && b.length() == 0) return null;
                    throw new EOFException();
                }
                if (c == '\n') break;
                if (c != '\r') b.append((char) c);
                if (b.length() > 16 * 1024) throw new IOException("line too long");
            }
            return b.toString();
        }
    }
}
