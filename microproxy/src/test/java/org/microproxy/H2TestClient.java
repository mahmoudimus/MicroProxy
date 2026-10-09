package org.microproxy;

import io.github.mahmoudimus.http2.ErrorCode;
import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.FrameReader;
import io.github.mahmoudimus.http2.FrameWriter;
import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.HpackDecoder;
import io.github.mahmoudimus.http2.HpackEncoder;
import io.github.mahmoudimus.http2.Http2Settings;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/**
 * A hand-written HTTP/2 client for protocol tests: it tunnels through the proxy with {@code
 * CONNECT}, negotiates {@code h2} with ALPN on the intercepted TLS session, and then writes
 * whatever frames a test wants, including ones a real client never would.
 */
final class H2TestClient implements AutoCloseable {

    /** A response collected from a stream. */
    record Response(int streamId, List<HeaderField> headers, byte[] body, List<HeaderField> trailers, ErrorCode reset) {
        String header(String name) {
            for (HeaderField f : headers) {
                if (f.name().equals(name)) return f.value();
            }
            return null;
        }

        int status() {
            String s = header(":status");
            return s == null ? 0 : Integer.parseInt(s);
        }

        String text() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    final Socket raw;
    final SSLSocket tls;
    final FrameReader reader;
    final FrameWriter writer;
    final HpackEncoder encoder = new HpackEncoder();
    final HpackDecoder decoder = new HpackDecoder();
    final String authority;
    /** The server's SETTINGS, once read. */
    Frame.Settings serverSettings;
    /** Frames read but not yet asked for. */
    final List<Frame> pending = new ArrayList<>();
    /** Header blocks decoded as they arrive, since HPACK state depends on their order. */
    private final Map<Frame, List<HeaderField>> decoded = new java.util.IdentityHashMap<>();
    private final OutputStream out;
    private final InputStream in;

    private H2TestClient(Socket raw, SSLSocket tls, String authority) throws IOException {
        this.raw = raw;
        this.tls = tls;
        this.authority = authority;
        this.in = new BufferedInputStream(tls.getInputStream());
        this.out = new BufferedOutputStream(tls.getOutputStream());
        this.reader = new FrameReader(in);
        this.writer = new FrameWriter(out);
        tls.setSoTimeout(10_000);
    }

    /** Thrown when the proxy answers the CONNECT with something other than 200. */
    static final class ConnectRefused extends IOException {
        final int status;

        ConnectRefused(int status) {
            super("CONNECT answered with " + status);
            this.status = status;
        }
    }

    /** Tunnels to {@code target} ({@code host:port}) and completes the TLS handshake with ALPN h2. */
    static H2TestClient connect(InetSocketAddress proxy, String target, SSLContext trust, String... connectHeaders)
            throws IOException {
        Socket raw = new Socket(proxy.getAddress(), proxy.getPort());
        raw.setSoTimeout(10_000);
        StringBuilder connect = new StringBuilder("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n");
        for (String h : connectHeaders) connect.append(h).append("\r\n");
        connect.append("\r\n");
        TestSupport.write(raw.getOutputStream(), connect.toString());
        String head = TestSupport.readUntil(raw.getInputStream(), "\r\n\r\n");
        int status = Integer.parseInt(head.substring(9, 12));
        if (status != 200) {
            raw.close();
            throw new ConnectRefused(status);
        }
        String host = target.substring(0, target.lastIndexOf(':'));
        int port = Integer.parseInt(target.substring(target.lastIndexOf(':') + 1));
        SSLSocket tls = (SSLSocket) trust.getSocketFactory().createSocket(raw, host, port, true);
        tls.setUseClientMode(true);
        SSLParameters params = tls.getSSLParameters();
        params.setApplicationProtocols(new String[] {"h2"});
        tls.setSSLParameters(params);
        tls.startHandshake();
        if (!"h2".equals(tls.getApplicationProtocol())) {
            tls.close();
            throw new IOException("ALPN did not select h2 but '" + tls.getApplicationProtocol() + "'");
        }
        return new H2TestClient(raw, tls, target);
    }

    /** Sends the preface and empty SETTINGS, reads the server's SETTINGS and acknowledges them. */
    H2TestClient handshake() throws IOException {
        writer.writeClientPreface();
        writer.writeSettings(Map.of());
        writer.flush();
        Frame f = awaitFrame(x -> x instanceof Frame.Settings s && !s.ack());
        serverSettings = (Frame.Settings) f;
        writer.writeSettingsAck();
        writer.flush();
        return this;
    }

    /** The server's value for a setting, or null. */
    Long setting(int id) {
        return serverSettings.values().get(id);
    }

    void headers(int streamId, List<HeaderField> fields, boolean endStream) throws IOException {
        writer.writeHeaders(streamId, encoder.encode(fields), endStream);
        writer.flush();
    }

    /** A request's header list: the pseudo-headers for {@code method} and {@code path}, then {@code extra} (name, value, ...). */
    List<HeaderField> request(String method, String path, String... extra) {
        List<HeaderField> fields = new ArrayList<>();
        fields.add(new HeaderField(":method", method));
        fields.add(new HeaderField(":scheme", "https"));
        fields.add(new HeaderField(":authority", authority));
        fields.add(new HeaderField(":path", path));
        for (int i = 0; i < extra.length; i += 2) fields.add(new HeaderField(extra[i], extra[i + 1]));
        return fields;
    }

    void get(int streamId, String path, String... extra) throws IOException {
        headers(streamId, request("GET", path, extra), true);
    }

    void data(int streamId, byte[] data, boolean endStream) throws IOException {
        writer.writeData(streamId, data, 0, data.length, endStream);
        writer.flush();
    }

    void rst(int streamId, ErrorCode code) throws IOException {
        writer.writeRstStream(streamId, code);
        writer.flush();
    }

    void ping(long data) throws IOException {
        writer.writePing(false, data);
        writer.flush();
    }

    /** Reads frames until one matches, keeping the others for later; SETTINGS are acknowledged. */
    Frame awaitFrame(Predicate<Frame> match) throws IOException {
        for (int i = 0; i < pending.size(); i++) {
            if (match.test(pending.get(i))) return pending.remove(i);
        }
        while (true) {
            Frame f = reader.readFrame();
            if (f == null) throw new IOException("connection closed while waiting for a frame");
            if (f instanceof Frame.Headers h) decoded.put(f, decoder.decode(h.streamId(), h.fieldBlock()));
            if (f instanceof Frame.Settings s && !s.ack() && serverSettings != null) {
                writer.writeSettingsAck();
                writer.flush();
            }
            if (match.test(f)) return f;
            if (!(f instanceof Frame.WindowUpdate) && !(f instanceof Frame.Settings) && !(f instanceof Frame.Ping)) {
                pending.add(f);
            }
        }
    }

    /** The decoded fields of a HEADERS frame returned by {@link #awaitFrame}. */
    List<HeaderField> fields(Frame.Headers h) {
        return decoded.remove(h);
    }

    /** Waits for GOAWAY. */
    Frame.GoAway awaitGoAway() throws IOException {
        return (Frame.GoAway) awaitFrame(f -> f instanceof Frame.GoAway);
    }

    /** Waits for RST_STREAM on {@code streamId}. */
    Frame.RstStream awaitReset(int streamId) throws IOException {
        return (Frame.RstStream) awaitFrame(f -> f instanceof Frame.RstStream r && r.streamId() == streamId);
    }

    /**
     * Collects stream {@code streamId}'s response until END_STREAM (or RST_STREAM), giving credit
     * back for the data so large bodies keep flowing. Interim (1xx) responses are skipped.
     */
    Response response(int streamId) throws IOException {
        List<HeaderField> headers = null;
        List<HeaderField> trailers = List.of();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        Map<Integer, Integer> unacked = new HashMap<>();
        while (true) {
            Frame f = awaitFrame(x -> x.streamId() == streamId
                    && (x instanceof Frame.Headers || x instanceof Frame.Data || x instanceof Frame.RstStream));
            switch (f) {
                case Frame.Headers h -> {
                    List<HeaderField> fields = decoded.remove(h);
                    if (headers == null) {
                        String status = fields.getFirst().value();
                        if (status.startsWith("1")) continue;
                        headers = fields;
                    } else {
                        trailers = fields;
                    }
                    if (h.endStream()) return new Response(streamId, headers, body.toByteArray(), trailers, null);
                }
                case Frame.Data d -> {
                    body.write(d.data());
                    int n = unacked.merge(streamId, d.flowControlledLength(), Integer::sum);
                    if (n >= 16_384) {
                        writer.writeWindowUpdate(streamId, n);
                        writer.writeWindowUpdate(0, n);
                        writer.flush();
                        unacked.put(streamId, 0);
                    }
                    if (d.endStream()) return new Response(streamId, headers, body.toByteArray(), trailers, null);
                }
                case Frame.RstStream r -> {
                    return new Response(streamId, headers == null ? List.of() : headers, body.toByteArray(), trailers, r.error());
                }
                default -> throw new IllegalStateException();
            }
        }
    }

    /** Whether the server closed the connection (reading gives end of stream or fails). */
    boolean closedByServer() {
        try {
            while (true) {
                Frame f = reader.readFrame();
                if (f == null) return true;
            }
        } catch (IOException e) {
            return true;
        }
    }

    static Http2Settings defaults() {
        return Http2Settings.DEFAULT;
    }

    @Override
    public void close() throws IOException {
        tls.close();
        raw.close();
    }
}
