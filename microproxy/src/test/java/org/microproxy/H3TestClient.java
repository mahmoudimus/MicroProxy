package org.microproxy;

import io.github.mahmoudimus.http3.FieldSectionSizeException;
import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3Frame;
import io.github.mahmoudimus.http3.Http3FrameReader;
import io.github.mahmoudimus.http3.Http3FrameWriter;
import io.github.mahmoudimus.http3.Http3Settings;
import io.github.mahmoudimus.http3.Http3StreamType;
import io.github.mahmoudimus.http3.QpackDecoder;
import io.github.mahmoudimus.http3.QpackEncoder;
import io.github.mahmoudimus.http3.QuicVarInt;
import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.QuicStreamException;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.SessionCache;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * A small HTTP/3 client for tests, on the QUIC module's blocking API and http3-codec: a control
 * stream with SETTINGS, QPACK with a dynamic table both ways (its encoder and decoder streams), and
 * requests on concurrent request streams, with bodies and trailers. It also gives tests the QUIC
 * connection itself, for streams and frames a well-behaved client would not send.
 */
public final class H3TestClient implements AutoCloseable {

    /** A response: status, fields, body and trailers. */
    public record Response(int status, List<HeaderField> fields, byte[] body, List<HeaderField> trailers) {
        public String header(String name) {
            for (HeaderField f : fields) {
                if (f.name().equals(name)) return f.value();
            }
            return null;
        }

        public String trailer(String name) {
            for (HeaderField f : trailers) {
                if (f.name().equals(name)) return f.value();
            }
            return null;
        }

        public String text() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    /** How the client connects. */
    public static final class Options {
        long qpackMaxTableCapacity = 4096;
        int qpackBlockedStreams = 16;
        long encoderTableCapacity = 4096;
        long maxFieldSectionSize = 1 << 20;
        /** Whether field sections stay within the server's SETTINGS_MAX_FIELD_SECTION_SIZE, as a well-behaved client's do. */
        boolean obeyFieldSectionSize = true;
        Duration idleTimeout = Duration.ofSeconds(30);
        /** Whether the client sends SETTINGS_H3_DATAGRAM (RFC 9297), and accepts QUIC DATAGRAM frames. */
        boolean datagrams = true;
        /** The {@code :authority} of requests, or null for the server name and port. */
        String authority;
        /** Session tickets and tokens to resume with and keep, shared by the connections that use them; null for none. */
        SessionCache sessions;
        /** Whether to send the first requests as 0-RTT data when a ticket allows it, before the handshake completes. */
        boolean earlyData;
    }

    final QuicClient client;
    final QuicConnection quic;
    private final ReentrantLock encoderLock = new ReentrantLock();
    private final QpackEncoder encoder;
    /** The client's QPACK encoder stream, for tests that write their own instructions on it. */
    final OutputStream encoderOut;
    private final ReentrantLock decoderLock = new ReentrantLock();
    private final Condition decoderReady = decoderLock.newCondition();
    private final QpackDecoder decoder;
    private final Set<Long> resumable = new HashSet<>();
    private final OutputStream decoderOut;
    private final ReentrantLock stateLock = new ReentrantLock();
    private final Condition stateChanged = stateLock.newCondition();
    private Http3Settings serverSettings;
    private long goAway = -1;
    private final List<Throwable> errors = new ArrayList<>();
    private final String authority;
    private final boolean obeyFieldSectionSize;

    private H3TestClient(QuicClient client, QuicConnection quic, Options options, String authority) throws IOException {
        this.client = client;
        this.quic = quic;
        this.authority = authority;
        this.obeyFieldSectionSize = options.obeyFieldSectionSize;
        this.encoder = new QpackEncoder(options.encoderTableCapacity);
        this.decoder = new QpackDecoder(options.qpackMaxTableCapacity, options.qpackBlockedStreams);
        decoder.setMaxFieldSectionSize(options.maxFieldSectionSize);
        QuicStream control = quic.openUnidirectionalStream();
        Http3FrameWriter w = new Http3FrameWriter(control.getOutputStream());
        w.writeStreamType(Http3StreamType.CONTROL);
        w.writeSettings(Http3Settings.builder()
                .qpackMaxTableCapacity(options.qpackMaxTableCapacity)
                .qpackBlockedStreams(options.qpackBlockedStreams)
                .maxFieldSectionSize(options.maxFieldSectionSize)
                .h3Datagram(options.datagrams)
                .grease(3, 7)
                .build());
        w.flush();
        QuicStream enc = quic.openUnidirectionalStream();
        encoderOut = enc.getOutputStream();
        encoderOut.write(Http3StreamType.encode(Http3StreamType.QPACK_ENCODER));
        QuicStream dec = quic.openUnidirectionalStream();
        decoderOut = dec.getOutputStream();
        decoderOut.write(Http3StreamType.encode(Http3StreamType.QPACK_DECODER));
        Thread.ofVirtual().name("h3-test-client-accept").start(this::acceptStreams);
        if (options.datagrams) Thread.ofVirtual().name("h3-test-client-datagrams").start(this::receiveDatagrams);
    }

    /** Connects to {@code address} as {@code serverName}, trusting {@code anchor} (or every server when null). */
    public static H3TestClient connect(InetSocketAddress address, String serverName, X509Certificate anchor) throws IOException {
        return connect(address, serverName, anchor, new Options());
    }

    public static H3TestClient connect(InetSocketAddress address, String serverName, X509Certificate anchor, Options options)
            throws IOException {
        TlsConfig.Builder tls = TlsConfig.builder().alpnProtocols("h3").serverName(serverName).earlyData(options.earlyData);
        if (anchor == null) {
            tls.trustAllCertificates(true);
        } else {
            tls.trustManager(trusting(anchor));
        }
        ClientConfig config = ClientConfig.builder(tls.build())
                .transport(TransportConfig.builder().maxIdleTimeout(options.idleTimeout)
                        .datagramReceiveBufferSize(options.datagrams ? 1 << 20 : 0).build())
                .sessionCache(options.sessions != null ? options.sessions : SessionCache.none())
                .build();
        QuicClient client = QuicClient.create(config);
        try {
            QuicConnection quic = options.earlyData ? client.connectEarly(address, serverName, Duration.ofSeconds(10))
                    : client.connect(address, serverName, Duration.ofSeconds(10));
            return new H3TestClient(client, quic, options,
                    options.authority != null ? options.authority : serverName + ":" + address.getPort());
        } catch (IOException | RuntimeException e) {
            client.close();
            throw e;
        }
    }

    static X509TrustManager trusting(X509Certificate anchor) {
        try {
            java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
            store.load(null, null);
            store.setCertificateEntry("anchor", anchor);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(store);
            for (var tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager x) return x;
            }
            throw new IllegalStateException("no X509TrustManager");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ---------------------------------------------------------------------------------------
    // The server's streams

    private void acceptStreams() {
        try {
            while (true) {
                QuicStream s = quic.acceptStream();
                Thread.ofVirtual().name("h3-test-client-uni").start(() -> readUni(s));
            }
        } catch (IOException e) {
            // the connection ended
        } finally {
            stateLock.lock();
            try {
                stateChanged.signalAll();
            } finally {
                stateLock.unlock();
            }
            decoderLock.lock();
            try {
                decoderReady.signalAll();
            } finally {
                decoderLock.unlock();
            }
        }
    }

    private void readUni(QuicStream s) {
        try {
            InputStream in = s.getInputStream();
            long type = Http3StreamType.read(in);
            if (type == Http3StreamType.CONTROL) {
                Http3FrameReader r = new Http3FrameReader(in);
                for (Http3Frame f; (f = r.readFrame()) != null; ) {
                    if (f instanceof Http3Frame.Settings settings) {
                        stateLock.lock();
                        try {
                            serverSettings = Http3Settings.fromFrame(settings);
                            stateChanged.signalAll();
                        } finally {
                            stateLock.unlock();
                        }
                        encoderLock.lock();
                        try {
                            if (obeyFieldSectionSize) {
                                encoder.applyPeerSettings(serverSettings);
                            } else {
                                encoder.setPeerSettings(serverSettings.qpackMaxTableCapacity(),
                                        serverSettings.qpackBlockedStreams());
                            }
                        } finally {
                            encoderLock.unlock();
                        }
                    } else if (f instanceof Http3Frame.GoAway g) {
                        stateLock.lock();
                        try {
                            goAway = g.id();
                            stateChanged.signalAll();
                        } finally {
                            stateLock.unlock();
                        }
                    }
                }
            } else if (type == Http3StreamType.QPACK_ENCODER) {
                byte[] buf = new byte[4096];
                for (int n; (n = in.read(buf)) >= 0; ) {
                    decoderLock.lock();
                    try {
                        resumable.addAll(decoder.onEncoderStream(buf, 0, n));
                        flushDecoder();
                        decoderReady.signalAll();
                    } finally {
                        decoderLock.unlock();
                    }
                }
            } else if (type == Http3StreamType.QPACK_DECODER) {
                byte[] buf = new byte[4096];
                for (int n; (n = in.read(buf)) >= 0; ) {
                    encoderLock.lock();
                    try {
                        encoder.onDecoderStream(buf, 0, n);
                    } finally {
                        encoderLock.unlock();
                    }
                }
            } else {
                in.transferTo(OutputStream.nullOutputStream());
            }
        } catch (IOException e) {
            if (quic.isOpen()) record(e);
        }
    }

    private void record(Throwable t) {
        stateLock.lock();
        try {
            errors.add(t);
        } finally {
            stateLock.unlock();
        }
    }

    List<Throwable> errors() {
        stateLock.lock();
        try {
            return List.copyOf(errors);
        } finally {
            stateLock.unlock();
        }
    }

    /** The server's SETTINGS, waiting for them. */
    Http3Settings serverSettings() throws IOException {
        stateLock.lock();
        try {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (serverSettings == null) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0 || !quic.isOpen()) throw new IOException("no SETTINGS from the server");
                stateChanged.awaitNanos(remaining);
            }
            return serverSettings;
        } catch (InterruptedException e) {
            throw new InterruptedIOException();
        } finally {
            stateLock.unlock();
        }
    }

    /** The id of the server's GOAWAY, waiting up to {@code timeout} for it; -1 if none came. */
    long awaitGoAway(Duration timeout) throws InterruptedIOException {
        stateLock.lock();
        try {
            long deadline = System.nanoTime() + timeout.toNanos();
            while (goAway < 0) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) return -1;
                stateChanged.awaitNanos(remaining);
            }
            return goAway;
        } catch (InterruptedException e) {
            throw new InterruptedIOException();
        } finally {
            stateLock.unlock();
        }
    }

    // ---------------------------------------------------------------------------------------
    // QPACK

    byte[] encode(long streamId, List<HeaderField> fields) throws IOException {
        encoderLock.lock();
        try {
            byte[] section = encoder.encode(streamId, fields);
            byte[] instructions = encoder.encoderStreamBytes();
            if (instructions.length > 0) {
                encoderOut.write(instructions);
                encoderOut.flush();
            }
            return section;
        } finally {
            encoderLock.unlock();
        }
    }

    List<HeaderField> decode(long streamId, byte[] section) throws IOException {
        decoderLock.lock();
        try {
            List<HeaderField> fields = decoder.decode(streamId, section);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (fields == null) {
                if (resumable.remove(streamId)) {
                    fields = decoder.resume(streamId);
                    break;
                }
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) throw new IOException("blocked section on stream " + streamId);
                decoderReady.awaitNanos(remaining);
            }
            flushDecoder();
            return fields;
        } catch (InterruptedException e) {
            throw new InterruptedIOException();
        } finally {
            decoderLock.unlock();
        }
    }

    private void flushDecoder() throws IOException {
        byte[] bytes = decoder.decoderStreamBytes();
        if (bytes.length > 0) {
            decoderOut.write(bytes);
            decoderOut.flush();
        }
    }

    // ---------------------------------------------------------------------------------------
    // Requests

    public Response get(String path) throws IOException {
        return request("GET", path, List.of(), null, List.of());
    }

    public Response post(String path, byte[] body) throws IOException {
        return request("POST", path, List.of(), body, List.of());
    }

    /** The request's pseudo-header fields, then {@code fields}. */
    List<HeaderField> head(String method, String path, List<HeaderField> fields) {
        List<HeaderField> all = new ArrayList<>();
        all.add(new HeaderField(":method", method));
        all.add(new HeaderField(":scheme", "https"));
        all.add(new HeaderField(":authority", authority));
        all.add(new HeaderField(":path", path));
        all.add(new HeaderField("user-agent", "h3-test-client"));
        all.addAll(fields);
        return all;
    }

    /** Opens a request stream and sends {@code fields} as its HEADERS, ending the stream after them if {@code end}. */
    QuicStream send(List<HeaderField> fields, boolean end) throws IOException {
        QuicStream s = quic.openBidirectionalStream();
        OutputStream out = s.getOutputStream();
        try {
            new Http3FrameWriter(out).writeHeaders(encode(s.id(), fields));
            if (end) out.close();
        } catch (QuicStreamException e) {
            stoppedSending(e);
        }
        return s;
    }

    /** Sends a request (body and trailers optional) and reads its response. */
    public Response request(String method, String path, List<HeaderField> fields, byte[] body, List<HeaderField> trailers)
            throws IOException {
        QuicStream s = quic.openBidirectionalStream();
        OutputStream out = s.getOutputStream();
        Http3FrameWriter w = new Http3FrameWriter(out);
        try {
            w.writeHeaders(encode(s.id(), head(method, path, fields)));
            if (body != null) {
                for (int off = 0; off < body.length; off += 32 * 1024) {
                    w.writeData(body, off, Math.min(32 * 1024, body.length - off));
                }
            }
            if (!trailers.isEmpty()) w.writeHeaders(encode(s.id(), trailers));
            out.close();
        } catch (QuicStreamException e) {
            stoppedSending(e);
        }
        return readResponse(s);
    }

    /**
     * A server may stop reading a request it has answered or refused (STOP_SENDING, RFC 9114
     * section 4.1.2) before the client has sent all of it: the client stops sending, and the
     * response, or the stream's reset, tells it the rest.
     */
    private static void stoppedSending(QuicStreamException e) throws QuicStreamException {
        if (e.kind() != QuicStreamException.Kind.STOPPED) throw e;
    }

    /** Reads a response from a request stream: interim responses are skipped. */
    Response readResponse(QuicStream s) throws IOException {
        Http3FrameReader r = new Http3FrameReader(s.getInputStream());
        r.setMaxFramePayloadSize(1 << 20);
        List<HeaderField> head = null;
        List<HeaderField> trailers = List.of();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (Http3Frame f; (f = r.readFrame()) != null; ) {
            switch (f) {
                case Http3Frame.Headers h -> {
                    List<HeaderField> fields;
                    try {
                        fields = decode(s.id(), h.fieldSection());
                    } catch (FieldSectionSizeException e) {
                        throw new IOException("response header section too large", e);
                    }
                    String status = fields.isEmpty() ? null : fields.getFirst().value();
                    if (head == null && status != null && status.startsWith("1")) continue;
                    if (head == null) {
                        head = fields;
                    } else {
                        trailers = fields;
                    }
                }
                case Http3Frame.Data d -> body.write(d.data());
                default -> {}
            }
        }
        if (head == null) throw new IOException("no response on stream " + s.id());
        int status = Integer.parseInt(head.getFirst().value());
        return new Response(status, head.subList(1, head.size()), body.toByteArray(), trailers);
    }

    // ---------------------------------------------------------------------------------------
    // CONNECT, extended CONNECT (RFC 9114 section 4.4, RFC 9220) and HTTP Datagrams (RFC 9297)

    /** A plain {@code CONNECT}'s head: {@code :method} and {@code :authority} only, then {@code fields}. */
    public static List<HeaderField> connect(String authority, HeaderField... fields) {
        List<HeaderField> all = new ArrayList<>();
        all.add(new HeaderField(":method", "CONNECT"));
        all.add(new HeaderField(":authority", authority));
        all.addAll(List.of(fields));
        return all;
    }

    /** An extended {@code CONNECT}'s head for {@code protocol}, then {@code fields}. */
    public static List<HeaderField> extendedConnect(String protocol, String scheme, String authority, String path,
            HeaderField... fields) {
        List<HeaderField> all = new ArrayList<>();
        all.add(new HeaderField(":method", "CONNECT"));
        all.add(new HeaderField(":protocol", protocol));
        all.add(new HeaderField(":scheme", scheme));
        all.add(new HeaderField(":authority", authority));
        all.add(new HeaderField(":path", path));
        all.addAll(List.of(fields));
        return all;
    }

    /**
     * A request stream that stays open after its response head: a tunnel ({@code CONNECT}, a
     * WebSocket, CONNECT-UDP). Its DATA arrive in {@link #in()}, DATA go out through {@link #out()},
     * and the stream's end is the tunnel's.
     */
    public final class Tunnel {
        final QuicStream stream;
        final long id;
        /** The response's status, 0 if the stream ended before one. */
        public int status;
        List<HeaderField> fields = List.of();
        private final Http3FrameReader reader;
        private final Http3FrameWriter writer;
        private final OutputStream rawOut;
        private final InputStream in;
        private byte[] pending = new byte[0];
        private int pendingAt;
        private final ReentrantLock datagramLock = new ReentrantLock();
        private final Condition datagramArrived = datagramLock.newCondition();
        private final ArrayDeque<byte[]> datagrams = new ArrayDeque<>();

        private Tunnel(QuicStream stream) {
            this.stream = stream;
            this.id = stream.id();
            this.rawOut = stream.getOutputStream();
            this.writer = new Http3FrameWriter(rawOut);
            this.reader = new Http3FrameReader(stream.getInputStream());
            reader.setMaxFramePayloadSize(1 << 20);
            this.in = new InputStream() {
                @Override
                public int read() throws IOException {
                    byte[] one = new byte[1];
                    return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
                }

                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    if (len == 0) return 0;
                    while (pendingAt == pending.length) {
                        Http3Frame f = reader.readFrame();
                        if (f == null) return -1;
                        if (f instanceof Http3Frame.Data d) {
                            pending = d.data();
                            pendingAt = 0;
                        } else if (f instanceof Http3Frame.Headers) {
                            throw new IOException("HEADERS in a tunnel");
                        }
                    }
                    int n = Math.min(len, pending.length - pendingAt);
                    System.arraycopy(pending, pendingAt, b, off, n);
                    pendingAt += n;
                    return n;
                }
            };
        }

        public String header(String name) {
            for (HeaderField f : fields) {
                if (f.name().equals(name)) return f.value();
            }
            return null;
        }

        /** Reads the final response head (skipping interim ones); false if the stream ended first. */
        private boolean readHead() throws IOException {
            for (Http3Frame f; (f = reader.readFrame()) != null; ) {
                if (f instanceof Http3Frame.Headers h) {
                    List<HeaderField> all = decode(id, h.fieldSection());
                    String st = all.getFirst().value();
                    if (st.startsWith("1")) continue;
                    status = Integer.parseInt(st);
                    fields = all.subList(1, all.size());
                    return true;
                }
            }
            return false;
        }

        /** The tunnel's bytes from the server: the payloads of its DATA frames. */
        public InputStream in() {
            return in;
        }

        /** Writes the tunnel's bytes to the server, as DATA frames. */
        public OutputStream out() {
            return new OutputStream() {
                @Override
                public void write(int b) throws IOException {
                    write(new byte[] {(byte) b}, 0, 1);
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    writer.writeData(b, off, len);
                    writer.flush();
                }

                @Override
                public void close() throws IOException {
                    end();
                }
            };
        }

        /** Ends the tunnel's output: the stream's FIN. */
        public void end() throws IOException {
            rawOut.close();
        }

        /** Resets the stream both ways with {@code code}. */
        public void reset(long code) throws IOException {
            stream.stopSending(code);
            stream.reset(code);
        }

        /** The tunnel as a connected socket, for TLS over it: closing it ends the stream's output. */
        java.net.Socket asSocket() {
            OutputStream out = out();
            return new java.net.Socket() {
                private volatile boolean closed;

                @Override
                public InputStream getInputStream() {
                    return in;
                }

                @Override
                public OutputStream getOutputStream() {
                    return out;
                }

                @Override
                public boolean isConnected() {
                    return true;
                }

                @Override
                public boolean isBound() {
                    return true;
                }

                @Override
                public boolean isClosed() {
                    return closed;
                }

                @Override
                public void setSoTimeout(int timeout) {}

                @Override
                public int getSoTimeout() {
                    return 0;
                }

                @Override
                public int getSoLinger() {
                    return -1;
                }

                @Override
                public void setSoLinger(boolean on, int linger) {}

                @Override
                public void setTcpNoDelay(boolean on) {}

                @Override
                public java.net.InetAddress getInetAddress() {
                    return null;
                }

                @Override
                public void shutdownOutput() throws IOException {
                    end();
                }

                @Override
                public void close() throws IOException {
                    if (closed) return;
                    closed = true;
                    try {
                        end();
                    } catch (IOException e) {
                        // ended already
                    }
                }
            };
        }

        /** Reads everything until the stream ends. */
        byte[] readAll() throws IOException {
            return in.readAllBytes();
        }

        /** Reads everything until the stream ends, as text. */
        String text() throws IOException {
            return new String(readAll(), StandardCharsets.UTF_8);
        }

        /** Sends a capsule (RFC 9297 section 3.2) of {@code type} on the stream. */
        void sendCapsule(long type, byte[] value) throws IOException {
            out().write(capsule(type, value));
        }

        /** Sends a UDP payload in a DATAGRAM capsule, with context ID 0. */
        public void sendDatagramCapsule(byte[] payload) throws IOException {
            sendCapsule(0, contextZero(payload));
        }

        /** Reads the next capsule from the stream: its type and value, or null at the stream's end. */
        Capsule readCapsule() throws IOException {
            long type = QuicVarInt.read(in);
            if (type < 0) return null;
            long length = QuicVarInt.read(in);
            byte[] value = in.readNBytes((int) length);
            if (value.length < length) throw new IOException("the stream ended inside a capsule");
            return new Capsule(type, value);
        }

        /** Sends a UDP payload as an HTTP/3 datagram of this stream, with context ID 0. */
        public void sendDatagram(byte[] payload) throws IOException {
            sendDatagram(contextZero(payload), true);
        }

        /** Sends an HTTP/3 datagram of this stream with {@code content} (its context ID first). */
        void sendDatagram(byte[] content, boolean ignored) throws IOException {
            byte[] quarter = QuicVarInt.encode(id / 4);
            byte[] d = new byte[quarter.length + content.length];
            System.arraycopy(quarter, 0, d, 0, quarter.length);
            System.arraycopy(content, 0, d, quarter.length, content.length);
            quic.sendDatagram(d);
        }

        /** The content (context ID first) of the next HTTP/3 datagram of this stream, or null after {@code timeout}. */
        public byte[] receiveDatagram(Duration timeout) throws InterruptedIOException {
            datagramLock.lock();
            try {
                long deadline = System.nanoTime() + timeout.toNanos();
                while (datagrams.isEmpty()) {
                    long remaining = deadline - System.nanoTime();
                    if (remaining <= 0) return null;
                    datagramArrived.awaitNanos(remaining);
                }
                return datagrams.pollFirst();
            } catch (InterruptedException e) {
                throw new InterruptedIOException();
            } finally {
                datagramLock.unlock();
            }
        }

        private void datagram(byte[] content) {
            datagramLock.lock();
            try {
                datagrams.addLast(content);
                datagramArrived.signalAll();
            } finally {
                datagramLock.unlock();
            }
        }
    }

    /** A capsule (RFC 9297 section 3.2). */
    record Capsule(long type, byte[] value) {}

    /** A capsule's bytes: its type, its length and {@code value}. */
    static byte[] capsule(long type, byte[] value) {
        ByteArrayOutputStream c = new ByteArrayOutputStream();
        c.writeBytes(QuicVarInt.encode(type));
        c.writeBytes(QuicVarInt.encode(value.length));
        c.writeBytes(value);
        return c.toByteArray();
    }

    /** {@code payload} after a context ID of 0: an HTTP Datagram's content for CONNECT-UDP. */
    static byte[] contextZero(byte[] payload) {
        byte[] out = new byte[payload.length + 1];
        System.arraycopy(payload, 0, out, 1, payload.length);
        return out;
    }

    /** The UDP payload of an HTTP Datagram's content with context ID 0, or null for another context. */
    public static byte[] udpPayload(byte[] content) {
        long context = QuicVarInt.read(content, 0, content.length);
        if (context != 0) return null;
        return Arrays.copyOfRange(content, 1, content.length);
    }

    private final Map<Long, Tunnel> tunnels = new ConcurrentHashMap<>();

    /**
     * Opens a request stream with {@code fields} as its head, not ending it, and reads the response
     * head: a 2xx leaves the tunnel open.
     */
    public Tunnel open(List<HeaderField> fields) throws IOException {
        QuicStream s = quic.openBidirectionalStream();
        Tunnel t = new Tunnel(s);
        tunnels.put(t.id, t);
        new Http3FrameWriter(s.getOutputStream()).writeHeaders(encode(s.id(), fields));
        s.getOutputStream().flush();
        t.readHead();
        return t;
    }

    private void receiveDatagrams() {
        try {
            while (true) {
                byte[] d = quic.receiveDatagram();
                long quarter = QuicVarInt.read(d, 0, d.length);
                if (quarter < 0) continue;
                int at = QuicVarInt.length(quarter);
                Tunnel t = tunnels.get(quarter * 4);
                if (t != null) t.datagram(Arrays.copyOfRange(d, at, d.length));
            }
        } catch (IOException | RuntimeException e) {
            // the connection ended
        }
    }

    @Override
    public void close() {
        quic.close(0x0100, "");
        client.close();
    }
}

