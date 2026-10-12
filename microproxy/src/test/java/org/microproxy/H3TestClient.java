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
import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.QuicStreamException;
import io.github.mahmoudimus.quic.connection.ClientConfig;
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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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
    }

    /** Connects to {@code address} as {@code serverName}, trusting {@code anchor} (or every server when null). */
    public static H3TestClient connect(InetSocketAddress address, String serverName, X509Certificate anchor) throws IOException {
        return connect(address, serverName, anchor, new Options());
    }

    public static H3TestClient connect(InetSocketAddress address, String serverName, X509Certificate anchor, Options options)
            throws IOException {
        TlsConfig.Builder tls = TlsConfig.builder().alpnProtocols("h3").serverName(serverName);
        if (anchor == null) {
            tls.trustAllCertificates(true);
        } else {
            tls.trustManager(trusting(anchor));
        }
        ClientConfig config = ClientConfig.builder(tls.build())
                .transport(TransportConfig.builder().maxIdleTimeout(options.idleTimeout).build())
                .build();
        QuicClient client = QuicClient.create(config);
        try {
            QuicConnection quic = client.connect(address, serverName, Duration.ofSeconds(10));
            return new H3TestClient(client, quic, options, serverName + ":" + address.getPort());
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

    @Override
    public void close() {
        quic.close(0x0100, "");
        client.close();
    }
}
