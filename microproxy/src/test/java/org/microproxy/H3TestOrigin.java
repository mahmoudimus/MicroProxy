package org.microproxy;

import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3Frame;
import io.github.mahmoudimus.http3.Http3FrameReader;
import io.github.mahmoudimus.http3.Http3FrameWriter;
import io.github.mahmoudimus.http3.Http3Headers;
import io.github.mahmoudimus.http3.Http3Settings;
import io.github.mahmoudimus.http3.Http3StreamType;
import io.github.mahmoudimus.http3.QpackDecoder;
import io.github.mahmoudimus.http3.QpackEncoder;
import io.github.mahmoudimus.http3.RequestHeaders;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicServer;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.tls.CertifiedKey;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.tls.CertificateAuthority;

/**
 * A small HTTP/3 origin server for tests, on the QUIC module and http3-codec, with a certificate
 * for {@code localhost}, {@code 127.0.0.1} and {@code origin.test} issued by a test CA. Its QPACK decoder takes the
 * proxy's dynamic table; it encodes with the static table only. Resources:
 *
 * <ul>
 *   <li>{@code /hello}: {@code hello over h3};
 *   <li>{@code /echo}: the request as {@link TestSupport#echo()} shows it (method, URI, fields,
 *       body), with the request's trailers sent back as trailers;
 *   <li>{@code /bytes/<n>}: {@code n} bytes;
 *   <li>{@code /trailers}: a body and the trailer {@code x-checksum: 42};
 *   <li>{@code /goaway}: {@code ok}, then GOAWAY on the connection.
 * </ul>
 */
final class H3TestOrigin implements AutoCloseable {

    static final byte[] HELLO = "hello over h3".getBytes(StandardCharsets.US_ASCII);

    final QuicServer server;
    final AtomicInteger connections = new AtomicInteger();
    final AtomicInteger requests = new AtomicInteger();
    private final ReentrantLock lock = new ReentrantLock();
    private final List<Throwable> errors = new ArrayList<>();
    private final List<String> requestLines = new ArrayList<>();

    H3TestOrigin(CertificateAuthority ca) throws IOException {
        this(ca, 0);
    }

    /** An origin on UDP {@code port} (0 for any), as an HTTPS server on the same TCP port would be reached. */
    H3TestOrigin(CertificateAuthority ca, int port) throws IOException {
        KeyPair keys;
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            keys = g.generateKeyPair();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        X509Certificate leaf = ca.issue(keys.getPublic(), List.of("localhost", "127.0.0.1", "origin.test"));
        CertifiedKey certified = new CertifiedKey(List.of(leaf, ca.getCertificate()), keys.getPrivate());
        ServerConfig config = ServerConfig.builder(TlsConfig.builder().certificate(certified).alpnProtocols("h3").build())
                .build();
        server = QuicServer.bind(new InetSocketAddress(TestSupport.LOOPBACK, port), config);
        Thread.ofVirtual().name("h3-origin-accept").start(this::acceptLoop);
    }

    int port() {
        return server.localAddress().getPort();
    }

    List<Throwable> errors() {
        lock.lock();
        try {
            return List.copyOf(errors);
        } finally {
            lock.unlock();
        }
    }

    /** "METHOD path" of each request, in arrival order. */
    List<String> requestLines() {
        lock.lock();
        try {
            return List.copyOf(requestLines);
        } finally {
            lock.unlock();
        }
    }

    private void fail(Throwable t) {
        lock.lock();
        try {
            errors.add(t);
        } finally {
            lock.unlock();
        }
    }

    private void acceptLoop() {
        while (true) {
            QuicConnection c;
            try {
                c = server.accept();
            } catch (IOException e) {
                return;
            }
            connections.incrementAndGet();
            Thread.ofVirtual().start(() -> new Connection(c).serve());
        }
    }

    /** One connection: its QPACK decoder and control stream. */
    private final class Connection {
        final QuicConnection quic;
        final ReentrantLock qpack = new ReentrantLock();
        final Condition ready = qpack.newCondition();
        final QpackDecoder decoder = new QpackDecoder(4096, 16);
        final Set<Long> resumable = new HashSet<>();
        OutputStream decoderOut;
        Http3FrameWriter control;
        final ReentrantLock controlLock = new ReentrantLock();
        final AtomicInteger lastStream = new AtomicInteger(-1);

        Connection(QuicConnection quic) {
            this.quic = quic;
        }

        void serve() {
            try {
                QuicStream c = quic.openUnidirectionalStream();
                control = new Http3FrameWriter(c.getOutputStream());
                control.writeStreamType(Http3StreamType.CONTROL);
                control.writeSettings(Http3Settings.builder().qpackMaxTableCapacity(4096).qpackBlockedStreams(16).build());
                control.flush();
                QuicStream d = quic.openUnidirectionalStream();
                decoderOut = d.getOutputStream();
                decoderOut.write(Http3StreamType.encode(Http3StreamType.QPACK_DECODER));
                while (true) {
                    QuicStream s = quic.acceptStream();
                    Thread.ofVirtual().start(() -> {
                        try {
                            if (s.isBidirectional()) {
                                lastStream.accumulateAndGet((int) s.id(), Math::max);
                                handle(s);
                            } else {
                                readUni(s);
                            }
                        } catch (IOException e) {
                            // the peer went away, or reset the stream
                        } catch (Throwable t) {
                            fail(t);
                        }
                    });
                }
            } catch (IOException e) {
                // closed
            } catch (Throwable t) {
                fail(t);
            }
        }

        void readUni(QuicStream s) throws IOException {
            InputStream in = s.getInputStream();
            long type = Http3StreamType.read(in);
            if (type == Http3StreamType.QPACK_ENCODER) {
                byte[] buf = new byte[4096];
                for (int n; (n = in.read(buf)) >= 0; ) {
                    qpack.lock();
                    try {
                        resumable.addAll(decoder.onEncoderStream(buf, 0, n));
                        flushDecoder();
                        ready.signalAll();
                    } finally {
                        qpack.unlock();
                    }
                }
            } else {
                in.transferTo(OutputStream.nullOutputStream());
            }
        }

        void flushDecoder() throws IOException {
            byte[] b = decoder.decoderStreamBytes();
            if (b.length > 0) {
                decoderOut.write(b);
                decoderOut.flush();
            }
        }

        List<HeaderField> decode(long id, byte[] section) throws IOException {
            qpack.lock();
            try {
                List<HeaderField> fields = decoder.decode(id, section);
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                while (fields == null) {
                    if (resumable.remove(id)) {
                        fields = decoder.resume(id);
                        break;
                    }
                    long remaining = deadline - System.nanoTime();
                    if (remaining <= 0) throw new IOException("blocked section");
                    ready.awaitNanos(remaining);
                }
                flushDecoder();
                return fields;
            } catch (InterruptedException e) {
                throw new InterruptedIOException();
            } finally {
                qpack.unlock();
            }
        }

        void handle(QuicStream s) throws IOException {
            long id = s.id();
            Http3FrameReader reader = new Http3FrameReader(s.getInputStream());
            reader.setMaxFramePayloadSize(1 << 20);
            RequestHeaders request = null;
            List<HeaderField> trailers = List.of();
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            for (Http3Frame frame; (frame = reader.readFrame()) != null; ) {
                switch (frame) {
                    case Http3Frame.Headers h -> {
                        List<HeaderField> fields = decode(id, h.fieldSection());
                        if (request == null) {
                            request = Http3Headers.toRequest(id, fields);
                        } else {
                            trailers = fields;
                        }
                    }
                    case Http3Frame.Data d -> body.write(d.data());
                    default -> {}
                }
            }
            if (request == null) throw new IOException("no request on stream " + id);
            requests.incrementAndGet();
            lock.lock();
            try {
                requestLines.add(request.method() + " " + request.path());
            } finally {
                lock.unlock();
            }
            String path = request.path();
            byte[] out;
            List<HeaderField> responseTrailers = List.of();
            if (path.equals("/hello") || path.equals("/goaway")) {
                out = path.equals("/hello") ? HELLO : "ok".getBytes(StandardCharsets.US_ASCII);
            } else if (path.startsWith("/echo")) {
                StringBuilder sb = new StringBuilder();
                sb.append("method: ").append(request.method()).append('\n');
                sb.append("uri: ").append(path).append('\n');
                Map<String, List<String>> sorted = new TreeMap<>();
                sorted.computeIfAbsent(":authority", k -> new ArrayList<>()).add(String.valueOf(request.authority()));
                for (HeaderField f : request.fields()) sorted.computeIfAbsent(f.name(), k -> new ArrayList<>()).add(f.value());
                sorted.forEach((k, v) -> v.forEach(value -> sb.append("h:").append(k).append(": ").append(value).append('\n')));
                sb.append('\n').append(body.toString(StandardCharsets.UTF_8));
                out = sb.toString().getBytes(StandardCharsets.UTF_8);
                responseTrailers = trailers;
            } else if (path.startsWith("/bytes/")) {
                int n = Integer.parseInt(path.substring("/bytes/".length()));
                out = new byte[n];
                for (int i = 0; i < n; i++) out[i] = (byte) i;
            } else if (path.equals("/trailers")) {
                out = "with trailers".getBytes(StandardCharsets.US_ASCII);
                responseTrailers = List.of(new HeaderField("x-checksum", "42"));
            } else {
                respond(s, "404", new byte[0], List.of());
                return;
            }
            respond(s, "200", out, responseTrailers);
            if (path.equals("/goaway")) {
                controlLock.lock();
                try {
                    control.writeGoAway(lastStream.get() + 4);
                    control.flush();
                } finally {
                    controlLock.unlock();
                }
            }
        }

        void respond(QuicStream s, String status, byte[] body, List<HeaderField> trailers) throws IOException {
            QpackEncoder encoder = new QpackEncoder();
            List<HeaderField> head = new ArrayList<>(List.of(new HeaderField(":status", status),
                    new HeaderField("x-origin-protocol", "h3"), new HeaderField("server", "h3-test-origin")));
            if (trailers.isEmpty()) head.add(new HeaderField("content-length", Integer.toString(body.length)));
            try (OutputStream out = s.getOutputStream()) {
                Http3FrameWriter w = new Http3FrameWriter(out);
                w.writeHeaders(encoder.encode(s.id(), head));
                for (int off = 0; off < body.length; off += 64 * 1024) {
                    w.writeData(body, off, Math.min(64 * 1024, body.length - off));
                }
                if (!trailers.isEmpty()) w.writeHeaders(encoder.encode(s.id(), trailers));
                w.flush();
            }
        }
    }

    @Override
    public void close() {
        server.close();
    }
}
