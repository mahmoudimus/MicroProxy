package io.github.mahmoudimus.quic;

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
import io.github.mahmoudimus.quic.connection.ServerConfig;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A minimal HTTP/3 server for the interop test, on the blocking QUIC API and http3-codec: static
 * QPACK only (no dynamic table, so no encoder or decoder stream traffic), a control stream with
 * SETTINGS, and three resources: {@code GET /hello}, {@code POST /echo} and {@code GET /bytes/<n>}.
 */
final class Http3TestServer implements AutoCloseable {

    static final byte[] HELLO = "hello from MicroProxy QUIC".getBytes(StandardCharsets.US_ASCII);

    final QuicServer server;
    private final List<Throwable> errors = new ArrayList<>();
    private final ReentrantLock lock = new ReentrantLock();

    Http3TestServer(ServerConfig config) throws IOException {
        server = QuicServer.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), config);
        Thread.ofVirtual().name("h3-acceptor").start(this::acceptLoop);
    }

    List<Throwable> errors() {
        lock.lock();
        try {
            return new ArrayList<>(errors);
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
            Thread.ofVirtual().start(() -> serve(c));
        }
    }

    private void serve(QuicConnection c) {
        try {
            // Our control stream stays open for the connection's life
            QuicStream control = c.openUnidirectionalStream();
            Http3FrameWriter w = new Http3FrameWriter(control.getOutputStream());
            w.writeStreamType(Http3StreamType.CONTROL);
            w.writeSettings(Http3Settings.builder().qpackMaxTableCapacity(0).qpackBlockedStreams(0).build());
            w.flush();
            while (true) {
                QuicStream s = c.acceptStream();
                Thread.ofVirtual().start(() -> {
                    try {
                        if (s.isBidirectional()) {
                            handleRequest(s);
                        } else {
                            // Control and QPACK streams: read the type, then the rest
                            InputStream in = s.getInputStream();
                            new Http3FrameReader(in).readStreamType();
                            in.transferTo(OutputStream.nullOutputStream());
                        }
                    } catch (QuicConnectionException e) {
                        // the client went away
                    } catch (Throwable t) {
                        fail(t);
                    }
                });
            }
        } catch (QuicConnectionException e) {
            // closed
        } catch (Throwable t) {
            fail(t);
        }
    }

    private static void handleRequest(QuicStream s) throws IOException {
        long id = s.id();
        Http3FrameReader reader = new Http3FrameReader(s.getInputStream());
        reader.setMaxFramePayloadSize(16 << 20);
        QpackDecoder decoder = new QpackDecoder(0, 0);
        RequestHeaders request = null;
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (Http3Frame frame; (frame = reader.readFrame()) != null; ) {
            switch (frame) {
                case Http3Frame.Headers h -> request = Http3Headers.toRequest(id, decoder.decode(id, h.fieldSection()));
                case Http3Frame.Data d -> body.write(d.data());
                default -> {}
            }
        }
        if (request == null) {
            throw new IOException("request stream " + id + " without HEADERS");
        }
        String path = request.path();
        byte[] response;
        String status = "200";
        if ("GET".equals(request.method()) && "/hello".equals(path)) {
            response = HELLO;
        } else if ("POST".equals(request.method()) && "/echo".equals(path)) {
            response = body.toByteArray();
        } else if ("GET".equals(request.method()) && path.startsWith("/bytes/")) {
            int n = Integer.parseInt(path.substring("/bytes/".length()));
            response = new byte[n];
            for (int i = 0; i < n; i++) {
                response[i] = (byte) i;
            }
        } else {
            status = "404";
            response = new byte[0];
        }
        byte[] fieldSection = new QpackEncoder().encode(id, List.of(new HeaderField(":status", status),
                new HeaderField("content-length", Integer.toString(response.length)),
                new HeaderField("server", "microproxy-quic")));
        try (OutputStream out = s.getOutputStream()) {
            Http3FrameWriter writer = new Http3FrameWriter(out);
            writer.writeHeaders(fieldSection);
            for (int off = 0; off < response.length; off += 64 * 1024) {
                writer.writeData(response, off, Math.min(64 * 1024, response.length - off));
            }
            writer.flush();
        }
    }

    @Override
    public void close() {
        server.close();
    }
}
