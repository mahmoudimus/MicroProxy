package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A Java echo server for the tests, with the same behaviour as the aioquic peer: bidirectional
 * streams are echoed, a unidirectional stream's SHA-256 digest comes back on a new unidirectional
 * stream, datagrams are echoed, and a stream carrying exactly {@code close-me} closes the
 * connection with code 42 and reason "bye".
 */
final class EchoServer implements AutoCloseable {

    final QuicServer server;
    /** Every connection accepted, in order. */
    final LinkedBlockingQueue<QuicConnection> accepted = new LinkedBlockingQueue<>();
    private final List<Throwable> errors = new ArrayList<>();
    private final ReentrantLock lock = new ReentrantLock();

    EchoServer(ServerConfig config) throws IOException {
        this(config, EndpointConfig.defaults());
    }

    EchoServer(ServerConfig config, EndpointConfig endpointConfig) throws IOException {
        this(config, endpointConfig, null);
    }

    /** A server whose {@code filter} sees the datagrams no connection claims (none when null). */
    EchoServer(ServerConfig config, EndpointConfig endpointConfig, QuicServer.DatagramFilter filter) throws IOException {
        InetSocketAddress loopback = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        server = filter == null ? QuicServer.bind(loopback, config, endpointConfig)
                : QuicServer.bind(loopback, config, endpointConfig, filter);
        Thread.ofVirtual().name("echo-acceptor").start(this::acceptLoop);
    }

    /** Echoes on the connections {@code server} accepts, such as an unbound server's. */
    EchoServer(QuicServer server) {
        this.server = server;
        Thread.ofVirtual().name("echo-acceptor").start(this::acceptLoop);
    }

    InetSocketAddress address() {
        return server.localAddress();
    }

    List<Throwable> errors() {
        lock.lock();
        try {
            return new ArrayList<>(errors);
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
                return; // closed
            }
            accepted.add(c);
            Thread.ofVirtual().start(() -> serveDatagrams(c));
            Thread.ofVirtual().start(() -> serveConnection(c));
        }
    }

    private static void serveDatagrams(QuicConnection c) {
        try {
            while (true) {
                byte[] d = c.receiveDatagram();
                if (d.length <= c.maxDatagramSize()) { // the path back may carry less
                    c.sendDatagram(d);
                }
            }
        } catch (IOException | RuntimeException e) {
            // closed
        }
    }

    private void serveConnection(QuicConnection c) {
        while (true) {
            QuicStream s;
            try {
                s = c.acceptStream();
            } catch (IOException e) {
                return;
            }
            Thread.ofVirtual().start(() -> {
                try {
                    serveStream(c, s);
                } catch (QuicConnectionException | QuicStreamException e) {
                    // the client went away or abandoned the stream
                } catch (Throwable t) {
                    lock.lock();
                    try {
                        errors.add(t);
                    } finally {
                        lock.unlock();
                    }
                }
            });
        }
    }

    private static void serveStream(QuicConnection c, QuicStream s) throws IOException {
        if (s.isBidirectional()) {
            InputStream in = s.getInputStream();
            byte[] buf = new byte[64 * 1024];
            int first = in.read(buf);
            // A command arrives whole in the first read; echoing never waits for more than a read
            if (first == 8 && new String(buf, 0, 8, java.nio.charset.StandardCharsets.US_ASCII).equals("close-me")) {
                c.close(42, "bye");
                return;
            }
            try (OutputStream out = s.getOutputStream()) {
                if (first > 0) {
                    out.write(buf, 0, first);
                    in.transferTo(out);
                }
            }
        } else {
            MessageDigest sha = sha256();
            byte[] buf = new byte[64 * 1024];
            InputStream in = s.getInputStream();
            for (int n; (n = in.read(buf)) > 0; ) {
                sha.update(buf, 0, n);
            }
            QuicStream reply = c.openUnidirectionalStream();
            try (OutputStream out = reply.getOutputStream()) {
                out.write(sha.digest());
            }
        }
    }

    static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        server.close();
    }
}
