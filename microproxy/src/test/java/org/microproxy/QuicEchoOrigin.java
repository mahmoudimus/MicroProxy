package org.microproxy;

import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicServer;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.QuicStreamException;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.CertifiedKey;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.microproxy.tls.CertificateAuthority;

/**
 * A QUIC server for tests that speaks a small protocol of its own over raw streams, with a
 * certificate for {@code localhost}, {@code 127.0.0.1} and {@code origin.test} from a test CA and
 * an ALPN of the test's choosing. A bidirectional stream the client opens starts with a command
 * line (read case-insensitively):
 *
 * <ul>
 *   <li>{@code echo}: the rest of the stream comes back, then the FIN;
 *   <li>{@code reset}: the server resets its side with code 77;
 *   <li>{@code stop}: the server asks the client to stop sending (code 55) and finishes its side;
 *   <li>{@code watch}: the server reads until the stream ends, and records {@code reset <code>}
 *       when the client resets it, or {@code fin <text>};
 *   <li>{@code push}: the server opens a bidirectional stream, sends {@code from server} on it and
 *       records the client's answer as {@code reply <text>}, and opens a unidirectional stream with
 *       {@code uni from server}; then finishes the command's stream.
 * </ul>
 *
 * <p>A unidirectional stream from the client is recorded as {@code uni <text>} and answered on a
 * unidirectional stream of the server's with {@code uni-echo:<text>}. Datagrams are echoed.
 */
public final class QuicEchoOrigin implements AutoCloseable {

    public final QuicServer server;
    /** What the server saw, in order. */
    public final List<String> events = new CopyOnWriteArrayList<>();
    /** Each connection the server accepted, with its ALPN. */
    final LinkedBlockingQueue<QuicConnection> accepted = new LinkedBlockingQueue<>();

    public QuicEchoOrigin(CertificateAuthority ca, String... alpn) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = g.generateKeyPair();
        X509Certificate leaf = ca.issue(keys.getPublic(), List.of("localhost", "127.0.0.1", "origin.test"));
        ServerConfig config = ServerConfig.builder(TlsConfig.builder()
                        .certificate(new CertifiedKey(List.of(leaf, ca.getCertificate()), keys.getPrivate()))
                        .alpnProtocols(alpn)
                        .build())
                .transport(TransportConfig.builder()
                        .maxIdleTimeout(Duration.ofSeconds(30))
                        .datagramReceiveBufferSize(64 * 1024)
                        .build())
                .build();
        server = QuicServer.bind(new InetSocketAddress(TestSupport.LOOPBACK, 0), config);
        Thread.ofVirtual().name("quic-echo-acceptor").start(this::acceptLoop);
    }

    public int port() {
        return server.localAddress().getPort();
    }

    /** Waits for the server's connection to end, and says why. */
    ConnectionError closeReason() throws Exception {
        QuicConnection c = accepted.poll(10, TimeUnit.SECONDS);
        return c == null ? null : c.awaitClosed(Duration.ofSeconds(10));
    }

    private void acceptLoop() {
        while (true) {
            QuicConnection c;
            try {
                c = server.accept();
            } catch (IOException e) {
                return;
            }
            accepted.add(c);
            events.add("connected " + c.alpn() + " " + c.serverName());
            Thread.ofVirtual().start(() -> datagrams(c));
            Thread.ofVirtual().start(() -> streams(c));
        }
    }

    private static void datagrams(QuicConnection c) {
        try {
            while (true) {
                byte[] d = c.receiveDatagram();
                c.sendDatagram(d);
            }
        } catch (IOException | RuntimeException e) {
            // closed
        }
    }

    private void streams(QuicConnection c) {
        while (true) {
            QuicStream s;
            try {
                s = c.acceptStream();
            } catch (IOException e) {
                return;
            }
            Thread.ofVirtual().start(() -> {
                try {
                    serve(c, s);
                } catch (IOException e) {
                    events.add("error " + e.getMessage());
                }
            });
        }
    }

    private void serve(QuicConnection c, QuicStream s) throws IOException {
        InputStream in = s.getInputStream();
        if (!s.isBidirectional()) {
            String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            events.add("uni " + text);
            QuicStream reply = c.openUnidirectionalStream();
            try (OutputStream out = reply.getOutputStream()) {
                out.write(("uni-echo:" + text).getBytes(StandardCharsets.UTF_8));
            }
            return;
        }
        String command = line(in).toLowerCase(java.util.Locale.ROOT);
        OutputStream out = s.getOutputStream();
        switch (command) {
            case "echo" -> {
                in.transferTo(out);
                out.close();
            }
            case "reset" -> s.reset(77);
            case "stop" -> {
                s.stopSending(55);
                events.add("stopped");
                out.close();
            }
            case "watch" -> {
                try {
                    byte[] rest = in.readAllBytes();
                    events.add("fin " + new String(rest, StandardCharsets.UTF_8));
                } catch (QuicStreamException e) {
                    events.add("reset " + e.errorCode());
                }
                out.close();
            }
            case "push" -> {
                QuicStream pushed = c.openBidirectionalStream();
                try (OutputStream pout = pushed.getOutputStream()) {
                    pout.write("from server".getBytes(StandardCharsets.UTF_8));
                }
                events.add("reply " + new String(pushed.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
                QuicStream uni = c.openUnidirectionalStream();
                try (OutputStream uout = uni.getOutputStream()) {
                    uout.write("uni from server".getBytes(StandardCharsets.UTF_8));
                }
                out.close();
            }
            default -> {
                events.add("unknown " + command);
                s.reset(1);
            }
        }
    }

    /** The bytes up to the first newline, as text. */
    private static String line(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (int ch; (ch = in.read()) >= 0 && ch != '\n'; ) b.write(ch);
        return b.toString(StandardCharsets.UTF_8);
    }

    @Override
    public void close() {
        server.close();
    }
}
