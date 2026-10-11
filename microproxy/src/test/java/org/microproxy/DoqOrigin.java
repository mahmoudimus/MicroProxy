package org.microproxy;

import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicServer;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.QuicStreamException;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.CertifiedKey;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.microproxy.dns.DnsMessage;
import org.microproxy.quic.MessageFramer;
import org.microproxy.tls.CertificateAuthority;

/**
 * A QUIC server for the message framing tests, with a certificate for {@code origin.test} (and
 * {@code localhost}) from a test CA. On a {@code doq} connection it is a DNS over QUIC server (RFC
 * 9250): each stream carries one query with a two-byte length prefix, answered on the same stream
 * from a zone of IPv4 addresses (NXDOMAIN for other names), then finished. On a connection of any
 * other ALPN it echoes each bidirectional stream as it is, finishing it when the client does.
 */
public final class DoqOrigin implements AutoCloseable {

    public final QuicServer server;
    /** The questions it was asked ({@code name TYPE}) and what else it saw ({@code reset <code>}). */
    public final List<String> events = new CopyOnWriteArrayList<>();
    private final Map<String, String> zone;

    /**
     * @param ca the CA that issues the server's certificate
     * @param zone names (lower case) and their IPv4 addresses
     * @param alpn the protocols the server speaks
     */
    public DoqOrigin(CertificateAuthority ca, Map<String, String> zone, String... alpn) throws Exception {
        this.zone = zone;
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = g.generateKeyPair();
        X509Certificate leaf = ca.issue(keys.getPublic(), List.of("localhost", "127.0.0.1", "origin.test"));
        ServerConfig config = ServerConfig.builder(TlsConfig.builder()
                        .certificate(new CertifiedKey(List.of(leaf, ca.getCertificate()), keys.getPrivate()))
                        .alpnProtocols(alpn)
                        .build())
                .transport(TransportConfig.builder().maxIdleTimeout(Duration.ofSeconds(30)).build())
                .build();
        server = QuicServer.bind(new InetSocketAddress(TestSupport.LOOPBACK, 0), config);
        Thread.ofVirtual().name("doq-origin-acceptor").start(this::acceptLoop);
    }

    public int port() {
        return server.localAddress().getPort();
    }

    private void acceptLoop() {
        while (true) {
            QuicConnection c;
            try {
                c = server.accept();
            } catch (IOException e) {
                return;
            }
            Thread.ofVirtual().start(() -> streams(c));
        }
    }

    private void streams(QuicConnection c) {
        boolean doq = "doq".equals(c.alpn());
        while (true) {
            QuicStream s;
            try {
                s = c.acceptStream();
            } catch (IOException e) {
                return;
            }
            Thread.ofVirtual().start(() -> {
                try {
                    if (doq) {
                        answer(s);
                    } else {
                        try (OutputStream out = s.getOutputStream()) {
                            s.getInputStream().transferTo(out);
                        }
                    }
                } catch (QuicStreamException e) {
                    events.add((e.kind() == QuicStreamException.Kind.RESET ? "reset " : "stopped ") + e.errorCode());
                } catch (IOException | RuntimeException e) {
                    events.add("error " + e.getMessage());
                }
            });
        }
    }

    /** Reads a query (all of the stream), answers it and finishes the stream. */
    private void answer(QuicStream s) throws IOException {
        byte[] framed = s.getInputStream().readAllBytes();
        MessageFramer u16 = MessageFramer.u16();
        if (u16.frameLength(framed, 0, framed.length) != framed.length) {
            events.add("bad framing " + framed.length);
            s.reset(2);
            return;
        }
        DnsMessage query = DnsMessage.decode(u16.payload(framed));
        DnsMessage.Question q = query.questions().getFirst();
        events.add(q.name() + " " + q.typeName());
        String address = zone.get(q.name().toLowerCase(Locale.ROOT));
        List<DnsMessage.ResourceRecord> answers = new ArrayList<>();
        if (address != null && q.type() == DnsMessage.A) {
            answers.add(DnsMessage.ResourceRecord.of(q.name(), DnsMessage.A, 300, DnsMessage.Address.of(address)));
        }
        DnsMessage reply = query.reply(answers);
        if (address == null) reply = reply.withRcode(3);
        try (OutputStream out = s.getOutputStream()) {
            out.write(u16.frame(reply.encode()));
        }
    }

    /**
     * A DNS over QUIC exchange on a new stream: the query, framed, then the stream's end; the
     * answer, read to the stream's end.
     */
    public static DnsMessage query(QuicConnection c, DnsMessage query) throws IOException {
        QuicStream s = c.openBidirectionalStream();
        try (OutputStream out = s.getOutputStream()) {
            out.write(MessageFramer.u16().frame(query.encode()));
        }
        InputStream in = s.getInputStream();
        byte[] framed = in.readAllBytes();
        long length = MessageFramer.u16().frameLength(framed, 0, framed.length);
        if (length != framed.length) throw new IOException("a DoQ answer of " + framed.length + " bytes, framed as " + length);
        return DnsMessage.decode(MessageFramer.u16().payload(framed));
    }

    @Override
    public void close() {
        server.close();
    }
}
