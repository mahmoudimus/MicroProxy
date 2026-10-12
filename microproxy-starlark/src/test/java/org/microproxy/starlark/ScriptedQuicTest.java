package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.starlark.ScriptedReadmeTest.inDocs;

import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.QuicEchoOrigin;
import org.microproxy.TestSupport;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * {@code on_quic_start}, {@code on_quic_stream_data}, {@code on_quic_datagram} and {@code
 * on_quic_end} on QUIC that is not HTTP/3, intercepted on a transparent QUIC listener: the
 * documented example and a typed script with {@code ctx.send}, {@code ctx.send_datagram} and {@code
 * ctx.vars}.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class ScriptedQuicTest {

    static final String ALPN = "microproxy-echo";
    static final String HOST = "origin.test";

    static final String REDACT = """
            def on_quic_start(ctx):
                log.info("QUIC %s to %s for %s" % (ctx.alpn, ctx.server, ctx.client_ip))

            def on_quic_stream_data(msg, ctx):
                # A stream is a byte stream, as TCP is: a message is whatever one read returned.
                if not msg.from_client and msg.text != None:
                    return msg.text.replace("secret", "******")

            def on_quic_datagram(msg, ctx):
                if msg.from_client and msg.text == "blocked":
                    return False
            """;

    static final String TYPED = """
            def on_quic_start(ctx: QuicContext) -> None:
                ctx.vars["streams"] = 0
                ctx.send_datagram(False, "hello from %s" % ctx.sni)

            def on_quic_stream_data(msg: QuicMessage, ctx: QuicContext) -> QuicMessage | str | bool | None:
                if msg.from_client and ctx.stream_id not in ctx.vars:
                    ctx.vars[ctx.stream_id] = True
                    ctx.vars["streams"] = ctx.vars["streams"] + 1
                    if ctx.bidirectional and ctx.client_initiated:
                        ctx.send(False, "[%s]" % ctx.alpn)
                if msg.from_client and msg.text != None:
                    return msg.with_text(cast(str, msg.text).upper())
                return None

            def on_quic_datagram(msg: QuicMessage, ctx: QuicContext) -> QuicMessage | bool | None:
                if msg.from_client and msg.text == "blocked":
                    return False
                return None

            def on_quic_end(ctx: QuicContext) -> None:
                log.info("QUIC to %s ended after %d streams, masque=%s, error=%s"
                         % (ctx.server, ctx.vars["streams"], ctx.masque, ctx.error))
            """;

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();
    private final List<String> logged = new CopyOnWriteArrayList<>();
    private final Handler handler = new Handler() {
        @Override
        public void publish(LogRecord record) {
            String message = java.text.MessageFormat.format(record.getMessage(), record.getParameters());
            logged.add(message.substring(message.indexOf(": ") + 2));
        }

        @Override
        public void flush() {}

        @Override
        public void close() {}
    };
    /** Held for the test: a logger that nothing references may be collected, with the handler on it. */
    private final Logger scriptLog = Logger.getLogger("microproxy.script");
    private java.util.logging.Level level;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("Scripted QUIC Origin CA");
        proxyCa = CertificateAuthority.generate("Scripted QUIC Proxy CA");
    }

    @AfterEach
    void tearDown() throws Exception {
        scriptLog.removeHandler(handler);
        scriptLog.setLevel(level);
        for (AutoCloseable c : closeables) c.close();
    }

    /** A transparent proxy whose QUIC that is not HTTP/3 goes through {@code source}'s hooks, and a client of it. */
    private QuicConnection connect(String source, QuicEchoOrigin origin) throws Exception {
        level = scriptLog.getLevel();
        scriptLog.setLevel(java.util.logging.Level.INFO);
        scriptLog.addHandler(handler);
        ScriptedProxy script = ScriptedProxy.builder(source, "quic.star").build();
        assertTrue(script.definesQuicHooks());
        assertFalse(script.definesTcpHooks());
        HttpProxyServer proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(origin.port())
                .withTransparentQuicPort(0)
                .withServerResolver((host, port) -> {
                    if (host.endsWith(".test")) return new InetSocketAddress(TestSupport.LOOPBACK, port);
                    throw new UnknownHostException(host);
                })
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withQuicInterceptor(script.quicInterceptor())
                .start();
        closeables.add(proxy::abort);
        ClientConfig config = ClientConfig.builder(TlsConfig.builder()
                        .alpnProtocols(ALPN)
                        .serverName(HOST)
                        .trustAllCertificates(true)
                        .build())
                .transport(TransportConfig.builder().datagramReceiveBufferSize(64 * 1024).build())
                .build();
        QuicClient client = QuicClient.create(config);
        closeables.add(client);
        QuicConnection c = client.connect(
                new InetSocketAddress(TestSupport.LOOPBACK, proxy.getTransparentQuicAddress().getPort()), HOST,
                Duration.ofSeconds(10));
        assertEquals(proxyCa.getCertificate().getSubjectX500Principal(),
                ((X509Certificate) c.peerCertificates().getFirst()).getIssuerX500Principal());
        return c;
    }

    private QuicEchoOrigin origin() throws Exception {
        QuicEchoOrigin origin = new QuicEchoOrigin(originCa, ALPN);
        closeables.add(origin);
        return origin;
    }

    private static String exchange(QuicConnection c, String commandAndBody) throws IOException {
        QuicStream s = c.openBidirectionalStream();
        try (OutputStream out = s.getOutputStream()) {
            out.write(commandAndBody.getBytes(StandardCharsets.UTF_8));
        }
        return new String(s.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    /** Sends datagrams until the answers to the last one arrive, collecting what came back. */
    private static Set<String> datagrams(QuicConnection c, String... payloads) throws IOException {
        Set<String> received = new HashSet<>();
        for (String p : payloads) {
            for (int i = 0; i < 5; i++) {
                c.sendDatagram(p.getBytes(StandardCharsets.UTF_8));
                byte[] d;
                while ((d = c.receiveDatagram(Duration.ofMillis(300))) != null) {
                    received.add(new String(d, StandardCharsets.UTF_8));
                }
                if (received.contains(p) || p.equals("blocked")) break;
            }
        }
        return received;
    }

    @Test
    void readmeExample() throws Exception {
        QuicEchoOrigin origin = origin();
        QuicConnection c = connect(inDocs(REDACT), origin);
        assertEquals("the ****** word", exchange(c, "echo\nthe secret word"));
        assertEquals(Set.of("allowed"), datagrams(c, "blocked", "allowed"));
        assertTrue(logged.contains("QUIC " + ALPN + " to " + HOST + ":" + origin.port() + " for 127.0.0.1"),
                logged.toString());
    }

    @Test
    void typedHooksSendCountAndEnd() throws Exception {
        QuicEchoOrigin origin = origin();
        QuicConnection c = connect(TYPED, origin);
        assertEquals("[" + ALPN + "]HELLO", exchange(c, "echo\nhello"));
        assertEquals("[" + ALPN + "]AGAIN", exchange(c, "echo\nagain"));
        Set<String> received = datagrams(c, "blocked", "ok");
        assertEquals(Set.of("hello from " + HOST, "ok"), received);
        c.close(0, "done");
        TestSupport.eventually("on_quic_end", () -> logged.stream().anyMatch(l -> l.contains("ended after")));
        assertTrue(logged.contains("QUIC to " + HOST + ":" + origin.port() + " ended after 2 streams, masque=False,"
                + " error=None"), logged.toString());
    }
}
