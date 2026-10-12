package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.starlark.ScriptedReadmeTest.inDocs;

import io.github.mahmoudimus.http3.HeaderField;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.H3TestClient;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * {@code on_udp_start}, {@code on_udp_message} and {@code on_udp_end} on live CONNECT-UDP flows of
 * a forward proxy's HTTP/3 listener: the documented example, {@code ctx.send}, {@code ctx.vars} and
 * typed scripts.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class ScriptedUdpTest {

    static final String TAG = """
            def on_udp_start(ctx):
                log.info("UDP flow to %s (%s) from %s" % (ctx.server, ctx.address, ctx.client_ip))

            def on_udp_message(msg, ctx):
                # Drop the client's datagrams that mention "blocked"; tag the target's answers.
                if msg.text == None:
                    return None
                if msg.from_client and "blocked" in msg.text:
                    return False
                if not msg.from_client:
                    return msg.text + " (via MicroProxy)"
            """;

    static final String TYPED = """
            def on_udp_start(ctx: UdpContext) -> None:
                ctx.send(False, "hello from %s" % ctx.server)

            def on_udp_message(msg: UdpMessage, ctx: UdpContext) -> UdpMessage | str | bool | None:
                ctx.vars["n"] = ctx.vars.get("n", 0) + 1
                if msg.from_client:
                    return msg.with_text("#%d %s" % (ctx.vars["n"], msg.text or ""))
                return None

            def on_udp_end(ctx: UdpContext) -> None:
                log.info("UDP flow to %s ended after %d datagrams" % (ctx.server, ctx.vars.get("n", 0)))
            """;

    private static final SelfSignedSslContextSource TLS = new SelfSignedSslContextSource();

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

    @AfterEach
    void tearDown() throws Exception {
        scriptLog.removeHandler(handler);
        scriptLog.setLevel(level);
        for (AutoCloseable c : closeables) c.close();
    }

    /** A UDP server on loopback that sends every datagram back; what it received is in {@code received}. */
    private DatagramSocket echo(List<String> received) throws IOException {
        DatagramSocket socket = new DatagramSocket(new InetSocketAddress(TestSupport.LOOPBACK, 0));
        closeables.add(socket::close);
        Thread.ofVirtual().start(() -> {
            byte[] buf = new byte[65535];
            while (!socket.isClosed()) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                try {
                    socket.receive(p);
                    received.add(new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8));
                    socket.send(new DatagramPacket(p.getData(), p.getLength(), p.getSocketAddress()));
                } catch (IOException e) {
                    return;
                }
            }
        });
        return socket;
    }

    /** A forward proxy serving HTTP/3 whose CONNECT-UDP flows go through {@code source}'s hooks, and a client of it. */
    private H3TestClient.Tunnel flow(String source, int port) throws Exception {
        level = scriptLog.getLevel();
        // (The tests' logging configuration shows warnings only.)
        scriptLog.setLevel(java.util.logging.Level.INFO);
        scriptLog.addHandler(handler);
        ScriptedProxy script = ScriptedProxy.builder(source, "udp.star").build();
        assertTrue(script.definesUdpHooks());
        assertFalse(script.definesTcpHooks());
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).withSslContextSource(TLS).withHttp3(true)
                .withUdpInterceptor(script.udpInterceptor()).start();
        closeables.add(proxy::abort);
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        H3TestClient client = H3TestClient.connect(address, "localhost", TLS.getCertificate());
        closeables.add(client);
        H3TestClient.Tunnel tunnel = client.open(H3TestClient.extendedConnect("connect-udp", "https",
                "localhost:" + proxy.getListenAddress().getPort(), "/.well-known/masque/udp/127.0.0.1/" + port + "/",
                new HeaderField("capsule-protocol", "?1")));
        assertEquals(200, tunnel.status);
        return tunnel;
    }

    private static String next(H3TestClient.Tunnel tunnel) throws IOException {
        byte[] content = tunnel.receiveDatagram(Duration.ofSeconds(10));
        assertNotNull(content, "no datagram");
        return new String(H3TestClient.udpPayload(content), StandardCharsets.UTF_8);
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void readmeExample() throws Exception {
        List<String> received = new CopyOnWriteArrayList<>();
        DatagramSocket udp = echo(received);
        H3TestClient.Tunnel tunnel = flow(inDocs(TAG), udp.getLocalPort());
        tunnel.sendDatagram(utf8("blocked.example?"));
        tunnel.sendDatagram(utf8("allowed.example?"));
        assertEquals("allowed.example? (via MicroProxy)", next(tunnel));
        assertEquals(List.of("allowed.example?"), received);
        assertTrue(logged.contains("UDP flow to 127.0.0.1:" + udp.getLocalPort() + " (127.0.0.1) from 127.0.0.1"),
                logged.toString());
    }

    @Test
    void typedHooksSendCountAndEnd() throws Exception {
        List<String> received = new CopyOnWriteArrayList<>();
        DatagramSocket udp = echo(received);
        H3TestClient.Tunnel tunnel = flow(TYPED, udp.getLocalPort());
        assertEquals("hello from 127.0.0.1:" + udp.getLocalPort(), next(tunnel));
        tunnel.sendDatagram(utf8("a"));
        assertEquals("#1 a", next(tunnel));
        tunnel.sendDatagram(utf8("b"));
        assertEquals("#3 b", next(tunnel), "the echo of #1 counted too");
        tunnel.end();
        assertEquals(-1, tunnel.in().read());
        TestSupport.eventually("on_udp_end", () -> logged.stream().anyMatch(l -> l.contains("ended after 4 datagrams")));
        assertEquals(List.of("#1 a", "#3 b"), received);
    }
}
