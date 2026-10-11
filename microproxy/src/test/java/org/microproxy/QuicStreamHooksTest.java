package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;

import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.QuicStreamException;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.quic.QuicContext;
import org.microproxy.quic.QuicDatagram;
import org.microproxy.quic.QuicInterceptor;
import org.microproxy.quic.QuicStreamContext;
import org.microproxy.quic.QuicStreamMessage;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * QUIC that is not HTTP/3, intercepted on the transparent QUIC listener with the QUIC hooks: a
 * Java client with an ALPN of its own talks to {@link QuicEchoOrigin} through the proxy, whose
 * {@link QuicInterceptor} rewrites, drops and adds stream data on bidirectional and unidirectional
 * streams in both directions, and datagrams; resets and STOP_SENDING are mirrored; {@code
 * --quic-hosts} relays even HTTP/3 stream by stream.
 */
@Timeout(value = 90, unit = TimeUnit.SECONDS)
class QuicStreamHooksTest {

    static final String HOST = "origin.test";
    static final String ALPN = "microproxy-echo";

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<String> decisions = new CopyOnWriteArrayList<>();
    private final List<String> hooks = new CopyOnWriteArrayList<>();
    private HttpProxyServer proxy;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("QUIC Hooks Origin CA");
        proxyCa = CertificateAuthority.generate("QUIC Hooks Proxy CA");
    }

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    private QuicEchoOrigin origin(String... alpn) throws Exception {
        QuicEchoOrigin o = new QuicEchoOrigin(originCa, alpn);
        closeables.add(o);
        return o;
    }

    /** A transparent proxy whose QUIC goes to {@code origin}, intercepting with a CA the clients trust. */
    private HttpProxyServerBootstrap transparent(QuicEchoOrigin origin) {
        return MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(origin.port())
                .withTransparentQuicPort(0)
                .withServerResolver(TransparentQuicTest.TEST_HOSTS)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .plusActivityTracker(new ActivityTracker() {
                    @Override
                    public void transparentQuicFlowDecided(FlowContext flow, ClientHello hello, boolean intercepted,
                            String reason) {
                        decisions.add(intercepted + " " + reason);
                    }
                });
    }

    private InetSocketAddress quicAddress() {
        return new InetSocketAddress(TestSupport.LOOPBACK, proxy.getTransparentQuicAddress().getPort());
    }

    /** A client of the transparent port, trusting {@code anchor}, offering {@code alpn}. */
    private QuicConnection connect(X509Certificate anchor, String... alpn) throws IOException {
        ClientConfig config = ClientConfig.builder(TlsConfig.builder()
                        .alpnProtocols(alpn)
                        .serverName(HOST)
                        .trustManager(H3TestClient.trusting(anchor))
                        .build())
                .transport(TransportConfig.builder().datagramReceiveBufferSize(64 * 1024).build())
                .build();
        QuicClient client = QuicClient.create(config);
        closeables.add(client);
        return client.connect(quicAddress(), HOST, Duration.ofSeconds(10));
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String text(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    /** Sends a command and a body on a new bidirectional stream, finishing it, and reads the answer. */
    private static String exchange(QuicConnection c, String commandAndBody) throws IOException {
        QuicStream s = c.openBidirectionalStream();
        try (OutputStream out = s.getOutputStream()) {
            out.write(utf8(commandAndBody));
        }
        return text(s.getInputStream().readAllBytes());
    }

    /**
     * Rewrites what each side sends byte by byte (so that it does not matter how the stream is cut
     * into messages): the client's to upper case without {@code x}, the server's {@code E} to
     * {@code 3}; greets the client on each stream it opens and adds a farewell before the server's
     * FIN.
     */
    private QuicInterceptor rewriting() {
        return new QuicInterceptor() {
            @Override
            public void quicStart(QuicContext ctx) {
                hooks.add("start " + ctx.sni() + " " + ctx.alpn() + " " + ctx.host() + ":" + ctx.port() + " masque="
                        + ctx.masque());
            }

            @Override
            public void streamOpened(QuicStreamContext s) {
                hooks.add("opened " + s.streamId() + " bidi=" + s.bidirectional() + " client=" + s.clientInitiated());
                if (s.bidirectional() && s.clientInitiated()) s.send(false, utf8("hi:"));
            }

            @Override
            public byte[] streamData(QuicStreamMessage m, QuicStreamContext s) {
                if (m.fromClient()) return m.text().replace("x", "").toUpperCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);
                return m.text().replace('E', '3').getBytes(StandardCharsets.UTF_8);
            }

            @Override
            public void streamFinished(QuicStreamContext s, boolean fromClient) {
                hooks.add("finished " + s.streamId() + " fromClient=" + fromClient);
                if (!fromClient && s.bidirectional() && s.clientInitiated()) s.send(false, utf8(":bye"));
            }

            @Override
            public void streamReset(QuicStreamContext s, boolean fromClient, long code) {
                hooks.add("reset " + s.streamId() + " fromClient=" + fromClient + " code=" + code);
            }

            @Override
            public void streamStopped(QuicStreamContext s, boolean fromClient, long code) {
                hooks.add("stopped " + s.streamId() + " fromClient=" + fromClient + " code=" + code);
            }

            @Override
            public void quicEnd(QuicContext ctx) {
                hooks.add("end");
            }

            @Override
            public void quicError(QuicContext ctx, Throwable error) {
                hooks.add("error " + error.getMessage());
            }
        };
    }

    @Test
    void bidirectionalStreamsAreRewrittenDroppedAndAddedTo() throws Exception {
        QuicEchoOrigin origin = origin(ALPN);
        proxy = transparent(origin).withQuicInterceptor(rewriting()).start();
        QuicConnection c = connect(proxyCa.getCertificate(), ALPN);
        assertEquals(ALPN, c.alpn(), "the server's choice, mirrored");
        assertEquals(proxyCa.getCertificate().getSubjectX500Principal(),
                ((X509Certificate) c.peerCertificates().getFirst()).getIssuerX500Principal());
        assertEquals("hi:3AMPL3 T3T:bye", exchange(c, "echo\nexample xtext"));
        // Many streams at once, each with its own greeting and farewell.
        List<Thread> threads = new ArrayList<>();
        List<String> answers = new CopyOnWriteArrayList<>();
        for (int i = 0; i < 8; i++) {
            int n = i;
            threads.add(Thread.ofVirtual().start(() -> {
                try {
                    answers.add(exchange(c, "echo\nstream " + n));
                } catch (IOException e) {
                    answers.add(e.toString());
                }
            }));
        }
        for (Thread t : threads) t.join();
        Set<String> expected = new HashSet<>();
        for (int i = 0; i < 8; i++) expected.add("hi:STR3AM " + i + ":bye");
        assertEquals(expected, new HashSet<>(answers));
        c.close(9, "done");
        ConnectionError closed = origin.closeReason();
        assertEquals(ConnectionError.Kind.APPLICATION_CLOSED, closed.kind(), "the client's close, mirrored: " + closed);
        assertEquals(9, closed.code());
        eventually("quicEnd", () -> hooks.contains("end"));
        assertEquals("start " + HOST + " " + ALPN + " " + HOST + ":" + origin.port() + " masque=false", hooks.getFirst());
        assertTrue(hooks.contains("opened 0 bidi=true client=true"), hooks.toString());
        assertTrue(hooks.contains("finished 0 fromClient=true"), hooks.toString());
        assertTrue(hooks.contains("finished 0 fromClient=false"), hooks.toString());
        assertEquals(List.of("true ALPN [" + ALPN + "]"), decisions);
        assertEquals("connected " + ALPN + " " + HOST, origin.events.getFirst(), "the server got the client's SNI and ALPN");
    }

    @Test
    void unidirectionalAndServerInitiatedStreamsGoBothWays() throws Exception {
        QuicEchoOrigin origin = origin(ALPN);
        proxy = transparent(origin).withQuicInterceptor(rewriting()).start();
        QuicConnection c = connect(proxyCa.getCertificate(), ALPN);
        QuicStream uni = c.openUnidirectionalStream();
        try (OutputStream out = uni.getOutputStream()) {
            out.write(utf8("uni hello"));
        }
        QuicStream reply = c.acceptStream();
        assertFalse(reply.isBidirectional());
        assertEquals("uni-echo:UNI H3LLO", text(reply.getInputStream().readAllBytes()));
        assertTrue(origin.events.contains("uni UNI HELLO"), origin.events.toString());

        // The server opens a bidirectional and a unidirectional stream of its own.
        QuicStream command = c.openBidirectionalStream();
        try (OutputStream out = command.getOutputStream()) {
            out.write(utf8("push\n"));
        }
        QuicStream pushed = c.acceptStream();
        assertTrue(pushed.isBidirectional());
        assertFalse(pushed.isLocal());
        assertEquals("from server", text(pushed.getInputStream().readAllBytes()));
        try (OutputStream out = pushed.getOutputStream()) {
            out.write(utf8("my reply"));
        }
        QuicStream pushedUni = c.acceptStream();
        assertFalse(pushedUni.isBidirectional());
        assertEquals("uni from server", text(pushedUni.getInputStream().readAllBytes()));
        assertEquals("hi::bye", text(command.getInputStream().readAllBytes()));
        eventually("the reply", () -> origin.events.contains("reply MY REPLY"));
        // Stream IDs on the client's connection: its own, and those the proxy opened for the server's.
        for (String opened : List.of("opened 2 bidi=false client=true", "opened 3 bidi=false client=false",
                "opened 0 bidi=true client=true", "opened 1 bidi=true client=false", "opened 7 bidi=false client=false")) {
            assertTrue(hooks.contains(opened), opened + " in " + hooks);
        }
    }

    @Test
    void datagramsAreRewrittenDroppedAndAdded() throws Exception {
        QuicEchoOrigin origin = origin(ALPN);
        proxy = transparent(origin).withQuicInterceptor(new QuicInterceptor() {
            @Override
            public void quicStart(QuicContext ctx) {
                ctx.sendDatagram(false, utf8("welcome"));
            }

            @Override
            public byte[] streamData(QuicStreamMessage m, QuicStreamContext s) {
                return m.data();
            }

            @Override
            public byte[] datagram(QuicDatagram d, QuicContext ctx) {
                if (d.fromClient()) return utf8("c:" + d.text());
                return d.text().contains("drop") ? null : d.data();
            }
        }).start();
        QuicConnection c = connect(proxyCa.getCertificate(), ALPN);
        assertTrue(c.maxDatagramSize() > 0, "the proxy takes datagrams, as the server does");
        Set<String> received = new HashSet<>();
        received.add(text(c.receiveDatagram(Duration.ofSeconds(10))));
        // Datagrams may be lost: send until each answer arrives.
        for (String d : List.of("ping", "drop", "after")) {
            for (int i = 0; i < 20 && !received.contains("c:" + d); i++) {
                c.sendDatagram(utf8(d));
                byte[] got = c.receiveDatagram(Duration.ofMillis(d.equals("drop") ? 100 : 500));
                if (got != null) received.add(text(got));
                if (d.equals("drop") && i >= 3) break;
            }
        }
        assertEquals(Set.of("welcome", "c:ping", "c:after"), received);
    }

    @Test
    void resetsAndStopSendingAreMirrored() throws Exception {
        QuicEchoOrigin origin = origin(ALPN);
        proxy = transparent(origin).withQuicInterceptor(rewriting()).start();
        QuicConnection c = connect(proxyCa.getCertificate(), ALPN);

        // The client resets its side: the server sees a reset with the same code.
        QuicStream watched = c.openBidirectionalStream();
        OutputStream out = watched.getOutputStream();
        out.write(utf8("watch\npartial"));
        out.flush();
        eventually("the stream reaching the server", () -> hooks.stream().anyMatch(h -> h.startsWith("opened 0")));
        Thread.sleep(200);
        watched.reset(42);
        eventually("the server seeing the reset", () -> origin.events.contains("reset 42"));
        assertTrue(hooks.contains("reset 0 fromClient=true code=42"), hooks.toString());

        // The server resets its side: the client sees a reset with the same code.
        QuicStream reset = c.openBidirectionalStream();
        reset.getOutputStream().write(utf8("reset\n"));
        QuicStreamException e = assertThrows(QuicStreamException.class, () -> reset.getInputStream().readAllBytes());
        assertEquals(QuicStreamException.Kind.RESET, e.kind());
        assertEquals(77, e.errorCode());
        eventually("streamReset", () -> hooks.contains("reset 4 fromClient=false code=77"));

        // The server asks the client to stop sending: the client is asked the same.
        QuicStream stopped = c.openBidirectionalStream();
        stopped.getOutputStream().write(utf8("stop\n"));
        assertEquals(55, stopped.awaitStopped());
        assertTrue(hooks.contains("stopped 8 fromClient=false code=55"), hooks.toString());
        // The connection goes on.
        assertEquals("hi:3CHO:bye", exchange(c, "echo\necho"));
    }

    /** The host rules and filters still decide first: an ignored host is relayed untouched. */
    @Test
    void ignoredHostsAreRelayedEvenWithAnInterceptor() throws Exception {
        QuicEchoOrigin origin = origin(ALPN);
        proxy = transparent(origin).withQuicInterceptor(rewriting()).withIgnoreHosts("^origin\\.test:").start();
        QuicConnection c = connect(originCa.getCertificate(), ALPN);
        assertEquals(originCa.getCertificate().getSubjectX500Principal(),
                ((X509Certificate) c.peerCertificates().getFirst()).getIssuerX500Principal());
        assertEquals("example", exchange(c, "echo\nexample"));
        assertTrue(decisions.getFirst().startsWith("false an ignored host"), decisions.toString());
        assertTrue(hooks.isEmpty(), hooks.toString());
    }

    /** Without an interceptor, QUIC that is not HTTP/3 is relayed as before. */
    @Test
    void withoutAnInterceptorOtherQuicIsRelayed() throws Exception {
        QuicEchoOrigin origin = origin(ALPN);
        proxy = transparent(origin).start();
        QuicConnection c = connect(originCa.getCertificate(), ALPN);
        assertEquals("example", exchange(c, "echo\nexample"));
        assertTrue(decisions.getFirst().contains("no HTTP/3"), decisions.toString());
    }

    /**
     * The QUIC hosts are relayed stream by stream even when they speak HTTP/3, and their other
     * QUIC is intercepted without an interceptor: the streams go across untouched.
     */
    @Test
    void quicHostsAreInterceptedStreamByStream() throws Exception {
        QuicEchoOrigin origin = origin("h3", ALPN);
        proxy = transparent(origin).withQuicHosts("^origin\\.").start();
        QuicConnection c = connect(proxyCa.getCertificate(), "h3");
        assertEquals("h3", c.alpn());
        assertEquals("example", exchange(c, "echo\nexample"));
        QuicConnection other = connect(proxyCa.getCertificate(), ALPN);
        assertEquals(ALPN, other.alpn());
        assertEquals("other", exchange(other, "echo\nother"));
        assertEquals(List.of("true a QUIC host", "true a QUIC host"), decisions);
    }

    /** A hook that throws passes the data on unchanged, and the stream goes on. */
    @Test
    void aThrowingHookPassesTheDataOn() throws Exception {
        QuicEchoOrigin origin = origin(ALPN);
        proxy = transparent(origin).withQuicInterceptor((m, s) -> {
            throw new IllegalStateException("broken hook");
        }).start();
        QuicConnection c = connect(proxyCa.getCertificate(), ALPN);
        assertEquals("unchanged", exchange(c, "echo\nunchanged"));
    }

    /** A large transfer goes through within flow control, without the proxy holding it. */
    @Test
    void largeTransfersFlowEndToEnd() throws Exception {
        QuicEchoOrigin origin = origin(ALPN);
        proxy = transparent(origin).withQuicInterceptor((m, s) -> m.data()).start();
        QuicConnection c = connect(proxyCa.getCertificate(), ALPN);
        byte[] big = new byte[3_000_000];
        new java.util.Random(5).nextBytes(big);
        QuicStream s = c.openBidirectionalStream();
        Thread writer = Thread.ofVirtual().start(() -> {
            try (OutputStream out = s.getOutputStream()) {
                out.write(utf8("echo\n"));
                out.write(big);
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        });
        byte[] echoed = s.getInputStream().readAllBytes();
        writer.join();
        assertArrayEquals(big, echoed);
    }
}
