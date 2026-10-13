package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Clients that move to a new UDP port in the middle of a transfer through the transparent QUIC
 * listener: a relayed flow (the proxy finds it by the client's IP address and sends the server's
 * datagrams to the new port), a flow intercepted stream by stream (the client's connection to the
 * proxy follows it; the proxy's own connection to the server stays where it is), and intercepted
 * HTTP/3. Every transfer is checked with SHA-256, and a relayed or intercepted flow whose client
 * moved is still one {@link FlowRecord} when it ends, with the bytes of both paths.
 */
@Timeout(value = 90, unit = TimeUnit.SECONDS)
class QuicMigrationProxyTest {

    static final String HOST = "origin.test";
    static final String ALPN = QuicStreamHooksTest.ALPN;

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<String> decisions = new CopyOnWriteArrayList<>();
    private HttpProxyServer proxy;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("QUIC Migration Origin CA");
        proxyCa = CertificateAuthority.generate("QUIC Migration Proxy CA");
    }

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (int i = closeables.size() - 1; i >= 0; i--) closeables.get(i).close();
    }

    private HttpProxyServerBootstrap transparent(int port) {
        return MicroProxy.bootstrap()
                .withPort(0)
                .withTransparent(true)
                .withTransparentTlsPort(port)
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

    private QuicConnection connect(X509Certificate anchor) throws IOException {
        return connect(anchor, null);
    }

    /** Connects through the proxy, sending a PING after {@code keepAlive} without sending, if not null. */
    private QuicConnection connect(X509Certificate anchor, Duration keepAlive) throws IOException {
        ClientConfig config = ClientConfig.builder(TlsConfig.builder()
                        .alpnProtocols(ALPN)
                        .serverName(HOST)
                        .trustManager(H3TestClient.trusting(anchor))
                        .build())
                .transport(TransportConfig.defaults().toBuilder().keepAliveInterval(keepAlive).build())
                .build();
        QuicClient client = QuicClient.create(config);
        closeables.add(client);
        return client.connect(quicAddress(), HOST, Duration.ofSeconds(10));
    }

    static byte[] data(long seed, int size) {
        byte[] b = new byte[size];
        new Random(seed).nextBytes(b);
        return b;
    }

    static byte[] sha256(byte[] b) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(b);
    }

    /**
     * Echoes {@code data} through {@link QuicEchoOrigin} on a new stream in the background,
     * counting the bytes that came back; the future holds their SHA-256.
     */
    static CompletableFuture<byte[]> echo(QuicConnection c, byte[] data, AtomicLong received) throws IOException {
        QuicStream s = c.openBidirectionalStream();
        CompletableFuture<byte[]> result = new CompletableFuture<>();
        Thread.ofVirtual().start(() -> {
            try (OutputStream out = s.getOutputStream()) {
                out.write("echo\n".getBytes(StandardCharsets.US_ASCII));
                for (int off = 0; off < data.length; off += 32 * 1024) {
                    out.write(data, off, Math.min(32 * 1024, data.length - off));
                }
            } catch (IOException e) {
                result.completeExceptionally(e);
            }
        });
        Thread.ofVirtual().start(() -> {
            try {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                InputStream in = s.getInputStream();
                byte[] buf = new byte[64 * 1024];
                for (int n; (n = in.read(buf)) >= 0; ) {
                    sha.update(buf, 0, n);
                    received.addAndGet(n);
                }
                result.complete(sha.digest());
            } catch (Exception e) {
                result.completeExceptionally(e);
            }
        });
        return result;
    }

    /** Echoes 8 MB, moving the client to a new port on loopback once a quarter came back. */
    private static void echoWhileMoving(QuicConnection c) throws Exception {
        byte[] data = data(7, 8 << 20);
        AtomicLong received = new AtomicLong();
        CompletableFuture<byte[]> echoed = echo(c, data, received);
        TestSupport.eventually("a quarter echoed", () -> received.get() > data.length / 4);
        InetSocketAddress before = c.localAddress();
        InetSocketAddress after = c.migrate(new InetSocketAddress(TestSupport.LOOPBACK, 0));
        assertNotEquals(before.getPort(), after.getPort());
        assertFalse(echoed.isDone() && received.get() < data.length, "the transfer went on");
        assertArrayEquals(sha256(data), echoed.get(60, TimeUnit.SECONDS), "every byte came back");
        // And a new stream on the new path
        byte[] more = data(8, 100_000);
        assertArrayEquals(sha256(more), echo(c, more, new AtomicLong()).get(30, TimeUnit.SECONDS));
    }

    @Test
    void relayedFlowFollowsAClientOnANewPort() throws Exception {
        QuicEchoOrigin origin = new QuicEchoOrigin(originCa, ALPN);
        closeables.add(origin);
        proxy = transparent(origin.port()).start(); // QUIC that is not HTTP/3, without QUIC hooks: relayed
        QuicConnection c = connect(originCa.getCertificate());
        echoWhileMoving(c);
        assertEquals(1, decisions.size());
        assertTrue(decisions.getFirst().startsWith("false "), "relayed: " + decisions);
        c.close(0, "");
    }

    @Test
    void streamsInterceptedFollowAClientOnANewPort() throws Exception {
        QuicEchoOrigin origin = new QuicEchoOrigin(originCa, ALPN);
        closeables.add(origin);
        proxy = transparent(origin.port()).withQuicInterceptor((message, stream) -> message.data()).start();
        QuicConnection c = connect(proxyCa.getCertificate());
        echoWhileMoving(c);
        assertEquals(List.of("true ALPN [" + ALPN + "]"), decisions);
        c.close(0, "");
    }

    /**
     * The record comes when the relay ends, once the flow has been idle for the relay's idle
     * timeout, shorter than the default so that it comes soon after the client closes. Until then
     * the flow must not go idle, or the relay ends under the transfer, which then never finishes:
     * a connection is quiet at times while it lives, while an endpoint computes its handshake
     * flight (a second on a starved CPU), before the echo starts, between probes as it recovers
     * from loss. Once connected the client sends a PING after 100 ms without sending; the timeout
     * leaves the handshake a few seconds.
     */
    @Test
    void aRelayedFlowWhoseClientMovedIsOneRecordWhenItEnds() throws Exception {
        QuicEchoOrigin origin = new QuicEchoOrigin(originCa, ALPN);
        closeables.add(origin);
        RecordedFlows flows = new RecordedFlows();
        proxy = transparent(origin.port()).plusActivityTracker(flows)
                .withHttp3Options(Http3Options.builder().transparentRelayIdleTimeout(Duration.ofSeconds(3)).build())
                .start();
        QuicConnection c = connect(originCa.getCertificate(), Duration.ofMillis(100));
        echoWhileMoving(c);
        c.close(0, "");
        FlowRecord r = flows.await(FlowRecord.Kind.QUIC_RELAY);
        assertEquals("quic_relayed", r.responseCodeDetails());
        assertTrue(r.bytesReceived() > 8 << 20 && r.bytesSent() > 8 << 20, "both paths counted: " + r);
        assertEquals(r.bytesReceived(), r.upstreamBytesSent());
        assertEquals(r.bytesSent(), r.upstreamBytesReceived());
        assertEquals(origin.port(), r.upstreamAddress().getPort());
        assertEquals(1, flows.records.size(), flows.records.toString());
    }

    @Test
    void aSessionWhoseClientMovedIsOneRecordWhenItEnds() throws Exception {
        QuicEchoOrigin origin = new QuicEchoOrigin(originCa, ALPN);
        closeables.add(origin);
        RecordedFlows flows = new RecordedFlows();
        proxy = transparent(origin.port()).withQuicInterceptor((message, stream) -> message.data())
                .plusActivityTracker(flows).start();
        QuicConnection c = connect(proxyCa.getCertificate());
        echoWhileMoving(c);
        c.close(0, "");
        FlowRecord r = flows.await(FlowRecord.Kind.QUIC);
        assertEquals("quic_streams", r.responseCodeDetails());
        assertTrue(r.bytesReceived() > 8 << 20 && r.bytesSent() > 8 << 20, "both paths counted: " + r);
        assertEquals(r.bytesReceived(), r.upstreamBytesSent());
        assertEquals(r.bytesSent(), r.upstreamBytesReceived());
        assertEquals(origin.port(), r.upstreamAddress().getPort());
        assertEquals(1, flows.records.size(), flows.records.toString());
    }

    @Test
    void interceptedHttp3FollowsAClientOnANewPort() throws Exception {
        H3TestOrigin origin = new H3TestOrigin(originCa);
        closeables.add(origin);
        proxy = transparent(origin.port()).withHttp3Upstream(true).start();
        try (H3TestClient client = H3TestClient.connect(quicAddress(), HOST, proxyCa.getCertificate())) {
            assertEquals("hello over h3", client.get("/hello").text());
            int before = client.quic.localAddress().getPort();
            InetSocketAddress after = client.quic.migrate(new InetSocketAddress(TestSupport.LOOPBACK, 0));
            assertNotEquals(before, after.getPort());
            for (int i = 0; i < 3; i++) assertEquals("hello over h3", client.get("/hello").text());
            byte[] big = data(9, 400_000);
            H3TestClient.Response echo = client.post("/echo", big);
            assertEquals(200, echo.status());
        }
        assertEquals(1, origin.connections.get(), "the proxy's connection to the origin stayed as it was");
        assertTrue(decisions.getFirst().startsWith("true"), decisions.toString());
        assertTrue(origin.errors().isEmpty(), origin.errors().toString());
    }
}
