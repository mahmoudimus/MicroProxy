package io.github.mahmoudimus.quic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import io.github.mahmoudimus.quic.connection.MtuDiscoveryConfig;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.TestCerts;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The blocking API over real UDP sockets on the loopback interface: a Java client and a Java
 * server, echoing data on many concurrent streams and checking it with SHA-256.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class LoopbackTest {

    static final String ALPN = "microproxy-test";

    private EchoServer echo;
    private QuicServer server;
    private QuicClient client;

    static TransportConfig fastTransport() {
        // Loopback carries large datagrams; let MTU discovery find them
        return TransportConfig.builder()
                .mtuDiscoveryConfig(MtuDiscoveryConfig.DEFAULT.withUpperBound(8192))
                .maxUdpPayloadSize(8192 + 28)
                .streamReceiveWindow(4 << 20)
                .receiveWindow(32 << 20)
                .sendWindow(32 << 20)
                .build();
    }

    static ServerConfig serverConfig(TransportConfig transport) {
        TlsConfig tls = TlsConfig.builder()
                .certificateSelector(hello -> TestCerts.CA.issue(TestCerts.KeyType.P256,
                        hello.serverName() != null ? hello.serverName() : "localhost"))
                .alpnProtocols(ALPN)
                .build();
        return ServerConfig.builder(tls).transport(transport).build();
    }

    static ClientConfig clientConfig(TransportConfig transport) {
        TlsConfig tls = TlsConfig.builder()
                .serverName("localhost")
                .trustManager(TestCerts.CA.trustManager())
                .alpnProtocols(ALPN)
                .build();
        return ClientConfig.builder(tls).transport(transport).build();
    }

    @BeforeEach
    void start() throws IOException {
        echo = new EchoServer(serverConfig(fastTransport()));
        server = echo.server;
        client = QuicClient.create(clientConfig(fastTransport()));
    }

    @AfterEach
    void stop() {
        client.close();
        echo.close();
        assertTrue(echo.errors().isEmpty(), "server errors: " + echo.errors());
    }

    static MessageDigest sha256() {
        return EchoServer.sha256();
    }

    static byte[] data(long seed, int length) {
        byte[] b = new byte[length];
        new Random(seed).nextBytes(b);
        return b;
    }

    private QuicConnection connect() throws IOException {
        return client.connect(server.localAddress(), "localhost", Duration.ofSeconds(10));
    }

    /** Sends data on a new bidirectional stream and returns the SHA-256 of the echo. */
    static byte[] echo(QuicConnection c, byte[] data) throws Exception {
        QuicStream s = c.openBidirectionalStream();
        Thread writer = Thread.ofVirtual().start(() -> {
            try (OutputStream out = s.getOutputStream()) {
                for (int off = 0; off < data.length; off += 50_000) {
                    out.write(data, off, Math.min(50_000, data.length - off));
                }
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        });
        MessageDigest sha = sha256();
        byte[] buf = new byte[64 * 1024];
        long total = 0;
        InputStream in = s.getInputStream();
        for (int n; (n = in.read(buf)) >= 0; ) {
            sha.update(buf, 0, n);
            total += n;
        }
        writer.join();
        assertEquals(data.length, total);
        return sha.digest();
    }

    static void pollUntil(BooleanSupplier condition, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("condition not met in " + timeout);
            }
            Thread.sleep(5);
        }
    }

    @Test
    void handshakeAndSmallEcho() throws Exception {
        try (QuicConnection c = connect()) {
            assertEquals(ALPN, c.alpn());
            assertEquals("localhost", c.serverName());
            assertFalse(c.peerCertificates().isEmpty());
            byte[] msg = "hello over QUIC".getBytes();
            assertArrayEquals(sha256().digest(msg), echo(c, msg));
        }
    }

    @Test
    void manyConcurrentStreamsWithLargeData() throws Exception {
        int streams = 32;
        int size = 1 << 20; // 32 MB each way
        try (QuicConnection c = connect()) {
            long start = System.nanoTime();
            try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
                List<Future<byte[]>> results = new ArrayList<>();
                List<byte[]> expected = new ArrayList<>();
                for (int i = 0; i < streams; i++) {
                    byte[] d = data(i, size);
                    expected.add(sha256().digest(d));
                    results.add(pool.submit(() -> echo(c, d)));
                }
                for (int i = 0; i < streams; i++) {
                    assertArrayEquals(expected.get(i), results.get(i).get(), "stream " + i);
                }
            }
            double seconds = (System.nanoTime() - start) / 1e9;
            double mb = 2.0 * streams * size / 1e6;
            System.out.printf("loopback echo: %d streams, %.0f MB moved in %.2f s = %.1f MB/s; %s%n", streams, mb,
                    seconds, mb / seconds, c.stats());
        }
    }

    @Test
    void largeUnidirectionalTransfer() throws Exception {
        byte[] d = data(99, 24 << 20);
        try (QuicConnection c = connect()) {
            long start = System.nanoTime();
            QuicStream s = c.openUnidirectionalStream();
            try (OutputStream out = s.getOutputStream()) {
                out.write(d);
            }
            QuicStream reply = c.acceptStream();
            assertFalse(reply.isBidirectional());
            byte[] digest = reply.getInputStream().readAllBytes();
            double seconds = (System.nanoTime() - start) / 1e9;
            System.out.printf("loopback upload: %d MB in %.2f s = %.1f MB/s; %s%n", d.length >> 20, seconds,
                    d.length / 1e6 / seconds, c.stats());
            assertArrayEquals(sha256().digest(d), digest);
            assertThrows(IllegalStateException.class, reply::getOutputStream);
        }
    }

    @Test
    void largeTransferWithBbr() throws Exception {
        TransportConfig bbr = fastTransport().toBuilder()
                .congestionControl(TransportConfig.CongestionControl.BBR)
                .build();
        byte[] d = data(7, 16 << 20);
        try (EchoServer bbrEcho = new EchoServer(serverConfig(bbr));
                QuicClient bbrClient = QuicClient.create(clientConfig(bbr));
                QuicConnection c = bbrClient.connect(bbrEcho.server.localAddress(), "localhost", Duration.ofSeconds(10))) {
            var controller = c.withLock(() -> c.connection().recovery().congestion());
            assertTrue(controller instanceof io.github.mahmoudimus.quic.congestion.Bbr, "controller " + controller);
            long start = System.nanoTime();
            assertArrayEquals(sha256().digest(d), echo(c, d));
            double seconds = (System.nanoTime() - start) / 1e9;
            var metrics = c.withLock(() -> c.connection().recovery().congestion().metrics());
            System.out.printf("loopback echo with BBR: %d MB each way in %.2f s = %.1f MB/s; %s; %s%n", d.length >> 20,
                    seconds, 2.0 * d.length / 1e6 / seconds, c.stats(), metrics);
            assertTrue(metrics.bandwidthEstimate() > 0, "metrics " + metrics);
            assertTrue(bbrEcho.errors().isEmpty(), "server errors: " + bbrEcho.errors());
        }
    }

    @Test
    void severalConnectionsInParallel() throws Exception {
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> tasks = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                int seed = i;
                tasks.add(pool.submit(() -> {
                    try (QuicConnection c = connect()) {
                        byte[] d = data(seed, 512 * 1024);
                        assertArrayEquals(sha256().digest(d), echo(c, d));
                    }
                    return null;
                }));
            }
            for (Future<?> f : tasks) {
                f.get();
            }
        }
    }

    @Test
    void datagrams() throws Exception {
        try (QuicConnection c = connect()) {
            assertTrue(c.maxDatagramSize() > 1000, "max " + c.maxDatagramSize());
            // Datagrams are unreliable: resend until the echo comes back
            byte[] reply = null;
            for (int i = 0; i < 50 && reply == null; i++) {
                c.sendDatagram(("ping " + i).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                reply = c.receiveDatagram(Duration.ofMillis(200));
            }
            assertNotNull(reply);
            assertTrue(new String(reply, java.nio.charset.StandardCharsets.US_ASCII).startsWith("ping "));
            byte[] big = data(8, c.maxDatagramSize());
            c.sendDatagram(big);
            assertThrows(IllegalArgumentException.class, () -> c.sendDatagram(new byte[c.maxDatagramSize() + 1]));
        }
    }

    @Test
    void closeWakesBlockedReaderWithReason() throws Exception {
        QuicConnection c = connect();
        QuicStream s = c.openBidirectionalStream();
        s.getOutputStream().write(1); // the server learns of the stream and starts echoing
        assertEquals(1, s.getInputStream().read());
        Thread closer = Thread.ofVirtual().start(() -> c.close(7, "bye"));
        IOException e = assertThrows(IOException.class, () -> s.getInputStream().read());
        assertTrue(e instanceof QuicConnectionException, e.toString());
        closer.join();
        assertEquals(ConnectionError.Kind.LOCALLY_CLOSED, c.closeReason().kind());
    }

    @Test
    void serverShutdownClosesClients() throws Exception {
        QuicConnection c = connect();
        QuicStream s = c.openBidirectionalStream();
        s.getOutputStream().write(1);
        assertEquals(1, s.getInputStream().read());
        pollUntil(() -> server.connectionCount() == 1, Duration.ofSeconds(5));
        server.close();
        ConnectionError reason = c.awaitClosed(Duration.ofSeconds(10));
        assertNotNull(reason);
        assertEquals(ConnectionError.Kind.APPLICATION_CLOSED, reason.kind());
        assertThrows(QuicConnectionException.class, () -> s.getInputStream().read());
        assertThrows(IOException.class, () -> server.accept());
    }

    @Test
    void resetAndStopSending() throws Exception {
        try (QuicConnection c = connect()) {
            QuicStream s = c.openBidirectionalStream();
            s.getOutputStream().write(new byte[1000]);
            s.reset(5);
            // The server's echo sees the reset and gives up; the stream's input may be stopped
            s.stopSending(9);
            assertThrows(IOException.class, () -> s.getOutputStream().write(1));
            byte[] d = data(3, 100_000);
            assertArrayEquals(sha256().digest(d), echo(c, d), "the connection still works");
        }
    }

    /**
     * {@link QuicStream#peerDone} tells, on the thread reading another stream, what the peer sent
     * on this one before what that thread reads: its FIN, a reset or STOP_SENDING, read or not.
     */
    @Test
    void peerDoneFollowsTheOrderFramesArrivedIn() throws Exception {
        try (QuicServer plain = QuicServer.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0),
                        serverConfig(fastTransport()));
                QuicConnection c = client.connect(plain.localAddress(), "localhost", Duration.ofSeconds(10))) {
            QuicConnection served = plain.accept();
            for (String end : List.of("fin", "reset", "stop")) {
                QuicStream ours = c.openBidirectionalStream();
                ours.getOutputStream().write(1);
                QuicStream theirs = served.acceptStream();
                assertEquals(1, theirs.getInputStream().read());
                assertFalse(theirs.peerDone(), end);
                switch (end) {
                    case "fin" -> ours.getOutputStream().close();
                    case "reset" -> ours.reset(5);
                    default -> ours.stopSending(9);
                }
                c.openBidirectionalStream().getOutputStream().write(2);
                QuicStream after = served.acceptStream();
                assertEquals(2, after.getInputStream().read());
                assertTrue(theirs.peerDone(), end);
                assertFalse(after.peerDone(), end);
            }
        }
    }

    @Test
    void keyUpdateDuringTransfer() throws Exception {
        try (QuicConnection c = connect()) {
            for (int i = 0; i < 5; i++) {
                // A key update starts once the previous one is confirmed; data then crosses it
                pollUntil(c::updateKeys, Duration.ofSeconds(10));
                byte[] d = data(i, 1 << 20);
                assertArrayEquals(sha256().digest(d), echo(c, d));
            }
            assertTrue(c.stats().keyUpdates() >= 5, c.stats().toString());
        }
    }

    @Test
    void connectTimesOutAgainstSilentServer() throws Exception {
        try (java.nio.channels.DatagramChannel silent = java.nio.channels.DatagramChannel.open()) {
            silent.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            InetSocketAddress addr = (InetSocketAddress) silent.getLocalAddress();
            QuicConnectionException e = assertThrows(QuicConnectionException.class,
                    () -> client.connect(addr, "localhost", Duration.ofMillis(300)));
            assertEquals(ConnectionError.Kind.TIMED_OUT, e.error().kind());
        }
    }
}
