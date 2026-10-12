/*
 * Ported from quinn-proto src/tests/mod.rs and src/tests/token.rs (Apache-2.0): the connection
 * tests that map onto this implementation, run on the in-memory pair with a fake clock.
 */
package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.packet.PacketHeader;
import io.github.mahmoudimus.quic.tls.TestCerts;
import io.github.mahmoudimus.quic.tls.TlsAlert;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

class ConnectionTest {

    private static final byte[] MSG = "hello".getBytes(StandardCharsets.US_ASCII);
    private static final long MS = 1_000_000L;

    /** Reads everything available on a stream: the bytes, and whether the FIN was seen. */
    private static byte[] readAvailable(Connection c, StreamId id) throws StreamException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteBuffer buf = ByteBuffer.allocate(64 * 1024);
        while (true) {
            buf.clear();
            int n;
            try {
                n = c.read(id, buf);
            } catch (StreamException e) {
                if (e.kind() == StreamException.Kind.BLOCKED) {
                    break;
                }
                throw e;
            }
            if (n < 0) {
                break;
            }
            out.write(buf.array(), 0, n);
        }
        return out.toByteArray();
    }

    private static Connection[] connected(Pair pair) {
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        Pair.assertConnected(client, server);
        pair.drive();
        Pair.drainEvents(client);
        Pair.drainEvents(server);
        return new Connection[] {client, server};
    }

    @Test
    void lifecycle() {
        Pair pair = new Pair();
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        Pair.assertConnected(client, server);
        assertNull(client.pollEvent());
        assertEquals(Pair.ALPN, client.alpn());
        assertEquals(Pair.ALPN, server.alpn());
        assertEquals("localhost", server.serverName());
        assertFalse(client.peerCertificates().isEmpty());
        assertEquals(0, client.recovery().bytesInFlight());

        client.close(pair.time, 42, "whee");
        pair.drive();
        ConnectionEvent.ConnectionLost lost = Pair.nextEvent(server, ConnectionEvent.ConnectionLost.class);
        assertNotNull(lost);
        assertEquals(new ConnectionError(ConnectionError.Kind.APPLICATION_CLOSED, 42, 0, "whee"), lost.reason());
        assertEquals(ConnectionError.Kind.LOCALLY_CLOSED,
                Pair.nextEvent(client, ConnectionEvent.ConnectionLost.class).reason().kind());
        assertNull(client.pollEvent());
        assertEquals(0, pair.client.endpoint.openConnections());
        assertEquals(0, pair.client.endpoint.knownCids());
        assertEquals(0, pair.server.endpoint.openConnections());
        assertEquals(0, pair.server.endpoint.knownCids());
    }

    @Test
    void handshakeWithEveryCipherSuiteAndVersion() {
        for (QuicVersion version : QuicVersion.values()) {
            for (io.github.mahmoudimus.quic.CipherSuite suite : io.github.mahmoudimus.quic.CipherSuite.values()) {
                Pair pair = new Pair();
                TlsConfig tls = TlsConfig.builder().serverName("localhost")
                        .trustManager(TestCerts.CA.trustManager()).alpnProtocols(Pair.ALPN)
                        .cipherSuites(suite).build();
                Connection client = pair.connect(ClientConfig.builder(tls).version(version).build());
                Connection server = pair.serverConnection();
                Pair.assertConnected(client, server);
                assertEquals(suite, client.tlsSession().cipherSuite());
                assertEquals(version, server.version());
                StreamId s = client.openStream(Dir.BI);
                assertDoesNotThrow(() -> client.write(s, ByteBuffer.wrap(MSG)));
                pair.drive();
                assertEquals(s, server.acceptStream(Dir.BI));
                assertArrayEquals(MSG, assertDoesNotThrow(() -> readAvailable(server, s)));
            }
        }
    }

    private interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static <T> T assertDoesNotThrow(ThrowingSupplier<T> s) {
        try {
            return s.get();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static void assertDoesNotThrow(ThrowingRunnable r) {
        try {
            r.run();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    @Test
    void versionNegotiateServer() {
        Endpoint server = new Endpoint(EndpointConfig.defaults(), Pair.serverConfig(TransportConfig.defaults()), true);
        byte[] header = HexFormat.of().parseHex("800a1a2a3a04000000000400000000" + "00");
        // RFC 9000 section 5.2.2: packets too small to start a connection are dropped
        assertNull(server.handle(0, Pair.address(7890), 0, ByteBuffer.wrap(header)));
        byte[] packet = Arrays.copyOf(header, 1200);
        Endpoint.DatagramEvent e = server.handle(0, Pair.address(7890), 0, ByteBuffer.wrap(packet));
        ByteBuffer vn = assertInstanceOf(Endpoint.DatagramEvent.Response.class, e).datagram();
        byte[] b = new byte[vn.remaining()];
        vn.get(b);
        assertTrue((b[0] & 0x80) != 0);
        assertArrayEquals(HexFormat.of().parseHex("0000000004000000000400000000"), Arrays.copyOfRange(b, 1, 15));
        boolean supported = false;
        for (int i = 15; i + 4 <= b.length; i += 4) {
            supported |= ByteBuffer.wrap(b, i, 4).getInt() == QuicVersion.V1.wireValue();
        }
        assertTrue(supported);
    }

    @Test
    void versionNegotiateClient() {
        EndpointConfig zeroLength = EndpointConfig.builder().cidLength(0).build();
        Endpoint client = new Endpoint(zeroLength, null, true);
        Connection conn = client.connect(0, Pair.clientConfig(), Pair.address(7890), "localhost");
        // A Version Negotiation packet for a reserved version, with an empty Destination Connection ID
        byte[] vn = HexFormat.of().parseHex("8000000000" + "00" + "0400000000" + "0a1a2a3a");
        Endpoint.DatagramEvent e = client.handle(0, Pair.address(7890), 0, ByteBuffer.wrap(vn));
        assertEquals(conn, assertInstanceOf(Endpoint.DatagramEvent.Deliver.class, e).connection());
        conn.handleDatagram(0, Pair.address(7890), 0, ByteBuffer.wrap(vn));
        ConnectionEvent.ConnectionLost lost = Pair.nextEvent(conn, ConnectionEvent.ConnectionLost.class);
        assertEquals(ConnectionError.Kind.VERSION_MISMATCH, lost.reason().kind());
    }

    @Test
    void versionNegotiationListingOurVersionIsIgnored() {
        EndpointConfig zeroLength = EndpointConfig.builder().cidLength(0).build();
        Endpoint client = new Endpoint(zeroLength, null, true);
        Connection conn = client.connect(0, Pair.clientConfig(), Pair.address(7890), "localhost");
        byte[] vn = HexFormat.of().parseHex("8000000000" + "00" + "0400000000" + "00000001");
        conn.handleDatagram(0, Pair.address(7890), 0, ByteBuffer.wrap(vn));
        assertFalse(conn.isClosed());
    }

    @Test
    void serverRespondsToUnknownVersionWithNegotiationAndClientConnectsWithV2() {
        EndpointConfig v1Only = EndpointConfig.builder().supportedVersions(QuicVersion.V1).build();
        Pair pair = new Pair(v1Only, Pair.serverConfig(TransportConfig.defaults()), EndpointConfig.defaults());
        Connection client = pair.connect(ClientConfig.builder(Pair.clientTls()).version(QuicVersion.V2).build());
        assertEquals(ConnectionError.Kind.VERSION_MISMATCH,
                Pair.nextEvent(client, ConnectionEvent.ConnectionLost.class).reason().kind());
        assertEquals(0, pair.server.connections.size());
    }

    @Test
    void serverStatelessReset() {
        byte[] resetKey = new byte[64];
        new Random(1).nextBytes(resetKey);
        EndpointConfig config = EndpointConfig.builder().resetKey(resetKey).build();
        Pair pair = new Pair(config, Pair.serverConfig(TransportConfig.defaults()), config);
        Connection client = connected(pair)[0];
        // The server restarts and forgets the connection
        pair.server.endpoint = new Endpoint(config, Pair.serverConfig(TransportConfig.defaults()), true);
        pair.server.connections.clear();
        client.ping();
        pair.drive();
        assertEquals(ConnectionError.Kind.RESET,
                Pair.nextEvent(client, ConnectionEvent.ConnectionLost.class).reason().kind());
        assertTrue(client.isDrained());
    }

    @Test
    void clientStatelessReset() {
        byte[] resetKey = new byte[64];
        new Random(2).nextBytes(resetKey);
        EndpointConfig config = EndpointConfig.builder().resetKey(resetKey).build();
        Pair pair = new Pair(config, Pair.serverConfig(TransportConfig.defaults()), config);
        Connection server = connected(pair)[1];
        pair.client.endpoint = new Endpoint(config, Pair.serverConfig(TransportConfig.defaults()), true);
        pair.client.connections.clear();
        // Something big enough to leave room for a smaller stateless reset
        server.close(pair.time, 42, "x".repeat(128));
        pair.drive();
        assertEquals(ConnectionError.Kind.RESET,
                Pair.nextEvent(server, ConnectionEvent.ConnectionLost.class).reason().kind());
    }

    @Test
    void statelessResetLimit() {
        EndpointConfig config = EndpointConfig.defaults();
        Endpoint endpoint = new Endpoint(config, Pair.serverConfig(TransportConfig.defaults()), true);
        byte[] junk = new byte[1024];
        junk[0] = 0x40; // a short header for an unknown connection
        long t = 5_000_000_000L;
        assertInstanceOf(Endpoint.DatagramEvent.Response.class,
                endpoint.handle(t, Pair.address(42), 0, ByteBuffer.wrap(junk)));
        assertNull(endpoint.handle(t, Pair.address(42), 0, ByteBuffer.wrap(junk)));
        assertNull(endpoint.handle(t + 20 * MS - 1, Pair.address(42), 0, ByteBuffer.wrap(junk)));
        ByteBuffer reset = assertInstanceOf(Endpoint.DatagramEvent.Response.class,
                endpoint.handle(t + 20 * MS, Pair.address(42), 0, ByteBuffer.wrap(junk))).datagram();
        assertTrue(reset.remaining() < junk.length);
        // Too small to answer without amplification
        assertNull(endpoint.handle(t + 40 * MS, Pair.address(42), 0, ByteBuffer.wrap(Arrays.copyOf(junk, 21))));
    }

    @Test
    void finishStreamSimple() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        StreamId s = client.openStream(Dir.UNI);
        client.write(s, ByteBuffer.wrap(MSG));
        assertEquals(1, client.sendStreams());
        client.finish(s);
        pair.drive();
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Finished(s)), client.pollEvent());
        assertNull(client.pollEvent());
        assertEquals(0, client.sendStreams());
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Opened(Dir.UNI)), server.pollEvent());
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Readable(s)), server.pollEvent());
        assertEquals(s, server.acceptStream(Dir.UNI));
        assertNull(server.pollEvent());
        ByteBuffer buf = ByteBuffer.allocate(100);
        assertEquals(MSG.length, server.read(s, buf));
        assertEquals(-1, server.read(s, buf));
    }

    @Test
    void resetStream() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        StreamId s = c[0].openStream(Dir.UNI);
        c[0].write(s, ByteBuffer.wrap(MSG));
        pair.drive();
        c[0].resetStream(s, 42);
        pair.drive();
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Opened(Dir.UNI)), c[1].pollEvent());
        assertEquals(s, c[1].acceptStream(Dir.UNI));
        StreamException e = assertThrows(StreamException.class, () -> c[1].read(s, ByteBuffer.allocate(10)));
        assertEquals(StreamException.Kind.RESET, e.kind());
        assertEquals(42, e.errorCode());
        assertNull(c[0].pollEvent());
    }

    @Test
    void stopStream() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        StreamId s = c[0].openStream(Dir.UNI);
        c[0].write(s, ByteBuffer.wrap(MSG));
        pair.drive();
        c[1].stopSending(s, 42);
        pair.drive();
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Opened(Dir.UNI)), c[1].pollEvent());
        assertEquals(s, c[1].acceptStream(Dir.UNI));
        StreamException e = assertThrows(StreamException.class, () -> c[0].write(s, ByteBuffer.wrap(MSG)));
        assertEquals(StreamException.Kind.STOPPED, e.kind());
        assertEquals(42, e.errorCode());
        e = assertThrows(StreamException.class, () -> c[0].finish(s));
        assertEquals(StreamException.Kind.STOPPED, e.kind());
    }

    @Test
    void rejectUntrustedServerCertificate() {
        Pair pair = new Pair();
        TlsConfig tls = TlsConfig.builder().serverName("localhost").trustManager(TestCerts.OTHER_CA.trustManager())
                .alpnProtocols(Pair.ALPN).build();
        Connection client = pair.connect(ClientConfig.builder(tls).build());
        ConnectionError reason = Pair.nextEvent(client, ConnectionEvent.ConnectionLost.class).reason();
        assertEquals(ConnectionError.Kind.TRANSPORT_ERROR, reason.kind());
        assertEquals(QuicException.CRYPTO_ERROR + TlsAlert.UNKNOWN_CA, reason.code());
        ConnectionError serverSide = Pair.nextEvent(pair.serverConnection(), ConnectionEvent.ConnectionLost.class)
                .reason();
        assertEquals(ConnectionError.Kind.CONNECTION_CLOSED, serverSide.kind());
        assertEquals(QuicException.CRYPTO_ERROR + TlsAlert.UNKNOWN_CA, serverSide.code());
    }

    @Test
    void alpnMismatch() {
        Pair pair = new Pair();
        TlsConfig tls = TlsConfig.builder().serverName("localhost").trustManager(TestCerts.CA.trustManager())
                .alpnProtocols("something-else").build();
        Connection client = pair.connect(ClientConfig.builder(tls).build());
        ConnectionError reason = Pair.nextEvent(client, ConnectionEvent.ConnectionLost.class).reason();
        assertEquals(ConnectionError.Kind.CONNECTION_CLOSED, reason.kind());
        assertEquals(QuicException.CRYPTO_ERROR + TlsAlert.NO_APPLICATION_PROTOCOL, reason.code());
    }

    @Test
    void congestion() throws Exception {
        Pair pair = new Pair();
        Connection client = connected(pair)[0];
        long target = 2048;
        assertTrue(window(client) > target);
        StreamId s = client.openStream(Dir.UNI);
        // Send without receiving ACKs until the window falls below the target
        while (window(client) > target) {
            assertEquals(1024, client.write(s, ByteBuffer.wrap(new byte[1024])));
            pair.driveClient();
        }
        pair.drive();
        assertTrue(window(client) >= target);
        client.write(s, ByteBuffer.wrap(new byte[1024]));
    }

    private static long window(Connection c) {
        return c.congestionWindow() - c.recovery().bytesInFlight();
    }

    @Test
    void highLatencyHandshake() {
        Pair pair = new Pair();
        pair.latency = 200 * MS;
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        Pair.assertConnected(client, server);
        assertEquals(0, client.recovery().bytesInFlight());
        assertEquals(0, server.recovery().bytesInFlight());
        assertTrue(client.rtt() >= 400 * MS);
    }

    @Test
    void streamIdLimit() throws Exception {
        Pair pair = new Pair(EndpointConfig.defaults(),
                Pair.serverConfig(TransportConfig.builder().maxConcurrentUniStreams(1).build()),
                EndpointConfig.defaults());
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        StreamId s = client.openStream(Dir.UNI);
        assertNotNull(s);
        assertNull(client.openStream(Dir.UNI), "only one stream at a time");
        client.write(s, ByteBuffer.wrap(MSG));
        client.finish(s);
        pair.drive();
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Finished(s)), client.pollEvent());
        assertNull(client.openStream(Dir.UNI), "no credit until the server reads");
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Opened(Dir.UNI)), server.pollEvent());
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Readable(s)), server.pollEvent());
        assertEquals(s, server.acceptStream(Dir.UNI));
        assertArrayEquals(MSG, readAvailable(server, s));
        pair.drive();
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Available(Dir.UNI)), client.pollEvent());
        StreamId s2 = client.openStream(Dir.UNI);
        assertNotNull(s2);
        client.finish(s2);
        pair.drive();
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Opened(Dir.UNI)), server.pollEvent());
        assertEquals(s2, server.acceptStream(Dir.UNI));
        assertEquals(-1, server.read(s2, ByteBuffer.allocate(10)));
    }

    @Test
    void keyUpdateSimple() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        StreamId s = client.openStream(Dir.BI);
        client.write(s, ByteBuffer.wrap("hello1".getBytes(StandardCharsets.US_ASCII)));
        pair.drive();
        assertEquals(s, server.acceptStream(Dir.BI));
        assertEquals("hello1", new String(readAvailable(server, s), StandardCharsets.US_ASCII));
        long updates = client.keyUpdates();
        assertTrue(client.forceKeyUpdate());
        client.write(s, ByteBuffer.wrap("hello2".getBytes(StandardCharsets.US_ASCII)));
        pair.drive();
        assertEquals("hello2", new String(readAvailable(server, s), StandardCharsets.US_ASCII));
        assertEquals(updates + 1, client.keyUpdates());
        assertEquals(client.keyPhase(), server.keyPhase());
        assertEquals(0, client.recovery().lostPackets());
        assertEquals(0, server.recovery().lostPackets());
        // Several more, once the previous one is confirmed
        for (int i = 0; i < 3; i++) {
            pair.time += 2_000 * MS;
            pair.drive();
            assertTrue(server.forceKeyUpdate());
            server.write(s, ByteBuffer.wrap(MSG));
            pair.drive();
            assertArrayEquals(MSG, readAvailable(client, s));
        }
        assertEquals(client.keyPhase(), server.keyPhase());
    }

    @Test
    void keyUpdateReordered() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        StreamId s = client.openStream(Dir.BI);
        client.write(s, ByteBuffer.wrap("1".getBytes(StandardCharsets.US_ASCII)));
        pair.client.drive(pair.time);
        assertFalse(pair.client.outbound.isEmpty());
        pair.client.delayOutbound();
        assertTrue(client.forceKeyUpdate());
        client.write(s, ByteBuffer.wrap("two".getBytes(StandardCharsets.US_ASCII)));
        pair.client.drive(pair.time);
        pair.client.finishDelay();
        pair.drive();
        assertEquals(0, client.recovery().lostPackets());
        assertEquals(s, server.acceptStream(Dir.BI));
        assertEquals("1two", new String(readAvailable(server, s), StandardCharsets.US_ASCII));
        assertEquals(0, server.recovery().lostPackets());
    }

    @Test
    void routineKeyUpdatesDuringLongTransfer() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        byte[] data = new byte[3_000_000];
        new Random(3).nextBytes(data);
        byte[] got = transfer(pair, c[0], c[1], data);
        assertArrayEquals(data, got);
        // quinn's first key phase lasts 10 to 1000 packets, so a 3 MB transfer updates keys
        assertTrue(c[0].keyUpdates() + c[1].keyUpdates() > 0);
    }

    /** Sends data from one side to the other on a new stream, driving until all is read. */
    private static byte[] transfer(Pair pair, Connection from, Connection to, byte[] data) throws Exception {
        StreamId s = from.openStream(Dir.UNI);
        ByteBuffer src = ByteBuffer.wrap(data);
        ByteArrayOutputStream received = new ByteArrayOutputStream();
        boolean finished = false;
        StreamId accepted = null;
        ByteBuffer buf = ByteBuffer.allocate(256 * 1024);
        for (int i = 0; i < 1_000_000; i++) {
            while (src.hasRemaining()) {
                try {
                    from.write(s, src);
                } catch (StreamException e) {
                    assertEquals(StreamException.Kind.BLOCKED, e.kind());
                    break;
                }
            }
            if (!src.hasRemaining() && !finished) {
                from.finish(s);
                finished = true;
            }
            if (!pair.step() && src.hasRemaining()) {
                throw new AssertionError("stalled");
            }
            if (accepted == null) {
                accepted = to.acceptStream(Dir.UNI);
            }
            if (accepted != null) {
                while (true) {
                    buf.clear();
                    int n;
                    try {
                        n = to.read(accepted, buf);
                    } catch (StreamException e) {
                        assertEquals(StreamException.Kind.BLOCKED, e.kind());
                        break;
                    }
                    if (n < 0) {
                        return received.toByteArray();
                    }
                    received.write(buf.array(), 0, n);
                }
            }
        }
        throw new AssertionError("transfer did not finish");
    }

    @Test
    void lossyReorderingTransfer() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        pair.lossRate = 0.05;
        pair.reorderRate = 0.1;
        pair.latency = 10 * MS;
        byte[] data = new byte[500_000];
        new Random(4).nextBytes(data);
        assertArrayEquals(data, transfer(pair, c[0], c[1], data));
        assertTrue(c[0].recovery().lostPackets() > 0);
        assertArrayEquals(data, transfer(pair, c[1], c[0], data));
    }

    @Test
    void initialRetransmit() {
        Pair pair = new Pair();
        Connection client = pair.beginConnect(Pair.clientConfig());
        pair.client.drive(pair.time);
        pair.client.outbound.clear(); // drop the Initial
        pair.drive();
        assertEquals(new ConnectionEvent.HandshakeDataReady(), client.pollEvent());
        assertEquals(new ConnectionEvent.Connected(), client.pollEvent());
    }

    @Test
    void instantClose1() {
        Pair pair = new Pair();
        Connection client = pair.beginConnect(Pair.clientConfig());
        client.close(pair.time, 0, "");
        pair.drive();
        Connection server = pair.serverConnection();
        ConnectionError reason = Pair.nextEvent(server, ConnectionEvent.ConnectionLost.class).reason();
        assertEquals(ConnectionError.Kind.CONNECTION_CLOSED, reason.kind());
        assertEquals(QuicException.APPLICATION_ERROR, reason.code());
    }

    @Test
    void instantClose2() {
        Pair pair = new Pair();
        Connection client = pair.beginConnect(Pair.clientConfig());
        // The server sees a valid Initial first
        pair.driveClient();
        client.close(pair.time, 42, "");
        pair.drive();
        Connection server = pair.serverConnection();
        assertEquals(new ConnectionEvent.HandshakeDataReady(), server.pollEvent());
        ConnectionError reason = Pair.nextEvent(server, ConnectionEvent.ConnectionLost.class).reason();
        assertEquals(ConnectionError.Kind.CONNECTION_CLOSED, reason.kind());
        assertEquals(QuicException.APPLICATION_ERROR, reason.code());
    }

    @Test
    void instantServerClose() {
        Pair pair = new Pair();
        Connection client = pair.beginConnect(Pair.clientConfig());
        pair.driveClient();
        pair.server.drive(pair.time);
        pair.server.outbound.clear();
        Connection server = pair.serverConnection();
        server.close(pair.time, 42, "");
        pair.drive();
        ConnectionError reason = Pair.nextEvent(client, ConnectionEvent.ConnectionLost.class).reason();
        assertEquals(ConnectionError.Kind.CONNECTION_CLOSED, reason.kind());
        assertEquals(QuicException.APPLICATION_ERROR, reason.code());
    }

    @Test
    void idleTimeout() {
        Pair pair = new Pair(EndpointConfig.defaults(),
                Pair.serverConfig(TransportConfig.builder().maxIdleTimeout(Duration.ofMillis(100)).build()),
                EndpointConfig.defaults());
        Connection[] c = connected(pair);
        assertEquals(100 * MS, c[0].idleTimeout());
        assertEquals(100 * MS, c[1].idleTimeout());
        c[0].ping();
        long start = pair.time;
        while (!c[0].isClosed() || !c[1].isClosed()) {
            if (!pair.step()) {
                long t = Math.min(pair.client.nextWakeup(), pair.server.nextWakeup());
                if (t != Long.MAX_VALUE) {
                    pair.time = t;
                }
            }
            pair.client.inbound.clear(); // total server-to-client loss
        }
        assertTrue(pair.time - start < 200 * MS + 3 * c[0].recovery().pto(SpaceId.DATA));
        assertEquals(ConnectionError.Kind.TIMED_OUT, Pair.nextEvent(c[0], ConnectionEvent.ConnectionLost.class)
                .reason().kind());
        assertEquals(ConnectionError.Kind.TIMED_OUT, Pair.nextEvent(c[1], ConnectionEvent.ConnectionLost.class)
                .reason().kind());
    }

    @Test
    void idleTimeoutIsTheMinimumOfBothSides() {
        Pair pair = new Pair(EndpointConfig.defaults(),
                Pair.serverConfig(TransportConfig.builder().maxIdleTimeout(Duration.ofSeconds(5)).build()),
                EndpointConfig.defaults());
        Connection client = pair.connect(Pair.clientConfig(
                TransportConfig.builder().maxIdleTimeout(Duration.ofSeconds(3)).build()));
        assertEquals(3_000 * MS, client.idleTimeout());
        assertEquals(3_000 * MS, pair.serverConnection().idleTimeout());
        Pair noTimeout = new Pair(EndpointConfig.defaults(),
                Pair.serverConfig(TransportConfig.builder().maxIdleTimeout(Duration.ZERO).build()),
                EndpointConfig.defaults());
        Connection c2 = noTimeout.connect(Pair.clientConfig(
                TransportConfig.builder().maxIdleTimeout(Duration.ofSeconds(7)).build()));
        assertEquals(7_000 * MS, c2.idleTimeout());
    }

    @Test
    void connectionCloseWhileCongestionBlocked() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        StreamId s = c[0].openStream(Dir.UNI);
        c[0].write(s, ByteBuffer.wrap(new byte[1 << 20]));
        pair.driveClient();
        long closeTime = pair.time;
        c[0].close(pair.time, 42, "whee");
        ConnectionError result = null;
        long deliveredAt = -1;
        while (true) {
            pair.driveClient();
            pair.driveServer();
            ConnectionEvent.ConnectionLost lost = Pair.nextEvent(c[1], ConnectionEvent.ConnectionLost.class);
            if (lost != null) {
                result = lost.reason();
                deliveredAt = pair.time;
            }
            if (result != null || !pair.step()) {
                break;
            }
        }
        assertEquals(new ConnectionError(ConnectionError.Kind.APPLICATION_CLOSED, 42, 0, "whee"), result);
        assertEquals(closeTime, deliveredAt);
    }

    @Test
    void serverHandshakeRetransmit() {
        Pair pair = new Pair();
        Connection client = pair.beginConnect(Pair.clientConfig());
        pair.step();
        assertFalse(pair.client.inbound.isEmpty());
        pair.client.inbound.clear();
        pair.drive();
        assertEquals(new ConnectionEvent.HandshakeDataReady(), client.pollEvent());
        assertEquals(new ConnectionEvent.Connected(), client.pollEvent());
    }

    private void flowControl(TransportConfig config, int window) throws Exception {
        Pair pair = new Pair(EndpointConfig.defaults(), Pair.serverConfig(config), EndpointConfig.defaults());
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        byte[] msg = new byte[window + 10];
        Arrays.fill(msg, (byte) 0xab);

        // Reset before read
        StreamId s = client.openStream(Dir.UNI);
        assertEquals(window, client.write(s, ByteBuffer.wrap(msg)));
        assertEquals(StreamException.Kind.BLOCKED, assertThrows(StreamException.class,
                () -> client.write(s, ByteBuffer.wrap(msg, window, 10))).kind());
        pair.drive();
        client.resetStream(s, 42);
        pair.drive();
        StreamException e = assertThrows(StreamException.class, () -> server.read(s, ByteBuffer.allocate(window * 2)));
        assertEquals(StreamException.Kind.RESET, e.kind());

        // Happy path
        StreamId s2 = client.openStream(Dir.UNI);
        assertEquals(window, client.write(s2, ByteBuffer.wrap(msg)));
        assertEquals(StreamException.Kind.BLOCKED, assertThrows(StreamException.class,
                () -> client.write(s2, ByteBuffer.wrap(msg, window, 10))).kind());
        pair.drive();
        assertEquals(window, readAvailable(server, s2).length);
        pair.drive();
        assertEquals(window, client.write(s2, ByteBuffer.wrap(msg)));
        assertEquals(StreamException.Kind.BLOCKED, assertThrows(StreamException.class,
                () -> client.write(s2, ByteBuffer.wrap(msg, window, 10))).kind());
        pair.drive();
        assertEquals(window, readAvailable(server, s2).length);
    }

    @Test
    void streamFlowControl() throws Exception {
        flowControl(TransportConfig.builder().streamReceiveWindow(2000).build(), 2000);
    }

    @Test
    void connectionFlowControl() throws Exception {
        flowControl(TransportConfig.builder().receiveWindow(2000).build(), 2000);
    }

    @Test
    void stopOpensBidi() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        assertEquals(0, client.sendStreams());
        StreamId s = client.openStream(Dir.BI);
        assertEquals(1, client.sendStreams());
        client.stopSending(s, 42);
        pair.drive();
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Opened(Dir.BI)), server.pollEvent());
        assertEquals(s, server.acceptStream(Dir.BI));
        assertEquals(StreamException.Kind.BLOCKED,
                assertThrows(StreamException.class, () -> server.read(s, ByteBuffer.allocate(10))).kind());
        StreamException e = assertThrows(StreamException.class, () -> server.write(s, ByteBuffer.wrap(MSG)));
        assertEquals(StreamException.Kind.STOPPED, e.kind());
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Stopped(s, 42)), server.pollEvent());
    }

    @Test
    void implicitOpen() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        StreamId s1 = c[0].openStream(Dir.UNI);
        StreamId s2 = c[0].openStream(Dir.UNI);
        c[0].write(s2, ByteBuffer.wrap(MSG));
        pair.drive();
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Opened(Dir.UNI)), c[1].pollEvent());
        assertEquals(s1, c[1].acceptStream(Dir.UNI));
        assertEquals(s2, c[1].acceptStream(Dir.UNI));
        assertNull(c[1].acceptStream(Dir.UNI));
    }

    @Test
    void zeroLengthCid() throws Exception {
        EndpointConfig zero = EndpointConfig.builder().cidLength(0).build();
        Pair pair = new Pair(zero, Pair.serverConfig(TransportConfig.defaults()), zero);
        Connection[] c = connected(pair);
        assertTrue(c[0].handshakeCid().isEmpty());
        assertTrue(c[0].remoteCid().isEmpty());
        byte[] data = new byte[100_000];
        new Random(5).nextBytes(data);
        assertArrayEquals(data, transfer(pair, c[0], c[1], data));
        c[0].close(pair.time, 42, "");
        pair.drive();
        c[1].close(pair.time, 42, "");
        pair.drive();
        assertEquals(0, pair.server.endpoint.openConnections());
        // A new connection from the same address works once the old one is gone
        pair.server.connections.clear();
        Connection again = pair.connect();
        Pair.assertConnected(again, pair.serverConnection());
    }

    @Test
    void keepAlive() {
        Pair pair = new Pair(EndpointConfig.defaults(), Pair.serverConfig(TransportConfig.builder()
                .keepAliveInterval(Duration.ofMillis(5)).maxIdleTimeout(Duration.ofMillis(10)).build()),
                EndpointConfig.defaults());
        Connection[] c = connected(pair);
        long end = pair.time + 200 * MS;
        while (pair.time < end) {
            if (!pair.step()) {
                long t = Math.min(pair.client.nextWakeup(), pair.server.nextWakeup());
                if (t != Long.MAX_VALUE) {
                    pair.time = t;
                }
            }
            assertFalse(c[0].isClosed());
            assertFalse(c[1].isClosed());
        }
    }

    @Test
    void cidRotation() {
        long lifetime = 2_000 * MS;
        EndpointConfig rotating = EndpointConfig.builder()
                .cidGenerator(new RandomConnectionIdGenerator(8, lifetime, new java.security.SecureRandom())).build();
        Pair pair = new Pair(rotating, Pair.serverConfig(TransportConfig.defaults()), EndpointConfig.defaults());
        long start = pair.time;
        Connection[] c = connected(pair);
        Connection server = c[1];
        long activeCount = Math.min(RemoteCidQueue.DEFAULT_LIMIT, LocalCidState.LOC_CID_COUNT);
        for (int round = 0; round < 5; round++) {
            // Halfway through a lifetime: each batch of IDs expired and was replaced at once
            long stop = start + round * lifetime + lifetime / 2;
            while (pair.time < stop) {
                if (!pair.step()) {
                    long t = Math.min(pair.client.nextWakeup(), pair.server.nextWakeup());
                    pair.time = t == Long.MAX_VALUE ? stop : Math.min(t, stop);
                }
            }
            List<Long> seqs = new ArrayList<>(server.localCids().keySet());
            assertEquals(round * activeCount, seqs.get(0), "round " + round + ": " + seqs);
            assertEquals(round * activeCount + activeCount - 1, seqs.get(seqs.size() - 1), "round " + round + ": " + seqs);
            assertFalse(c[0].isClosed());
            // Routes follow: the server endpoint knows exactly the active IDs
            assertEquals(server.localCids().size(), pair.server.endpoint.knownCids());
        }
    }

    @Test
    void cidRetirement() {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        server.rotateLocalCid(1, pair.time);
        pair.drive();
        assertFalse(client.isClosed());
        assertFalse(server.isClosed());
        assertEquals(1, client.remoteCidSequence());
        long next = Math.min(RemoteCidQueue.DEFAULT_LIMIT, LocalCidState.LOC_CID_COUNT) + 1;
        client.ping();
        server.rotateLocalCid(next, pair.time);
        pair.drive();
        assertFalse(client.isClosed());
        assertFalse(server.isClosed());
        assertEquals(next, client.remoteCidSequence());
        assertEquals(server.localCids().size(), pair.server.endpoint.knownCids());
    }

    @Test
    void finishStreamFlowControlReordered() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        StreamId s = client.openStream(Dir.UNI);
        client.write(s, ByteBuffer.wrap(MSG));
        pair.driveClient();
        pair.server.drive(pair.time);
        assertArrayEquals(MSG, readAvailable(server, s));
        pair.server.drive(pair.time);
        pair.server.delayOutbound();
        client.finish(s);
        pair.driveClient();
        pair.server.drive(pair.time);
        pair.server.finishDelay();
        pair.drive();
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Finished(s)), client.pollEvent());
        assertNull(client.pollEvent());
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Opened(Dir.UNI)), server.pollEvent());
        assertEquals(s, server.acceptStream(Dir.UNI));
        assertEquals(-1, server.read(s, ByteBuffer.allocate(10)));
    }

    @Test
    void handshake1rttHandling() throws Exception {
        Pair pair = new Pair();
        Connection client = pair.beginConnect(Pair.clientConfig());
        pair.driveClient();
        pair.driveServer();
        Connection server = pair.serverConnection();
        // The server has 1-RTT keys but waits for the client's Finished; hold that back
        pair.client.drive(pair.time);
        pair.client.delayOutbound();
        StreamId s = client.openStream(Dir.UNI);
        client.write(s, ByteBuffer.wrap(MSG));
        client.finish(s);
        pair.client.drive(pair.time);
        int early = pair.client.outbound.size();
        assertTrue(early > 0);
        pair.client.finishDelay();
        pair.driveClient();
        // Deliver only the 1-RTT data first
        List<Pair.Inbound> all = new ArrayList<>(pair.server.inbound);
        all.sort(java.util.Comparator.comparingLong(Pair.Inbound::sequence));
        pair.server.inbound.clear();
        pair.server.inbound.addAll(all.subList(0, early));
        pair.driveServer();
        assertTrue(server.isHandshaking());
        assertNull(server.acceptStream(Dir.UNI));
        pair.server.inbound.addAll(all.subList(early, all.size()));
        pair.drive();
        assertEquals(0, client.recovery().lostPackets());
        assertEquals(s, server.acceptStream(Dir.UNI));
        assertArrayEquals(MSG, readAvailable(server, s));
    }

    @Test
    void stopBeforeFinish() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        StreamId s = c[0].openStream(Dir.UNI);
        c[0].write(s, ByteBuffer.wrap(MSG));
        pair.drive();
        c[1].stopSending(s, 42);
        pair.drive();
        StreamException e = assertThrows(StreamException.class, () -> c[0].finish(s));
        assertEquals(StreamException.Kind.STOPPED, e.kind());
        assertEquals(42, e.errorCode());
    }

    @Test
    void stopDuringFinish() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        StreamId s = c[0].openStream(Dir.UNI);
        c[0].write(s, ByteBuffer.wrap(MSG));
        pair.drive();
        assertEquals(s, c[1].acceptStream(Dir.UNI));
        c[1].stopSending(s, 42);
        pair.driveServer();
        c[0].finish(s);
        pair.driveClient();
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Stopped(s, 42)),
                Pair.nextEvent(c[0], ConnectionEvent.Stream.class));
    }

    @Test
    void congestedTailLoss() throws Exception {
        Pair pair = new Pair();
        Connection client = connected(pair)[0];
        long target = 2048;
        StreamId s = client.openStream(Dir.UNI);
        while (window(client) > target) {
            client.write(s, ByteBuffer.wrap(new byte[1024]));
            pair.driveClient();
        }
        assertFalse(pair.server.inbound.isEmpty());
        pair.server.inbound.clear(); // the tail is lost
        pair.drive();
        assertTrue(window(client) >= target);
        client.write(s, ByteBuffer.wrap(new byte[1024]));
    }

    @Test
    void datagramSendReceive() {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        assertTrue(c[0].maxDatagramSize() > 0);
        c[0].sendDatagram(ByteBuffer.wrap("whee".getBytes(StandardCharsets.US_ASCII)));
        pair.drive();
        assertEquals(new ConnectionEvent.DatagramReceived(), c[1].pollEvent());
        assertEquals(ByteBuffer.wrap("whee".getBytes(StandardCharsets.US_ASCII)), c[1].receiveDatagram());
        assertNull(c[1].receiveDatagram());
    }

    @Test
    void datagramReceiveBufferOverflow() {
        int window = 100 + 2 * 32;
        Pair pair = new Pair(EndpointConfig.defaults(),
                Pair.serverConfig(TransportConfig.builder().datagramReceiveBufferSize(window).build()),
                EndpointConfig.defaults());
        Connection[] c = connected(pair);
        assertEquals(window - DatagramState.SIZE_BOUND, c[0].maxDatagramSize());
        byte[] d1 = new byte[34];
        Arrays.fill(d1, (byte) 0xab);
        byte[] d2 = new byte[34];
        Arrays.fill(d2, (byte) 0xbc);
        byte[] d3 = new byte[34];
        Arrays.fill(d3, (byte) 0xcd);
        c[0].sendDatagram(ByteBuffer.wrap(d1));
        c[0].sendDatagram(ByteBuffer.wrap(d2));
        c[0].sendDatagram(ByteBuffer.wrap(d3));
        pair.drive();
        assertEquals(new ConnectionEvent.DatagramReceived(), c[1].pollEvent());
        assertEquals(ByteBuffer.wrap(d2), c[1].receiveDatagram());
        assertEquals(ByteBuffer.wrap(d3), c[1].receiveDatagram());
        assertNull(c[1].receiveDatagram());
        c[0].sendDatagram(ByteBuffer.wrap(d1));
        pair.drive();
        assertEquals(ByteBuffer.wrap(d1), c[1].receiveDatagram());
    }

    @Test
    void datagramLargerThanSendBufferIsTooLarge() {
        Pair pair = new Pair();
        Connection client = pair.connect(Pair.clientConfig(TransportConfig.builder().datagramSendBufferSize(1).build()));
        assertThrows(IllegalArgumentException.class, () -> client.sendDatagram(ByteBuffer.allocate(2)));
    }

    @Test
    void datagramUnsupported() {
        Pair pair = new Pair(EndpointConfig.defaults(),
                Pair.serverConfig(TransportConfig.builder().datagramReceiveBufferSize(0).build()),
                EndpointConfig.defaults());
        Connection[] c = connected(pair);
        assertEquals(-1, c[0].maxDatagramSize());
        assertThrows(IllegalStateException.class, () -> c[0].sendDatagram(ByteBuffer.allocate(0)));
    }

    @Test
    void largeInitial() {
        // A ClientHello with 1000 ALPN protocols spans several Initial packets
        TlsConfig serverTls = TlsConfig.builder().certificate(TestCerts.CA.issue(TestCerts.KeyType.P256, "localhost"))
                .alpnProtocols("p999").build();
        String[] protocols = new String[1000];
        for (int i = 0; i < protocols.length; i++) {
            protocols[i] = "p" + i;
        }
        TlsConfig clientTls = TlsConfig.builder().serverName("localhost").trustManager(TestCerts.CA.trustManager())
                .alpnProtocols(protocols).build();
        Pair pair = new Pair(EndpointConfig.defaults(), ServerConfig.builder(serverTls).build(),
                EndpointConfig.defaults());
        Connection client = pair.connect(ClientConfig.builder(clientTls).build());
        Pair.assertConnected(client, pair.serverConnection());
        assertEquals("p999", client.alpn());
    }

    @Test
    void finishAcked() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        StreamId s = c[0].openStream(Dir.UNI);
        c[0].write(s, ByteBuffer.wrap(MSG));
        pair.drive();
        // Send the FIN, then lose the ACK
        c[0].finish(s);
        pair.driveClient();
        pair.server.drive(pair.time);
        pair.server.outbound.clear();
        assertNull(Pair.nextEvent(c[0], ConnectionEvent.Stream.class), "no Finished before the FIN is acked");
        pair.drive();
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Finished(s)),
                Pair.nextEvent(c[0], ConnectionEvent.Stream.class));
        assertEquals(s, c[1].acceptStream(Dir.UNI));
        assertArrayEquals(MSG, readAvailable(c[1], s));
    }

    @Test
    void finishRetransmit() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        StreamId s = c[0].openStream(Dir.UNI);
        c[0].write(s, ByteBuffer.wrap(MSG));
        pair.drive();
        c[0].finish(s);
        pair.client.drive(pair.time);
        pair.client.outbound.clear(); // lose the FIN
        pair.drive();
        assertEquals(new ConnectionEvent.Stream(new StreamEvent.Finished(s)),
                Pair.nextEvent(c[0], ConnectionEvent.Stream.class));
        assertEquals(s, c[1].acceptStream(Dir.UNI));
        ByteBuffer buf = ByteBuffer.allocate(100);
        assertEquals(MSG.length, c[1].read(s, buf));
        assertEquals(-1, c[1].read(s, buf));
    }

    @Test
    void repeatedRequestResponse() throws Exception {
        Pair pair = new Pair(EndpointConfig.defaults(),
                Pair.serverConfig(TransportConfig.builder().maxConcurrentBidiStreams(1).build()),
                EndpointConfig.defaults());
        Connection[] c = connected(pair);
        byte[] request = "request".getBytes(StandardCharsets.US_ASCII);
        byte[] response = "response".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < 3; i++) {
            StreamId s = c[0].openStream(Dir.BI);
            assertNotNull(s, "round " + i);
            c[0].write(s, ByteBuffer.wrap(request));
            c[0].finish(s);
            pair.drive();
            assertEquals(s, c[1].acceptStream(Dir.BI));
            assertArrayEquals(request, readAvailable(c[1], s));
            c[1].write(s, ByteBuffer.wrap(response));
            c[1].finish(s);
            pair.drive();
            assertArrayEquals(response, readAvailable(c[0], s));
            pair.drive();
        }
    }

    @Test
    void handshakeAntiDeadlockProbe() {
        // The server's first flight is lost and it cannot resend for the anti-amplification limit:
        // the client's probe unblocks it
        Pair pair = new Pair();
        Connection client = pair.beginConnect(Pair.clientConfig());
        pair.driveClient();
        pair.server.drive(pair.time);
        pair.server.outbound.clear();
        pair.drive();
        assertEquals(new ConnectionEvent.HandshakeDataReady(), client.pollEvent());
        assertEquals(new ConnectionEvent.Connected(), client.pollEvent());
    }

    @Test
    void serverRespectsAntiAmplificationLimit() {
        // A large certificate chain cannot go out in one flight before the client is validated
        Pair pair = new Pair();
        Connection client = pair.beginConnect(Pair.clientConfig());
        pair.driveClient();
        long received = pair.datagramsFromClient;
        pair.server.drive(pair.time);
        long sent = 0;
        for (ByteBuffer d : pair.server.outbound) {
            sent += d.remaining();
        }
        assertTrue(sent <= 3 * 1200L * received, sent + " bytes after " + received + " datagrams");
        pair.drive();
        assertEquals(new ConnectionEvent.HandshakeDataReady(), client.pollEvent());
    }

    @Test
    void clientInitialsArePadded() {
        Pair pair = new Pair();
        pair.beginConnect(Pair.clientConfig());
        pair.client.drive(pair.time);
        for (ByteBuffer d : pair.client.outbound) {
            assertTrue(d.remaining() >= 1200, "client datagram of " + d.remaining());
        }
        pair.drive();
        Pair.assertConnected(pair.client.connections.get(0), pair.serverConnection());
    }

    @Test
    void connectDetectsMtu() throws Exception {
        Pair pair = new Pair();
        pair.mtu = 1400;
        Connection[] c = connected(pair);
        pair.drive();
        // Probes larger than the path are lost; the search settles below it
        byte[] data = new byte[200_000];
        transfer(pair, c[0], c[1], data);
        pair.drive();
        assertTrue(c[0].currentMtu() > 1200 && c[0].currentMtu() <= 1400, "MTU " + c[0].currentMtu());
    }

    @Test
    void mtuDiscoveryOff() throws Exception {
        Pair pair = new Pair();
        Connection client = pair.connect(Pair.clientConfig(TransportConfig.builder().mtuDiscovery(false).build()));
        Connection server = pair.serverConnection();
        Pair.drainEvents(server);
        transfer(pair, client, server, new byte[100_000]);
        assertEquals(1200, client.currentMtu());
    }

    @Test
    void rejectShortInitialDcid() {
        Endpoint client = new Endpoint(EndpointConfig.defaults(), null, true);
        Connection conn = client.connect(0, ClientConfig.builder(Pair.clientTls()).build(), Pair.address(4433),
                "localhost");
        ByteBuffer initial = conn.pollTransmit(0, 1).get(0);
        // Rewrite the 20-byte DCID length to 7 is not possible after protection; build an Initial
        // with a 7-byte DCID from scratch instead
        io.github.mahmoudimus.quic.ConnectionId shortDcid = io.github.mahmoudimus.quic.ConnectionId.of(new byte[7]);
        io.github.mahmoudimus.quic.crypto.Keys keys = io.github.mahmoudimus.quic.crypto.Keys.initial(QuicVersion.V1,
                shortDcid, false);
        ByteBuffer buf = ByteBuffer.allocate(1200);
        io.github.mahmoudimus.quic.packet.PacketBuilder b = new io.github.mahmoudimus.quic.packet.PacketBuilder(buf, 1200);
        ByteBuffer f = b.begin(new PacketHeader.Initial(QuicVersion.V1, shortDcid,
                io.github.mahmoudimus.quic.ConnectionId.of(new byte[8]), new byte[0], 0, 1), keys.local());
        f.put((byte) 0x01);
        b.finish(1200);
        Endpoint server = new Endpoint(EndpointConfig.defaults(), Pair.serverConfig(TransportConfig.defaults()), true);
        Endpoint.DatagramEvent e = server.handle(0, Pair.address(5000), 0, b.datagram());
        assertInstanceOf(Endpoint.DatagramEvent.Response.class, e);
        assertEquals(0, server.openConnections());
        assertTrue(initial.remaining() >= 1200);
    }

    @Test
    void connectionCap() {
        ServerConfig capped = ServerConfig.builder(Pair.serverTls()).maxConnections(1).build();
        Pair pair = new Pair(EndpointConfig.defaults(), capped, EndpointConfig.defaults());
        Connection first = pair.connect();
        Pair.assertConnected(first, pair.serverConnection());
        Connection second = pair.connect();
        ConnectionError reason = Pair.nextEvent(second, ConnectionEvent.ConnectionLost.class).reason();
        assertEquals(ConnectionError.Kind.CONNECTION_CLOSED, reason.kind());
        assertEquals(QuicException.CONNECTION_REFUSED, reason.code());
        assertEquals(1, pair.server.endpoint.openConnections());
    }

    @Test
    void statelessRetry() {
        ServerConfig retry = ServerConfig.builder(Pair.serverTls()).retry(true).build();
        Pair pair = new Pair(EndpointConfig.defaults(), retry, EndpointConfig.defaults());
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        Pair.assertConnected(client, server);
        assertEquals(1, pair.server.responses.size(), "one Retry");
        byte[] first = new byte[pair.server.responses.get(0).remaining()];
        pair.server.responses.get(0).duplicate().get(first);
        assertEquals(0xf0, first[0] & 0xf0, "a Retry packet");
    }

    @Test
    void retryTokenExpired() {
        java.time.Instant[] now = {java.time.Instant.parse("2026-01-01T00:00:00Z")};
        ServerConfig retry = ServerConfig.builder(Pair.serverTls()).retry(true).clock(() -> now[0]).build();
        Pair pair = new Pair(EndpointConfig.defaults(), retry, EndpointConfig.defaults());
        Connection client = pair.beginConnect(Pair.clientConfig());
        pair.driveClient();
        pair.driveServer(); // the Retry
        now[0] = now[0].plusSeconds(60); // the token expires before the client returns
        pair.drive();
        ConnectionError reason = Pair.nextEvent(client, ConnectionEvent.ConnectionLost.class).reason();
        assertEquals(ConnectionError.Kind.CONNECTION_CLOSED, reason.kind());
        assertEquals(QuicException.INVALID_TOKEN, reason.code());
    }

    @Test
    void retryWithLossAndSmallCids() {
        EndpointConfig small = EndpointConfig.builder().cidLength(4).build();
        ServerConfig retry = ServerConfig.builder(Pair.serverTls()).retry(true).build();
        Pair pair = new Pair(small, retry, small);
        pair.lossRate = 0.2;
        Connection client = pair.connect();
        Pair.assertConnected(client, pair.serverConnection());
    }

    @Test
    void connectionCloseInEveryHandshakeSpace() {
        // A server error during the handshake closes in Initial and Handshake packets
        TlsConfig requireClientCert = TlsConfig.builder()
                .certificate(TestCerts.CA.issue(TestCerts.KeyType.P256, "localhost"))
                .alpnProtocols(Pair.ALPN).clientAuth(io.github.mahmoudimus.quic.tls.ClientAuth.REQUIRE)
                .clientTrustManager(TestCerts.CA.trustManager()).build();
        Pair pair = new Pair(EndpointConfig.defaults(), ServerConfig.builder(requireClientCert).build(),
                EndpointConfig.defaults());
        Connection client = pair.connect();
        ConnectionError reason = Pair.nextEvent(client, ConnectionEvent.ConnectionLost.class).reason();
        assertEquals(ConnectionError.Kind.CONNECTION_CLOSED, reason.kind());
        assertTrue(reason.code() >= QuicException.CRYPTO_ERROR, Long.toHexString(reason.code()));
    }

    @Test
    void manyStreamsInterleaved() throws Exception {
        Pair pair = new Pair();
        Connection[] c = connected(pair);
        int count = 40;
        byte[][] payloads = new byte[count][];
        StreamId[] ids = new StreamId[count];
        Random r = new Random(6);
        for (int i = 0; i < count; i++) {
            payloads[i] = new byte[1000 + r.nextInt(20_000)];
            r.nextBytes(payloads[i]);
            ids[i] = c[0].openStream(Dir.BI);
            assertEquals(payloads[i].length, c[0].write(ids[i], ByteBuffer.wrap(payloads[i])));
            c[0].finish(ids[i]);
        }
        pair.drive();
        for (int i = 0; i < count; i++) {
            StreamId s = c[1].acceptStream(Dir.BI);
            assertNotNull(s);
            int index = (int) s.index();
            assertArrayEquals(payloads[index], readAvailable(c[1], s));
        }
    }

    @Test
    void keyLogWritesEverySecret() {
        List<String> lines = new ArrayList<>();
        KeyLog log = (label, random, secret) -> {
            addLine(lines, KeyLog.line(label, random, secret));
        };
        Pair pair = new Pair();
        Connection client = pair.connect(Pair.clientConfig(TransportConfig.builder().keyLog(log).build()));
        Pair.assertConnected(client, pair.serverConnection());
        assertEquals(4, lines.size(), lines.toString());
        assertTrue(lines.get(0).startsWith("CLIENT_HANDSHAKE_TRAFFIC_SECRET "));
        assertTrue(lines.get(3).startsWith("SERVER_TRAFFIC_SECRET_0 "));
    }

    private static void addLine(List<String> list, String s) {
        list.add(s);
    }

    @Test
    void qlogReportsPackets() {
        List<String> names = new ArrayList<>();
        Pair pair = new Pair();
        Connection client = pair.connect(Pair.clientConfig(TransportConfig.builder()
                .qlog((id, time, name, data) -> names.add(name)).build()));
        Pair.assertConnected(client, pair.serverConnection());
        assertTrue(names.contains("transport:packet_sent"));
        assertTrue(names.contains("transport:packet_received"));
    }

    @Test
    void newRenoCongestionControl() throws Exception {
        TransportConfig reno = TransportConfig.builder().congestionControl(TransportConfig.CongestionControl.NEW_RENO)
                .build();
        Pair pair = new Pair(EndpointConfig.defaults(), Pair.serverConfig(reno), EndpointConfig.defaults());
        Connection client = pair.connect(Pair.clientConfig(reno));
        Connection server = pair.serverConnection();
        Pair.drainEvents(server);
        pair.lossRate = 0.02;
        byte[] data = new byte[300_000];
        new Random(7).nextBytes(data);
        assertArrayEquals(data, transfer(pair, client, server, data));
        assertInstanceOf(io.github.mahmoudimus.quic.congestion.NewReno.class, client.recovery().congestion());
    }
}
