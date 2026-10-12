package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * {@link QuicConnection.Stats} of connections on a simulated network: plausible RTTs, windows,
 * packet and byte counts, losses and probe timeouts under induced loss, migrations, NAT rebindings
 * and failed path validations, and the endpoint's own counts.
 */
class ConnectionStatsTest {

    private static final long MS = 1_000_000L;

    @Test
    void lossyTransferShowsInTheStats() throws Exception {
        TransportConfig transport = TransportConfig.builder().congestionControl(TransportConfig.CongestionControl.NEW_RENO)
                .build();
        Pair pair = Pair.seeded(7, transport);
        pair.latency = 10 * MS;
        Connection client = pair.connect(pair.client(transport));
        Connection server = pair.serverConnection();
        Pair.drainEvents(client);
        Pair.drainEvents(server);
        pair.lossRate = 0.05;

        byte[] data = new byte[400_000];
        new Random(1).nextBytes(data);
        send(pair, client, server, data);

        QuicConnection.Stats c = QuicConnection.Stats.of(client);
        QuicConnection.Stats s = QuicConnection.Stats.of(server);
        String both = c + "\n" + s;
        // 20 ms of round trip on the link, and the sampled RTTs say so
        assertTrue(c.minRtt().compareTo(Duration.ofMillis(20)) >= 0, both);
        assertTrue(c.minRtt().compareTo(Duration.ofMillis(40)) < 0, both);
        assertTrue(c.rtt().compareTo(c.minRtt()) >= 0, both);
        assertTrue(c.congestionWindow() > 0 && c.mtu() >= 1200, both);
        assertEquals("new_reno", c.congestionController());
        // The client sent the data: at least its size, in more packets than the server received
        assertTrue(c.sentBytes() > data.length, both);
        assertTrue(s.receivedBytes() > data.length && s.receivedBytes() < c.sentBytes(), both);
        assertTrue(c.sentPackets() > s.receivedPackets(), both);
        assertTrue(s.sentPackets() > 0 && c.receivedPackets() > 0, both);
        // 5% of datagrams were dropped: some packets were deemed lost, with their bytes
        assertTrue(c.lostPackets() > 0 && c.lostBytes() >= c.lostPackets() * 20, both);
        assertTrue(c.lostPackets() < c.sentPackets() / 4, both);
        assertTrue(c.congestionEvents() > 0, both);
        assertEquals(0, c.migrations() + s.migrations());
        assertEquals(0, c.natRebindings() + s.natRebindings());
        assertEquals(0, c.pathValidationFailures() + s.pathValidationFailures());
        assertEquals(0, c.strayDatagrams() + s.strayDatagrams());
        assertFalse(c.zeroRttAccepted() || c.zeroRttRejected(), both);
        assertTrue(c.bytesInFlight() >= 0 && c.bytesInFlight() <= c.congestionWindow() + 2 * c.mtu(), both);
    }

    @Test
    void probeTimeoutsAreCountedWhenEverythingIsLost() {
        Pair pair = new Pair();
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        Pair.drainEvents(client);
        Pair.drainEvents(server);
        long before = QuicConnection.Stats.of(client).probeTimeouts();
        // Nothing from the client arrives for a while: its probes time out, one after another
        pair.dropFromClient = d -> true;
        client.ping();
        long until = pair.time + 3_000 * MS;
        pair.driveUntil(() -> pair.time >= until || client.isClosed());
        assertTrue(QuicConnection.Stats.of(client).probeTimeouts() >= before + 2, QuicConnection.Stats.of(client).toString());
    }

    @Test
    void datagramsFromAddressesAConnectionTakesNothingFromAreCounted() {
        Pair pair = new Pair();
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        pair.drive();
        ByteBuffer junk = ByteBuffer.allocate(1200);
        // A client takes packets from its server's address alone (and from a path it probes)
        client.handleDatagram(pair.time, Pair.address(50001), 0, junk.duplicate());
        assertEquals(1, QuicConnection.Stats.of(client).strayDatagrams());
        // A server that lets clients migrate reads them, as it would a client that moved: junk
        // moves nothing
        server.handleDatagram(pair.time, Pair.address(50001), 0, junk.duplicate());
        QuicConnection.Stats s = QuicConnection.Stats.of(server);
        assertEquals(0, s.strayDatagrams());
        assertEquals(0, s.migrations());
    }

    @Test
    void aServerThatDisablesMigrationCountsDatagramsFromNewAddresses() {
        Pair pair = new Pair(EndpointConfig.defaults(),
                ServerConfig.builder(Pair.serverTls()).migration(false).build(), EndpointConfig.defaults());
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        pair.drive();
        InetSocketAddress home = pair.client.address;
        pair.client.rebind(Pair.address(home.getPort() + 1));
        client.ping();
        pair.driveClient();
        pair.driveServer();
        QuicConnection.Stats s = QuicConnection.Stats.of(server);
        assertTrue(s.strayDatagrams() >= 1, s.toString());
        assertEquals(0, s.migrations());
        assertEquals(0, s.natRebindings());
    }

    /** A client's new port: the server follows it, a migration that is a NAT rebinding. */
    @Test
    void aNatRebindingIsAMigration() {
        Pair pair = new Pair();
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        pair.drive();
        InetSocketAddress rebound = Pair.address(pair.client.address.getPort() + 1);
        pair.client.rebind(rebound);
        client.ping();
        pair.driveUntil(() -> rebound.equals(server.remoteAddress()) && server.path().isValidated());
        QuicConnection.Stats s = QuicConnection.Stats.of(server);
        assertEquals(1, s.migrations(), s.toString());
        assertEquals(1, s.natRebindings(), s.toString());
        assertEquals(0, s.pathValidationFailures(), s.toString());
        // The client did not move: its socket did, which it does not know
        assertEquals(0, QuicConnection.Stats.of(client).migrations());
    }

    /** A client on another host: a migration, not a NAT rebinding. */
    @Test
    void aNewAddressIsAMigrationButNoNatRebinding() throws Exception {
        Pair pair = new Pair();
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        pair.drive();
        InetSocketAddress moved = new InetSocketAddress(InetAddress.getByName("127.0.0.2"), 51000);
        pair.client.rebind(moved);
        client.ping();
        pair.driveUntil(() -> moved.equals(server.remoteAddress()) && server.path().isValidated());
        QuicConnection.Stats s = QuicConnection.Stats.of(server);
        assertEquals(1, s.migrations(), s.toString());
        assertEquals(0, s.natRebindings(), s.toString());
        assertEquals(0, s.pathValidationFailures(), s.toString());
    }

    /**
     * The client sends one ping from a new port and goes silent there: the server follows it,
     * gets no PATH_RESPONSE, and goes back to the path it had validated. The move counts; the
     * return does not, and the validation counts as failed.
     */
    @Test
    void aFailedValidationIsCounted() {
        Pair pair = new Pair();
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        pair.drive();
        InetSocketAddress home = pair.client.address;
        InetSocketAddress away = Pair.address(home.getPort() + 7);
        pair.client.rebind(away);
        boolean[] sentOne = new boolean[1];
        pair.dropFromClient = d -> {
            if (sentOne[0]) return true; // silent from now on: no PATH_RESPONSE
            sentOne[0] = true;
            return false;
        };
        client.ping();
        pair.driveClient();
        assertTrue(sentOne[0]);
        pair.client.rebind(home);
        pair.driveUntil(() -> away.equals(server.remoteAddress()));
        pair.driveUntil(() -> home.equals(server.remoteAddress()));
        QuicConnection.Stats s = QuicConnection.Stats.of(server);
        assertEquals(1, s.migrations(), s.toString());
        assertEquals(1, s.natRebindings(), s.toString());
        assertEquals(1, s.pathValidationFailures(), s.toString());
    }

    /** A client's probes: one that gets no answer fails, one that does moves the client. */
    @Test
    void aClientCountsItsProbesAndMoves() {
        Pair pair = new Pair();
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        pair.drive();
        InetSocketAddress home = pair.client.address;
        InetSocketAddress nowhere = Pair.address(home.getPort() + 200); // the server's answers are lost
        client.probePath(pair.time, nowhere);
        pair.driveUntil(() -> !client.isProbingPath());
        QuicConnection.Stats c = QuicConnection.Stats.of(client);
        assertEquals(1, c.pathValidationFailures(), c.toString());
        assertEquals(0, c.migrations(), c.toString());

        InetSocketAddress next = Pair.address(home.getPort() + 100);
        pair.client.addresses.add(next);
        client.probePath(pair.time, next);
        pair.driveUntil(() -> !client.isProbingPath());
        assertEquals(next, client.localAddress());
        c = QuicConnection.Stats.of(client);
        assertEquals(1, c.migrations(), c.toString());
        assertEquals(1, c.pathValidationFailures(), c.toString());
        // The server followed the client to the probed path's port
        pair.driveUntil(() -> next.equals(server.remoteAddress()));
        assertEquals(1, QuicConnection.Stats.of(server).natRebindings());
    }

    @Test
    void theEndpointCountsRetries() {
        Pair pair = new Pair(EndpointConfig.defaults(),
                ServerConfig.builder(Pair.serverTls()).retry(true).build(), EndpointConfig.defaults());
        pair.connect();
        assertEquals(1, pair.server.endpoint.retriesSent());
        assertEquals(0, pair.server.endpoint.versionNegotiationsSent());
        assertEquals(0, pair.server.endpoint.connectionsRefused());
    }

    /** Sends {@code data} on a stream from {@code from}, driving the pair until {@code to} has read it all. */
    private static void send(Pair pair, Connection from, Connection to, byte[] data) throws Exception {
        StreamId s = from.openStream(Dir.UNI);
        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer buf = ByteBuffer.allocate(64 * 1024);
        StreamId accepted = null;
        long total = 0;
        boolean finished = false;
        for (int i = 0; i < 1_000_000; i++) {
            while (src.hasRemaining()) {
                try {
                    from.write(s, src);
                } catch (StreamException e) {
                    break;
                }
            }
            if (!src.hasRemaining() && !finished) {
                from.finish(s);
                finished = true;
            }
            pair.step();
            if (accepted == null) accepted = to.acceptStream(Dir.UNI);
            if (accepted == null) continue;
            while (true) {
                buf.clear();
                int n;
                try {
                    n = to.read(accepted, buf);
                } catch (StreamException e) {
                    break;
                }
                if (n < 0) {
                    assertEquals(data.length, total);
                    return;
                }
                total += n;
            }
        }
        throw new AssertionError("the transfer did not finish");
    }
}
