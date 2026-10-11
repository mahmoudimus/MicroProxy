package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicConnection;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * {@link QuicConnection.Stats} of connections on a simulated network: plausible RTTs, windows,
 * packet and byte counts, losses and probe timeouts under induced loss, and the endpoint's own
 * counts.
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
        assertEquals(0, c.migrations());
        assertEquals(0, c.peerAddressChanges());
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
    void datagramsFromAnotherAddressAreCounted() {
        Pair pair = new Pair();
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        ByteBuffer junk = ByteBuffer.allocate(1200);
        server.handleDatagram(pair.time, Pair.address(50001), 0, junk);
        assertEquals(1, QuicConnection.Stats.of(server).peerAddressChanges());
        assertEquals(0, QuicConnection.Stats.of(client).peerAddressChanges());
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
