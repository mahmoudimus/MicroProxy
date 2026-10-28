/*
 * Ported in part from quinn-proto src/tests/mod.rs (migration,
 * migrate_detects_new_mtu_and_respects_original_peer_max_udp_payload_size,
 * path_changes_unblock_oversized_datagrams) (Apache-2.0), with tests of RFC 9000 sections 8.2, 9
 * and 9.6 that quinn does not have.
 */
package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.congestion.RttEstimator;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;

/**
 * Connection migration between {@link Pair}s on a fake clock: a NAT rebinding in the middle of a
 * transfer, a change of address, failed path validation, the anti-amplification limit of a new
 * path, a spoofed source address, a client that probes a new path and one whose probe fails, the
 * preferred address, and {@code disable_active_migration} in both directions.
 */
class MigrationTest {

    private static final long MS = 1_000_000L;

    /** A transfer on one stream, driven a step at a time. */
    private static final class Transfer {
        final Pair pair;
        final Connection from;
        final Connection to;
        final ByteBuffer src;
        final StreamId stream;
        final ByteArrayOutputStream received = new ByteArrayOutputStream();
        final ByteBuffer buf = ByteBuffer.allocate(256 * 1024);
        StreamId accepted;
        boolean finished;
        boolean ended;

        Transfer(Pair pair, Connection from, Connection to, byte[] data) {
            this.pair = pair;
            this.from = from;
            this.to = to;
            this.src = ByteBuffer.wrap(data);
            this.stream = from.openStream(Dir.UNI);
        }

        void pump() throws StreamException {
            while (src.hasRemaining()) {
                try {
                    from.write(stream, src);
                } catch (StreamException e) {
                    assertEquals(StreamException.Kind.BLOCKED, e.kind());
                    break;
                }
            }
            if (!src.hasRemaining() && !finished) {
                from.finish(stream);
                finished = true;
            }
            if (accepted == null) {
                accepted = to.acceptStream(Dir.UNI);
            }
            while (accepted != null && !ended) {
                buf.clear();
                int n;
                try {
                    n = to.read(accepted, buf);
                } catch (StreamException e) {
                    assertEquals(StreamException.Kind.BLOCKED, e.kind());
                    break;
                }
                if (n < 0) {
                    ended = true;
                    break;
                }
                received.write(buf.array(), 0, n);
            }
        }

        /** Steps the pair until the condition holds or the transfer ends. */
        void runUntil(BooleanSupplier condition) throws StreamException {
            for (int i = 0; i < 1_000_000; i++) {
                pump();
                if (ended || condition.getAsBoolean()) {
                    return;
                }
                if (!pair.step()) {
                    pump();
                    if (!ended && !condition.getAsBoolean()) {
                        throw new AssertionError("stalled at " + received.size() + " bytes");
                    }
                    return;
                }
            }
            throw new AssertionError("never done");
        }

        byte[] finish() throws StreamException {
            runUntil(() -> false);
            assertTrue(ended, "the transfer ended");
            return received.toByteArray();
        }
    }

    private static byte[] data(int size) {
        byte[] data = new byte[size];
        new Random(size).nextBytes(data);
        return data;
    }

    private static Connection[] connected(Pair pair, ClientConfig clientConfig) {
        Connection client = pair.connect(clientConfig);
        Connection server = pair.serverConnection();
        pair.drive();
        return new Connection[] {client, server};
    }

    private static Connection[] connected(Pair pair) {
        return connected(pair, Pair.clientConfig());
    }

    private static Pair pair(ServerConfig.Builder server) {
        Pair pair = new Pair(EndpointConfig.defaults(), server.build(), EndpointConfig.defaults());
        pair.latency = 5 * MS;
        return pair;
    }

    private static Pair pair() {
        return pair(ServerConfig.builder(Pair.serverTls()));
    }

    private static <T extends ConnectionEvent> List<T> events(Connection c, Class<T> type) {
        List<T> out = new ArrayList<>();
        for (ConnectionEvent e : Pair.drainEvents(c)) {
            if (type.isInstance(e)) {
                out.add(type.cast(e));
            }
        }
        return out;
    }

    private static InetSocketAddress address(String ip, int port) throws Exception {
        return new InetSocketAddress(InetAddress.getByName(ip), port);
    }

    /** quinn's {@code migration}: a ping from a new port moves the server, and its bytes count. */
    @Test
    void migration() {
        Pair pair = new Pair();
        Connection client = pair.connect();
        Connection server = pair.serverConnection();
        pair.drive();
        pair.client.rebind(Pair.address(pair.client.address.getPort() + 1));
        client.ping();
        pair.driveClient();
        pair.driveServer();
        assertTrue(server.path().totalReceived > 0, "the ping counts for the new path's anti-amplification budget");
        pair.drive();
        assertEquals(pair.client.address, server.remoteAddress());
        assertTrue(server.path().isValidated());
    }

    /**
     * quinn's {@code migrate_detects_new_mtu_and_respects_original_peer_max_udp_payload_size}, with
     * a new IP address, which is what makes quinn start a fresh path there (its client is on IPv6).
     */
    @Test
    void migrationDetectsTheNewMtuAndKeepsThePeersMaxUdpPayloadSize() throws Exception {
        Pair pair = new Pair();
        pair.mtu = 1300;
        Connection client = pair.connect(ClientConfig.builder(Pair.clientTls())
                .transport(TransportConfig.builder().maxUdpPayloadSize(1400).build()).build());
        Connection server = pair.serverConnection();
        pair.drive();
        assertEquals(1293, client.currentMtu());
        assertEquals(1300, server.currentMtu());

        pair.mtu = 1500;
        pair.client.rebind(address("127.0.0.2", 50001));
        client.ping();
        pair.drive();
        assertEquals(pair.client.address, server.remoteAddress());
        assertEquals(1400, server.currentMtu(), "discovery ran again on the new path, up to the client's limit");
        assertEquals(1293, client.currentMtu(), "the client, which did not see a new path, keeps its MTU");
    }

    /** quinn's {@code path_changes_unblock_oversized_datagrams}: a smaller path MTU drops the datagrams that no longer fit. */
    @Test
    void pathChangesDropOversizedDatagrams() throws Exception {
        TransportConfig transport = TransportConfig.builder().datagramReceiveBufferSize(1 << 20).build();
        Pair pair = new Pair(EndpointConfig.defaults(), Pair.serverConfig(transport), EndpointConfig.defaults());
        Connection client = pair.connect(Pair.clientConfig(transport));
        Connection server = pair.serverConnection();
        pair.drive();
        int oldMax = server.maxDatagramSize();
        assertTrue(oldMax > 1200, "MTU discovery raised it: " + oldMax);
        server.sendDatagram(ByteBuffer.wrap(new byte[oldMax]));
        pair.mtu = 1200;
        pair.client.rebind(address("127.0.0.2", 50001));
        client.ping();
        pair.driveClient();
        pair.time += 1;
        pair.server.drive(pair.time); // the migration, then the server sends what fits
        assertEquals(pair.client.address, server.remoteAddress());
        assertTrue(server.maxDatagramSize() < oldMax);
        server.sendDatagram(ByteBuffer.wrap("small".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        pair.drive();
        ByteBuffer got = client.receiveDatagram();
        assertNotNull(got);
        assertEquals(5, got.remaining(), "the oversized datagram was dropped, the small one arrived");
        assertEquals(null, client.receiveDatagram());
    }

    @Test
    void natRebindingMidTransferKeepsTheCongestionState() throws Exception {
        Pair pair = pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        InetSocketAddress before = pair.client.address;
        byte[] data = data(3 << 20);
        Transfer t = new Transfer(pair, server, client, data);
        t.runUntil(() -> t.received.size() > data.length / 3);
        Pair.drainEvents(server);
        long window = server.congestionWindow();
        long rtt = server.rtt();
        ConnectionId cid = server.remoteCid();

        InetSocketAddress after = Pair.address(before.getPort() + 1);
        pair.client.rebind(after); // same IP, new port
        t.runUntil(() -> server.remoteAddress().equals(after));
        PathData path = server.path();
        assertEquals(after, path.remote());
        assertTrue(path.isValidating(), "the new path is being validated");
        assertTrue(server.congestionWindow() >= window, "a NAT rebinding keeps the congestion window");
        assertTrue(server.rtt() < 2 * rtt, "and the RTT");
        assertNotEquals(cid, server.remoteCid(), "a new connection ID of the client's, against linkability");
        assertEquals(List.of(new ConnectionEvent.PathUpdated(after, null)),
                events(server, ConnectionEvent.PathUpdated.class));

        t.runUntil(() -> server.path().isValidated());
        assertFalse(server.path().isValidating());
        assertArrayEquals(data, t.finish(), "every byte arrived");
        assertEquals(after, server.remoteAddress());
        assertTrue(server.isEstablished() && client.isEstablished());
    }

    /**
     * A NAT rebinding keeps the old path's RTT, so a validation timeout made from it alone is a few
     * of that path's PTOs. A client slower than that to answer from its new address (one busy, or
     * behind a loaded link) is waited for: RFC 9000 section 8.2.4 makes the timeout three times
     * the larger of the current PTO and the new path's as one without RTT samples would have it.
     */
    @Test
    void aRebindingClientSlowToAnswerIsWaitedFor() throws Exception {
        Pair pair = pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        InetSocketAddress home = pair.client.address;
        byte[] data = data(2 << 20);
        Transfer t = new Transfer(pair, server, client, data);
        t.runUntil(() -> t.received.size() > data.length / 3);
        Pair.drainEvents(server);
        long pto = server.recovery().pto(SpaceId.DATA);
        // quiet for longer than three of the path's PTOs, far shorter than three new-path ones
        long quiet = 4 * pto;
        assertTrue(quiet < 3 * RttEstimator.DEFAULT_INITIAL_RTT, "a fast path's PTO: " + pto);

        InetSocketAddress after = Pair.address(home.getPort() + 1);
        pair.client.rebind(after);
        long[] firstFromAfter = {-1};
        pair.dropFromClient = d -> {
            if (firstFromAfter[0] < 0) {
                firstFromAfter[0] = pair.time; // the packet that moves the server
                return false;
            }
            return pair.time - firstFromAfter[0] < quiet;
        };
        t.runUntil(() -> server.remoteAddress().equals(after));
        t.runUntil(() -> server.path().isValidated() && server.remoteAddress().equals(after));
        assertEquals(List.of(new ConnectionEvent.PathUpdated(after, null)),
                events(server, ConnectionEvent.PathUpdated.class), "the server never went back to the old address");
        assertTrue(pair.time - firstFromAfter[0] >= quiet);
        pair.dropFromClient = d -> false;
        assertArrayEquals(data, t.finish(), "every byte arrived");
    }

    @Test
    void addressChangeValidatesThePathAndResetsCongestion() throws Exception {
        Pair pair = pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        byte[] data = data(2 << 20);
        Transfer t = new Transfer(pair, server, client, data);
        t.runUntil(() -> t.received.size() > data.length / 3);
        long window = server.congestionWindow();
        ConnectionId cid = server.remoteCid();
        long initialWindow = server.recovery().congestion().initialWindow();
        assertNotEquals(initialWindow, window, "the window grew during the transfer");

        InetSocketAddress after = address("127.0.0.2", 51000); // another host: not a NAT rebinding
        pair.client.rebind(after);
        t.runUntil(() -> server.remoteAddress().equals(after));
        assertEquals(RttEstimator.DEFAULT_INITIAL_RTT, server.rtt(), "the RTT starts over");
        assertTrue(server.congestionWindow() <= initialWindow, "the congestion window starts over");
        assertEquals(RecoveryConfig.MIN_MTU, server.currentMtu(), "and so does the MTU");
        assertNotEquals(cid, server.remoteCid(), "a new connection ID of the client's");
        assertFalse(server.path().isValidated());

        t.runUntil(() -> server.path().isValidated());
        assertArrayEquals(data, t.finish());
        assertEquals(after, server.remoteAddress());
        assertTrue(server.rtt() < RttEstimator.DEFAULT_INITIAL_RTT, "measured on the new path");
    }

    /**
     * The client sends one packet from a new address, which it then loses: the server moves
     * there, gets no PATH_RESPONSE, and goes back to the old path, which it validated. Meanwhile it
     * sent the new address no more than three times what it got from there.
     */
    @Test
    void failedValidationFallsBackAndRespectsTheAmplificationLimit() throws Exception {
        Pair pair = pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        InetSocketAddress home = pair.client.address;
        byte[] data = data(2 << 20);
        Transfer t = new Transfer(pair, server, client, data);
        t.runUntil(() -> t.received.size() > data.length / 3);
        Pair.drainEvents(server);

        InetSocketAddress away = Pair.address(home.getPort() + 7);
        pair.client.rebind(away);
        boolean[] sentOne = new boolean[1];
        pair.dropFromClient = d -> {
            if (sentOne[0]) {
                return true; // silent from now on: no PATH_RESPONSE, no PING
            }
            sentOne[0] = true;
            return false;
        };
        pair.driveClient();
        assertTrue(sentOne[0]);
        pair.client.rebind(home); // the new address is gone again: whatever goes there is lost
        t.runUntil(() -> server.remoteAddress().equals(away));
        long received = pair.serverBytesFrom.getOrDefault(away, 0L);
        assertTrue(received > 0);
        t.runUntil(() -> server.remoteAddress().equals(home));
        long sent = pair.serverBytesTo.getOrDefault(away, 0L);
        assertTrue(sent > 0, "the server challenged the new address");
        assertTrue(sent <= 3 * received, sent + " bytes sent to an unvalidated address after receiving " + received);
        assertEquals(List.of(new ConnectionEvent.PathUpdated(away, null), new ConnectionEvent.PathUpdated(home, null)),
                events(server, ConnectionEvent.PathUpdated.class));
        assertTrue(server.path().isValidated(), "back on the path validated before");

        pair.dropFromClient = d -> false;
        assertArrayEquals(data, t.finish());
        assertEquals(home, server.remoteAddress());
    }

    /** A new path that keeps sending gets no more than three times what came from it until validated. */
    @Test
    void unvalidatedPathIsLimitedToThreeTimesWhatItSent() throws Exception {
        Pair pair = pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        byte[] data = data(1 << 20);
        Transfer t = new Transfer(pair, server, client, data);
        t.runUntil(() -> t.received.size() > data.length / 4);
        InetSocketAddress away = address("127.0.0.3", 40000);
        pair.client.rebind(away);
        // The client hears nothing on its new address: the server's datagrams there are lost, so
        // its path never validates while the client keeps acknowledging what arrived before
        pair.dropFromServer = d -> true;
        for (int i = 0; i < 200 && !server.remoteAddress().equals(away); i++) {
            pair.step();
        }
        assertEquals(away, server.remoteAddress());
        for (int i = 0; i < 50; i++) {
            client.ping();
            pair.step();
            long sent = pair.serverBytesTo.getOrDefault(away, 0L);
            long received = pair.serverBytesFrom.getOrDefault(away, 0L);
            assertTrue(sent <= 3 * received, sent + " > 3 * " + received);
        }
        assertTrue(pair.serverBytesTo.getOrDefault(away, 0L) > 0);
        assertFalse(server.path().isValidated());
    }

    /**
     * An attacker replays a client's datagram from another address. A replay that comes after the
     * original is a duplicate and moves nothing; one that overtakes it moves the server, which
     * challenges both paths and returns to the client's, whose answer is a newer packet.
     */
    @Test
    void spoofedSourceAddressDoesNotHijackTheConnection() throws Exception {
        Pair pair = pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        InetSocketAddress home = pair.client.address;
        InetSocketAddress attacker = address("192.0.2.66", 6666);
        byte[] data = data(1 << 20);
        Transfer t = new Transfer(pair, client, server, data);
        t.runUntil(() -> t.received.size() > data.length / 4);
        Pair.drainEvents(server);

        // A replay after the original: a duplicate
        List<ByteBuffer> captured = new ArrayList<>();
        pair.dropFromClient = d -> {
            if (captured.isEmpty()) {
                captured.add(ByteBuffer.allocate(d.remaining()).put(d.duplicate()).flip());
            }
            return false;
        };
        t.runUntil(() -> !captured.isEmpty());
        pair.dropFromClient = d -> false;
        pair.time += pair.latency; // the original arrives
        pair.driveServer();
        pair.server.inbound.add(new Pair.Inbound(pair.time, pair.server.sequence++, attacker, captured.get(0).duplicate()));
        pair.driveServer();
        assertEquals(home, server.remoteAddress(), "a duplicate moves nothing");
        assertEquals(0L, pair.serverBytesTo.getOrDefault(attacker, 0L), "nor elicits anything");

        // A replay that overtakes the original
        captured.clear();
        pair.dropFromClient = d -> {
            if (captured.isEmpty()) {
                captured.add(ByteBuffer.allocate(d.remaining()).put(d.duplicate()).flip());
                return true;
            }
            return false;
        };
        t.runUntil(() -> !captured.isEmpty());
        pair.dropFromClient = d -> false;
        ByteBuffer original = captured.get(0);
        pair.server.inbound.add(new Pair.Inbound(pair.time, pair.server.sequence++, attacker, original.duplicate()));
        pair.server.inbound.add(new Pair.Inbound(pair.time + MS, pair.server.sequence++, home, original.duplicate()));
        pair.driveServer();
        assertEquals(attacker, server.remoteAddress(), "the overtaking replay moved the server");
        assertFalse(server.path().isValidated());

        assertArrayEquals(data, t.finish());
        assertEquals(home, server.remoteAddress(), "back with the client");
        assertTrue(server.path().isValidated());
        long sent = pair.serverBytesTo.getOrDefault(attacker, 0L);
        assertTrue(sent <= 3L * original.remaining(), "at most three times the replayed datagram: " + sent);
    }

    @Test
    void clientProbesANewPathAndMovesThere() throws Exception {
        Pair pair = pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        byte[] data = data(2 << 20);
        Transfer t = new Transfer(pair, client, server, data);
        t.runUntil(() -> t.received.size() > data.length / 3);
        Pair.drainEvents(client);
        ConnectionId cid = client.remoteCid();
        long window = client.congestionWindow();
        InetSocketAddress next = Pair.address(pair.client.address.getPort() + 100);
        pair.client.addresses.add(next);
        client.probePath(pair.time, next);
        assertTrue(client.isProbingPath());
        assertThrows(IllegalStateException.class, () -> client.probePath(pair.time, next), "one probe at a time");
        t.runUntil(() -> !client.isProbingPath());
        assertEquals(List.of(new ConnectionEvent.PathUpdated(Pair.address(4433), next)),
                events(client, ConnectionEvent.PathUpdated.class));
        assertEquals(next, client.localAddress());
        assertNotEquals(cid, client.remoteCid(), "a connection ID not used on the old path");
        assertTrue(client.congestionWindow() >= window, "only the port changed: the window carried over");
        t.runUntil(() -> server.remoteAddress().equals(next));
        assertArrayEquals(data, t.finish());
        assertEquals(next, server.remoteAddress());
        pair.driveUntil(() -> server.path().isValidated());
    }

    /** A client that rebinds without probing: the server sees a NAT rebinding with a new connection ID. */
    @Test
    void clientRebindsWithoutProbing() throws Exception {
        Pair pair = pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        byte[] data = data(1 << 20);
        Transfer t = new Transfer(pair, client, server, data);
        t.runUntil(() -> t.received.size() > data.length / 3);
        Pair.drainEvents(client);
        ConnectionId cid = client.remoteCid();
        InetSocketAddress next = Pair.address(pair.client.address.getPort() + 300);
        pair.client.addresses.add(next);
        client.rebind(pair.time, next);
        assertFalse(client.isProbingPath());
        assertEquals(next, client.localAddress());
        assertNotEquals(cid, client.remoteCid());
        assertEquals(List.of(new ConnectionEvent.PathUpdated(Pair.address(4433), next)),
                events(client, ConnectionEvent.PathUpdated.class));
        t.runUntil(() -> server.remoteAddress().equals(next));
        assertArrayEquals(data, t.finish());
        pair.driveUntil(() -> server.path().isValidated());
        assertEquals(next, server.remoteAddress());
    }

    /**
     * The server answers the client's probe on the path it uses, not the probed one, as aioquic's
     * would if it answered: the PATH_RESPONSE reaches the client's old socket and still validates
     * the new path, by its data (RFC 9000 section 8.2.2).
     */
    @Test
    void probeAnsweredOnTheOldPathValidatesTheNewOne() throws Exception {
        Pair pair = pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        InetSocketAddress home = pair.client.address;
        InetSocketAddress next = Pair.address(home.getPort() + 400);
        pair.client.addresses.add(next);
        // Whatever the server sends the new address while the client probes lands on the old one
        pair.serverRoute = a -> client.isProbingPath() && a.equals(next) ? home : a;
        Pair.drainEvents(client);
        client.probePath(pair.time, next);
        pair.driveUntil(() -> !client.isProbingPath());
        assertEquals(List.of(new ConnectionEvent.PathUpdated(Pair.address(4433), next)),
                events(client, ConnectionEvent.PathUpdated.class));
        assertEquals(next, client.localAddress());
        byte[] data = data(300_000);
        assertArrayEquals(data, new Transfer(pair, client, server, data).finish());
        assertEquals(next, server.remoteAddress());
    }

    /**
     * The client's answer to the server's PATH_CHALLENGE on its new address comes from another
     * address (its old one): it validates the new path all the same, by its data.
     */
    @Test
    void serverValidatesAPathByAResponseFromAnotherAddress() throws Exception {
        Pair pair = pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        InetSocketAddress home = pair.client.address;
        InetSocketAddress away = Pair.address(home.getPort() + 500);
        pair.client.rebind(away);
        pair.client.addresses.add(home);
        // The server's datagrams to the new address reach the client at the old one, which then
        // answers the challenge off its path, from there
        pair.serverRoute = a -> a.equals(away) ? home : a;
        client.ping();
        pair.driveUntil(() -> away.equals(server.remoteAddress()));
        pair.driveUntil(() -> server.path().isValidated());
        assertEquals(away, server.remoteAddress(), "validated, and no fallback");
        assertTrue(pair.serverBytesFrom.getOrDefault(home, 0L) > 0, "the answer came from the old address");
    }

    @Test
    void clientProbeWithoutAnAnswerKeepsTheOldPath() throws Exception {
        Pair pair = pair();
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        InetSocketAddress home = pair.client.address;
        InetSocketAddress nowhere = Pair.address(home.getPort() + 200); // the server's answers are lost
        Pair.drainEvents(client);
        client.probePath(pair.time, nowhere);
        byte[] data = data(256 * 1024);
        Transfer t = new Transfer(pair, client, server, data);
        assertArrayEquals(data, t.finish());
        pair.driveUntil(() -> !client.isProbingPath());
        assertEquals(List.of(new ConnectionEvent.PathProbeFailed(Pair.address(4433), nowhere)),
                events(client, ConnectionEvent.PathProbeFailed.class));
        assertEquals(home, server.remoteAddress());
        assertEquals(null, client.localAddress());
        byte[] more = data(100_000);
        assertArrayEquals(more, new Transfer(pair, client, server, more).finish(), "still connected");
    }

    @Test
    void clientMovesToThePreferredAddress() throws Exception {
        InetSocketAddress preferred = Pair.address(4434);
        Pair pair = pair(ServerConfig.builder(Pair.serverTls()).preferredAddress(preferred, null));
        pair.server.addresses.add(preferred);
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        assertNotNull(client.peerParams().preferredAddress());
        pair.driveUntil(() -> client.remoteAddress().equals(preferred) && preferred.equals(server.localAddress()));
        assertEquals(preferred, client.remoteAddress(), "the client moved");
        assertEquals(preferred, server.localAddress(), "the server sends from its preferred address");
        assertEquals(pair.client.address, server.remoteAddress());
        assertTrue(server.path().isValidated());
        byte[] data = data(1 << 20);
        assertArrayEquals(data, new Transfer(pair, server, client, data).finish());
        assertArrayEquals(data, new Transfer(pair, client, server, data).finish());
    }

    @Test
    void clientMayIgnoreThePreferredAddress() throws Exception {
        InetSocketAddress preferred = Pair.address(4434);
        Pair pair = pair(ServerConfig.builder(Pair.serverTls()).preferredAddress(preferred, null));
        pair.server.addresses.add(preferred);
        Connection[] c = connected(pair, ClientConfig.builder(Pair.clientTls()).preferredAddress(false).build());
        assertEquals(Pair.address(4433), c[0].remoteAddress());
        assertEquals(null, c[1].localAddress());
        byte[] data = data(100_000);
        assertArrayEquals(data, new Transfer(pair, c[1], c[0], data).finish());
    }

    @Test
    void serverThatDisablesMigrationDropsPacketsFromNewAddresses() throws Exception {
        Pair pair = pair(ServerConfig.builder(Pair.serverTls()).migration(false));
        Connection[] c = connected(pair);
        Connection client = c[0];
        Connection server = c[1];
        assertTrue(client.peerParams().disableActiveMigration(), "the server says so");
        assertThrows(IllegalStateException.class, () -> client.probePath(pair.time, Pair.address(50123)),
                "the client honours it");
        InetSocketAddress home = pair.client.address;
        byte[] data = data(256 * 1024);
        Transfer t = new Transfer(pair, client, server, data);
        t.runUntil(() -> t.received.size() > 0);
        pair.client.rebind(Pair.address(home.getPort() + 3));
        for (int i = 0; i < 20; i++) {
            t.pump();
            pair.step();
        }
        assertEquals(home, server.remoteAddress(), "the server did not follow");
        assertEquals(0L, pair.serverBytesTo.getOrDefault(pair.client.address, 0L));
        pair.client.rebind(home);
        assertArrayEquals(data, t.finish(), "back on the address of the handshake");
    }

    @Test
    void clientThatDisablesMigrationSaysSoAndDoesNotMigrate() {
        Pair pair = pair();
        Connection[] c = connected(pair, ClientConfig.builder(Pair.clientTls()).activeMigration(false).build());
        assertTrue(c[1].peerParams().disableActiveMigration(), "the client says so");
        assertFalse(c[0].peerParams().disableActiveMigration(), "the server allows migration");
        assertThrows(IllegalStateException.class, () -> c[0].probePath(pair.time, Pair.address(50123)));
    }

    @Test
    void probingRequiresAConfirmedHandshake() {
        Pair pair = pair();
        Connection client = pair.beginConnect(Pair.clientConfig());
        assertThrows(IllegalStateException.class, () -> client.probePath(pair.time, Pair.address(50123)));
        pair.drive();
        Connection server = pair.serverConnection();
        assertThrows(IllegalStateException.class, () -> server.probePath(pair.time, Pair.address(4435)),
                "a server does not migrate");
    }
}
