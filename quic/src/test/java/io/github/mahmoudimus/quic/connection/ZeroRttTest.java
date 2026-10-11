package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.packet.PacketDecodeException;
import io.github.mahmoudimus.quic.packet.PacketType;
import io.github.mahmoudimus.quic.packet.ProtectedPacket;
import io.github.mahmoudimus.quic.tls.ClientSessionMemoryCache;
import io.github.mahmoudimus.quic.tls.EarlyDataPolicy;
import io.github.mahmoudimus.quic.tls.TestCerts;
import io.github.mahmoudimus.quic.tls.Ticketer;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import io.github.mahmoudimus.quic.token.TokenMemoryCache;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Resumption, 0-RTT and NEW_TOKEN between in-memory endpoints: early data accepted, rejected and
 * sent again in 1-RTT, replayed, refused for an expired ticket, an ALPN change or smaller transport
 * parameters, and a token that lets the client skip Retry.
 */
class ZeroRttTest {

    private static final byte[] REQUEST = "GET /index.html".getBytes(StandardCharsets.US_ASCII);

    /** A wall clock for ticket ages, moved by hand. */
    private static final class Clock implements InstantSource {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        @Override
        public Instant instant() {
            return now;
        }
    }

    private final Clock clock = new Clock();
    private final Ticketer ticketer = Ticketer.create(Duration.ofHours(1), clock);
    private final SessionCache cache = new SessionCache(new ClientSessionMemoryCache(), new TokenMemoryCache());

    private TlsConfig.Builder serverTls(boolean earlyData, String... alpn) {
        return TlsConfig.builder()
                .certificate(TestCerts.CA.issue(TestCerts.KeyType.P256, "localhost"))
                .alpnProtocols(alpn.length > 0 ? alpn : new String[] {Pair.ALPN})
                .clock(clock)
                .sessionTickets(ticketer)
                .earlyData(earlyData);
    }

    private ClientConfig clientConfig(boolean earlyData) {
        return clientConfig(earlyData, cache);
    }

    private ClientConfig clientConfig(boolean earlyData, SessionCache cache) {
        return ClientConfig.builder(TlsConfig.builder()
                .serverName("localhost")
                .trustManager(TestCerts.CA.trustManager())
                .alpnProtocols(Pair.ALPN, "other")
                .clock(clock)
                .earlyData(earlyData)
                .build()).sessionCache(cache).build();
    }

    private Pair pair(TlsConfig.Builder serverTls) {
        return pair(ServerConfig.builder(serverTls.build()));
    }

    private Pair pair(ServerConfig.Builder server) {
        return new Pair(EndpointConfig.defaults(), server.build(), EndpointConfig.defaults());
    }

    /** A first, full connection that leaves tickets (and tokens) in the cache. */
    private void firstConnection(Pair pair) {
        Connection client = pair.connect(clientConfig(false));
        assertTrue(client.isEstablished());
        assertFalse(client.isResumed());
        pair.drive(); // the tickets and tokens arrive after the handshake
        client.close(pair.time, 0, "");
        pair.drive();
    }

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

    /** Counts the packets of a type in a datagram. */
    private static int count(ByteBuffer datagram, PacketType type) {
        ByteBuffer in = datagram.duplicate();
        int n = 0;
        while (in.hasRemaining()) {
            try {
                if (ProtectedPacket.parse(in, 8).type() == type) {
                    n++;
                }
            } catch (PacketDecodeException e) {
                break;
            }
        }
        return n;
    }

    /** Records the client's datagrams. */
    private static List<ByteBuffer> recordClient(Pair pair) {
        List<ByteBuffer> sent = new ArrayList<>();
        pair.dropFromClient = d -> {
            sent.add(ByteBuffer.allocate(d.remaining()).put(d.duplicate()).flip());
            return false;
        };
        return sent;
    }

    private static int zeroRttPackets(List<ByteBuffer> datagrams) {
        int n = 0;
        for (ByteBuffer d : datagrams) {
            n += count(d, PacketType.ZERO_RTT);
        }
        return n;
    }

    /** Opens a stream at once and writes a request with its FIN, as 0-RTT data if possible. */
    private static StreamId request(Connection client) throws StreamException {
        StreamId s = client.openStream(Dir.BI);
        assertNotNull(s, "a stream within the remembered limits");
        assertEquals(REQUEST.length, client.write(s, ByteBuffer.wrap(REQUEST)));
        client.finish(s);
        return s;
    }

    @Test
    void resumesWithoutEarlyData() throws Exception {
        Pair pair = pair(serverTls(false));
        firstConnection(pair);
        assertEquals(2, ((ClientSessionMemoryCache) cache.tickets()).size("localhost"));
        Connection client = pair.connect(clientConfig(true));
        Connection server = pair.server.connections.get(1);
        assertTrue(client.isResumed());
        assertTrue(server.isResumed());
        assertFalse(client.zeroRttAttempted(), "the ticket does not allow 0-RTT");
        assertFalse(client.earlyDataAccepted());
        assertEquals(3, ((ClientSessionMemoryCache) cache.tickets()).size("localhost"),
                "one ticket used, two fresh ones kept");
    }

    @Test
    void earlyDataAccepted() throws Exception {
        Pair pair = pair(serverTls(true));
        firstConnection(pair);
        List<ByteBuffer> sent = recordClient(pair);
        Connection client = pair.beginConnect(clientConfig(true));
        assertTrue(client.isZeroRtt(), "0-RTT keys at once");
        StreamId s = request(client);
        pair.driveClient();
        assertTrue(zeroRttPackets(sent) > 0, "the request went out in 0-RTT packets");
        assertEquals(1, count(sent.get(0), PacketType.INITIAL));
        assertEquals(1, count(sent.get(0), PacketType.ZERO_RTT), "coalesced with the Initial");

        pair.driveServer();
        Connection server = pair.server.connections.get(1);
        assertTrue(server.earlyDataAccepted());
        assertTrue(server.isHandshaking(), "the request is there before the handshake completes");
        assertEquals(s, server.acceptStream(Dir.BI));
        assertArrayEquals(REQUEST, readAvailable(server, s));
        assertTrue(server.receivedEarlyData(s));
        assertFalse(server.isHandshakeComplete());

        pair.drive();
        assertTrue(client.isEstablished());
        assertTrue(client.earlyDataAccepted());
        assertTrue(client.isResumed());
        assertFalse(client.isZeroRtt());
        assertTrue(server.isHandshakeComplete());
        // The response, and a stream opened after the handshake, which is not early data
        server.write(s, ByteBuffer.wrap("200".getBytes(StandardCharsets.US_ASCII)));
        server.finish(s);
        StreamId later = client.openStream(Dir.BI);
        client.write(later, ByteBuffer.wrap(REQUEST));
        pair.drive();
        assertEquals("200", new String(readAvailable(client, s), StandardCharsets.US_ASCII));
        assertEquals(later, server.acceptStream(Dir.BI));
        assertArrayEquals(REQUEST, readAvailable(server, later));
        assertFalse(server.receivedEarlyData(later));
        assertEquals(0, client.recovery().lostPackets());
    }

    @Test
    void earlyDataRejectedIsSentAgainIn1Rtt() throws Exception {
        Pair first = pair(serverTls(true));
        firstConnection(first);
        // The same ticketer, but this server has 0-RTT off
        Pair pair = pair(serverTls(false));
        List<ByteBuffer> sent = recordClient(pair);
        Connection client = pair.beginConnect(clientConfig(true));
        assertTrue(client.isZeroRtt());
        StreamId s = request(client);
        pair.drive();
        assertTrue(zeroRttPackets(sent) > 0);
        Connection server = pair.serverConnection();
        assertTrue(client.isResumed());
        assertTrue(client.zeroRttAttempted());
        assertFalse(client.earlyDataAccepted());
        assertFalse(server.earlyDataAccepted());
        assertEquals(s, server.acceptStream(Dir.BI));
        assertArrayEquals(REQUEST, readAvailable(server, s), "the request arrived in 1-RTT");
        assertFalse(server.receivedEarlyData(s));
        assertEquals(0, client.recovery().lostPackets(), "rejected 0-RTT packets are not losses");
    }

    @Test
    void earlyDataRejectedIsSentAgainWhenItsFirst1RttPacketIsLost() throws Exception {
        Pair first = pair(serverTls(true));
        firstConnection(first);
        Pair pair = pair(serverTls(false));
        Connection client = pair.beginConnect(clientConfig(true));
        StreamId s = request(client);
        // The client learns of the rejection with the server's Finished, and at once sends the
        // request again in 1-RTT, before the handshake is confirmed. Every 1-RTT packet it sends
        // until then is lost.
        int[] dropped = {0};
        pair.dropFromClient = d -> {
            boolean confirmed = client.isEstablished() && client.recovery().space(SpaceId.HANDSHAKE).keys() == null;
            if (!confirmed && count(d, PacketType.ONE_RTT) > 0) {
                dropped[0]++;
                return true;
            }
            return false;
        };
        pair.drive();
        assertTrue(dropped[0] > 0);
        assertTrue(client.zeroRttAttempted());
        assertFalse(client.earlyDataAccepted());
        Connection server = pair.serverConnection();
        assertEquals(s, server.acceptStream(Dir.BI), "the request was sent once more after the loss");
        assertArrayEquals(REQUEST, readAvailable(server, s));
        assertFalse(server.receivedEarlyData(s));
    }

    @Test
    void replayedFirstFlightGetsNoEarlyData() throws Exception {
        Pair pair = pair(serverTls(true));
        firstConnection(pair);
        List<ByteBuffer> sent = recordClient(pair);
        Connection client = pair.beginConnect(clientConfig(true));
        StreamId s = request(client);
        pair.driveClient();
        List<ByteBuffer> firstFlight = new ArrayList<>(sent);
        pair.drive();
        Connection server = pair.server.connections.get(1);
        assertTrue(server.earlyDataAccepted());
        client.close(pair.time, 0, "");
        pair.drive();
        assertTrue(server.isDrained(), "the server forgot the connection");

        // An attacker sends the captured first flight again, from its own address
        pair.server.connections.clear();
        java.net.InetSocketAddress attacker = Pair.address(50001);
        for (ByteBuffer d : firstFlight) {
            pair.server.inbound.add(new Pair.Inbound(pair.time, pair.server.sequence++, attacker, d.duplicate()));
        }
        pair.driveServer();
        Connection replayed = pair.server.only();
        assertFalse(replayed.earlyDataAccepted(), "the ticket was already used for early data");
        assertNull(replayed.acceptStream(Dir.BI), "the replayed request is not processed");
        assertTrue(replayed.isHandshaking());
        assertNotNull(s);
    }

    @Test
    void expiredTicketMeansAFullHandshake() throws Exception {
        Pair pair = pair(serverTls(true));
        firstConnection(pair);
        clock.now = clock.now.plus(Duration.ofHours(2));
        Connection client = pair.beginConnect(clientConfig(true));
        assertFalse(client.isZeroRtt(), "an expired ticket is not offered");
        pair.drive();
        assertTrue(client.isEstablished());
        assertFalse(client.isResumed());
        assertFalse(client.earlyDataAccepted());
    }

    @Test
    void alpnChangeRejectsEarlyData() throws Exception {
        firstConnection(pair(serverTls(true, Pair.ALPN, "other")));
        Pair pair = pair(serverTls(true, "other", Pair.ALPN));
        Connection client = pair.beginConnect(clientConfig(true));
        assertTrue(client.isZeroRtt());
        StreamId s = request(client);
        pair.drive();
        Connection server = pair.serverConnection();
        assertEquals("other", client.alpn());
        assertTrue(client.isResumed());
        assertFalse(client.earlyDataAccepted());
        assertEquals(s, server.acceptStream(Dir.BI));
        assertArrayEquals(REQUEST, readAvailable(server, s), "sent again in 1-RTT");
    }

    @Test
    void smallerTransportParametersRejectEarlyData() throws Exception {
        firstConnection(pair(serverTls(true)));
        // Fewer streams and a smaller window than the ticket remembers
        Pair pair = pair(ServerConfig.builder(serverTls(true).build())
                .transport(TransportConfig.builder().maxConcurrentBidiStreams(1).receiveWindow(4096).build()));
        Connection client = pair.beginConnect(clientConfig(true));
        assertTrue(client.isZeroRtt());
        StreamId one = request(client);
        StreamId two = request(client);
        pair.drive();
        Connection server = pair.serverConnection();
        assertTrue(client.isResumed());
        assertFalse(server.earlyDataAccepted());
        assertFalse(client.earlyDataAccepted());
        // Two streams do not fit the server's limit of one: the client forgot them
        assertNull(server.acceptStream(Dir.BI));
        assertThrows(StreamException.class, () -> client.write(one, ByteBuffer.wrap(REQUEST)));
        assertNotNull(two);
        assertTrue(client.isEstablished());
        StreamId again = request(client);
        pair.drive();
        assertEquals(again, server.acceptStream(Dir.BI));
        assertArrayEquals(REQUEST, readAvailable(server, again));
    }

    @Test
    void applicationVetoRejectsEarlyData() throws Exception {
        firstConnection(pair(serverTls(true)));
        Pair pair = pair(serverTls(true).earlyDataPolicy(EarlyDataPolicy.antiReplay().and(a -> false)));
        Connection client = pair.beginConnect(clientConfig(true));
        StreamId s = request(client);
        pair.drive();
        assertFalse(client.earlyDataAccepted());
        Connection server = pair.serverConnection();
        assertEquals(s, server.acceptStream(Dir.BI));
        assertArrayEquals(REQUEST, readAvailable(server, s));
    }

    @Test
    void zeroRttDataSentBeforeARetryIsSentAgain() throws Exception {
        // No NEW_TOKEN tokens, so the resumed connection meets a Retry too
        Pair pair = pair(ServerConfig.builder(serverTls(true).build()).retry(true).newTokens(0));
        firstConnection(pair);
        pair.server.responses.clear();
        List<ByteBuffer> sent = recordClient(pair);
        Connection client = pair.beginConnect(clientConfig(true));
        StreamId s = request(client);
        pair.drive();
        assertEquals(1, pair.server.responses.size(), "a Retry");
        assertTrue(zeroRttPackets(sent) >= 2, "0-RTT before and after the Retry");
        Connection server = pair.server.connections.get(1);
        assertTrue(client.earlyDataAccepted());
        assertEquals(s, server.acceptStream(Dir.BI));
        assertArrayEquals(REQUEST, readAvailable(server, s));
        assertTrue(server.receivedEarlyData(s), "sent again as 0-RTT data after the Retry");
    }

    @Test
    void newTokenSkipsRetry() throws Exception {
        Pair pair = pair(ServerConfig.builder(serverTls(false).build()).retry(true));
        firstConnection(pair);
        assertEquals(1, pair.server.responses.size(), "a Retry for the first connection");
        pair.server.responses.clear();
        Connection client = pair.connect(clientConfig(false));
        assertTrue(client.isEstablished());
        assertTrue(client.isResumed());
        assertTrue(pair.server.responses.isEmpty(), "the NEW_TOKEN token validated the address: no Retry");

        // Tokens are single-use: without any left, Retry again
        while (cache.tokens().take("localhost") != null) {
            // drop the rest
        }
        pair.server.responses.clear();
        Connection third = pair.connect(clientConfig(false));
        assertTrue(third.isEstablished());
        assertEquals(1, pair.server.responses.size());
    }

    @Test
    void reusedTokenIsNotValidatedTwice() throws Exception {
        Pair pair = pair(ServerConfig.builder(serverTls(false).build()).retry(true).newTokens(1));
        firstConnection(pair);
        byte[] token = cache.tokens().take("localhost");
        assertNotNull(token);
        assertNull(cache.tokens().take("localhost"), "one token per connection as configured");
        cache.tokens().put("localhost", token);
        pair.server.responses.clear();
        pair.connect(clientConfig(false));
        assertTrue(pair.server.responses.isEmpty());
        cache.tokens().put("localhost", token); // a client that reuses it
        // drain the fresh tokens the second connection got, so the reused one is presented
        while (cache.tokens().take("localhost") != null) {
            // drop
        }
        cache.tokens().put("localhost", token);
        pair.server.responses.clear();
        pair.connect(clientConfig(false));
        assertEquals(1, pair.server.responses.size(), "a reused token gets a Retry");
    }

    // ---------------------------------------------------------------------------------------
    // Under loss

    /**
     * As a proxy uses a server under seeded loss and reordering: a full connection, a resumed one
     * with a request as 0-RTT data (accepted, or rejected and sent again in 1-RTT), and another
     * resumed one with a request sent as soon as its handshake completes, as a POST is. Each
     * request must be answered: none may wait for the idle timeout.
     */
    @Test
    void resumedConnectionsAnswerEveryRequestUnderLoss() throws Exception {
        for (int seed = 0; seed < 16; seed++) {
            for (boolean accepted : new boolean[] {true, false}) {
                SessionCache sessions = new SessionCache(new ClientSessionMemoryCache(), new TokenMemoryCache());
                Pair full = lossy(pair(serverTls(true)), seed);
                String where = "seed " + seed + (accepted ? ", 0-RTT accepted" : ", 0-RTT rejected");
                exchange(full, sessions, false, "GET /first", where + ", full handshake");
                Pair pair = full;
                if (!accepted) {
                    // The same ticketer, but this server has 0-RTT off
                    pair = lossy(pair(serverTls(false)), seed);
                    pair.time = full.time;
                }
                exchange(pair, sessions, true, "GET /early", where + ", 0-RTT request");
                exchange(pair, sessions, false, "POST /after-the-handshake", where + ", request after the handshake");
            }
        }
    }

    private static Pair lossy(Pair pair, int seed) {
        pair.random.setSeed(seed);
        pair.latency = 5_000_000L;
        pair.lossRate = 0.1;
        pair.reorderRate = 0.2;
        return pair;
    }

    /**
     * A request on a new connection, as 0-RTT data if {@code early} and the ticket allows it, else
     * once the client's handshake completes; the server echoes it. Then the client closes.
     */
    private void exchange(Pair pair, SessionCache sessions, boolean early, String request, String where)
            throws StreamException {
        byte[] bytes = request.getBytes(StandardCharsets.US_ASCII);
        int index = pair.server.connections.size();
        Connection client = pair.beginConnect(clientConfig(true, sessions));
        StreamId s = early ? client.openStream(Dir.BI) : null;
        if (s != null) {
            client.write(s, ByteBuffer.wrap(bytes));
            client.finish(s);
        }
        Map<StreamId, ByteArrayOutputStream> received = new HashMap<>();
        ByteArrayOutputStream response = new ByteArrayOutputStream();
        while (true) {
            if (pair.server.connections.size() > index) {
                echo(pair.server.connections.get(index), received);
            }
            if (s == null && client.isEstablished()) {
                s = client.openStream(Dir.BI);
                client.write(s, ByteBuffer.wrap(bytes));
                client.finish(s);
            }
            if (s != null && readToEnd(client, s, response)) {
                break;
            }
            assertTrue(pair.step(), where + ": idle with the request unanswered");
        }
        assertArrayEquals(bytes, response.toByteArray(), where);
        pair.drive(); // the tickets for the next connection
        client.close(pair.time, 0, "");
        pair.drive();
    }

    /** Sends each request stream's bytes back once its FIN has arrived. */
    private static void echo(Connection server, Map<StreamId, ByteArrayOutputStream> received) throws StreamException {
        for (StreamId id; (id = server.acceptStream(Dir.BI)) != null; ) {
            received.put(id, new ByteArrayOutputStream());
        }
        for (Map.Entry<StreamId, ByteArrayOutputStream> e : received.entrySet()) {
            if (e.getValue() != null && readToEnd(server, e.getKey(), e.getValue())) {
                server.write(e.getKey(), ByteBuffer.wrap(e.getValue().toByteArray()));
                server.finish(e.getKey());
                e.setValue(null);
            }
        }
    }

    /** Reads what is available into {@code out}; true once the FIN has been read. */
    private static boolean readToEnd(Connection c, StreamId id, ByteArrayOutputStream out) throws StreamException {
        ByteBuffer buf = ByteBuffer.allocate(64 * 1024);
        while (true) {
            buf.clear();
            int n;
            try {
                n = c.read(id, buf);
            } catch (StreamException e) {
                if (e.kind() == StreamException.Kind.BLOCKED) {
                    return false;
                }
                throw e;
            }
            if (n < 0) {
                return true;
            }
            out.write(buf.array(), 0, n);
        }
    }
}
