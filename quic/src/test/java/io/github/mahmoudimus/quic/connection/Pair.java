/*
 * Ported from quinn-proto src/tests/util.rs (Pair, TestEndpoint) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import io.github.mahmoudimus.quic.tls.TestCerts;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Random;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Two endpoints joined by an in-memory network on a fake clock, as quinn's tests drive them: no
 * sockets, no threads, no sleeping. The network can drop datagrams above an MTU, add latency, lose
 * and reorder datagrams from a seeded random source, drop chosen datagrams, or pass them through a
 * bottleneck of limited rate with a drop-tail queue.
 *
 * <p>Datagrams go to the endpoint that has their destination address: its {@link
 * TestEndpoint#address} or one of its {@link TestEndpoint#addresses other addresses} (a server's
 * preferred address, a client's new local address). {@link TestEndpoint#rebind} changes an
 * endpoint's address without telling its connections, as a NAT rebinding does; datagrams to an
 * address no endpoint has are lost.
 */
final class Pair {

    static final String ALPN = "microproxy-test";
    static final int DEFAULT_MTU = 1452;

    final TestEndpoint client;
    final TestEndpoint server;
    /** The current time, in nanoseconds. */
    long time = 1_000_000_000L;
    /** Datagrams larger than this are dropped. */
    int mtu = DEFAULT_MTU;
    /** One-way latency, in nanoseconds. */
    long latency;
    /** The probability that a datagram is lost. */
    double lossRate;
    /** The probability that a datagram is delayed by an extra random amount, reordering it. */
    double reorderRate;
    /**
     * The bottleneck rate of each direction in bytes per second, or 0 for none: a token bucket
     * refilled at this rate with no room for bursts, so that datagrams leave one after another at
     * the rate, waiting in a FIFO queue, and then take the latency.
     */
    long bandwidth;
    /** The bytes the bottleneck queue of each direction holds; datagrams arriving to a full queue are dropped. */
    long queueLimit = Long.MAX_VALUE;
    /** When each direction's bottleneck is free again: client to server, then server to client. */
    private final long[] linkFreeAt = new long[2];
    /** Datagrams dropped by a full bottleneck queue. */
    long queueDrops;
    /** The longest a datagram waited in a bottleneck queue, in nanoseconds. */
    long maxQueueDelay;
    /** Drops datagrams the client sends when it returns true. */
    Predicate<ByteBuffer> dropFromClient = d -> false;
    /** Drops datagrams the server sends when it returns true. */
    Predicate<ByteBuffer> dropFromServer = d -> false;
    final Random random = new Random(42);
    long datagramsFromClient;
    long datagramsFromServer;
    /** Datagrams to an address no endpoint has. */
    long misaddressed;
    /** Bytes the server sent to each address, whether they arrived or not. */
    final Map<InetSocketAddress, Long> serverBytesTo = new HashMap<>();
    /** Bytes that reached the server from each address. */
    final Map<InetSocketAddress, Long> serverBytesFrom = new HashMap<>();

    Pair() {
        this(EndpointConfig.defaults(), serverConfig(TransportConfig.defaults()), EndpointConfig.defaults());
    }

    Pair(EndpointConfig serverEndpoint, ServerConfig serverConfig, EndpointConfig clientEndpoint) {
        server = new TestEndpoint(new Endpoint(serverEndpoint, serverConfig, true), address(4433));
        client = new TestEndpoint(new Endpoint(clientEndpoint, null, true), address(50000));
    }

    /** The client TLS settings of a {@link #seeded} pair, or null for {@link #clientTls()}. */
    private TlsConfig seededClientTls;

    /**
     * A pair whose every random choice comes from a seed, so that a run repeats exactly, in this
     * JVM or another: the network's loss and reordering, both endpoints' connection IDs, packet
     * number skips and padding, the TLS randoms, key shares and signatures, and a certificate from
     * an authority made from the seed. (Only the server's token key stays random, which changes
     * the bytes of its NEW_TOKEN frames but not their size.)
     *
     * @param seed the seed
     * @param transport the transport settings of the server; pass them to {@link #client} too
     * @return the pair
     */
    static Pair seeded(long seed, TransportConfig transport) {
        TestCerts.Authority ca = TestCerts.seeded("Seeded CA", seed);
        TlsConfig serverTls = TlsConfig.builder()
                .certificate(ca.issue(TestCerts.KeyType.P256, "localhost"))
                .alpnProtocols(ALPN)
                .secureRandom(TestCerts.seededRandom(seed + 1))
                .build();
        Pair pair = new Pair(EndpointConfig.builder().random(TestCerts.seededRandom(seed + 2)).build(),
                ServerConfig.builder(serverTls).transport(transport).build(),
                EndpointConfig.builder().random(TestCerts.seededRandom(seed + 3)).build());
        pair.random.setSeed(seed);
        pair.seededClientTls = TlsConfig.builder()
                .serverName("localhost")
                .trustManager(ca.trustManager())
                .alpnProtocols(ALPN)
                .secureRandom(TestCerts.seededRandom(seed + 4))
                .build();
        return pair;
    }

    /**
     * Client settings for this pair: those of a {@link #seeded} pair, else {@link
     * #clientConfig(TransportConfig)}.
     *
     * @param transport the transport settings
     * @return the client settings
     */
    ClientConfig client(TransportConfig transport) {
        return seededClientTls != null
                ? ClientConfig.builder(seededClientTls).transport(transport).build()
                : clientConfig(transport);
    }

    static InetSocketAddress address(int port) {
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), port);
    }

    static TlsConfig serverTls() {
        return TlsConfig.builder()
                .certificate(TestCerts.CA.issue(TestCerts.KeyType.P256, "localhost"))
                .alpnProtocols(ALPN)
                .build();
    }

    static TlsConfig clientTls() {
        return TlsConfig.builder()
                .serverName("localhost")
                .trustManager(TestCerts.CA.trustManager())
                .alpnProtocols(ALPN)
                .build();
    }

    static ServerConfig serverConfig(TransportConfig transport) {
        return ServerConfig.builder(serverTls()).transport(transport).build();
    }

    static ClientConfig clientConfig() {
        return ClientConfig.builder(clientTls()).build();
    }

    static ClientConfig clientConfig(TransportConfig transport) {
        return ClientConfig.builder(clientTls()).transport(transport).build();
    }

    /** Drives both sides one round; returns false when both are idle. */
    boolean step() {
        driveClient();
        driveServer();
        if (client.isIdle() && server.isIdle()) {
            return false;
        }
        long t = Math.min(client.nextWakeup(), server.nextWakeup());
        if (t == Long.MAX_VALUE) {
            return false;
        }
        time = Math.max(time, t);
        return true;
    }

    /** Drives until both sides are idle. */
    void drive() {
        for (int i = 0; i < 1_000_000; i++) {
            if (!step()) {
                return;
            }
        }
        fail("connections never became idle");
    }

    /** Drives at most {@code steps} rounds; returns true if they did not become idle. */
    boolean driveBounded(int steps) {
        for (int i = 0; i < steps; i++) {
            if (!step()) {
                return false;
            }
        }
        return true;
    }

    /** Drives until a condition holds. */
    void driveUntil(java.util.function.BooleanSupplier condition) {
        for (int i = 0; i < 1_000_000; i++) {
            if (condition.getAsBoolean()) {
                return;
            }
            if (!step()) {
                if (condition.getAsBoolean()) {
                    return;
                }
                fail("idle before the condition held");
            }
        }
        fail("condition never held");
    }

    void driveClient() {
        client.drive(time);
        for (ByteBuffer d; (d = client.outbound.poll()) != null; ) {
            datagramsFromClient++;
            transfer(d, client, server, dropFromClient);
        }
    }

    void driveServer() {
        server.drive(time);
        for (ByteBuffer d; (d = server.outbound.poll()) != null; ) {
            datagramsFromServer++;
            transfer(d, server, client, dropFromServer);
        }
    }

    /** The endpoint that has an address, or null. */
    TestEndpoint owner(InetSocketAddress address) {
        for (TestEndpoint e : new TestEndpoint[] {client, server}) {
            if (e.address.equals(address) || e.addresses.contains(address)) {
                return e;
            }
        }
        return null;
    }

    private void transfer(ByteBuffer d, TestEndpoint from, TestEndpoint peer, Predicate<ByteBuffer> drop) {
        Transmit t = from.routing.remove(d);
        InetSocketAddress source = t != null && t.source() != null ? t.source() : from.address;
        InetSocketAddress destination = t != null ? t.destination() : peer.address;
        if (from == server) {
            serverBytesTo.merge(destination, (long) d.remaining(), Long::sum);
        }
        TestEndpoint to = owner(destination);
        if (to == null || to == from) {
            misaddressed++;
            return;
        }
        if (d.remaining() > mtu || drop.test(d.duplicate())) {
            return;
        }
        if (to == server) {
            serverBytesFrom.merge(source, (long) d.remaining(), Long::sum);
        }
        if (lossRate > 0 && random.nextDouble() < lossRate) {
            return;
        }
        long at = time;
        if (bandwidth > 0) {
            int direction = to == server ? 0 : 1;
            long start = Math.max(time, linkFreeAt[direction]);
            long queued = (start - time) * bandwidth / 1_000_000_000L; // bytes ahead of this one
            if (queued + d.remaining() > queueLimit) {
                queueDrops++;
                return;
            }
            maxQueueDelay = Math.max(maxQueueDelay, start - time);
            linkFreeAt[direction] = start + d.remaining() * 1_000_000_000L / bandwidth;
            at = linkFreeAt[direction];
        }
        at += latency;
        if (reorderRate > 0 && random.nextDouble() < reorderRate) {
            at += 1 + random.nextInt(5_000_000);
        }
        // A copy: the receiver keeps views of the buffer
        ByteBuffer copy = ByteBuffer.allocate(d.remaining()).put(d).flip();
        InetSocketAddress local = destination.equals(to.address) ? null : destination;
        to.inbound.add(new Inbound(at, to.sequence++, source, local, copy));
    }

    /** Connects with the default client configuration; returns the client connection. */
    Connection connect() {
        return connect(clientConfig());
    }

    Connection connect(ClientConfig config) {
        Connection c = beginConnect(config);
        drive();
        return c;
    }

    Connection beginConnect(ClientConfig config) {
        Connection c = client.endpoint.connect(time, config, server.address, "localhost");
        client.connections.add(c);
        return c;
    }

    /** The single connection the server accepted. */
    Connection serverConnection() {
        assertEquals(1, server.connections.size(), "server connections");
        return server.connections.get(0);
    }

    /** Asserts the handshake events of a connected pair, as quinn's {@code finish_connect} does. */
    static void assertConnected(Connection client, Connection server) {
        assertEquals(new ConnectionEvent.HandshakeDataReady(), client.pollEvent());
        assertEquals(new ConnectionEvent.Connected(), client.pollEvent());
        assertEquals(new ConnectionEvent.HandshakeDataReady(), server.pollEvent());
        assertEquals(new ConnectionEvent.HandshakeConfirmed(), server.pollEvent());
        assertEquals(new ConnectionEvent.Connected(), server.pollEvent());
        assertEquals(new ConnectionEvent.HandshakeConfirmed(), client.pollEvent());
    }

    /** The next event of a type, skipping others. */
    static <T extends ConnectionEvent> T nextEvent(Connection c, Class<T> type) {
        for (ConnectionEvent e; (e = c.pollEvent()) != null; ) {
            if (type.isInstance(e)) {
                return type.cast(e);
            }
        }
        return null;
    }

    static List<ConnectionEvent> drainEvents(Connection c) {
        List<ConnectionEvent> out = new ArrayList<>();
        for (ConnectionEvent e; (e = c.pollEvent()) != null; ) {
            out.add(e);
        }
        return out;
    }

    /**
     * A datagram on its way.
     *
     * @param local the address it was sent to, or null for the endpoint's own
     */
    record Inbound(long time, long sequence, InetSocketAddress from, InetSocketAddress local, ByteBuffer datagram) {

        Inbound(long time, long sequence, InetSocketAddress from, ByteBuffer datagram) {
            this(time, sequence, from, null, datagram);
        }
    }

    /** One endpoint with its connections and network queues. */
    static final class TestEndpoint {
        Endpoint endpoint;
        /** The endpoint's own address, which its connections know as null. */
        InetSocketAddress address;
        /** Other addresses the endpoint receives at. */
        final Set<InetSocketAddress> addresses = new HashSet<>();
        /** Where each outbound datagram goes, when not to the peer's own address. */
        final Map<ByteBuffer, Transmit> routing = new IdentityHashMap<>();
        final List<Connection> connections = new ArrayList<>();
        final PriorityQueue<Inbound> inbound = new PriorityQueue<>(
                Comparator.comparingLong(Inbound::time).thenComparingLong(Inbound::sequence));
        final ArrayDeque<ByteBuffer> outbound = new ArrayDeque<>();
        final ArrayDeque<ByteBuffer> delayed = new ArrayDeque<>();
        final List<ByteBuffer> responses = new ArrayList<>();
        long sequence;

        TestEndpoint(Endpoint endpoint, InetSocketAddress address) {
            this.endpoint = endpoint;
            this.address = address;
        }

        void drive(long now) {
            for (Connection c : connections) {
                long t = c.pollTimeout();
                if (t != NanoClock.NONE && t <= now) {
                    c.handleTimeout(now);
                }
            }
            while (!inbound.isEmpty() && inbound.peek().time() <= now) {
                Inbound in = inbound.poll();
                Endpoint.DatagramEvent e = endpoint.handle(now, in.from(), 0, in.datagram().duplicate());
                switch (e) {
                    case Endpoint.DatagramEvent.Deliver d -> d.connection().handleDatagram(now, in.local(), in.from(), 0,
                            in.datagram());
                    case Endpoint.DatagramEvent.NewConnection n -> {
                        connections.add(n.connection());
                        n.connection().handleDatagram(now, in.local(), in.from(), 0, in.datagram());
                    }
                    case Endpoint.DatagramEvent.Response r -> {
                        responses.add(r.datagram().duplicate());
                        routing.put(r.datagram(), new Transmit(r.datagram(), in.from(), in.local()));
                        outbound.add(r.datagram());
                    }
                    case null -> {}
                }
            }
            for (Connection c : new ArrayList<>(connections)) {
                for (EndpointEvent e; (e = c.pollEndpointEvent()) != null; ) {
                    endpoint.handleEvent(c, e);
                }
                for (Transmit t : c.pollTransmit(now, 64)) {
                    routing.put(t.datagram(), t);
                    outbound.add(t.datagram());
                }
                for (EndpointEvent e; (e = c.pollEndpointEvent()) != null; ) {
                    endpoint.handleEvent(c, e);
                }
            }
        }

        /**
         * Moves the endpoint to a new address without telling its connections, as a NAT that
         * rebinds does: datagrams to the old address are lost from now on.
         *
         * @param to the new address
         */
        void rebind(InetSocketAddress to) {
            address = to;
        }

        /** Holds back what was sent so far, to reorder it after later datagrams. */
        void delayOutbound() {
            delayed.addAll(outbound);
            outbound.clear();
        }

        /** Releases the held-back datagrams after those sent since. */
        void finishDelay() {
            outbound.addAll(delayed);
            delayed.clear();
        }

        /** Idle: nothing in flight but the long-running timers. */
        boolean isIdle() {
            if (!inbound.isEmpty()) {
                return false;
            }
            for (Connection c : connections) {
                TimerTable timers = c.timers();
                for (Timer t : Timer.values()) {
                    if (t == Timer.IDLE || t == Timer.KEEP_ALIVE || t == Timer.PUSH_NEW_CID || t == Timer.KEY_DISCARD) {
                        continue;
                    }
                    if (timers.isSet(t)) {
                        return false;
                    }
                }
            }
            return true;
        }

        long nextWakeup() {
            long t = Long.MAX_VALUE;
            if (!inbound.isEmpty()) {
                t = inbound.peek().time();
            }
            for (Connection c : connections) {
                long timeout = c.pollTimeout();
                if (timeout != NanoClock.NONE) {
                    t = Math.min(t, timeout);
                }
            }
            return t;
        }

        Connection only() {
            assertEquals(1, connections.size());
            return assertNotNull(connections.get(0));
        }

        private static Connection assertNotNull(Connection c) {
            org.junit.jupiter.api.Assertions.assertNotNull(c);
            return c;
        }
    }
}
