/*
 * Ported from quinn-proto src/endpoint.rs (Endpoint: handle, stateless_reset, connect,
 * handle_first_packet, retry, initial_close, ConnectionIndex) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.StatelessResetToken;
import io.github.mahmoudimus.quic.crypto.Keys;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.packet.Packet;
import io.github.mahmoudimus.quic.packet.PacketBuilder;
import io.github.mahmoudimus.quic.packet.PacketDecodeException;
import io.github.mahmoudimus.quic.packet.PacketHeader;
import io.github.mahmoudimus.quic.packet.PacketType;
import io.github.mahmoudimus.quic.packet.ProtectedPacket;
import io.github.mahmoudimus.quic.packet.UnsupportedVersionException;
import io.github.mahmoudimus.quic.token.IncomingToken;
import io.github.mahmoudimus.quic.token.TokenValidator;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.SplittableRandom;

/**
 * The connections of one UDP socket, as a sans-I/O state machine after quinn-proto's {@code
 * Endpoint}: it routes incoming datagrams to connections by Destination Connection ID (or by the
 * peer's address when local IDs are zero-length), creates server connections from Initial packets,
 * and answers what no connection should see: Version Negotiation for unknown versions, Retry for
 * address validation, stateless resets for unknown connection IDs, and CONNECTION_CLOSE for refused
 * attempts.
 *
 * <p>The I/O layer passes every datagram to {@link #handle}, delivers the datagram to the connection
 * it names, sends any response, and passes each connection's {@link Connection#pollEndpointEvent()
 * endpoint events} back through {@link #handleEvent}, which keeps the routes current as connection
 * IDs are issued and retired.
 *
 * <p><b>Threads.</b> Not thread-safe and takes no locks; the I/O layer serializes access.
 */
public final class Endpoint {

    /** What to do with a datagram. */
    public sealed interface DatagramEvent {

        /**
         * The datagram belongs to a connection: pass it to {@link Connection#handleDatagram}.
         *
         * @param connection the connection
         */
        record Deliver(Connection connection) implements DatagramEvent {}

        /**
         * A client's first Initial created a server connection: start driving it, then pass it the
         * datagram.
         *
         * @param connection the new connection
         */
        record NewConnection(Connection connection) implements DatagramEvent {}

        /**
         * Send this datagram back to the datagram's sender (Version Negotiation, Retry, stateless
         * reset or CONNECTION_CLOSE).
         *
         * @param datagram the response
         */
        record Response(ByteBuffer datagram) implements DatagramEvent {}
    }

    private record ResetKey(InetSocketAddress remote, StatelessResetToken token) {}

    private static final class Routes {
        final Set<ConnectionId> cids = new HashSet<>();
        final List<ConnectionId> initialCids = new ArrayList<>();
        ResetKey resetKey;
        final InetSocketAddress remote;

        Routes(InetSocketAddress remote) {
            this.remote = remote;
        }
    }

    private static final byte[] EMPTY = new byte[0];
    /** Minimum padding for a stateless reset to look like a short header packet. */
    private static final int MIN_RESET_PADDING = 5;

    private final EndpointConfig config;
    private final ServerConfig serverConfig;
    private final boolean allowMtud;
    private final SecureRandom secureRandom;
    private final SplittableRandom random;
    private final TokenValidator tokenValidator;
    private final Map<ConnectionId, Connection> initialCids = new HashMap<>();
    private final Map<ConnectionId, Connection> cids = new HashMap<>();
    private final Map<InetSocketAddress, Connection> remotes = new HashMap<>();
    private final Map<ResetKey, Connection> resetTokens = new HashMap<>();
    private final Map<Connection, Routes> connections = new LinkedHashMap<>();
    private long lastStatelessReset = NanoClock.NONE;

    /**
     * An endpoint.
     *
     * @param config the endpoint's settings
     * @param serverConfig how to accept connections, or null for a client-only endpoint
     * @param allowMtud whether the socket never fragments datagrams, which path MTU discovery needs
     */
    public Endpoint(EndpointConfig config, ServerConfig serverConfig, boolean allowMtud) {
        this.config = Objects.requireNonNull(config, "config");
        this.serverConfig = serverConfig;
        this.allowMtud = allowMtud;
        this.secureRandom = config.newRandom();
        this.random = new SplittableRandom(secureRandom.nextLong());
        this.tokenValidator = serverConfig != null ? serverConfig.tokenValidator(secureRandom) : null;
    }

    /**
     * Routes a datagram.
     *
     * @param now the current time
     * @param remote the sender
     * @param ecn the ECN codepoint
     * @param datagram the datagram, between its position and limit; not modified
     * @return what to do with it, or null to drop it
     */
    public DatagramEvent handle(long now, InetSocketAddress remote, int ecn, ByteBuffer datagram) {
        int length = datagram.remaining();
        ProtectedPacket first;
        try {
            first = ProtectedPacket.parse(datagram.duplicate(), config.cidLength());
        } catch (UnsupportedVersionException e) {
            if (serverConfig == null || length < Connection.MIN_INITIAL_SIZE) {
                return null; // RFC 9000 section 5.2.2: no reply to small packets
            }
            return new DatagramEvent.Response(versionNegotiation(e.version(), e.destinationId(), e.sourceId()));
        } catch (PacketDecodeException e) {
            Connection c = byResetToken(remote, datagram);
            return c != null ? new DatagramEvent.Deliver(c) : null;
        }
        ConnectionId dcid = first.destinationId();
        Connection c = route(remote, first);
        if (c != null) {
            return new DatagramEvent.Deliver(c);
        }
        if (first.type() == PacketType.INITIAL) {
            return handleFirstPacket(now, remote, length, datagram, first);
        }
        if (first.type().isLongHeader()) {
            return null; // a non-Initial packet for an unknown connection
        }
        c = byResetToken(remote, datagram);
        if (c != null) {
            return new DatagramEvent.Deliver(c);
        }
        if (dcid.isEmpty() || !config.cidGenerator.validate(dcid)) {
            return null;
        }
        ByteBuffer reset = statelessReset(now, length, dcid);
        return reset != null ? new DatagramEvent.Response(reset) : null;
    }

    /**
     * Whether a datagram belongs to one of the endpoint's connections, by its first packet's
     * Destination Connection ID (or the sender's address, for zero-length IDs): what {@link #handle}
     * would {@linkplain DatagramEvent.Deliver deliver}, short of stateless resets. Nothing changes.
     *
     * @param remote the sender
     * @param datagram the datagram, between its position and limit; not modified
     * @return whether a connection would get it
     */
    public boolean knows(InetSocketAddress remote, ByteBuffer datagram) {
        try {
            return route(remote, ProtectedPacket.parse(datagram.duplicate(), config.cidLength())) != null;
        } catch (PacketDecodeException e) {
            return false;
        }
    }

    private Connection route(InetSocketAddress remote, ProtectedPacket p) {
        ConnectionId dcid = p.destinationId();
        if (p.type() == PacketType.INITIAL || p.type() == PacketType.ZERO_RTT) {
            Connection c = initialCids.get(dcid);
            if (c != null) {
                return c;
            }
        }
        if (!dcid.isEmpty()) {
            Connection c = cids.get(dcid);
            if (c != null) {
                return c;
            }
        }
        if (dcid.isEmpty()) {
            return remotes.get(remote);
        }
        return null;
    }

    private Connection byResetToken(InetSocketAddress remote, ByteBuffer datagram) {
        if (resetTokens.isEmpty() || datagram.remaining() < StatelessResetToken.MIN_RESET_DATAGRAM) {
            return null;
        }
        byte[] tail = new byte[StatelessResetToken.LENGTH];
        datagram.get(datagram.limit() - StatelessResetToken.LENGTH, tail);
        return resetTokens.get(new ResetKey(remote, StatelessResetToken.of(tail)));
    }

    private ByteBuffer versionNegotiation(int clientVersion, byte[] dcid, byte[] scid) {
        int grease = clientVersion == 0x0a1a2a3a ? 0x0a1a2a4a : 0x0a1a2a3a;
        int[] versions = new int[config.supportedVersions.size() + 1];
        versions[0] = grease;
        for (int i = 0; i < config.supportedVersions.size(); i++) {
            versions[i + 1] = config.supportedVersions.get(i).wireValue();
        }
        byte[] vn = new UnsupportedVersionException(clientVersion, dcid, scid).versionNegotiation(versions);
        vn[0] = (byte) (0x80 | random.nextInt(0x80)); // the unused bits are random (RFC 8999)
        return ByteBuffer.wrap(vn);
    }

    private DatagramEvent handleFirstPacket(long now, InetSocketAddress remote, int length, ByteBuffer datagram,
            ProtectedPacket first) {
        if (serverConfig == null || length < Connection.MIN_INITIAL_SIZE) {
            return null;
        }
        QuicVersion version = first.version();
        ConnectionId dcid = first.destinationId();
        ConnectionId scid = first.sourceId();
        if (!config.supportedVersions.contains(version)) {
            return new DatagramEvent.Response(versionNegotiation(version.wireValue(), dcid.toByteArray(),
                    scid.toByteArray()));
        }
        byte[] token = first.token();
        Keys keys = Keys.initial(version, dcid, true);
        if (dcid.length() < 8 && (token.length == 0 || dcid.length() != config.cidLength())) {
            // RFC 9000 section 7.2: a client's first Destination Connection ID has at least 8 bytes
            return new DatagramEvent.Response(initialClose(version, keys, scid, QuicException.PROTOCOL_VIOLATION,
                    "invalid destination CID length"));
        }
        // Authenticate a copy before creating any state: removing protection works in place
        ByteBuffer copy = ByteBuffer.allocate(length).put(datagram.duplicate()).flip();
        try {
            ProtectedPacket p = ProtectedPacket.parse(copy, config.cidLength());
            Packet packet = p.unprotect(keys.remote(), 0);
            if (packet == null) {
                return null;
            }
        } catch (PacketDecodeException | QuicException | RuntimeException e) {
            return null;
        }
        if (connections.size() >= serverConfig.maxConnections) {
            return new DatagramEvent.Response(initialClose(version, keys, scid, QuicException.CONNECTION_REFUSED,
                    "server busy"));
        }
        IncomingToken incoming;
        try {
            incoming = tokenValidator.validate(token, dcid, remote);
        } catch (QuicException e) {
            return new DatagramEvent.Response(initialClose(version, keys, scid, QuicException.INVALID_TOKEN, ""));
        }
        if (serverConfig.retry && !incoming.validated()) {
            return new DatagramEvent.Response(retry(version, remote, dcid, scid));
        }
        ConnectionId localCid = newCid();
        Connection conn = Connection.server(now, serverConfig, config, remote, version, dcid, scid, localCid,
                incoming.originalDestinationId(), incoming.retrySourceId(), incoming.validated(), token, allowMtud,
                random.split());
        Routes routes = register(conn, localCid, remote);
        initialCids.put(dcid, conn);
        routes.initialCids.add(dcid);
        return new DatagramEvent.NewConnection(conn);
    }

    private ByteBuffer retry(QuicVersion version, InetSocketAddress remote, ConnectionId dcid, ConnectionId scid) {
        // The client's next Initial is addressed to this ID; it is looked up only through the token
        ConnectionId retryCid = config.cidLength() >= 8 ? config.cidGenerator.generateCid()
                : ConnectionId.random(secureRandom, 8);
        byte[] token = tokenValidator.retryToken(remote, dcid);
        PacketHeader.Retry retry = PacketHeader.Retry.create(version, scid, retryCid, token, dcid);
        ByteBuffer out = ByteBuffer.allocate(64 + token.length + 2 * ConnectionId.MAX_LENGTH);
        retry.encode(out);
        return out.flip();
    }

    private ByteBuffer initialClose(QuicVersion version, Keys keys, ConnectionId clientScid, long code, String reason) {
        ByteBuffer buf = ByteBuffer.allocate(Connection.MIN_INITIAL_SIZE);
        PacketBuilder builder = new PacketBuilder(buf, Connection.MIN_INITIAL_SIZE);
        ConnectionId localCid = ConnectionId.random(secureRandom, Math.max(config.cidLength(), 8));
        ByteBuffer frames = builder.begin(new PacketHeader.Initial(version, clientScid, localCid, EMPTY, 0, 1),
                keys.local());
        Frame.ConnectionClose.of(code, 0, reason).encode(frames, frames.remaining());
        builder.finish();
        return builder.datagram();
    }

    private ByteBuffer statelessReset(long now, int incitingLength, ConnectionId dcid) {
        if (lastStatelessReset != NanoClock.NONE && now - lastStatelessReset < config.minResetInterval.toNanos()) {
            return null;
        }
        int headroom = incitingLength - StatelessResetToken.LENGTH;
        if (headroom <= MIN_RESET_PADDING) {
            return null; // too small to answer without amplifying or looping
        }
        int maxPadding = headroom - 1;
        int idealMin = MIN_RESET_PADDING + ConnectionId.MAX_LENGTH;
        int padding = maxPadding <= idealMin ? maxPadding : random.nextInt(idealMin, maxPadding);
        lastStatelessReset = now;
        byte[] out = new byte[padding + StatelessResetToken.LENGTH];
        secureRandom.nextBytes(out);
        out[0] = (byte) (0x40 | ((out[0] & 0xff) >>> 2));
        StatelessResetToken.derive(config.resetKey, dcid).writeTo(ByteBuffer.wrap(out, padding, StatelessResetToken.LENGTH));
        return ByteBuffer.wrap(out);
    }

    /**
     * Starts a client connection.
     *
     * @param now the current time
     * @param clientConfig how to connect
     * @param remote the server's address
     * @param serverName the server name for SNI and certificate checks, or null for the TLS
     *     configuration's
     * @return the connection, with its first Initial ready in {@link Connection#pollTransmit}
     * @throws IllegalArgumentException if the address is unusable or the version is not enabled
     */
    public Connection connect(long now, ClientConfig clientConfig, InetSocketAddress remote, String serverName) {
        if (remote.isUnresolved() || remote.getPort() == 0 || remote.getAddress().isAnyLocalAddress()) {
            throw new IllegalArgumentException("invalid remote address " + remote);
        }
        if (!config.supportedVersions.contains(clientConfig.version)) {
            throw new IllegalArgumentException("version " + clientConfig.version + " is not enabled");
        }
        ConnectionId initialDcid = ConnectionId.random(secureRandom, clientConfig.initialDcidLength);
        ConnectionId localCid = newCid();
        Connection conn = Connection.client(now, clientConfig, config, remote, serverName, initialDcid, localCid,
                allowMtud, random.split());
        register(conn, localCid, remote);
        return conn;
    }

    private ConnectionId newCid() {
        while (true) {
            ConnectionId cid = config.cidGenerator.generateCid();
            if (cid.isEmpty() || !cids.containsKey(cid)) {
                return cid;
            }
        }
    }

    private Routes register(Connection conn, ConnectionId localCid, InetSocketAddress remote) {
        Routes routes = new Routes(remote);
        connections.put(conn, routes);
        if (localCid.isEmpty()) {
            remotes.put(remote, conn);
        } else {
            cids.put(localCid, conn);
            routes.cids.add(localCid);
        }
        return routes;
    }

    /**
     * Applies a connection's endpoint event to the routes.
     *
     * @param conn the connection
     * @param event the event from {@link Connection#pollEndpointEvent()}
     */
    public void handleEvent(Connection conn, EndpointEvent event) {
        Routes routes = connections.get(conn);
        if (routes == null) {
            return;
        }
        switch (event) {
            case EndpointEvent.CidIssued e -> {
                if (!e.cid().isEmpty() && !cids.containsKey(e.cid())) {
                    cids.put(e.cid(), conn);
                    routes.cids.add(e.cid());
                }
            }
            case EndpointEvent.CidRetired e -> {
                if (cids.get(e.cid()) == conn) {
                    cids.remove(e.cid());
                }
                routes.cids.remove(e.cid());
            }
            case EndpointEvent.ResetToken e -> {
                if (routes.resetKey != null) {
                    resetTokens.remove(routes.resetKey, conn);
                }
                routes.resetKey = new ResetKey(e.remote(), e.token());
                resetTokens.put(routes.resetKey, conn);
            }
            case EndpointEvent.Drained e -> forget(conn, routes);
        }
    }

    private void forget(Connection conn, Routes routes) {
        connections.remove(conn);
        for (ConnectionId cid : routes.cids) {
            cids.remove(cid, conn);
        }
        for (ConnectionId cid : routes.initialCids) {
            initialCids.remove(cid, conn);
        }
        if (routes.resetKey != null) {
            resetTokens.remove(routes.resetKey, conn);
        }
        remotes.remove(routes.remote, conn);
    }

    /**
     * The connections the endpoint routes to, until each is drained.
     *
     * @return a snapshot
     */
    public List<Connection> connections() {
        return new ArrayList<>(connections.keySet());
    }

    /**
     * The number of connections.
     *
     * @return the count
     */
    public int openConnections() {
        return connections.size();
    }

    /**
     * The number of local connection IDs routed, for tests and monitoring.
     *
     * @return the count
     */
    public int knownCids() {
        return cids.size();
    }

    /**
     * The endpoint's settings.
     *
     * @return the settings
     */
    public EndpointConfig config() {
        return config;
    }

    /**
     * Whether this endpoint accepts connections.
     *
     * @return true for a server
     */
    public boolean isServer() {
        return serverConfig != null;
    }
}
