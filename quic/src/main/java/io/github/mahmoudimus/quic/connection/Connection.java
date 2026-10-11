/*
 * Ported from quinn-proto src/connection/mod.rs (Connection: poll_transmit, handle_event,
 * handle_timeout, close, the handshake state machine in process_decrypted_packet,
 * process_early_payload and process_payload, read_crypto, write_crypto, populate_packet, key
 * update, spin bit, connection ID handling, 0-RTT: init_0rtt, zero_rtt_crypto, accepted_0rtt and
 * the rejection of 0-RTT data, NEW_TOKEN issuance and storage; path handling: migrate, the
 * migration in process_payload, send_path_challenge, PATH_CHALLENGE and PATH_RESPONSE, prev_path,
 * update_rem_cid and the PathValidation timer), src/connection/paths.rs (PathResponses),
 * src/connection/packet_builder.rs and src/connection/packet_crypto.rs (Apache-2.0). The client's
 * probing of a new path and the preferred address follow RFC 9000 sections 9.1, 9.5 and 9.6.
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.Secrets;
import io.github.mahmoudimus.quic.StatelessResetToken;
import io.github.mahmoudimus.quic.congestion.RttEstimator;
import io.github.mahmoudimus.quic.crypto.DirectionalKeys;
import io.github.mahmoudimus.quic.crypto.Keys;
import io.github.mahmoudimus.quic.crypto.PacketKey;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.frame.FrameDecoder;
import io.github.mahmoudimus.quic.packet.Packet;
import io.github.mahmoudimus.quic.packet.PacketBuilder;
import io.github.mahmoudimus.quic.packet.PacketDecodeException;
import io.github.mahmoudimus.quic.packet.PacketHeader;
import io.github.mahmoudimus.quic.packet.PacketNumber;
import io.github.mahmoudimus.quic.packet.PacketType;
import io.github.mahmoudimus.quic.packet.ProtectedPacket;
import io.github.mahmoudimus.quic.params.PreferredAddress;
import io.github.mahmoudimus.quic.params.TransportParameters;
import io.github.mahmoudimus.quic.tls.SessionTicket;
import io.github.mahmoudimus.quic.tls.TlsSession;
import io.github.mahmoudimus.quic.token.TokenValidator;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.random.RandomGenerator;

/**
 * One QUIC connection (RFC 9000, 9001, 9002) as a sans-I/O state machine, after quinn-proto's
 * {@code Connection}. It performs no I/O, reads no clock and starts no thread: the caller feeds it
 * datagrams ({@link #handleDatagram}) and timeouts ({@link #handleTimeout}), takes datagrams to send
 * ({@link #pollTransmit}), sleeps until {@link #pollTimeout()}, and reads {@link #pollEvent()
 * events}. Connections are made by an {@link Endpoint}, which routes datagrams to them.
 *
 * <p>The connection drives the TLS handshake ({@link TlsSession}) through CRYPTO frames at each
 * encryption level, installs keys as secrets arrive, discards Initial and Handshake keys (RFC 9001
 * section 4.9), confirms the handshake with HANDSHAKE_DONE, enforces the anti-amplification limit,
 * exchanges and authenticates transport parameters, and then carries streams ({@link
 * StreamsState}), DATAGRAM frames (RFC 9221), connection ID rotation, key updates and the close
 * and draining states (RFC 9000 section 10). Loss detection and congestion control are {@link
 * Recovery}'s.
 *
 * <p><b>Buffers.</b> {@link #handleDatagram} keeps views of the datagram buffer (received stream
 * data is not copied), so give each call a buffer of its own. Each datagram {@link #pollTransmit}
 * returns is a new buffer.
 *
 * <p><b>Threads.</b> Not thread-safe and takes no locks: the I/O layer owns each connection and
 * serializes every call, the application's stream operations included.
 *
 * <p><b>Resumption and 0-RTT.</b> A client with a {@link SessionCache} keeps the session tickets
 * and NEW_TOKEN tokens it receives, and starts its next connection to the same server with one of
 * each: the token in its Initial packets lets the server skip Retry, and the ticket resumes the
 * TLS session. If the ticket allows 0-RTT and the TLS configuration enables it, the client sends
 * stream data and datagrams in 0-RTT packets at once, within the transport parameters the ticket
 * remembers (RFC 9000 section 7.4.1). If the server rejects the early data, everything the
 * streams sent is sent again in 1-RTT packets, provided it fits the server's new limits (the local
 * streams are forgotten otherwise). A server with tickets and 0-RTT enabled in its TLS
 * configuration decrypts 0-RTT packets with the client early traffic secret and processes their
 * frames during the handshake; {@link #receivedEarlyData(StreamId)} tells which streams carried
 * early data, which the application must treat as replayable.
 *
 * <p><b>Migration (RFC 9000 section 9).</b> A server that allows it ({@link
 * ServerConfig.Builder#migration}) follows its client to a new address once the handshake is
 * confirmed and a non-probing packet with the largest packet number so far arrives from there: it
 * validates the new path with PATH_CHALLENGE, sends there no more than three times what it received
 * there until the client answers, keeps the congestion and RTT state when only the port changed (a
 * NAT rebinding) and resets them otherwise, challenges the previous path as well, moves to an unused
 * connection ID of the client's, and goes back to the previous path if validation times out. A
 * replayed or reordered packet, whose number is not the largest, moves nothing. A client probes a
 * new path before it moves there ({@link #probePath}, and the server's preferred address), with a
 * connection ID of the server's not used before, and switches when the PATH_RESPONSE arrives.
 * Datagrams may then go to or come from addresses other than the current path's: see {@link
 * Transmit} and {@link #handleDatagram(long, InetSocketAddress, InetSocketAddress, int, ByteBuffer)}.
 *
 * <p>Not supported: sending ACK_FREQUENCY.
 */
public final class Connection {

    /** The connection states (RFC 9000 section 10). */
    enum State {
        HANDSHAKE,
        ESTABLISHED,
        /** Closing: this endpoint sent CONNECTION_CLOSE and repeats it in answer to packets. */
        CLOSED,
        /** Draining: the peer closed; nothing more is sent. */
        DRAINING,
        /** Gone: the endpoint may forget the connection. */
        DRAINED
    }

    private record Close(boolean application, long code, long frameType, String reason) {}

    private record EarlyPacket(long number, Packet packet, ConnectionId destination) {}

    /** A packet being assembled in the current datagram. */
    private static final class OpenPacket {
        SpaceId space;
        long number;
        int start;
        boolean ackEliciting;
        boolean track = true;
        long largestAcked = -1;
        int payloadStart;
        /** A client's 0-RTT packet: no ACK, CRYPTO, HANDSHAKE_DONE or connection ID frames. */
        boolean zeroRtt;
        /** Whether it carries PATH_CHALLENGE or PATH_RESPONSE, whose datagram is padded. */
        boolean pathFrames;
        Retransmits sent = new Retransmits();
        List<StreamMeta> streamFrames = List.of();
    }

    private static final SpaceId[] SPACES = SpaceId.values();
    private static final byte[] EMPTY = new byte[0];
    /** The smallest datagram that carries an Initial packet (RFC 9000 section 14.1). */
    static final int MIN_INITIAL_SIZE = PacketBuilder.MIN_INITIAL_DATAGRAM;
    /** Room a packet needs to be worth starting: a header and a few frames. */
    private static final int MIN_PACKET_SPACE = 64;
    /** Packets left under the confidentiality limit at which a key update is forced. */
    private static final long KEY_UPDATE_MARGIN = 10_000;
    /** 1-RTT packets a server keeps while its handshake completes. */
    private static final int MAX_EARLY_1RTT_PACKETS = 100;
    /** A CRYPTO frame's overhead bound: type, an 8-byte offset and a 2-byte length. */
    private static final int CRYPTO_SIZE_BOUND = 1 + 8 + 2;

    /**
     * A client's probe of a new path (RFC 9000 section 9.1): where to, from where, with which of
     * the server's connection IDs, and the PATH_CHALLENGE data the server must echo.
     */
    private static final class Probe {
        final InetSocketAddress remote;
        final InetSocketAddress local;
        final ConnectionId cid;
        final long challenge;
        final long deadline;
        /** Whether a PATH_CHALLENGE must be sent. */
        boolean pending = true;
        /** The wait before the PATH_CHALLENGE is sent again. */
        long backoff;

        Probe(InetSocketAddress remote, InetSocketAddress local, ConnectionId cid, long challenge, long deadline) {
            this.remote = remote;
            this.local = local;
            this.cid = cid;
            this.challenge = challenge;
            this.deadline = deadline;
        }
    }

    private final Side side;
    private final TransportConfig config;
    private final QuicVersion version;
    private final TlsSession tls;
    private final RandomGenerator random;
    private final TimerTable timers = new TimerTable();
    private final Recovery recovery;
    private final StreamsState streams;
    private final Recovery.Listener listener;
    private final LocalCidState localCids;
    private final RemoteCidQueue remoteCids;
    private final int localCidLength;
    private final DatagramState datagrams = new DatagramState();
    private final ArrayDeque<ConnectionEvent> events = new ArrayDeque<>();
    private final ArrayDeque<EndpointEvent> endpointEvents = new ArrayDeque<>();
    private final List<EarlyPacket> early1rtt = new ArrayList<>();
    private final Set<StreamId> finishedReads = new HashSet<>();
    private final String logId;

    /** The connection ID this endpoint chose for the handshake. */
    private final ConnectionId handshakeCid;
    /** The connection ID the peer chose for the handshake. */
    private ConnectionId remoteHandshakeCid;
    /** The Source Connection ID of the peer's first packet. */
    private ConnectionId origRemoteCid;
    /** The Destination Connection ID of the client's first Initial. */
    private final ConnectionId initialDcid;
    /** The Source Connection ID of the Retry this client processed. */
    private ConnectionId retrySrcCid;
    /** The peer's address on the current path, for reading without the connection's owner. */
    private volatile InetSocketAddress remote;
    /** The loss recovery settings new paths start from. */
    private final RecoveryConfig recoveryConfig;
    /** Whether a server follows its client to new addresses. */
    private boolean remoteMayMigrate;
    /** Whether a client may move to new local addresses. */
    private boolean activeMigration = true;
    /** Whether a client moves to the server's preferred address. */
    private boolean followPreferredAddress;
    /** Paths seen, which numbers their generations. */
    private long pathCounter;
    /** The peer's connection ID in use on the previous path, for its PATH_CHALLENGE. */
    private ConnectionId prevPathCid;
    private final PathResponses pathResponses = new PathResponses();
    /** A client's probe of a new path; null when none is under way. */
    private Probe probe;
    /** The sender, local address and size of the datagram being handled. */
    private InetSocketAddress rxFrom;
    private InetSocketAddress rxLocal;
    private int rxLength;

    private State state = State.HANDSHAKE;
    private boolean remoteCidSet;
    /** A client's token from a Retry, sent in every Initial; a server's expected token. */
    private byte[] token;
    private byte[] clientHello;
    private boolean retryReceived;
    private SpaceId highestSpace = SpaceId.INITIAL;
    private TransportParameters peerParams = TransportParameters.defaults();
    private boolean handshakeDataReady;
    private boolean handshakeConfirmed;

    private boolean keyPhase;
    private long keyPhaseSize;
    private Keys prevKeys;
    /** The incoming packet number that ended the previous key phase, or -1. */
    private long prevEndPacket = -1;
    private boolean prevUpdateUnacked;
    private Keys nextKeys;
    private long keyUpdates;
    private long authenticationFailures;

    private ConnectionError error;
    private boolean errorReported;
    private Close closeReason;
    private boolean closePending;
    private long idleTimeout;
    private boolean permitIdleReset = true;
    private long nextBundledAckTime = NanoClock.NONE;
    private final boolean spinEnabled;
    private boolean spin;
    private long totalAuthedPackets;
    private boolean receivingEcn;
    private StatelessResetToken peerResetToken;

    /** A client's cache of tickets and tokens, and its key there; null on a server or without one. */
    private SessionCache sessionCache;
    private String cacheKey;
    /** 0-RTT packet keys: a client's for sending, a server's for receiving; null without (or after) 0-RTT. */
    private DirectionalKeys zeroRttKeys;
    /** Whether 0-RTT was attempted (client) or accepted (server). */
    private boolean zeroRttEnabled;
    /** Whether the server accepted the client's 0-RTT data. */
    private boolean zeroRttAccepted;
    /** The transport parameters a client remembered from its ticket and used for 0-RTT. */
    private TransportParameters rememberedParams;
    /** Remote streams that carried data in 0-RTT packets (server). */
    private final Set<StreamId> earlyStreams = new HashSet<>();
    /** A server's token issuer, for NEW_TOKEN frames; null on a client. */
    private TokenValidator tokenValidator;
    /** How many NEW_TOKEN frames a server sends once the handshake completes. */
    private int newTokens;

    private Connection(Side side, long now, TransportConfig config, EndpointConfig endpointConfig,
            QuicVersion version, TlsSession tls, InetSocketAddress remote, ConnectionId initialDcid,
            ConnectionId localCid, ConnectionId remoteCid, boolean addressValidated, byte[] token,
            boolean allowMtud, RandomGenerator random, ConnectionId preferredCid) {
        this.side = side;
        this.config = config;
        this.version = version;
        this.tls = tls;
        this.random = random;
        this.remote = remote;
        this.initialDcid = initialDcid;
        this.handshakeCid = localCid;
        this.remoteHandshakeCid = remoteCid;
        this.origRemoteCid = remoteCid;
        this.remoteCidSet = side.isServer();
        this.token = token;
        this.localCidLength = endpointConfig.cidLength();
        this.logId = initialDcid.toString();
        this.recoveryConfig = config.recoveryConfig(allowMtud);
        this.recovery = new Recovery(side, recoveryConfig, timers, random, now, remote, null);
        recovery.setSendingEcn(false); // the socket layer cannot mark ECN
        if (addressValidated) {
            recovery.setAddressValidated();
        }
        recovery.space(SpaceId.INITIAL).setKeys(Keys.initial(version, initialDcid, side.isServer()));
        this.streams = new StreamsState(side, config.maxConcurrentUniStreams, config.maxConcurrentBidiStreams,
                config.sendWindow, config.receiveWindow, config.streamReceiveWindow);
        this.listener = Recovery.Listener.forStreams(streams);
        this.localCids = preferredCid == null
                ? new LocalCidState(endpointConfig.cidGenerator, endpointConfig.resetKey, now, localCid)
                : new LocalCidState(endpointConfig.cidGenerator, endpointConfig.resetKey, now, localCid, preferredCid);
        this.remoteCids = new RemoteCidQueue(remoteCid, activeCidLimit(config, localCidLength));
        this.spinEnabled = config.allowSpin && random.nextInt(8) != 0;
        // A small first key phase makes peers that mishandle key updates fail early, as quinn does
        this.keyPhaseSize = random.nextLong(10, 1000);
        this.idleTimeout = config.maxIdleTimeout.toNanos();
    }

    private static int activeCidLimit(TransportConfig config, int localCidLength) {
        return localCidLength == 0 ? (int) TransportParameters.DEFAULT_ACTIVE_CONNECTION_ID_LIMIT
                : config.activeConnectionIdLimit;
    }

    private static TransportParameters.Builder localParams(TransportConfig c, int localCidLength,
            ConnectionId localCid) {
        return TransportParameters.builder()
                .initialSourceConnectionId(localCid)
                .initialMaxStreamsBidi(c.maxConcurrentBidiStreams)
                .initialMaxStreamsUni(c.maxConcurrentUniStreams)
                .initialMaxData(c.receiveWindow)
                .initialMaxStreamDataBidiLocal(c.streamReceiveWindow)
                .initialMaxStreamDataBidiRemote(c.streamReceiveWindow)
                .initialMaxStreamDataUni(c.streamReceiveWindow)
                .maxUdpPayloadSize(c.maxUdpPayloadSize)
                .maxIdleTimeout(c.maxIdleTimeout.toMillis())
                .activeConnectionIdLimit(activeCidLimit(c, localCidLength))
                .maxDatagramFrameSize(Math.min(c.datagramReceiveBufferSize, 0xffff))
                .ackDelayExponent(c.ackDelayExponent)
                .maxAckDelay(c.maxAckDelay.toMillis());
    }

    /**
     * Starts a client connection; its first Initial is ready to send at once.
     *
     * @param now the current time
     * @param config the client configuration
     * @param endpointConfig the endpoint's settings
     * @param remote the server's address
     * @param serverName the name to send as SNI and to check the certificate against, or null for
     *     the TLS configuration's
     * @param initialDcid the random Destination Connection ID of the first Initial
     * @param localCid this client's connection ID
     * @param allowMtud whether the socket supports path MTU discovery (does not fragment)
     * @param random the source of randomness for the spin bit, packet number skipping and key phases
     * @return the connection
     */
    static Connection client(long now, ClientConfig config, EndpointConfig endpointConfig, InetSocketAddress remote,
            String serverName, ConnectionId initialDcid, ConnectionId localCid, boolean allowMtud,
            RandomGenerator random) {
        return client(now, config, endpointConfig, remote, serverName, initialDcid, localCid, allowMtud, random,
                config.sessionCache);
    }

    /**
     * Starts a client connection with a cache of session tickets and tokens.
     *
     * @param cache the cache, or null for none
     * @see #client(long, ClientConfig, EndpointConfig, InetSocketAddress, String, ConnectionId,
     *     ConnectionId, boolean, RandomGenerator)
     */
    static Connection client(long now, ClientConfig config, EndpointConfig endpointConfig, InetSocketAddress remote,
            String serverName, ConnectionId initialDcid, ConnectionId localCid, boolean allowMtud,
            RandomGenerator random, SessionCache cache) {
        TransportConfig transport = config.transport;
        byte[] params = localParams(transport, endpointConfig.cidLength(), localCid)
                .disableActiveMigration(!config.activeMigration)
                .build().encode();
        String name = serverName != null ? serverName : config.tls.serverName();
        String key = cacheKey(name, remote);
        SessionTicket ticket = cache != null ? cache.tickets().take(key) : null;
        byte[] token = cache != null ? cache.tokens().take(key) : null;
        TlsSession tls = TlsSession.client(config.tls, name, params, ticket);
        Connection c = new Connection(Side.CLIENT, now, transport, endpointConfig, config.version, tls, remote,
                initialDcid, localCid, initialDcid, true, token != null ? token : EMPTY, allowMtud, random, null);
        c.activeMigration = config.activeMigration;
        c.followPreferredAddress = config.preferredAddress;
        c.sessionCache = cache;
        c.cacheKey = key;
        c.ticket = ticket;
        c.writeCrypto();
        return c;
    }

    /** The cache key for a server: its name without a trailing dot, or its address. */
    static String cacheKey(String serverName, InetSocketAddress remote) {
        if (serverName == null) {
            return remote.getHostString() + ":" + remote.getPort();
        }
        String name = serverName.toLowerCase(Locale.ROOT);
        return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
    }

    /** The ticket a client offered, whose transport parameters 0-RTT uses. */
    private SessionTicket ticket;

    /**
     * Accepts a server connection for a client's first Initial, which the endpoint checked.
     *
     * @param now the current time
     * @param config the server configuration
     * @param endpointConfig the endpoint's settings
     * @param remote the client's address
     * @param version the client's QUIC version
     * @param dcid the Destination Connection ID of the client's Initial, which sets the Initial keys
     * @param clientScid the client's Source Connection ID
     * @param localCid the server's connection ID
     * @param originalDcid the Destination Connection ID of the client's very first Initial (before
     *     any Retry)
     * @param retrySrcCid the Source Connection ID of the Retry this server sent, or null
     * @param addressValidated whether a Retry token proved the client's address
     * @param token the token of the client's Initial, which every later Initial must repeat
     * @param allowMtud whether the socket supports path MTU discovery
     * @param random the source of randomness
     * @return the connection, ready for the datagram that carried the Initial
     */
    static Connection server(long now, ServerConfig config, EndpointConfig endpointConfig, InetSocketAddress remote,
            QuicVersion version, ConnectionId dcid, ConnectionId clientScid, ConnectionId localCid,
            ConnectionId originalDcid, ConnectionId retrySrcCid, boolean addressValidated, byte[] token,
            boolean allowMtud, RandomGenerator random) {
        return server(now, config, endpointConfig, remote, version, dcid, clientScid, localCid, originalDcid,
                retrySrcCid, addressValidated, token, allowMtud, random, null, null);
    }

    /**
     * Accepts a server connection, with a token issuer for the NEW_TOKEN frames it sends.
     *
     * @param tokens the endpoint's token validator, or null to send no NEW_TOKEN frames
     * @param preferredCid the connection ID (sequence number 1) of the configuration's preferred
     *     address, or null to advertise none
     * @see #server(long, ServerConfig, EndpointConfig, InetSocketAddress, QuicVersion, ConnectionId,
     *     ConnectionId, ConnectionId, ConnectionId, ConnectionId, boolean, byte[], boolean,
     *     RandomGenerator)
     */
    static Connection server(long now, ServerConfig config, EndpointConfig endpointConfig, InetSocketAddress remote,
            QuicVersion version, ConnectionId dcid, ConnectionId clientScid, ConnectionId localCid,
            ConnectionId originalDcid, ConnectionId retrySrcCid, boolean addressValidated, byte[] token,
            boolean allowMtud, RandomGenerator random, TokenValidator tokens, ConnectionId preferredCid) {
        TransportParameters.Builder params = localParams(config.transport, endpointConfig.cidLength(), localCid)
                .originalDestinationConnectionId(originalDcid)
                .statelessResetToken(StatelessResetToken.derive(endpointConfig.resetKey, localCid))
                .disableActiveMigration(!config.migration);
        if (preferredCid != null) {
            params.preferredAddress(new PreferredAddress(config.preferredIpv4, config.preferredIpv6, preferredCid,
                    StatelessResetToken.derive(endpointConfig.resetKey, preferredCid)));
        }
        if (retrySrcCid != null) {
            params.retrySourceConnectionId(retrySrcCid);
        }
        TransportParameters local = params.build();
        // RFC 9000 section 7.4.1: no 0-RTT if a limit the client may use in it is smaller now
        TlsSession tls = TlsSession.server(config.tls, local.encode(), remembered -> {
            try {
                return local.allowsResumptionFrom(TransportParameters.decode(remembered, true));
            } catch (QuicException e) {
                return false;
            }
        });
        Connection c = new Connection(Side.SERVER, now, config.transport, endpointConfig, version, tls, remote, dcid,
                localCid, clientScid, addressValidated, token, allowMtud, random, preferredCid);
        c.remoteMayMigrate = config.migration;
        c.retrySrcCid = retrySrcCid;
        c.tokenValidator = tokens;
        c.newTokens = tokens != null ? config.newTokens : 0;
        return c;
    }

    // ---------------------------------------------------------------------------------------
    // Inputs

    /**
     * Processes a datagram from the peer that arrived at the endpoint's default local address.
     *
     * @param now the current time
     * @param from the address it came from
     * @param ecn the ECN codepoint it carried (0 not-ECT, 1 ECT(1), 2 ECT(0), 3 CE)
     * @param datagram the datagram, between its position and limit
     * @see #handleDatagram(long, InetSocketAddress, InetSocketAddress, int, ByteBuffer)
     */
    public void handleDatagram(long now, InetSocketAddress from, int ecn, ByteBuffer datagram) {
        handleDatagram(now, null, from, ecn, datagram);
    }

    /**
     * Processes a datagram from the peer: splits coalesced packets, removes protection, and
     * handles their frames. The connection keeps views of {@code datagram}'s contents.
     *
     * <p>A datagram from an address other than the current path's is dropped, except on a server
     * that allows migration once its handshake is done (the client may be probing a new path, or
     * moving to it), and on a client from the address it probes. A server whose client moves to
     * its preferred address learns it from {@code local}.
     *
     * @param now the current time
     * @param local the local address it arrived at, or null for the endpoint's default
     * @param from the address it came from
     * @param ecn the ECN codepoint it carried (0 not-ECT, 1 ECT(1), 2 ECT(0), 3 CE)
     * @param datagram the datagram, between its position and limit
     */
    public void handleDatagram(long now, InetSocketAddress local, InetSocketAddress from, int ecn,
            ByteBuffer datagram) {
        if (state == State.DRAINED) {
            return;
        }
        if (!from.equals(recovery.path().remote())) {
            // Only a server that allows migration follows its peer, and only after the handshake;
            // a client takes packets only from the server's address and the one it probes
            boolean allowed = side.isServer() ? remoteMayMigrate && state != State.HANDSHAKE
                    : probe != null && from.equals(probe.remote);
            if (!allowed) {
                return;
            }
        }
        boolean wasBlocked = recovery.antiAmplificationBlocked(1);
        int length = datagram.remaining();
        rxFrom = from;
        rxLocal = local;
        rxLength = length;
        ByteBuffer in = datagram.duplicate();
        ConnectionId first = null;
        while (in.hasRemaining() && state != State.DRAINED) {
            int start = in.position();
            ProtectedPacket packet;
            try {
                packet = ProtectedPacket.parse(in, localCidLength);
            } catch (PacketDecodeException e) {
                if (first == null && isStatelessReset(datagram.duplicate().position(start))) {
                    finishPacket(now, ConnectionError.of(ConnectionError.Kind.RESET));
                }
                break;
            }
            if (first == null) {
                first = packet.destinationId();
            } else if (!first.equals(packet.destinationId())) {
                break; // RFC 9000 section 12.2
            }
            try {
                handlePacket(now, packet, ecn);
            } catch (RuntimeException e) {
                break; // unauthenticated input the codecs did not expect: drop the rest
            }
        }
        rxFrom = null;
        rxLocal = null;
        // The bytes count for the anti-amplification limit of the path they came on: the current
        // one, possibly new since this datagram moved the connection there (quinn counts them on
        // the current path whatever their sender)
        if (from.equals(recovery.path().remote())) {
            recovery.onDatagramReceived(length);
        }
        if (wasBlocked) {
            // A loss detection timer the limit kept off may be needed now
            recovery.setLossDetectionTimer(now);
        }
    }

    private boolean isStatelessReset(ByteBuffer bytes) {
        return peerResetToken != null && bytes.remaining() >= StatelessResetToken.MIN_RESET_DATAGRAM
                && (bytes.get(bytes.position()) & PacketHeader.LONG_HEADER_FORM) == 0
                && peerResetToken.matches(bytes);
    }

    private void handlePacket(long now, ProtectedPacket p, int ecn) {
        boolean statelessReset = p.type() == PacketType.ONE_RTT && isStatelessReset(p.bytes());
        switch (p.type()) {
            case VERSION_NEGOTIATION -> {
                handleVersionNegotiation(now, (PacketHeader.VersionNegotiation) p.header());
                return;
            }
            case RETRY -> {
                handleRetry(now, p);
                return;
            }
            case ZERO_RTT -> {
                if (side.isServer() && zeroRttKeys != null) {
                    handleZeroRtt(now, p, ecn);
                }
                return;
            }
            default -> {}
        }
        SpaceId spaceId = SpaceId.of(p.type().level());
        PacketSpace space = recovery.space(spaceId);
        Keys keys = space.keys();
        if (keys == null) {
            if (statelessReset) {
                finishPacket(now, ConnectionError.of(ConnectionError.Kind.RESET));
            }
            return; // keys not yet available, or discarded
        }
        PacketHeader.Numbered header = p.removeHeaderProtection(keys.remote().header(), space.rxPacket());
        long number = header.packetNumber();
        PacketKey key = keys.remote().packet();
        boolean incomingKeyUpdate = false;
        boolean packetPhase = false;
        if (spaceId == SpaceId.DATA) {
            packetPhase = ((PacketHeader.Short) header).keyPhase();
            if (packetPhase != keyPhase) {
                if (prevKeys != null && (prevEndPacket < 0 || number < prevEndPacket)) {
                    key = prevKeys.remote().packet();
                } else {
                    // A key phase mismatch with no update of ours pending: the peer updated
                    incomingKeyUpdate = true;
                    key = nextKeys.remote().packet();
                }
            }
        }
        Packet packet;
        try {
            packet = p.decrypt(key);
        } catch (QuicException e) {
            finishPacket(now, statelessReset ? ConnectionError.of(ConnectionError.Kind.RESET) : ConnectionError.transport(e));
            return;
        }
        if (statelessReset) {
            finishPacket(now, ConnectionError.of(ConnectionError.Kind.RESET));
            return;
        }
        if (packet == null) {
            authenticationFailures++;
            if (authenticationFailures > keys.local().packet().integrityLimit()) {
                finishPacket(now, ConnectionError.transport(new QuicException(QuicException.AEAD_LIMIT_REACHED,
                        "integrity limit violated")));
            }
            return;
        }
        if (spaceId == SpaceId.DATA) {
            if (incomingKeyUpdate && (number <= space.rxPacket() || (prevKeys != null && prevUpdateUnacked))) {
                finishPacket(now, ConnectionError.transport(new QuicException(QuicException.KEY_UPDATE_ERROR,
                        "invalid key update")));
                return;
            }
            if (prevKeys != null && prevEndPacket < 0 && packetPhase == keyPhase) {
                // The peer acknowledged our key update by using the new keys
                prevEndPacket = number;
                recovery.setKeyDiscardTimer(now, SpaceId.DATA);
            }
            if (incomingKeyUpdate) {
                updateKeys(number, true);
                recovery.setKeyDiscardTimer(now, SpaceId.DATA);
                qlog(now, "security:key_updated", "{\"trigger\":\"remote_update\",\"generation\":" + keyUpdates + "}");
            }
        }
        if (state == State.HANDSHAKE && spaceId == SpaceId.DATA) {
            // A server must not process 1-RTT packets before its handshake completes (RFC 9001
            // section 5.7), but keeps a few that overtook the client's Finished
            if (early1rtt.size() < MAX_EARLY_1RTT_PACKETS) {
                early1rtt.add(new EarlyPacket(number, packet, header.destinationId()));
            }
            return;
        }
        if (header instanceof PacketHeader.Initial initial && side.isServer() && state == State.HANDSHAKE
                && !Arrays.equals(initial.token(), token)) {
            return; // every Initial must repeat the first one's token; spoofable, so drop
        }
        boolean wasClosed = isClosed();
        ConnectionError result = processAuthenticated(now, spaceId, number, packet, header, ecn);
        finishPacket(now, result, wasClosed);
        if (state != State.HANDSHAKE && !early1rtt.isEmpty()) {
            List<EarlyPacket> early = new ArrayList<>(early1rtt);
            early1rtt.clear();
            for (EarlyPacket e : early) {
                if (isClosed()) {
                    break;
                }
                boolean closed = isClosed();
                ConnectionError r = processAuthenticated(now, SpaceId.DATA, e.number(), e.packet(),
                        e.packet().header(), 0);
                finishPacket(now, r, closed);
            }
        }
    }

    /** A server's 0-RTT packet: decrypted with the client early traffic keys, in the data space. */
    private void handleZeroRtt(long now, ProtectedPacket p, int ecn) {
        PacketSpace space = recovery.space(SpaceId.DATA);
        PacketHeader.Numbered header = p.removeHeaderProtection(zeroRttKeys.header(), space.rxPacket());
        Packet packet;
        try {
            packet = p.decrypt(zeroRttKeys.packet());
        } catch (QuicException e) {
            finishPacket(now, ConnectionError.transport(e));
            return;
        }
        if (packet == null) {
            authenticationFailures++;
            if (authenticationFailures > zeroRttKeys.packet().integrityLimit()) {
                finishPacket(now, ConnectionError.transport(new QuicException(QuicException.AEAD_LIMIT_REACHED,
                        "integrity limit violated")));
            }
            return;
        }
        boolean wasClosed = isClosed();
        ConnectionError result = processAuthenticated(now, SpaceId.DATA, header.packetNumber(), packet, header, ecn);
        finishPacket(now, result, wasClosed);
    }

    private ConnectionError processAuthenticated(long now, SpaceId spaceId, long number, Packet packet,
            PacketHeader.Numbered header, int ecn) {
        try {
            return processAuthenticatedFrames(now, spaceId, number, packet, header, ecn);
        } catch (RuntimeException e) {
            // A bug, not the peer's fault, but an authenticated packet: close rather than crash
            return ConnectionError.transport(new QuicException(QuicException.INTERNAL_ERROR, String.valueOf(e)));
        }
    }

    private ConnectionError processAuthenticatedFrames(long now, SpaceId spaceId, long number, Packet packet,
            PacketHeader.Numbered header, int ecn) {
        List<Frame> frames;
        try {
            frames = FrameDecoder.decodeAll(packet.payload(), header.type());
        } catch (QuicException e) {
            return ConnectionError.transport(e);
        }
        boolean ackEliciting = false;
        for (Frame f : frames) {
            ackEliciting |= f.isAckEliciting();
        }
        if (!isClosed()) {
            PacketSpace space = recovery.space(spaceId);
            long prevRx = space.rxPacket();
            if (recovery.onPacketReceived(now, spaceId, number, ackEliciting)) {
                return null; // duplicate
            }
            onPacketAuthenticated(now, spaceId, number, prevRx, header, ecn, ackEliciting);
        }
        if (config.qlog != null) {
            qlog(now, "transport:packet_received", "{\"header\":{\"packet_type\":\"" + header.type()
                    + "\",\"packet_number\":" + number + "},\"frames\":" + frames.size() + "}");
        }
        try {
            processDecrypted(now, spaceId, number, header, frames, packet.payload().remaining());
            return null;
        } catch (QuicException e) {
            return ConnectionError.transport(e);
        }
    }

    private void onPacketAuthenticated(long now, SpaceId spaceId, long number, long prevRx,
            PacketHeader.Numbered header, int ecn, boolean ackEliciting) {
        totalAuthedPackets++;
        resetKeepAlive(now);
        recovery.resetIdleTimer(now, spaceId, idleTimeout);
        permitIdleReset = true;
        if (ecn != 0) {
            receivingEcn = true;
            recovery.space(spaceId).onEcnReceived(ecn);
        }
        if (side.isServer() && spaceId == SpaceId.HANDSHAKE && recovery.space(SpaceId.INITIAL).keys() != null) {
            // A server stops sending and processing Initial packets at its first Handshake packet
            recovery.discardSpace(now, SpaceId.INITIAL);
        }
        if (spaceId != SpaceId.DATA && ackEliciting) {
            // In the Initial and Handshake spaces, ACKs must be sent at once
            recovery.space(spaceId).pendingAcks().setImmediateAckRequired();
        }
        if (spaceId == SpaceId.DATA && ackEliciting) {
            nextBundledAckTime = now;
        }
        if (number >= prevRx && header instanceof PacketHeader.Short s) {
            spin = side.isClient() ^ s.spin();
        }
        if (side.isServer() && zeroRttKeys != null && header instanceof PacketHeader.Short
                && !timers.isSet(Timer.KEY_DISCARD)) {
            // Discard 0-RTT keys soon after the first 1-RTT packet, as quinn does
            recovery.setKeyDiscardTimer(now, SpaceId.DATA);
        }
    }

    private void processDecrypted(long now, SpaceId spaceId, long number, PacketHeader.Numbered header,
            List<Frame> frames, int payloadLength) throws QuicException {
        switch (state) {
            case ESTABLISHED -> {
                if (spaceId == SpaceId.DATA) {
                    processPayload(now, number, header, frames, payloadLength);
                } else {
                    processEarlyPayload(now, spaceId, frames, payloadLength);
                }
                return;
            }
            case CLOSED -> {
                for (Frame f : frames) {
                    if (f instanceof Frame.ConnectionClose || f instanceof Frame.ApplicationClose) {
                        state = State.DRAINING;
                        break;
                    }
                }
                return;
            }
            case DRAINING, DRAINED -> {
                return;
            }
            default -> {}
        }
        // Handshake
        switch (header) {
            case PacketHeader.Handshake h -> {
                if (!h.sourceId().equals(remoteHandshakeCid)) {
                    return; // mismatched remote CID
                }
                onPathValidated();
                processEarlyPayload(now, spaceId, frames, payloadLength);
                if (isClosed() || tls.isHandshaking()) {
                    return;
                }
                if (side.isClient()) {
                    TransportParameters params = peerTransportParameters();
                    if (zeroRttEnabled) {
                        if (tls.isEarlyDataAccepted()) {
                            zeroRttAccepted = true;
                            if (rememberedParams != null) {
                                params.validateResumptionFrom(rememberedParams);
                            }
                        } else {
                            zeroRttRejected(now, params);
                        }
                    }
                    handlePeerParams(params);
                    issueFirstCids(now);
                } else {
                    Retransmits pending = recovery.space(SpaceId.DATA).pending();
                    pending.handshakeDone = true;
                    for (int i = 0; i < newTokens; i++) {
                        pending.newTokens.add(remote);
                    }
                    // Confirmed first: discarding the Handshake space rearms loss detection, which
                    // must then cover the application data already in flight
                    confirmHandshake(now);
                    recovery.discardSpace(now, SpaceId.HANDSHAKE);
                }
                events.add(new ConnectionEvent.Connected());
                state = State.ESTABLISHED;
                resetKeepAlive(now);
                qlog(now, "connectivity:connection_state_updated", "{\"new\":\"handshake_complete\"}");
            }
            case PacketHeader.ZeroRtt z -> processPayload(now, number, header, frames, payloadLength);
            case PacketHeader.Initial i -> {
                if (!remoteCidSet) {
                    remoteCids.updateInitialCid(i.sourceId());
                    remoteHandshakeCid = i.sourceId();
                    origRemoteCid = i.sourceId();
                    remoteCidSet = true;
                } else if (!i.sourceId().equals(remoteHandshakeCid)) {
                    return;
                }
                SpaceId starting = highestSpace;
                processEarlyPayload(now, spaceId, frames, payloadLength);
                if (side.isServer() && starting == SpaceId.INITIAL && highestSpace != SpaceId.INITIAL && !isClosed()) {
                    handlePeerParams(peerTransportParameters());
                    issueFirstCids(now);
                }
            }
            default -> {}
        }
    }

    private TransportParameters peerTransportParameters() throws QuicException {
        byte[] encoded = tls.peerTransportParameters();
        if (encoded == null) {
            throw QuicException.tlsAlert(0x6d, "transport parameters missing");
        }
        return TransportParameters.decode(encoded, side.isClient());
    }

    /**
     * The handshake is confirmed (RFC 9001 section 4.1.2). Until now the probe timeout ignored the
     * application data space (RFC 9002 section 6.2.1), so loss detection is armed again: 1-RTT
     * packets sent before confirmation, such as 0-RTT data sent again after a rejection or a
     * request sent as soon as the handshake completed, would otherwise never be probed for, and a
     * lost one would stall its stream until the idle timeout.
     */
    private void confirmHandshake(long now) {
        if (!handshakeConfirmed) {
            handshakeConfirmed = true;
            recovery.setHandshakeConfirmed(true);
            recovery.setLossDetectionTimer(now);
            events.add(new ConnectionEvent.HandshakeConfirmed());
            if (side.isClient() && followPreferredAddress) {
                probePreferredAddress(now);
            }
        }
    }

    /**
     * Probes the server's preferred address of the current path's address family, if it gave one
     * (RFC 9000 section 9.6.1), with the connection ID it gave for it.
     */
    private void probePreferredAddress(long now) {
        PreferredAddress preferred = peerParams.preferredAddress();
        if (preferred == null || state != State.ESTABLISHED) {
            return;
        }
        InetSocketAddress current = recovery.path().remote();
        InetSocketAddress to = current.getAddress() instanceof Inet4Address ? preferred.ipv4() : preferred.ipv6();
        if (to == null || to.equals(current) || to.getPort() == 0 || to.getAddress().isAnyLocalAddress()) {
            return;
        }
        if (remoteCids.peekNext() == null || !remoteCids.peekNext().equals(preferred.connectionId())) {
            return; // the ID for the preferred address is gone already
        }
        startProbe(now, to, recovery.path().local());
    }

    private void startProbe(long now, InetSocketAddress to, InetSocketAddress local) {
        ConnectionId cid = remoteCids.peekNext();
        long pto = recovery.pto(SpaceId.DATA);
        // RFC 9000 section 8.2.4: three times the larger of the current PTO and the new path's,
        // which starts from the initial RTT
        long newPathPto = new RttEstimator(recoveryConfig.initialRtt()).ptoBase()
                + recovery.ackFrequency().maxAckDelayForPto();
        Probe pr = new Probe(to, local, cid, random.nextLong(), now + 3 * Math.max(pto, newPathPto));
        pr.backoff = Math.max(pto, RttEstimator.TIMER_GRANULARITY);
        probe = pr;
        timers.set(Timer.PATH_PROBE, Math.min(pr.deadline, now + pr.backoff));
        qlog(now, "connectivity:path_probe", "{\"remote\":\"" + to + "\",\"local\":\"" + local + "\"}");
    }

    /**
     * Client: starts moving the connection to a new local address (RFC 9000 section 9.1): probes
     * the path from {@code local} to the server's address with PATH_CHALLENGE and a connection ID
     * of the server's not used before, and switches to it when the PATH_RESPONSE arrives ({@link
     * ConnectionEvent.PathUpdated}), or stays if none comes in three PTOs ({@link
     * ConnectionEvent.PathProbeFailed}). Datagrams to send from {@code local} come out of {@link
     * #pollTransmit} with it as their {@linkplain Transmit#source() source}. The congestion and RTT
     * state carry over when only the port changes, and start over otherwise.
     *
     * @param now the current time
     * @param local the new local address
     * @throws IllegalStateException on a server; before the handshake is confirmed; while another
     *     path is probed; when this client or the server disabled active migration; when the
     *     server uses zero-length connection IDs or gave no unused one
     */
    public void probePath(long now, InetSocketAddress local) {
        Objects.requireNonNull(local, "local");
        checkMayMigrate();
        if (remoteCids.peekNext() == null) {
            throw new IllegalStateException("no unused connection ID of the server's");
        }
        startProbe(now, recovery.path().remote(), local);
    }

    /**
     * Client: moves the connection to a new local address at once, without probing the path
     * first, as quinn's {@code local_address_changed} does after its endpoint rebinds: the next
     * packets carry a connection ID of the server's not used before (when the server gave one), and
     * a PING from the new address makes the server follow and validate it. To the server this looks
     * like a NAT rebinding. Some servers never answer {@link #probePath}'s PATH_CHALLENGE on any
     * path (aioquic's queues the response on the probed path and sends only on its active one);
     * this works with them.
     *
     * @param now the current time
     * @param local the new local address
     * @throws IllegalStateException as {@link #probePath} does, except that a server that gave no
     *     unused connection ID is no obstacle
     */
    public void rebind(long now, InetSocketAddress local) {
        Objects.requireNonNull(local, "local");
        checkMayMigrate();
        PathData cur = recovery.path();
        pathCounter++;
        PathData next = cur.sameHosts(cur.remote(), local)
                ? PathData.fromPrevious(cur.remote(), local, cur, pathCounter, now)
                : PathData.create(recoveryConfig, cur.remote(), local, peerMaxUdpPayloadSize(), pathCounter, now);
        next.validated = true;
        recovery.setPath(next, true);
        try {
            updateRemoteCid();
        } catch (QuicException e) {
            finishPacket(now, ConnectionError.transport(e)); // the peer made us retire too many IDs
            return;
        }
        pathChanged(now, next);
        spin = false;
        ping();
        recovery.setLossDetectionTimer(now);
    }

    private void checkMayMigrate() {
        if (side.isServer()) {
            throw new IllegalStateException("only a client migrates");
        }
        if (!activeMigration) {
            throw new IllegalStateException("active migration is disabled");
        }
        if (peerParams.disableActiveMigration()) {
            throw new IllegalStateException("the server disabled active migration");
        }
        if (state != State.ESTABLISHED || !handshakeConfirmed) {
            throw new IllegalStateException("the handshake is not confirmed");
        }
        if (probe != null) {
            throw new IllegalStateException("a path is being probed already");
        }
        if (remoteCids.active().isEmpty()) {
            throw new IllegalStateException("the server uses zero-length connection IDs");
        }
    }

    /**
     * Whether a client is probing a new path.
     *
     * @return true from {@link #probePath} (or the probe of a preferred address) until it ends
     */
    public boolean isProbingPath() {
        return probe != null;
    }

    /**
     * The path packets are sent on.
     *
     * @return the current path
     */
    public PathData path() {
        return recovery.path();
    }

    /**
     * The local address of the current path.
     *
     * @return the address, or null for the endpoint's default
     */
    public InetSocketAddress localAddress() {
        return recovery.path().local();
    }

    /** Processes an Initial or Handshake packet's frames. */
    private void processEarlyPayload(long now, SpaceId spaceId, List<Frame> frames, int payloadLength)
            throws QuicException {
        for (Frame frame : frames) {
            switch (frame) {
                case Frame.Padding p -> {}
                case Frame.Ping p -> {}
                case Frame.Crypto c -> readCrypto(spaceId, c, payloadLength);
                case Frame.Ack a -> recovery.onAckReceived(now, spaceId, a, listener);
                case Frame.ConnectionClose c -> {
                    peerClosed(new ConnectionError(ConnectionError.Kind.CONNECTION_CLOSED, c.errorCode(), c.frameType(),
                            c.reasonPhrase()));
                    return;
                }
                default -> throw new QuicException(QuicException.PROTOCOL_VIOLATION, "illegal frame type in handshake");
            }
        }
        writeCrypto();
    }

    private void peerClosed(ConnectionError reason) {
        error = reason;
        state = State.DRAINING;
    }

    /** Processes a 1-RTT packet's frames. */
    private void processPayload(long now, long number, PacketHeader.Numbered header, List<Frame> frames,
            int payloadLength) throws QuicException {
        PacketSpace data = recovery.space(SpaceId.DATA);
        Retransmits pending = data.pending();
        ConnectionError close = null;
        // A packet of only these frames is a probing packet (RFC 9000 section 9.1), which does
        // not move the connection to the address it came from
        boolean probing = true;
        for (Frame frame : frames) {
            probing &= frame instanceof Frame.Padding || frame instanceof Frame.PathChallenge
                    || frame instanceof Frame.PathResponse || frame instanceof Frame.NewConnectionId;
            switch (frame) {
                case Frame.Padding p -> {}
                case Frame.Ping p -> {}
                case Frame.Crypto c -> readCrypto(SpaceId.DATA, c, payloadLength);
                case Frame.Stream s -> {
                    if (streams.received(s, payloadLength)) {
                        pending.maxData = true;
                    }
                    if (header instanceof PacketHeader.ZeroRtt) {
                        earlyStreams.add(new StreamId(s.streamId()));
                    }
                }
                case Frame.Ack a -> recovery.onAckReceived(now, SpaceId.DATA, a, listener);
                case Frame.ConnectionClose c -> close = new ConnectionError(ConnectionError.Kind.CONNECTION_CLOSED,
                        c.errorCode(), c.frameType(), c.reasonPhrase());
                case Frame.ApplicationClose c -> close = new ConnectionError(ConnectionError.Kind.APPLICATION_CLOSED,
                        c.errorCode(), 0, c.reasonPhrase());
                case Frame.PathChallenge c -> {
                    if (rxFrom == null) {
                        break; // a 1-RTT packet held during the handshake: answered on the path
                    }
                    pathResponses.push(number, c.data(), rxFrom, rxLocal, rxLength);
                    PathData path = recovery.path();
                    if (rxFrom.equals(path.remote()) && Objects.equals(rxLocal, path.local())) {
                        // A PATH_CHALLENGE on the active path may mean an attacker forwards our
                        // packets elsewhere: a non-probing packet takes the connection back here
                        ping();
                    }
                }
                case Frame.PathResponse r -> onPathResponse(now, r.data());
                case Frame.MaxData m -> streams.receivedMaxData(m.maximum());
                case Frame.MaxStreamData m -> streams.receivedMaxStreamData(new StreamId(m.streamId()), m.maximum());
                case Frame.MaxStreams m -> streams.receivedMaxStreams(m.bidirectional() ? Dir.BI : Dir.UNI, m.maximum());
                case Frame.ResetStream r -> {
                    if (streams.receivedReset(r)) {
                        pending.maxData = true;
                    }
                }
                case Frame.DataBlocked d -> {}
                case Frame.StreamDataBlocked d -> streams.receivedStreamDataBlocked(d);
                case Frame.StreamsBlocked b -> streams.receivedStreamsBlocked(b);
                case Frame.StopSending s -> streams.receivedStopSending(s);
                case Frame.RetireConnectionId r -> {
                    LocalCidState.Retirement retirement = localCids.onRetireConnectionId(r.sequence(),
                            header.destinationId(), peerParams.activeConnectionIdLimit());
                    if (retirement.retired() != null) {
                        endpointEvents.add(new EndpointEvent.CidRetired(retirement.retired()));
                    }
                    if (retirement.issueReplacement()) {
                        issueCids(now, 1);
                    }
                }
                case Frame.NewConnectionId n -> {
                    StatelessResetToken t = remoteCids.onNewConnectionId(n, pending);
                    if (t != null) {
                        setResetToken(t);
                    }
                    if (side.isServer() && remoteCids.activeSeq() == 0) {
                        // Switch from the handshake ID at once, so the client can detect our resets
                        updateRemoteCid();
                    }
                }
                case Frame.NewToken t -> {
                    if (side.isServer()) {
                        throw new QuicException(QuicException.PROTOCOL_VIOLATION, "client sent NEW_TOKEN");
                    }
                    if (!t.token().hasRemaining()) {
                        throw new QuicException(QuicException.FRAME_ENCODING_ERROR, "empty NEW_TOKEN");
                    }
                    if (sessionCache != null) {
                        ByteBuffer token = t.token();
                        byte[] copy = new byte[token.remaining()];
                        token.get(copy);
                        sessionCache.tokens().put(cacheKey, copy);
                    }
                }
                case Frame.Datagram d -> {
                    if (datagrams.received(d.data(), config.datagramReceiveBufferSize)) {
                        events.add(new ConnectionEvent.DatagramReceived());
                    }
                }
                case Frame.AckFrequency f -> {
                    if (recovery.ackFrequency().ackFrequencyReceived(f, data.pendingAcks())) {
                        long deadline = data.pendingAcks().maxAckDelayTimeout(recovery.ackFrequency().maxAckDelay());
                        if (deadline != NanoClock.NONE) {
                            timers.set(Timer.MAX_ACK_DELAY, deadline);
                        }
                    }
                }
                case Frame.ImmediateAck i -> data.pendingAcks().setImmediateAckRequired();
                case Frame.HandshakeDone h -> {
                    if (side.isServer()) {
                        throw new QuicException(QuicException.PROTOCOL_VIOLATION, "client sent HANDSHAKE_DONE");
                    }
                    confirmHandshake(now);
                    if (recovery.space(SpaceId.HANDSHAKE).keys() != null) {
                        recovery.discardSpace(now, SpaceId.HANDSHAKE);
                    }
                }
            }
        }
        // Stream credit freed by acknowledged FINs and resets
        streams.queueMaxStreamId(pending);
        if (close != null) {
            peerClosed(close);
            closePending = true; // one CONNECTION_CLOSE in answer, as RFC 9000 section 10.2.2 allows
            return;
        }
        PathData path = recovery.path();
        if (side.isServer() && !probing && rxFrom != null && number == data.rxPacket()
                && (!rxFrom.equals(path.remote()) || !Objects.equals(rxLocal, path.local()))) {
            // The client moved: a non-probing packet newer than any other from a new address
            migrate(now, rxFrom, rxLocal);
        }
    }

    /**
     * Follows the client to a new path (quinn's {@code migrate}, RFC 9000 section 9.3): new
     * congestion and RTT state unless only the ports changed, validation of the new path with the
     * previous one kept for going back, and an unused connection ID of the client's.
     */
    private void migrate(long now, InetSocketAddress to, InetSocketAddress local) throws QuicException {
        PathData cur = recovery.path();
        pathCounter++;
        PathData next = cur.sameHosts(to, local) ? PathData.fromPrevious(to, local, cur, pathCounter, now)
                : PathData.create(recoveryConfig, to, local, peerMaxUdpPayloadSize(), pathCounter, now);
        if (to.equals(cur.remote())) {
            // Only the local address changed: the client moved to our preferred address, from an
            // address already validated
            next.validated = cur.validated;
            recovery.setPath(next, true);
            pathChanged(now, next);
            return;
        }
        next.challenge = random.nextLong();
        next.hasChallenge = true;
        next.challengePending = true;
        long prevPto = recovery.pto(SpaceId.DATA);
        // Do not lose the last validated path while an unvalidated one is replaced
        boolean keepPrevious = !cur.hasChallenge;
        recovery.setPath(next, keepPrevious);
        if (keepPrevious) {
            cur.challenge = random.nextLong();
            cur.hasChallenge = true;
            cur.challengePending = true;
            prevPathCid = remoteCids.active(); // before the update below
        }
        timers.set(Timer.PATH_VALIDATION, now + 3 * Math.max(recovery.pto(SpaceId.DATA), prevPto));
        pathChanged(now, next);
        // Break linkability, if the client gave us another connection ID (RFC 9000 section 9.5)
        updateRemoteCid();
        spin = false;
    }

    /** The current path changed: datagrams that no longer fit go, and the application is told. */
    private void pathChanged(long now, PathData path) {
        remote = path.remote();
        int max = maxDatagramSize();
        if (max >= 0) {
            datagrams.dropOversized(max);
        }
        events.add(new ConnectionEvent.PathUpdated(path.remote(), path.local()));
        qlog(now, "connectivity:path_updated", "{\"remote\":\"" + path.remote() + "\",\"local\":\""
                + path.local() + "\",\"validated\":" + path.validated + "}");
    }

    private int peerMaxUdpPayloadSize() {
        return (int) Math.min(peerParams.maxUdpPayloadSize(), MtuDiscoveryConfig.MAX_UDP_PAYLOAD);
    }

    /**
     * A PATH_RESPONSE: the end of the current path's validation, or of a client's probe. It is
     * matched by its data alone, whatever path it came on: "A PATH_RESPONSE frame received on any
     * network path validates the path on which the PATH_CHALLENGE was sent" (RFC 9000 section
     * 8.2.2). quinn also requires it to come from the new path; a peer may answer on its active
     * path instead.
     */
    private void onPathResponse(long now, long token) throws QuicException {
        PathData path = recovery.path();
        if (path.hasChallenge && token == path.challenge) {
            timers.stop(Timer.PATH_VALIDATION);
            path.hasChallenge = false;
            path.challengePending = false;
            path.validated = true;
            PathData prev = recovery.prevPath();
            if (prev != null) {
                prev.hasChallenge = false;
                prev.challengePending = false;
            }
            qlog(now, "connectivity:path_validated", "{\"remote\":\"" + path.remote() + "\"}");
            return;
        }
        if (probe != null && token == probe.challenge) {
            switchToProbe(now);
        }
        // else a response to an older challenge, or a forged one: ignored
    }

    /** A client's probe succeeded: the new path becomes the current one, with a fresh connection ID. */
    private void switchToProbe(long now) throws QuicException {
        Probe pr = probe;
        probe = null;
        timers.stop(Timer.PATH_PROBE);
        PathData cur = recovery.path();
        pathCounter++;
        PathData next = cur.sameHosts(pr.remote, pr.local)
                ? PathData.fromPrevious(pr.remote, pr.local, cur, pathCounter, now)
                : PathData.create(recoveryConfig, pr.remote, pr.local, peerMaxUdpPayloadSize(), pathCounter, now);
        next.validated = true;
        recovery.setPath(next, true);
        if (!remoteCids.active().equals(pr.cid)) {
            updateRemoteCid(); // to the ID the probe used, unused on the old path
        } else {
            setResetToken(peerResetToken); // the same token, from the new address
        }
        pathChanged(now, next);
        spin = false;
        recovery.setLossDetectionTimer(now);
    }

    private void readCrypto(SpaceId spaceId, Frame.Crypto frame, int payloadLength) throws QuicException {
        SpaceId expected = state != State.HANDSHAKE ? SpaceId.DATA
                : highestSpace == SpaceId.INITIAL ? SpaceId.INITIAL : SpaceId.HANDSHAKE;
        PacketSpace space = recovery.space(spaceId);
        Assembler stream = space.cryptoStream();
        long end = frame.offset() + frame.data().remaining();
        if (spaceId.ordinal() < expected.ordinal() && end > stream.bytesRead()) {
            throw new QuicException(QuicException.PROTOCOL_VIOLATION, "new data at unexpected encryption level");
        }
        if (end - stream.bytesRead() > config.cryptoBufferSize) {
            throw new QuicException(QuicException.CRYPTO_BUFFER_EXCEEDED, "too much out-of-order CRYPTO data");
        }
        if (!stream.insert(frame.offset(), frame.data(), Math.max(payloadLength, frame.data().remaining()))) {
            throw new QuicException(QuicException.INTERNAL_ERROR, "too many gaps in the CRYPTO stream");
        }
        EncryptionLevel level = switch (spaceId) {
            case INITIAL -> EncryptionLevel.INITIAL;
            case HANDSHAKE -> EncryptionLevel.HANDSHAKE;
            case DATA -> EncryptionLevel.ONE_RTT;
        };
        for (Chunk chunk; (chunk = stream.read(Integer.MAX_VALUE, true)) != null; ) {
            tls.readHandshake(level, chunk.bytes().duplicate());
        }
        for (SessionTicket t; (t = tls.pollNewTicket()) != null; ) {
            if (sessionCache != null) {
                sessionCache.tickets().put(cacheKey, t);
            }
        }
        if (!handshakeDataReady && tls.negotiatedAlpn() != null) {
            handshakeDataReady = true;
            events.add(new ConnectionEvent.HandshakeDataReady());
        }
    }

    /** Installs new keys and queues the handshake bytes TLS produced, per level. */
    private void writeCrypto() {
        for (Secrets s; (s = tls.nextSecrets()) != null; ) {
            installSecrets(s);
        }
        for (EncryptionLevel level : new EncryptionLevel[] {EncryptionLevel.INITIAL, EncryptionLevel.HANDSHAKE,
                EncryptionLevel.ONE_RTT}) {
            byte[] out = tls.writeHandshake(level);
            if (out.length == 0) {
                continue;
            }
            PacketSpace space = recovery.space(SpaceId.of(level));
            long offset = space.cryptoOffset();
            if (side.isClient() && level == EncryptionLevel.INITIAL && offset == 0) {
                clientHello = out;
            }
            space.advanceCryptoOffset(out.length);
            space.pending().crypto.addLast(new Frame.Crypto(offset, ByteBuffer.wrap(out)));
        }
    }

    private void installSecrets(Secrets s) {
        boolean isServer = side.isServer();
        // 0-RTT secrets have the client's direction only
        Keys keys = s.level() == EncryptionLevel.ZERO_RTT ? null : Keys.fromSecrets(s, isServer, version);
        KeyLog keyLog = config.keyLog;
        byte[] clientRandom = tls.clientRandom();
        switch (s.level()) {
            case HANDSHAKE -> {
                recovery.space(SpaceId.HANDSHAKE).setKeys(keys);
                highestSpace = SpaceId.HANDSHAKE;
                if (keyLog != null && clientRandom != null) {
                    keyLog.log("CLIENT_HANDSHAKE_TRAFFIC_SECRET", clientRandom, s.client());
                    keyLog.log("SERVER_HANDSHAKE_TRAFFIC_SECRET", clientRandom, s.server());
                }
            }
            case ONE_RTT -> {
                recovery.space(SpaceId.DATA).setKeys(keys);
                highestSpace = SpaceId.DATA;
                if (isClient()) {
                    zeroRttKeys = null; // 1-RTT keys replace them
                }
                // Derive the next generation now, so a spoofed key update costs no key derivation
                nextKeys = keys.update(tls.nextOneRttSecrets(), isServer, version);
                if (keyLog != null && clientRandom != null) {
                    keyLog.log("CLIENT_TRAFFIC_SECRET_0", clientRandom, s.client());
                    keyLog.log("SERVER_TRAFFIC_SECRET_0", clientRandom, s.server());
                }
            }
            case ZERO_RTT -> {
                zeroRttKeys = DirectionalKeys.fromSecret(s.suite(), s.client(), version);
                zeroRttEnabled = true;
                if (keyLog != null && clientRandom != null) {
                    keyLog.log("CLIENT_EARLY_TRAFFIC_SECRET", clientRandom, s.client());
                }
                if (isClient()) {
                    initZeroRtt();
                } else {
                    zeroRttAccepted = true;
                }
            }
            default -> {}
        }
    }

    private boolean isClient() {
        return side.isClient();
    }

    /**
     * A client about to send 0-RTT data: until the server's own parameters arrive, it keeps within
     * the ones its ticket remembers (RFC 9000 section 7.4.1).
     */
    private void initZeroRtt() {
        byte[] encoded = ticket != null ? ticket.transportParameters() : null;
        TransportParameters remembered = null;
        try {
            remembered = encoded != null ? TransportParameters.decode(encoded, true).forZeroRtt() : null;
        } catch (QuicException e) {
            remembered = null;
        }
        if (remembered == null) {
            zeroRttKeys = null; // no limits to keep within: send nothing early
            return;
        }
        rememberedParams = remembered;
        streams.setParams(remembered);
        recovery.setPeerParams(remembered);
        peerParams = remembered;
    }

    /**
     * The server rejected 0-RTT: forget the 0-RTT packets without counting them lost, queue their
     * control frames again, and send the stream data again in 1-RTT if it fits the server's limits.
     */
    private void zeroRttRejected(long now, TransportParameters params) {
        Retransmits pending = recovery.space(SpaceId.DATA).pending();
        for (SentPacket p : recovery.discardZeroRttPackets(now)) {
            if (p.retransmits() != null) {
                pending.merge(p.retransmits());
            }
        }
        if (!streams.retransmitAfterZeroRttRejected(params)) {
            // The local streams are gone: their frames must not go out
            pending.resetStream.clear();
            pending.stopSending.clear();
            pending.maxStreamData.clear();
            pending.streamDataBlocked.clear();
        }
        zeroRttKeys = null;
    }

    private void handleRetry(long now, ProtectedPacket p) {
        if (side.isServer() || state != State.HANDSHAKE || retryReceived || totalAuthedPackets > 0) {
            return;
        }
        byte[] retryToken = p.token();
        if (retryToken == null || retryToken.length == 0 || !p.verifyRetry(remoteCids.active())
                || p.sourceId().equals(initialDcid)) {
            return; // RFC 9000 section 17.2.5.2: discard
        }
        retryReceived = true;
        ConnectionId newCid = p.sourceId();
        retrySrcCid = newCid;
        remoteCids.updateInitialCid(newCid);
        remoteHandshakeCid = newCid;
        token = retryToken;
        PacketSpace initial = recovery.space(SpaceId.INITIAL);
        recovery.discardSpace(now, SpaceId.INITIAL);
        initial.setKeys(Keys.initial(version, newCid, false));
        initial.pending().crypto.clear();
        initial.pending().crypto.addLast(new Frame.Crypto(0, ByteBuffer.wrap(clientHello)));
        if (zeroRttKeys != null) {
            // The server dropped the 0-RTT packets with the first Initial: send it all again, still
            // as 0-RTT data, since the ClientHello and so the early keys stay the same
            Retransmits pending = recovery.space(SpaceId.DATA).pending();
            for (SentPacket sent : recovery.discardZeroRttPackets(now)) {
                if (sent.retransmits() != null) {
                    pending.merge(sent.retransmits());
                }
            }
            streams.retransmitAllForZeroRtt();
        }
        remoteCidSet = false;
        qlog(now, "transport:packet_received", "{\"header\":{\"packet_type\":\"retry\"}}");
    }

    private void handleVersionNegotiation(long now, PacketHeader.VersionNegotiation vn) {
        if (side.isServer() || state != State.HANDSHAKE || totalAuthedPackets > 0) {
            return;
        }
        if (vn.versions().contains(version.wireValue())) {
            return; // RFC 9000 section 6.2: ignore one listing our version
        }
        finishPacket(now, ConnectionError.of(ConnectionError.Kind.VERSION_MISMATCH));
    }

    private void finishPacket(long now, ConnectionError result) {
        finishPacket(now, result, isClosed());
    }

    /** Applies the state change an error causes (quinn's {@code finish_packet}). */
    private void finishPacket(long now, ConnectionError result, boolean wasClosed) {
        boolean wasDrained = state == State.DRAINED;
        if (result != null) {
            if (result.kind() == ConnectionError.Kind.RESET && (state == State.DRAINING || state == State.DRAINED)) {
                state = State.DRAINED; // keep the original close reason
            } else {
                if (!errorReported) {
                    error = result;
                }
                switch (result.kind()) {
                    case RESET -> state = State.DRAINED;
                    case VERSION_MISMATCH -> state = State.DRAINING;
                    case TRANSPORT_ERROR -> {
                        if (result.code() == QuicException.AEAD_LIMIT_REACHED) {
                            state = State.DRAINED;
                        } else if (!isClosed()) {
                            closeReason = new Close(false, result.code(), result.frameType(), result.reason());
                            state = State.CLOSED;
                        }
                    }
                    default -> {}
                }
            }
        }
        if (!wasClosed && isClosed()) {
            closeCommon();
            if (state != State.DRAINED) {
                setCloseTimer(now);
            }
            qlog(now, "connectivity:connection_closed", "{\"reason\":\"" + jsonEscape(String.valueOf(error)) + "\"}");
        }
        if (!wasDrained && state == State.DRAINED) {
            endpointEvents.add(new EndpointEvent.Drained());
            timers.stop(Timer.CLOSE);
        }
        if (state == State.CLOSED) {
            closePending = true; // answer packets with CONNECTION_CLOSE
        }
    }

    private void handlePeerParams(TransportParameters params) throws QuicException {
        params.authenticateConnectionIds(side.isClient(), origRemoteCid, initialDcid, retrySrcCid);
        streams.setParams(params);
        long peerIdle = params.maxIdleTimeout() * 1_000_000L;
        long localIdle = config.maxIdleTimeout.toNanos();
        idleTimeout = localIdle == 0 ? peerIdle : peerIdle == 0 ? localIdle : Math.min(localIdle, peerIdle);
        recovery.setPeerParams(params);
        if (params.preferredAddress() != null) {
            try {
                remoteCids.insert(new Frame.NewConnectionId(1, 0, params.preferredAddress().connectionId(),
                        params.preferredAddress().statelessResetToken()));
            } catch (RemoteCidQueue.CidInsertException e) {
                throw new QuicException(QuicException.PROTOCOL_VIOLATION, "bad preferred address connection ID");
            }
        }
        peerParams = params;
        if (side.isClient() && params.statelessResetToken() != null) {
            setResetToken(params.statelessResetToken());
        }
    }

    private void setResetToken(StatelessResetToken t) {
        if (t == null) {
            return;
        }
        peerResetToken = t;
        endpointEvents.add(new EndpointEvent.ResetToken(recovery.path().remote(), t));
    }

    private void issueFirstCids(long now) {
        issueCids(now, localCids.initialIssueCount(peerParams.activeConnectionIdLimit()));
    }

    private void issueCids(long now, long count) {
        List<IssuedCid> ids = localCids.issue(now, count);
        Retransmits pending = recovery.space(SpaceId.DATA).pending();
        for (IssuedCid id : ids) {
            pending.newCids.add(id);
            endpointEvents.add(new EndpointEvent.CidIssued(id.id()));
        }
        long t = localCids.nextTimeout();
        if (t != NanoClock.NONE && (!timers.isSet(Timer.PUSH_NEW_CID) || timers.get(Timer.PUSH_NEW_CID) <= now)) {
            timers.set(Timer.PUSH_NEW_CID, t);
        }
    }

    private void updateRemoteCid() throws QuicException {
        RemoteCidQueue.Retired retired = remoteCids.next();
        if (retired == null) {
            return;
        }
        recovery.space(SpaceId.DATA).pending().retireCids(retired.start(), retired.end());
        setResetToken(retired.resetToken());
    }

    private void onPathValidated() {
        recovery.setAddressValidated();
    }

    private void updateKeys(long endPacket, boolean remoteInitiated) {
        boolean isServer = side.isServer();
        Keys newer = nextKeys.update(tls.nextOneRttSecrets(), isServer, version);
        keyPhaseSize = Math.max(0, newer.local().packet().confidentialityLimit() - KEY_UPDATE_MARGIN);
        PacketSpace data = recovery.space(SpaceId.DATA);
        Keys old = data.keys();
        data.setKeys(nextKeys);
        data.sentWithKeys = 0;
        nextKeys = newer;
        prevKeys = old;
        prevEndPacket = endPacket;
        prevUpdateUnacked = remoteInitiated;
        keyPhase = !keyPhase;
        keyUpdates++;
    }

    /**
     * Handles expired timers: loss detection and probes, idle timeout, the end of closing and
     * draining, key discard, connection ID rotation, delayed ACKs and keep-alives. Calling it early
     * or twice does nothing.
     *
     * @param now the current time
     */
    public void handleTimeout(long now) {
        for (Timer timer : Timer.values()) {
            if (!timers.isExpired(timer, now)) {
                continue;
            }
            timers.stop(timer);
            switch (timer) {
                case CLOSE -> {
                    if (state != State.DRAINED) {
                        state = State.DRAINED;
                        endpointEvents.add(new EndpointEvent.Drained());
                    }
                }
                case IDLE -> kill(now, ConnectionError.of(ConnectionError.Kind.TIMED_OUT));
                case KEEP_ALIVE -> ping();
                case LOSS_DETECTION -> {
                    long lostBefore = recovery.lostPackets();
                    recovery.onLossDetectionTimeout(now, listener);
                    if (config.qlog != null && recovery.lostPackets() != lostBefore) {
                        qlog(now, "recovery:packet_lost", "{\"count\":" + (recovery.lostPackets() - lostBefore) + "}");
                    }
                }
                case KEY_DISCARD -> {
                    prevKeys = null;
                    if (side.isServer() && state != State.HANDSHAKE) {
                        zeroRttKeys = null;
                    }
                }
                case PATH_VALIDATION -> {
                    // The client did not answer on its new path: back to the previous one
                    PathData prev = recovery.prevPath();
                    if (prev != null) {
                        recovery.setPath(prev, false);
                        recovery.setPrevPath(null);
                        recovery.setLossDetectionTimer(now);
                        pathChanged(now, prev);
                    }
                    PathData path = recovery.path();
                    path.hasChallenge = false;
                    path.challengePending = false;
                }
                case PATH_PROBE -> {
                    Probe pr = probe;
                    if (pr == null) {
                        break;
                    }
                    if (now - pr.deadline >= 0) {
                        probe = null;
                        events.add(new ConnectionEvent.PathProbeFailed(pr.remote, pr.local));
                        qlog(now, "connectivity:path_probe_failed", "{\"remote\":\"" + pr.remote + "\"}");
                    } else {
                        pr.pending = true; // send the PATH_CHALLENGE again
                        pr.backoff = Math.min(pr.backoff * 2, pr.deadline - now);
                        timers.set(Timer.PATH_PROBE, Math.min(pr.deadline, now + pr.backoff));
                    }
                }
                case PACING -> {}
                case PUSH_NEW_CID -> {
                    boolean push = localCids.onCidTimeout();
                    if (!isClosed() && push) {
                        issueCids(now, 1);
                    }
                    long t = localCids.nextTimeout();
                    if (t != NanoClock.NONE) {
                        timers.set(Timer.PUSH_NEW_CID, t);
                    }
                }
                case MAX_ACK_DELAY -> recovery.onMaxAckDelayTimeout();
            }
        }
    }

    /**
     * When {@link #handleTimeout} should next be called.
     *
     * @return the time, or {@link NanoClock#NONE} if no timer is set
     */
    public long pollTimeout() {
        return timers.nextTimeout();
    }

    // ---------------------------------------------------------------------------------------
    // Outputs

    /**
     * Takes the next application event: handshake progress, stream events, received datagrams,
     * and finally {@link ConnectionEvent.ConnectionLost}.
     *
     * @return the event, or null if there is none
     */
    public ConnectionEvent pollEvent() {
        ConnectionEvent e = events.poll();
        if (e != null) {
            return e;
        }
        StreamEvent s = streams.poll();
        if (s != null) {
            return new ConnectionEvent.Stream(s);
        }
        if (error != null && !errorReported && isClosed()) {
            errorReported = true;
            return new ConnectionEvent.ConnectionLost(error);
        }
        return null;
    }

    /**
     * Takes the next event for the endpoint: connection IDs to route or forget, reset tokens, and
     * {@link EndpointEvent.Drained} once the connection is gone.
     *
     * @return the event, or null if there is none
     */
    public EndpointEvent pollEndpointEvent() {
        return endpointEvents.poll();
    }

    /**
     * Builds datagrams to send: first a PATH_CHALLENGE on the previous path or on a path the
     * client probes, and PATH_RESPONSEs for other paths, each in a datagram of its own; then, to
     * the current path's address, coalesced packets of each encryption level, Initial datagrams
     * padded to 1200 bytes, within the congestion window, the pacing rate and the
     * anti-amplification limit; then path MTU probes.
     *
     * @param now the current time
     * @param maxDatagrams the most datagrams to return
     * @return the datagrams, possibly none; each a new buffer from position 0 to its length, with
     *     where to send it
     */
    public List<Transmit> pollTransmit(long now, int maxDatagrams) {
        List<Transmit> out = new ArrayList<>();
        PathData path = recovery.path();
        if (state == State.ESTABLISHED && recovery.space(SpaceId.DATA).keys() != null) {
            pollPathTransmits(now, maxDatagrams, out);
        }
        boolean appLimited = false;
        while (out.size() < maxDatagrams) {
            boolean[] limited = new boolean[1];
            ByteBuffer d = buildDatagram(now, limited);
            if (d == null) {
                // Each round is one of quinn's poll_transmit calls, which its caller repeats until
                // one builds nothing: that last call, unless the congestion window or the pacer
                // stopped it, leaves the connection application limited
                appLimited = !limited[0];
                break;
            }
            out.add(new Transmit(d, path.remote(), path.local()));
        }
        if (out.size() < maxDatagrams && state == State.ESTABLISHED) {
            ByteBuffer mtuProbe = buildMtuProbe(now);
            if (mtuProbe != null) {
                out.add(new Transmit(mtuProbe, path.remote(), path.local()));
            }
        }
        recovery.setAppLimited(appLimited);
        return out;
    }

    /**
     * The datagrams of path validation that do not go on the current path, each on its own and
     * not tracked for loss: the PATH_CHALLENGE for the previous path (quinn's {@code
     * send_path_challenge}), with the connection ID used there; a client's PATH_CHALLENGE on the
     * path it probes, with an unused connection ID; and PATH_RESPONSEs for other paths (quinn's
     * off-path responses), no larger than three times the datagram that carried the challenge.
     */
    private void pollPathTransmits(long now, int maxDatagrams, List<Transmit> out) {
        PathData prev = recovery.prevPath();
        if (prev != null && prev.challengePending && out.size() < maxDatagrams) {
            prev.challengePending = false;
            long token = prev.challenge;
            out.add(new Transmit(buildPathPacket(prevPathCid, MIN_INITIAL_SIZE, f -> new Frame.PathChallenge(token).encode(f)),
                    prev.remote(), prev.local()));
        }
        Probe pr = probe;
        if (pr != null && pr.pending && out.size() < maxDatagrams) {
            pr.pending = false;
            out.add(new Transmit(buildPathPacket(pr.cid, MIN_INITIAL_SIZE, f -> new Frame.PathChallenge(pr.challenge).encode(f)),
                    pr.remote, pr.local));
        }
        PathData path = recovery.path();
        while (out.size() < maxDatagrams) {
            PathResponses.PathResponse r = pathResponses.popOffPath(path.remote(), path.local());
            if (r == null) {
                break;
            }
            // RFC 9000 section 8.2.2: padded to 1200 bytes, unless that would amplify
            int size = (int) Math.min(MIN_INITIAL_SIZE, 3L * r.received());
            if (size < min1rttDatagram()) {
                continue;
            }
            out.add(new Transmit(buildPathPacket(remoteCids.active(), size, f -> new Frame.PathResponse(r.token()).encode(f)),
                    r.remote(), r.local()));
        }
    }

    /**
     * The smallest 1-RTT datagram worth sending: a short header, a PATH_CHALLENGE or PATH_RESPONSE
     * (or a small ACK) and the tag, which is what an unvalidated path may be limited to.
     */
    private int min1rttDatagram() {
        return 1 + remoteCids.active().length() + 4 + 9 + PacketKey.TAG_LENGTH;
    }

    /** A 1-RTT packet of path validation frames, alone in a datagram padded to {@code size}; not tracked. */
    private ByteBuffer buildPathPacket(ConnectionId dcid, int size, java.util.function.Consumer<ByteBuffer> frames) {
        PacketSpace space = recovery.space(SpaceId.DATA);
        ByteBuffer buf = ByteBuffer.allocate(size);
        PacketBuilder builder = new PacketBuilder(buf, size);
        long pn = recovery.nextPacketNumber(SpaceId.DATA);
        int pnLength = PacketNumber.encodedLength(pn, space.largestAckedPacket());
        ByteBuffer out = builder.begin(new PacketHeader.Short(spinEnabled ? spin : random.nextBoolean(), keyPhase,
                dcid, pn, pnLength), space.keys().local());
        frames.accept(out);
        builder.finish(size);
        return builder.datagram();
    }

    private ByteBuffer buildDatagram(long now, boolean[] congestionLimited) {
        if (state == State.DRAINED) {
            return null;
        }
        boolean close = false;
        if (state == State.CLOSED || state == State.DRAINING) {
            if (!closePending) {
                return null;
            }
            close = true;
        }
        long budget = recovery.antiAmplificationBudget();
        // During the handshake a datagram may need to carry a padded Initial; after it, a server
        // on an unvalidated new path sends what the limit allows (RFC 9000 section 8.2.1)
        if (budget < (state == State.HANDSHAKE ? MIN_INITIAL_SIZE : min1rttDatagram())) {
            return null;
        }
        int mtu = recovery.mtud().currentMtu();
        int limit = (int) Math.min(mtu, budget);
        if (!close) {
            for (SpaceId id : SPACES) {
                PacketSpace s = recovery.space(id);
                if (s.keys() != null) {
                    s.maybeQueueProbe(false, id == SpaceId.DATA && canSend1rtt(limit), streams);
                }
            }
        }
        boolean congestionBlocked = !close && recovery.isCongestionBlocked(limit);
        boolean pacingChecked = false;
        boolean pacingBlocked = false;

        ByteBuffer buf = ByteBuffer.allocate(limit);
        PacketBuilder builder = new PacketBuilder(buf, limit);
        OpenPacket open = null;
        int used = 0;
        boolean padDatagram = false;
        long lastNumber = -1;
        for (SpaceId id : SPACES) {
            PacketSpace space = recovery.space(id);
            DirectionalKeys keys = space.keys() != null ? space.keys().local()
                    : id == SpaceId.DATA && side.isClient() && !close ? zeroRttKeys : null;
            if (keys == null) {
                continue;
            }
            if (close) {
                if (id.ordinal() > highestSpace.ordinal()) {
                    break;
                }
                if (open != null) {
                    if (limit - (currentFrames.position() + PacketKey.TAG_LENGTH) < MIN_PACKET_SPACE) {
                        break;
                    }
                    used = finish(now, builder, open, 0);
                    lastNumber = open.number;
                    open = null;
                }
                open = begin(now, id, builder, keys, used);
                open.track = false;
                ByteBuffer frames = currentFrames;
                writeCloseFrames(now, id, space, frames);
                if (id == SpaceId.INITIAL && side.isClient()) {
                    padDatagram = true;
                }
                if (id == highestSpace) {
                    closePending = false;
                    break;
                }
                continue;
            }
            boolean probe = space.lossProbes() > 0;
            PacketSpace.Sendable can = space.canSend(streams);
            boolean other = can.other() || (id == SpaceId.DATA && canSend1rtt(limit));
            if (!can.acks() && !other) {
                continue;
            }
            boolean dataAllowed = false;
            if (other) {
                if (probe) {
                    dataAllowed = true;
                } else if (congestionBlocked) {
                    congestionLimited[0] = true;
                } else {
                    if (!pacingChecked) {
                        pacingChecked = true;
                        // No pacing before the first RTT sample: the initial RTT guess would spread
                        // the handshake flight over tens of milliseconds
                        pacingBlocked = recovery.rtt().hasSample() && recovery.pacingDelay(now, limit) != NanoClock.NONE;
                    }
                    if (pacingBlocked) {
                        congestionLimited[0] = true;
                    } else {
                        dataAllowed = true;
                    }
                }
            }
            if (!dataAllowed && !can.acks()) {
                continue;
            }
            if (open != null) {
                if (limit - (currentFrames.position() + PacketKey.TAG_LENGTH) < MIN_PACKET_SPACE) {
                    break; // no room to coalesce another packet
                }
                used = finish(now, builder, open, 0);
                lastNumber = open.number;
                open = null;
            }
            if (side.isClient() && id == SpaceId.HANDSHAKE && recovery.space(SpaceId.INITIAL).keys() != null) {
                // A client stops sending and processing Initial packets when it sends its first
                // Handshake packet
                recovery.discardSpace(now, SpaceId.INITIAL);
            }
            if (id == SpaceId.DATA) {
                if (handshakeConfirmed && space.sentWithKeys >= keyPhaseSize && prevKeys == null) {
                    forceKeyUpdate(); // routine key update before the key wears out
                    keys = space.keys().local();
                }
                prevUpdateUnacked = false;
            }
            open = begin(now, id, builder, keys, used);
            populate(now, open, space, currentFrames, dataAllowed);
            if (currentFrames.position() == open.payloadStart && used == 0) {
                // Nothing fit after all: abandon the datagram (and its packet number) rather
                // than send PADDING, which the caller would be asked for again and again
                currentFrames = null;
                return null;
            }
            if (probe && dataAllowed) {
                space.probeSent();
            }
            if (id == SpaceId.INITIAL && (side.isClient() || open.ackEliciting)) {
                padDatagram = true;
            }
            if (open.pathFrames) {
                padDatagram = true; // RFC 9000 section 8.2.1, within the anti-amplification limit
            }
            if (id == SpaceId.DATA) {
                break; // a short header packet ends the datagram
            }
        }
        if (close) {
            closePending = false; // one CONNECTION_CLOSE datagram per occasion
        }
        if (open == null) {
            return null;
        }
        int end = finish(now, builder, open, padDatagram ? Math.min(MIN_INITIAL_SIZE, limit) : 0);
        lastNumber = open.number;
        ByteBuffer datagram = builder.datagram();
        recovery.onDatagramSent(now, end, lastNumber);
        return datagram;
    }

    /** The frames buffer of the packet {@link #begin} started. */
    private ByteBuffer currentFrames;

    private OpenPacket begin(long now, SpaceId id, PacketBuilder builder, DirectionalKeys keys, int start) {
        PacketSpace space = recovery.space(id);
        long pn = recovery.nextPacketNumber(id);
        int pnLength = PacketNumber.encodedLength(pn, space.largestAckedPacket());
        ConnectionId dcid = remoteCids.active();
        boolean zeroRtt = id == SpaceId.DATA && space.keys() == null;
        PacketHeader.Numbered header = switch (id) {
            case INITIAL -> new PacketHeader.Initial(version, dcid, handshakeCid,
                    side.isClient() ? token : EMPTY, pn, pnLength);
            case HANDSHAKE -> new PacketHeader.Handshake(version, dcid, handshakeCid, pn, pnLength);
            case DATA -> zeroRtt ? new PacketHeader.ZeroRtt(version, dcid, handshakeCid, pn, pnLength)
                    : new PacketHeader.Short(spinEnabled ? spin : random.nextBoolean(), keyPhase, dcid, pn, pnLength);
        };
        OpenPacket p = new OpenPacket();
        p.space = id;
        p.number = pn;
        p.zeroRtt = zeroRtt;
        currentFrames = builder.begin(header, keys);
        p.start = start;
        p.payloadStart = currentFrames.position();
        return p;
    }

    /** Finishes the open packet, padding the datagram to {@code minSize}; returns its end. */
    private int finish(long now, PacketBuilder builder, OpenPacket p, int minSize) {
        int end = builder.finish(minSize);
        currentFrames = null;
        if (!p.track) {
            return end;
        }
        boolean padded = minSize > 0;
        int size = end - p.start;
        SentPacket sent = new SentPacket(now, (p.ackEliciting || padded) ? size : 0,
                p.ackEliciting, p.largestAcked, p.sent, p.streamFrames);
        recovery.onPacketSent(now, p.space, p.number, sent);
        if (p.largestAcked >= 0) {
            recovery.onAcksSent(p.space);
            if (p.space == SpaceId.DATA) {
                nextBundledAckTime = now + recovery.rtt().get() + recovery.ackFrequency().peerMaxAckDelay()
                        + RttEstimator.TIMER_GRANULARITY;
            }
        }
        if (p.ackEliciting) {
            if (permitIdleReset) {
                recovery.resetIdleTimer(now, p.space, idleTimeout);
            }
            permitIdleReset = false;
            resetKeepAlive(now);
        }
        if (config.qlog != null) {
            qlog(now, "transport:packet_sent", "{\"header\":{\"packet_type\":\"" + p.space + "\",\"packet_number\":"
                    + p.number + "},\"ack_eliciting\":" + p.ackEliciting + "}");
        }
        return end;
    }

    private void writeCloseFrames(long now, SpaceId id, PacketSpace space, ByteBuffer out) {
        int limit = out.limit();
        if (!space.pendingAcks().ranges().isEmpty()) {
            Frame.Ack ack = space.pendingAcks().ackFrame(now, config.ackDelayExponent, null);
            if (ack != null && out.position() + ack.encodedLength() + 64 <= limit) {
                ack.encode(out);
            }
        }
        int budget = limit - out.position();
        if (state == State.DRAINING) {
            Frame.ConnectionClose.of(QuicException.NO_ERROR, 0, "").encode(out, budget);
        } else if (closeReason.application() && id != SpaceId.DATA) {
            // An application close must not reveal anything before the handshake is done
            Frame.ConnectionClose.of(QuicException.APPLICATION_ERROR, 0, "").encode(out, budget);
        } else if (closeReason.application()) {
            Frame.ApplicationClose.of(closeReason.code(), closeReason.reason()).encode(out, budget);
        } else {
            Frame.ConnectionClose.of(closeReason.code(), closeReason.frameType(), closeReason.reason())
                    .encode(out, budget);
        }
    }

    /** Fills a packet's frames (quinn's {@code populate_packet}). */
    private void populate(long now, OpenPacket p, PacketSpace space, ByteBuffer out, boolean dataAllowed) {
        int limit = out.limit();
        int payloadStart = out.position();
        Retransmits pending = space.pending();
        space.pendingAcks().maybeAckNonEliciting();
        if (dataAllowed) {
            if (p.space == SpaceId.DATA && pending.handshakeDone && !p.zeroRtt) {
                out.put((byte) 0x1e);
                pending.handshakeDone = false;
                p.sent.handshakeDone = true;
                p.ackEliciting = true;
            }
            if (space.pingPending()) {
                out.put((byte) 0x01);
                space.setPingPending(false);
                p.ackEliciting = true;
            }
            if (space.immediateAckPending()) {
                out.put((byte) 0x1f);
                space.setImmediateAckPending(false);
                p.ackEliciting = true;
            }
        }
        if (space.pendingAcks().canSend() && !p.zeroRtt) {
            writeAck(now, p, space, out, limit);
        }
        if (!dataAllowed) {
            return;
        }
        // CRYPTO
        while (out.position() + CRYPTO_SIZE_BOUND < limit && !p.zeroRtt) {
            Frame.Crypto frame = pending.crypto.pollFirst();
            if (frame == null) {
                break;
            }
            ByteBuffer data = frame.data();
            int n = Frame.Crypto.encode(out, frame.offset(), data, Math.min(limit - out.position(), (1 << 14) - 1));
            if (n <= 0) {
                pending.crypto.addFirst(frame);
                break;
            }
            p.sent.crypto.addLast(new Frame.Crypto(frame.offset(), frame.data().limit(n)));
            p.ackEliciting = true;
            if (data.hasRemaining()) {
                pending.crypto.addFirst(new Frame.Crypto(frame.offset() + n, data.slice()));
            }
        }
        if (p.space != SpaceId.DATA) {
            return;
        }
        int before = out.position();
        streams.writeControlFrames(out, pending, p.sent, limit);
        p.ackEliciting |= out.position() > before;
        // NEW_CONNECTION_ID
        while (!pending.newCids.isEmpty() && !p.zeroRtt) {
            IssuedCid c = pending.newCids.get(0);
            long retirePriorTo = localCids.retirePriorTo();
            if (c.sequence() < retirePriorTo || !localCids.activeCids().containsKey(c.sequence())) {
                pending.newCids.remove(0); // retired since
                continue;
            }
            Frame.NewConnectionId f = new Frame.NewConnectionId(c.sequence(), retirePriorTo, c.id(), c.resetToken());
            if (out.position() + f.encodedLength() > limit) {
                break;
            }
            f.encode(out);
            pending.newCids.remove(0);
            p.sent.newCids.add(c);
            p.ackEliciting = true;
        }
        // RETIRE_CONNECTION_ID
        while (!pending.retireCids.isEmpty() && !p.zeroRtt) {
            Frame.RetireConnectionId f = new Frame.RetireConnectionId(pending.retireCids.get(0));
            if (out.position() + f.encodedLength() > limit) {
                break;
            }
            f.encode(out);
            p.sent.retireCids.add(pending.retireCids.remove(0));
            p.ackEliciting = true;
        }
        // NEW_TOKEN: a fresh token each time, for the path it was meant for (RFC 9000 section 8.1.3)
        while (!pending.newTokens.isEmpty() && !p.zeroRtt) {
            InetSocketAddress path = pending.newTokens.get(0);
            if (tokenValidator == null || !path.equals(recovery.path().remote())) {
                pending.newTokens.remove(0);
                continue;
            }
            Frame.NewToken f = new Frame.NewToken(ByteBuffer.wrap(tokenValidator.validationToken(path.getAddress())));
            if (out.position() + f.encodedLength() > limit) {
                break;
            }
            f.encode(out);
            p.sent.newTokens.add(pending.newTokens.remove(0));
            p.ackEliciting = true;
        }
        PathData path = recovery.path();
        // PATH_CHALLENGE with every packet on a path being validated, as quinn sends it, though
        // only once in a packet of its own
        if (path.hasChallenge && out.position() + 9 <= limit && !p.zeroRtt) {
            new Frame.PathChallenge(path.challenge).encode(out);
            path.challengePending = false;
            p.ackEliciting = true;
            p.pathFrames = true;
        }
        // PATH_RESPONSE on the current path
        if (out.position() + 9 <= limit && !p.zeroRtt) {
            PathResponses.PathResponse r = pathResponses.popOnPath(path.remote(), path.local());
            if (r != null) {
                new Frame.PathResponse(r.token()).encode(out);
                p.ackEliciting = true;
                p.pathFrames = true;
            }
        }
        // DATAGRAM
        while (out.position() + DatagramState.SIZE_BOUND < limit && datagrams.write(out, limit)) {
            p.ackEliciting = true;
        }
        // STREAM
        p.streamFrames = streams.writeStreamFrames(out, limit, config.sendFairness);
        p.ackEliciting |= !p.streamFrames.isEmpty();
        // An ACK rides along with other frames once in a while
        if (out.position() > payloadStart && p.largestAcked < 0 && !p.zeroRtt && nextBundledAckTime != NanoClock.NONE
                && nextBundledAckTime <= now && space.pendingAcks().canSendWithOtherFrames()) {
            writeAck(now, p, space, out, limit);
        }
    }

    private void writeAck(long now, OpenPacket p, PacketSpace space, ByteBuffer out, int limit) {
        Frame.Ack ack = space.pendingAcks().ackFrame(now, config.ackDelayExponent,
                receivingEcn ? space.ecnCounters() : null);
        if (ack == null || out.position() + ack.encodedLength() > limit) {
            return;
        }
        ack.encode(out);
        p.largestAcked = ack.largest();
    }

    private boolean canSend1rtt(int limit) {
        int frameSpace = limit - (1 + remoteCids.active().length() + 4 + PacketKey.TAG_LENGTH);
        PathData path = recovery.path();
        return streams.canSendStreamData() || path.challengePending
                || pathResponses.hasOnPath(path.remote(), path.local()) || datagrams.canSend(frameSpace);
    }

    private ByteBuffer buildMtuProbe(long now) {
        PacketSpace space = recovery.space(SpaceId.DATA);
        if (space.keys() == null || !recovery.path().validated) {
            return null; // and no probes beyond the anti-amplification limit of a new path
        }
        int size = recovery.mtud().pollTransmit(now, recovery.peekPacketNumber(SpaceId.DATA));
        if (size < 0) {
            return null;
        }
        ByteBuffer buf = ByteBuffer.allocate(size);
        PacketBuilder builder = new PacketBuilder(buf, size);
        OpenPacket p = begin(now, SpaceId.DATA, builder, space.keys().local(), 0);
        currentFrames.put((byte) 0x01); // a PING padded to the probe size
        p.ackEliciting = true;
        int end = finish(now, builder, p, size);
        recovery.onDatagramSent(now, end, p.number);
        return builder.datagram();
    }

    // ---------------------------------------------------------------------------------------
    // Application control

    /**
     * Closes the connection (RFC 9000 section 10.2): sends CONNECTION_CLOSE with an application
     * error code, then waits three PTOs in the closing state before {@link EndpointEvent.Drained}.
     * Data not yet acknowledged is abandoned.
     *
     * @param now the current time
     * @param code the application error code
     * @param reason the reason phrase
     */
    public void close(long now, long code, String reason) {
        if (isClosed()) {
            return;
        }
        closeCommon();
        setCloseTimer(now);
        closeReason = new Close(true, code, 0, reason == null ? "" : reason);
        closePending = true;
        state = State.CLOSED;
        if (error == null) {
            error = new ConnectionError(ConnectionError.Kind.LOCALLY_CLOSED, code, 0, closeReason.reason());
        }
        qlog(now, "connectivity:connection_closed", "{\"owner\":\"local\",\"application_code\":" + code + "}");
    }

    private void kill(long now, ConnectionError reason) {
        closeCommon();
        error = reason;
        if (state != State.DRAINED) {
            state = State.DRAINED;
            endpointEvents.add(new EndpointEvent.Drained());
        }
        qlog(now, "connectivity:connection_closed", "{\"reason\":\"" + reason.kind() + "\"}");
    }

    private void closeCommon() {
        timers.stopAll();
        recovery.close();
        streams.onConnectionClosed();
    }

    private void setCloseTimer(long now) {
        timers.set(Timer.CLOSE, now + 3 * recovery.pto(highestSpace));
    }

    /** Queues a PING in the highest space with keys, to elicit an acknowledgement. */
    public void ping() {
        recovery.space(highestSpace).setPingPending(true);
    }

    /**
     * Starts a key update (RFC 9001 section 6) now, rather than when the key's packet budget runs
     * out. Ignored before the handshake is confirmed or while the previous update is unconfirmed.
     *
     * @return true if the update started
     */
    public boolean forceKeyUpdate() {
        if (state != State.ESTABLISHED || !handshakeConfirmed || prevKeys != null) {
            return false;
        }
        updateKeys(-1, false);
        return true;
    }

    private void resetKeepAlive(long now) {
        if (config.keepAliveInterval != null && state == State.ESTABLISHED) {
            timers.set(Timer.KEEP_ALIVE, now + config.keepAliveInterval.toNanos());
        }
    }

    // ---------------------------------------------------------------------------------------
    // Streams

    /**
     * Opens a stream.
     *
     * @param dir the directionality
     * @return the stream, or null if the peer's stream limit is reached (wait for {@link
     *     StreamEvent.Available}) or the connection is closed
     */
    public StreamId openStream(Dir dir) {
        if (isClosed()) {
            return null;
        }
        return streams.open(dir);
    }

    /**
     * Accepts a stream the peer opened.
     *
     * @param dir the directionality
     * @return the stream, or null if none is waiting (wait for {@link StreamEvent.Opened})
     */
    public StreamId acceptStream(Dir dir) {
        return streams.accept(dir);
    }

    /**
     * Writes stream data, copying as much as flow control and the send window allow.
     *
     * @param id the stream
     * @param data the bytes; the position advances past those taken
     * @return the number of bytes taken, at least 1 unless {@code data} is empty
     * @throws StreamException {@code BLOCKED} if nothing could be taken (wait for {@link
     *     StreamEvent.Writable}), {@code STOPPED} after STOP_SENDING, {@code CLOSED_STREAM} if the
     *     stream is not writable or the connection is closed
     */
    public int write(StreamId id, ByteBuffer data) throws StreamException {
        if (isClosed()) {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
        return streams.write(id, data, recovery.space(SpaceId.DATA).pending());
    }

    /**
     * Finishes a stream's sending side: a FIN follows the data written.
     *
     * @param id the stream
     * @throws StreamException {@code STOPPED} after STOP_SENDING, {@code CLOSED_STREAM} if already
     *     finished or reset
     */
    public void finish(StreamId id) throws StreamException {
        if (isClosed()) {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
        streams.finish(id);
    }

    /**
     * Abandons a stream's sending side with RESET_STREAM.
     *
     * @param id the stream
     * @param errorCode the application error code
     * @throws StreamException {@code CLOSED_STREAM} if already reset or gone
     */
    public void resetStream(StreamId id, long errorCode) throws StreamException {
        streams.reset(id, errorCode, recovery.space(SpaceId.DATA).pending());
    }

    /**
     * Reads stream data in order.
     *
     * @param id the stream
     * @param dst where to put the bytes
     * @return the number of bytes read, or -1 at the end of the stream
     * @throws StreamException {@code BLOCKED} if no data is available yet (wait for {@link
     *     StreamEvent.Readable}), {@code RESET} with the code if the peer reset the stream, {@code
     *     CLOSED_STREAM} if it was stopped or is unknown
     */
    public int read(StreamId id, ByteBuffer dst) throws StreamException {
        if (finishedReads.contains(id)) {
            return -1;
        }
        if (!dst.hasRemaining()) {
            return 0;
        }
        int total = 0;
        Chunks chunks = streams.read(id, true, recovery.space(SpaceId.DATA).pending());
        try {
            while (dst.hasRemaining()) {
                Chunk chunk;
                try {
                    chunk = chunks.next(dst.remaining());
                } catch (StreamException e) {
                    if (e.kind() == StreamException.Kind.BLOCKED && total > 0) {
                        break;
                    }
                    throw e;
                }
                if (chunk == null) {
                    if (total > 0) {
                        finishedReads.add(id);
                        return total;
                    }
                    return -1;
                }
                dst.put(chunk.bytes().duplicate());
                total += chunk.length();
            }
        } finally {
            chunks.close();
        }
        return total;
    }

    /**
     * Forgets a stream whose end of data {@link #read} reported, once the application no longer
     * reads it.
     *
     * @param id the stream
     */
    public void releaseRead(StreamId id) {
        finishedReads.remove(id);
    }

    /**
     * Asks the peer to stop sending on a stream (STOP_SENDING); unread data is discarded.
     *
     * @param id the stream
     * @param errorCode the application error code
     * @throws StreamException {@code CLOSED_STREAM} if the stream is gone or already stopped
     */
    public void stopSending(StreamId id, long errorCode) throws StreamException {
        finishedReads.remove(id);
        streams.stop(id, errorCode, recovery.space(SpaceId.DATA).pending());
    }

    /**
     * Whether the peer sent STOP_SENDING for a stream.
     *
     * @param id the stream
     * @return the error code, or -1
     * @throws StreamException {@code CLOSED_STREAM} if the stream's sending side is gone
     */
    public long stopped(StreamId id) throws StreamException {
        return streams.stopped(id);
    }

    /**
     * The state of a stream's sending side.
     *
     * @param id the stream
     * @return the state, or null once released
     */
    public SendState sendState(StreamId id) {
        return streams.sendState(id);
    }

    /**
     * Sets a stream's send priority; higher goes first.
     *
     * @param id the stream
     * @param priority the priority
     * @throws StreamException {@code CLOSED_STREAM} if the stream's sending side is gone
     */
    public void setPriority(StreamId id, int priority) throws StreamException {
        streams.setPriority(id, priority);
    }

    /**
     * The number of streams with unacknowledged outgoing data.
     *
     * @return the count; 0 once everything written has been delivered
     */
    public int sendStreams() {
        return streams.sendStreams();
    }

    // ---------------------------------------------------------------------------------------
    // Datagrams

    /**
     * Queues an unreliable datagram (RFC 9221). The oldest queued datagrams are dropped if the send
     * buffer is full.
     *
     * @param data the payload, copied
     * @throws IllegalStateException if datagrams are disabled here or not accepted by the peer
     * @throws IllegalArgumentException if the payload is larger than {@link #maxDatagramSize()}
     */
    public void sendDatagram(ByteBuffer data) {
        if (config.datagramReceiveBufferSize == 0) {
            throw new IllegalStateException("datagrams are disabled");
        }
        int max = maxDatagramSize();
        if (max < 0) {
            throw new IllegalStateException("the peer does not accept datagrams");
        }
        if (data.remaining() > Math.min(max, config.datagramSendBufferSize)) {
            throw new IllegalArgumentException("datagram of " + data.remaining() + " bytes exceeds " + max);
        }
        ByteBuffer copy = ByteBuffer.allocate(data.remaining()).put(data).flip();
        datagrams.send(copy, config.datagramSendBufferSize);
    }

    /**
     * Takes a received datagram.
     *
     * @return the payload, or null if none is waiting
     */
    public ByteBuffer receiveDatagram() {
        return datagrams.recv();
    }

    /**
     * The largest datagram payload {@link #sendDatagram} takes now, which depends on the path MTU
     * and the peer's {@code max_datagram_frame_size}.
     *
     * @return bytes, or -1 if the peer does not accept datagrams (or has not said yet)
     */
    public int maxDatagramSize() {
        long peerMax = peerParams.maxDatagramFrameSize();
        if (peerMax == 0) {
            return -1;
        }
        int overhead = 1 + remoteCids.active().length() + 4 + PacketKey.TAG_LENGTH;
        long pathMax = recovery.mtud().currentMtu() - overhead - DatagramState.SIZE_BOUND;
        return (int) Math.max(0, Math.min(peerMax - DatagramState.SIZE_BOUND, pathMax));
    }

    // ---------------------------------------------------------------------------------------
    // State and statistics

    /**
     * Which side this is.
     *
     * @return client or server
     */
    public Side side() {
        return side;
    }

    /**
     * The peer's address.
     *
     * @return the address
     */
    public InetSocketAddress remoteAddress() {
        return remote;
    }

    /**
     * The QUIC version in use.
     *
     * @return the version
     */
    public QuicVersion version() {
        return version;
    }

    /**
     * Whether the handshake is still in progress.
     *
     * @return true until the handshake completes or the connection closes
     */
    public boolean isHandshaking() {
        return state == State.HANDSHAKE;
    }

    /**
     * Whether the TLS handshake resumed a session from a ticket.
     *
     * @return true once known to be resumed: on a client after the ServerHello, on a server after
     *     the ClientHello
     */
    public boolean isResumed() {
        return tls.isResumed();
    }

    /**
     * Whether a client may send 0-RTT data now: it offered a ticket that allows it, and the
     * handshake has not completed. Stream data written now goes out in 0-RTT packets.
     *
     * @return true while 0-RTT keys are in use on a client
     */
    public boolean isZeroRtt() {
        return side.isClient() && zeroRttKeys != null && state == State.HANDSHAKE;
    }

    /**
     * Whether 0-RTT was attempted: offered by this client, or accepted by this server.
     *
     * @return true if 0-RTT keys were installed
     */
    public boolean zeroRttAttempted() {
        return zeroRttEnabled;
    }

    /**
     * Whether the server accepted 0-RTT data. A client knows once its handshake completes (false
     * before); a server knows from the ClientHello.
     *
     * @return true if accepted
     */
    public boolean earlyDataAccepted() {
        return zeroRttAccepted;
    }

    /**
     * Server: whether a stream the client opened carried data in 0-RTT packets, which an attacker
     * may have replayed. Data that arrives after the handshake completes is not replayable.
     *
     * @param id the stream
     * @return true if any of its data arrived as early data
     */
    public boolean receivedEarlyData(StreamId id) {
        return earlyStreams.contains(id);
    }

    /**
     * Whether the TLS handshake is complete: for a server, once it has verified the client's
     * Finished, which proves the client is live and so its early data was not replayed by others.
     *
     * @return true when complete
     */
    public boolean isHandshakeComplete() {
        return tls.isHandshakeComplete();
    }

    /**
     * Whether the handshake is confirmed (RFC 9001 section 4.1.2): on a client once HANDSHAKE_DONE
     * arrives, on a server once its handshake completes. Migration waits for it.
     *
     * @return true once confirmed
     */
    public boolean isHandshakeConfirmed() {
        return handshakeConfirmed;
    }

    /**
     * Whether the connection is established: the handshake completed and it is not closing.
     *
     * @return true when streams can be used
     */
    public boolean isEstablished() {
        return state == State.ESTABLISHED;
    }

    /**
     * Whether the connection is closing, draining or drained.
     *
     * @return true once closed for any reason
     */
    public boolean isClosed() {
        return state == State.CLOSED || state == State.DRAINING || state == State.DRAINED;
    }

    /**
     * Whether the connection is gone, so the endpoint may forget it.
     *
     * @return true once drained
     */
    public boolean isDrained() {
        return state == State.DRAINED;
    }

    /**
     * Why the connection closed.
     *
     * @return the reason, or null while it is open
     */
    public ConnectionError closeReason() {
        return isClosed() ? error : null;
    }

    /**
     * The application protocol agreed with ALPN.
     *
     * @return the protocol, or null until known
     */
    public String alpn() {
        return tls.negotiatedAlpn();
    }

    /**
     * The server name: the one a client connects to, or the client's SNI on a server.
     *
     * @return the name, or null
     */
    public String serverName() {
        return tls.serverName();
    }

    /**
     * The peer's certificate chain, end-entity first.
     *
     * @return the chain; empty until received or if the peer sent none
     */
    public List<X509Certificate> peerCertificates() {
        return tls.peerCertificates();
    }

    /**
     * The TLS session, for its negotiated parameters and exporter.
     *
     * @return the session
     */
    public TlsSession tlsSession() {
        return tls;
    }

    /**
     * The Destination Connection ID of the client's first Initial packet: chosen by the client, or
     * after a Retry, the Retry's Source Connection ID. A server connection is created for it.
     *
     * @return the ID
     */
    public ConnectionId initialDcid() {
        return initialDcid;
    }

    /**
     * The local connection ID used during the handshake.
     *
     * @return the ID
     */
    public ConnectionId handshakeCid() {
        return handshakeCid;
    }

    /**
     * The connection ID packets to the peer carry now.
     *
     * @return the ID
     */
    public ConnectionId remoteCid() {
        return remoteCids.active();
    }

    /**
     * The sequence number of the peer's connection ID in use.
     *
     * @return the sequence number
     */
    public long remoteCidSequence() {
        return remoteCids.activeSeq();
    }

    /**
     * The smoothed RTT.
     *
     * @return nanoseconds
     */
    public long rtt() {
        return recovery.rtt().get();
    }

    /**
     * The congestion window.
     *
     * @return bytes
     */
    public long congestionWindow() {
        return recovery.congestion().window();
    }

    /**
     * The current path MTU.
     *
     * @return the largest UDP payload sent
     */
    public int currentMtu() {
        return recovery.mtud().currentMtu();
    }

    /**
     * The negotiated idle timeout.
     *
     * @return nanoseconds, or 0 for none
     */
    public long idleTimeout() {
        return idleTimeout;
    }

    /**
     * Key updates so far, initiated by either side.
     *
     * @return the count
     */
    public long keyUpdates() {
        return keyUpdates;
    }

    /**
     * The current 1-RTT key phase bit.
     *
     * @return the key phase
     */
    public boolean keyPhase() {
        return keyPhase;
    }

    /**
     * The loss recovery state, with its statistics.
     *
     * @return the recovery state
     */
    public Recovery recovery() {
        return recovery;
    }

    /**
     * The peer's transport parameters.
     *
     * @return the parameters; the defaults until received
     */
    public TransportParameters peerParams() {
        return peerParams;
    }

    /**
     * The local connection IDs the peer may use.
     *
     * @return the IDs by sequence number
     */
    public java.util.Map<Long, ConnectionId> localCids() {
        return localCids.activeCids();
    }

    /** Retires the local IDs below {@code v} and issues replacements, as a test hook. */
    void rotateLocalCid(long v, long now) {
        issueCids(now, localCids.assignRetireSeq(v));
    }

    LocalCidState localCidState() {
        return localCids;
    }

    StreamsState streamsState() {
        return streams;
    }

    TimerTable timers() {
        return timers;
    }

    @Override
    public String toString() {
        return "Connection[" + side + " " + logId + " " + state + " " + remote + "]";
    }

    private void qlog(long now, String name, String data) {
        QlogSink sink = config.qlog;
        if (sink != null) {
            sink.event(logId, now, name, data);
        }
    }

    private static String jsonEscape(String s) {
        StringBuilder b = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') {
                b.append('\\').append(c);
            } else if (c < 0x20) {
                b.append(String.format("\\u%04x", (int) c));
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }
}
