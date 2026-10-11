/*
 * Ported from quinn-proto src/connection/mod.rs (Connection: poll_transmit, handle_event,
 * handle_timeout, close, the handshake state machine in process_decrypted_packet,
 * process_early_payload and process_payload, read_crypto, write_crypto, populate_packet, key
 * update, spin bit, connection ID handling), src/connection/packet_builder.rs and
 * src/connection/packet_crypto.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.Secrets;
import io.github.mahmoudimus.quic.StatelessResetToken;
import io.github.mahmoudimus.quic.congestion.RttEstimator;
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
import io.github.mahmoudimus.quic.params.TransportParameters;
import io.github.mahmoudimus.quic.tls.TlsSession;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
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
 * <p>Not supported: 0-RTT and session resumption, connection migration and path validation (packets
 * from another address are dropped; PATH_CHALLENGE is answered on the current path), NEW_TOKEN
 * tokens (received ones are ignored), and sending ACK_FREQUENCY.
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
    private final InetSocketAddress remote;

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
    private long pathResponse;
    private boolean pathResponsePending;

    private Connection(Side side, long now, TransportConfig config, EndpointConfig endpointConfig,
            QuicVersion version, TlsSession tls, InetSocketAddress remote, ConnectionId initialDcid,
            ConnectionId localCid, ConnectionId remoteCid, boolean addressValidated, byte[] token,
            boolean allowMtud, RandomGenerator random) {
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
        this.recovery = new Recovery(side, config.recoveryConfig(allowMtud), timers, random, now);
        recovery.setSendingEcn(false); // the socket layer cannot mark ECN
        if (addressValidated) {
            recovery.setAddressValidated();
        }
        recovery.space(SpaceId.INITIAL).setKeys(Keys.initial(version, initialDcid, side.isServer()));
        this.streams = new StreamsState(side, config.maxConcurrentUniStreams, config.maxConcurrentBidiStreams,
                config.sendWindow, config.receiveWindow, config.streamReceiveWindow);
        this.listener = Recovery.Listener.forStreams(streams);
        this.localCids = new LocalCidState(endpointConfig.cidGenerator, endpointConfig.resetKey, now, localCid);
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
        TransportConfig transport = config.transport;
        byte[] params = localParams(transport, endpointConfig.cidLength(), localCid).build().encode();
        TlsSession tls = serverName != null ? TlsSession.client(config.tls, serverName, params)
                : TlsSession.client(config.tls, params);
        Connection c = new Connection(Side.CLIENT, now, transport, endpointConfig, config.version, tls, remote,
                initialDcid, localCid, initialDcid, true, EMPTY, allowMtud, random);
        c.writeCrypto();
        return c;
    }

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
        TransportParameters.Builder params = localParams(config.transport, endpointConfig.cidLength(), localCid)
                .originalDestinationConnectionId(originalDcid)
                .statelessResetToken(StatelessResetToken.derive(endpointConfig.resetKey, localCid))
                .disableActiveMigration(true);
        if (retrySrcCid != null) {
            params.retrySourceConnectionId(retrySrcCid);
        }
        TlsSession tls = TlsSession.server(config.tls, params.build().encode());
        Connection c = new Connection(Side.SERVER, now, config.transport, endpointConfig, version, tls, remote, dcid,
                localCid, clientScid, addressValidated, token, allowMtud, random);
        c.retrySrcCid = retrySrcCid;
        return c;
    }

    // ---------------------------------------------------------------------------------------
    // Inputs

    /**
     * Processes a datagram from the peer: splits coalesced packets, removes protection, and
     * handles their frames. The connection keeps views of {@code datagram}'s contents.
     *
     * @param now the current time
     * @param from the address it came from; datagrams from other addresses are dropped
     * @param ecn the ECN codepoint it carried (0 not-ECT, 1 ECT(1), 2 ECT(0), 3 CE)
     * @param datagram the datagram, between its position and limit
     */
    public void handleDatagram(long now, InetSocketAddress from, int ecn, ByteBuffer datagram) {
        if (state == State.DRAINED) {
            return;
        }
        if (!remote.equals(from)) {
            return; // no migration: a client never follows, and the server forbids it
        }
        boolean wasBlocked = recovery.antiAmplificationBlocked(1);
        int length = datagram.remaining();
        recovery.onDatagramReceived(length);
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
                return; // no 0-RTT
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
                    handlePeerParams(peerTransportParameters());
                    issueFirstCids(now);
                } else {
                    recovery.space(SpaceId.DATA).pending().handshakeDone = true;
                    recovery.discardSpace(now, SpaceId.HANDSHAKE);
                    confirmHandshake();
                }
                events.add(new ConnectionEvent.Connected());
                state = State.ESTABLISHED;
                resetKeepAlive(now);
                qlog(now, "connectivity:connection_state_updated", "{\"new\":\"handshake_complete\"}");
            }
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

    private void confirmHandshake() {
        if (!handshakeConfirmed) {
            handshakeConfirmed = true;
            recovery.setHandshakeConfirmed(true);
            events.add(new ConnectionEvent.HandshakeConfirmed());
        }
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
        for (Frame frame : frames) {
            switch (frame) {
                case Frame.Padding p -> {}
                case Frame.Ping p -> {}
                case Frame.Crypto c -> readCrypto(SpaceId.DATA, c, payloadLength);
                case Frame.Stream s -> {
                    if (streams.received(s, payloadLength)) {
                        pending.maxData = true;
                    }
                }
                case Frame.Ack a -> recovery.onAckReceived(now, SpaceId.DATA, a, listener);
                case Frame.ConnectionClose c -> close = new ConnectionError(ConnectionError.Kind.CONNECTION_CLOSED,
                        c.errorCode(), c.frameType(), c.reasonPhrase());
                case Frame.ApplicationClose c -> close = new ConnectionError(ConnectionError.Kind.APPLICATION_CLOSED,
                        c.errorCode(), 0, c.reasonPhrase());
                case Frame.PathChallenge c -> {
                    pathResponse = c.data();
                    pathResponsePending = true;
                }
                case Frame.PathResponse r -> {} // no path validation of ours
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
                    // Tokens would only help 0-RTT and resumption, which are not supported
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
                    if (recovery.space(SpaceId.HANDSHAKE).keys() != null) {
                        recovery.discardSpace(now, SpaceId.HANDSHAKE);
                    }
                    confirmHandshake();
                }
            }
        }
        // Stream credit freed by acknowledged FINs and resets
        streams.queueMaxStreamId(pending);
        if (close != null) {
            peerClosed(close);
            closePending = true; // one CONNECTION_CLOSE in answer, as RFC 9000 section 10.2.2 allows
        }
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
        Keys keys = Keys.fromSecrets(s, isServer, version);
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
                // Derive the next generation now, so a spoofed key update costs no key derivation
                nextKeys = keys.update(tls.nextOneRttSecrets(), isServer, version);
                if (keyLog != null && clientRandom != null) {
                    keyLog.log("CLIENT_TRAFFIC_SECRET_0", clientRandom, s.client());
                    keyLog.log("SERVER_TRAFFIC_SECRET_0", clientRandom, s.server());
                }
            }
            default -> {} // no 0-RTT
        }
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
        peerResetToken = t;
        endpointEvents.add(new EndpointEvent.ResetToken(remote, t));
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
                case KEY_DISCARD -> prevKeys = null;
                case PATH_VALIDATION, PACING -> {}
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
     * Builds datagrams to send to {@link #remoteAddress()}: coalesced packets of each encryption
     * level, Initial datagrams padded to 1200 bytes, within the congestion window, the pacing rate
     * and the anti-amplification limit; then path MTU probes.
     *
     * @param now the current time
     * @param maxDatagrams the most datagrams to return
     * @return the datagrams, possibly none; each a new buffer from position 0 to its length
     */
    public List<ByteBuffer> pollTransmit(long now, int maxDatagrams) {
        List<ByteBuffer> out = new ArrayList<>();
        boolean congestionLimited = false;
        while (out.size() < maxDatagrams) {
            boolean[] limited = new boolean[1];
            ByteBuffer d = buildDatagram(now, limited);
            congestionLimited |= limited[0];
            if (d == null) {
                break;
            }
            out.add(d);
        }
        if (out.size() < maxDatagrams && state == State.ESTABLISHED) {
            ByteBuffer probe = buildMtuProbe(now);
            if (probe != null) {
                out.add(probe);
            }
        }
        recovery.setAppLimited(out.isEmpty() && !congestionLimited);
        return out;
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
        if (budget < MIN_INITIAL_SIZE) {
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
            Keys keys = space.keys();
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
                    keys = space.keys();
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
        int end = finish(now, builder, open, padDatagram ? MIN_INITIAL_SIZE : 0);
        lastNumber = open.number;
        ByteBuffer datagram = builder.datagram();
        recovery.onDatagramSent(now, end, lastNumber);
        return datagram;
    }

    /** The frames buffer of the packet {@link #begin} started. */
    private ByteBuffer currentFrames;

    private OpenPacket begin(long now, SpaceId id, PacketBuilder builder, Keys keys, int start) {
        PacketSpace space = recovery.space(id);
        long pn = recovery.nextPacketNumber(id);
        int pnLength = PacketNumber.encodedLength(pn, space.largestAckedPacket());
        ConnectionId dcid = remoteCids.active();
        PacketHeader.Numbered header = switch (id) {
            case INITIAL -> new PacketHeader.Initial(version, dcid, handshakeCid,
                    side.isClient() ? token : EMPTY, pn, pnLength);
            case HANDSHAKE -> new PacketHeader.Handshake(version, dcid, handshakeCid, pn, pnLength);
            case DATA -> new PacketHeader.Short(spinEnabled ? spin : random.nextBoolean(), keyPhase, dcid, pn, pnLength);
        };
        OpenPacket p = new OpenPacket();
        p.space = id;
        p.number = pn;
        currentFrames = builder.begin(header, keys.local());
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
            if (p.space == SpaceId.DATA && pending.handshakeDone) {
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
        if (space.pendingAcks().canSend()) {
            writeAck(now, p, space, out, limit);
        }
        if (!dataAllowed) {
            return;
        }
        // CRYPTO
        while (out.position() + CRYPTO_SIZE_BOUND < limit) {
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
        while (!pending.newCids.isEmpty()) {
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
        while (!pending.retireCids.isEmpty()) {
            Frame.RetireConnectionId f = new Frame.RetireConnectionId(pending.retireCids.get(0));
            if (out.position() + f.encodedLength() > limit) {
                break;
            }
            f.encode(out);
            p.sent.retireCids.add(pending.retireCids.remove(0));
            p.ackEliciting = true;
        }
        // PATH_RESPONSE
        if (pathResponsePending && out.position() + 9 <= limit) {
            new Frame.PathResponse(pathResponse).encode(out);
            pathResponsePending = false;
            p.ackEliciting = true;
        }
        // DATAGRAM
        while (out.position() + DatagramState.SIZE_BOUND < limit && datagrams.write(out, limit)) {
            p.ackEliciting = true;
        }
        // STREAM
        p.streamFrames = streams.writeStreamFrames(out, limit, config.sendFairness);
        p.ackEliciting |= !p.streamFrames.isEmpty();
        // An ACK rides along with other frames once in a while
        if (out.position() > payloadStart && p.largestAcked < 0 && nextBundledAckTime != NanoClock.NONE
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
        return streams.canSendStreamData() || pathResponsePending || datagrams.canSend(frameSpace);
    }

    private ByteBuffer buildMtuProbe(long now) {
        PacketSpace space = recovery.space(SpaceId.DATA);
        if (space.keys() == null) {
            return null;
        }
        int size = recovery.mtud().pollTransmit(now, recovery.peekPacketNumber(SpaceId.DATA));
        if (size < 0) {
            return null;
        }
        ByteBuffer buf = ByteBuffer.allocate(size);
        PacketBuilder builder = new PacketBuilder(buf, size);
        OpenPacket p = begin(now, SpaceId.DATA, builder, space.keys(), 0);
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
