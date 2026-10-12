/*
 * Ported from quinn-proto src/transport_parameters.rs (TransportParameters, TransportParameterId,
 * write, read, validate_resumption_from and the semantic validation) and the parameters
 * src/connection/mod.rs remembers for 0-RTT (Apache-2.0), with version_information from RFC 9368.
 */
package io.github.mahmoudimus.quic.params;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.StatelessResetToken;
import io.github.mahmoudimus.quic.VarInt;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * QUIC transport parameters (RFC 9000 section 18), with the extensions {@code
 * max_datagram_frame_size} (RFC 9221), {@code grease_quic_bit} (RFC 9287), {@code
 * version_information} (RFC 9368) and the ACK frequency draft's {@code min_ack_delay}.
 *
 * <p>Absent parameters take their RFC defaults: {@code max_udp_payload_size} 65527, {@code
 * ack_delay_exponent} 3, {@code max_ack_delay} 25 ms, {@code active_connection_id_limit} 2, and 0,
 * false or null otherwise ({@code minAckDelay} is -1 when absent). Integer parameters equal to
 * their defaults are not encoded.
 *
 * <p>{@link #decode} rejects, with {@code TRANSPORT_PARAMETER_ERROR}: malformed values, duplicate
 * parameters, values outside RFC 9000's limits, server-only parameters from a client, and invalid
 * version information. Unknown and reserved (GREASE) parameters are kept in {@link
 * #unknownParameters()}. Instances are immutable.
 *
 * @param originalDestinationConnectionId server only: the Destination Connection ID of the
 *     client's first Initial, or null
 * @param maxIdleTimeout the idle timeout in milliseconds, 0 to disable
 * @param statelessResetToken server only: the reset token for the server's handshake connection
 *     ID, or null
 * @param maxUdpPayloadSize the largest UDP payload the endpoint will receive, at least 1200
 * @param initialMaxData the initial connection flow control limit
 * @param initialMaxStreamDataBidiLocal the initial limit for bidirectional streams the endpoint
 *     opens
 * @param initialMaxStreamDataBidiRemote the initial limit for bidirectional streams the peer
 *     opens
 * @param initialMaxStreamDataUni the initial limit for unidirectional streams the peer opens
 * @param initialMaxStreamsBidi how many bidirectional streams the peer may open, at most
 *     2<sup>60</sup>
 * @param initialMaxStreamsUni how many unidirectional streams the peer may open, at most
 *     2<sup>60</sup>
 * @param ackDelayExponent the exponent of the ACK Delay field, at most 20
 * @param maxAckDelay the most milliseconds the endpoint delays acknowledgments, below
 *     2<sup>14</sup>
 * @param disableActiveMigration whether the endpoint refuses active connection migration
 * @param preferredAddress server only: an address to migrate to, or null
 * @param activeConnectionIdLimit how many connection IDs the endpoint will store, at least 2
 * @param initialSourceConnectionId the Source Connection ID of the endpoint's first Initial, or
 *     null
 * @param retrySourceConnectionId server only: the Source Connection ID of the server's Retry, or
 *     null
 * @param maxDatagramFrameSize the largest DATAGRAM frame the endpoint accepts, 0 if it accepts
 *     none (RFC 9221)
 * @param greaseQuicBit whether the endpoint accepts packets with the Fixed Bit cleared (RFC 9287)
 * @param minAckDelay the smallest ACK delay in microseconds the endpoint supports, or -1 if it
 *     does not support the ACK frequency extension
 * @param versionInformation the version information (RFC 9368), or null
 * @param unknownParameters parameters this module does not interpret, in order
 */
public record TransportParameters(
        ConnectionId originalDestinationConnectionId,
        long maxIdleTimeout,
        StatelessResetToken statelessResetToken,
        long maxUdpPayloadSize,
        long initialMaxData,
        long initialMaxStreamDataBidiLocal,
        long initialMaxStreamDataBidiRemote,
        long initialMaxStreamDataUni,
        long initialMaxStreamsBidi,
        long initialMaxStreamsUni,
        long ackDelayExponent,
        long maxAckDelay,
        boolean disableActiveMigration,
        PreferredAddress preferredAddress,
        long activeConnectionIdLimit,
        ConnectionId initialSourceConnectionId,
        ConnectionId retrySourceConnectionId,
        long maxDatagramFrameSize,
        boolean greaseQuicBit,
        long minAckDelay,
        VersionInformation versionInformation,
        List<UnknownParameter> unknownParameters) {

    /** The default {@code max_udp_payload_size}: the largest UDP payload. */
    public static final long DEFAULT_MAX_UDP_PAYLOAD_SIZE = 65527;
    /** The default {@code ack_delay_exponent}. */
    public static final long DEFAULT_ACK_DELAY_EXPONENT = 3;
    /** The default {@code max_ack_delay}, in milliseconds. */
    public static final long DEFAULT_MAX_ACK_DELAY = 25;
    /** The default and smallest {@code active_connection_id_limit}. */
    public static final long DEFAULT_ACTIVE_CONNECTION_ID_LIMIT = 2;
    /** The smallest valid {@code max_udp_payload_size}. */
    public static final long MIN_UDP_PAYLOAD_SIZE = 1200;
    /** The largest valid {@code ack_delay_exponent}. */
    public static final long MAX_ACK_DELAY_EXPONENT = 20;
    /** The smallest invalid {@code max_ack_delay}, 2<sup>14</sup> milliseconds. */
    public static final long MAX_ACK_DELAY_LIMIT = 1L << 14;
    /** The largest valid stream count, 2<sup>60</sup>. */
    public static final long MAX_STREAM_COUNT = 1L << 60;

    private static final int ORIGINAL_DESTINATION_CONNECTION_ID = 0x00;
    private static final int MAX_IDLE_TIMEOUT = 0x01;
    private static final int STATELESS_RESET_TOKEN = 0x02;
    private static final int MAX_UDP_PAYLOAD_SIZE = 0x03;
    private static final int INITIAL_MAX_DATA = 0x04;
    private static final int INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05;
    private static final int INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06;
    private static final int INITIAL_MAX_STREAM_DATA_UNI = 0x07;
    private static final int INITIAL_MAX_STREAMS_BIDI = 0x08;
    private static final int INITIAL_MAX_STREAMS_UNI = 0x09;
    private static final int ACK_DELAY_EXPONENT = 0x0a;
    private static final int MAX_ACK_DELAY = 0x0b;
    private static final int DISABLE_ACTIVE_MIGRATION = 0x0c;
    private static final int PREFERRED_ADDRESS = 0x0d;
    private static final int ACTIVE_CONNECTION_ID_LIMIT = 0x0e;
    private static final int INITIAL_SOURCE_CONNECTION_ID = 0x0f;
    private static final int RETRY_SOURCE_CONNECTION_ID = 0x10;
    private static final int VERSION_INFORMATION = 0x11;
    private static final int MAX_DATAGRAM_FRAME_SIZE = 0x20;
    private static final int GREASE_QUIC_BIT = 0x2ab2;
    private static final long MIN_ACK_DELAY = 0xff04de1bL;

    /**
     * Transport parameters.
     *
     * @param originalDestinationConnectionId the original Destination Connection ID, or null
     * @param maxIdleTimeout the idle timeout in milliseconds
     * @param statelessResetToken the stateless reset token, or null
     * @param maxUdpPayloadSize the largest UDP payload
     * @param initialMaxData the connection flow control limit
     * @param initialMaxStreamDataBidiLocal the limit for local bidirectional streams
     * @param initialMaxStreamDataBidiRemote the limit for remote bidirectional streams
     * @param initialMaxStreamDataUni the limit for unidirectional streams
     * @param initialMaxStreamsBidi the bidirectional stream count limit
     * @param initialMaxStreamsUni the unidirectional stream count limit
     * @param ackDelayExponent the ACK delay exponent
     * @param maxAckDelay the maximum ACK delay in milliseconds
     * @param disableActiveMigration whether active migration is disabled
     * @param preferredAddress the preferred address, or null
     * @param activeConnectionIdLimit the active connection ID limit
     * @param initialSourceConnectionId the initial Source Connection ID, or null
     * @param retrySourceConnectionId the Retry Source Connection ID, or null
     * @param maxDatagramFrameSize the largest DATAGRAM frame, 0 for none
     * @param greaseQuicBit whether a cleared Fixed Bit is accepted
     * @param minAckDelay the minimum ACK delay in microseconds, or -1
     * @param versionInformation the version information, or null
     * @param unknownParameters the uninterpreted parameters
     */
    public TransportParameters {
        for (long v : new long[] {maxIdleTimeout, maxUdpPayloadSize, initialMaxData, initialMaxStreamDataBidiLocal,
                initialMaxStreamDataBidiRemote, initialMaxStreamDataUni, initialMaxStreamsBidi, initialMaxStreamsUni,
                ackDelayExponent, maxAckDelay, activeConnectionIdLimit, maxDatagramFrameSize}) {
            if (v < 0 || v > VarInt.MAX) {
                throw new IllegalArgumentException("transport parameter out of varint range: " + v);
            }
        }
        if (minAckDelay < -1 || minAckDelay > VarInt.MAX) {
            throw new IllegalArgumentException("min_ack_delay " + minAckDelay);
        }
        unknownParameters = List.copyOf(unknownParameters);
    }

    /**
     * The parameters a peer is assumed to have when it sends none: all defaults.
     *
     * @return the defaults
     */
    public static TransportParameters defaults() {
        return builder().build();
    }

    /**
     * A builder starting from the defaults.
     *
     * @return the builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder starting from these parameters.
     *
     * @return the builder
     */
    public Builder toBuilder() {
        return new Builder(this);
    }

    /**
     * The parameters a client remembers from a session for 0-RTT (RFC 9000 section 7.4.1), as quinn
     * keeps them: the flow control and stream limits, the idle timeout, the payload size, the
     * connection ID limit and DATAGRAM support, but not the connection IDs, the reset token, the
     * preferred address or the ACK delay parameters, which belong to one connection.
     *
     * @return the parameters to use until the server's new ones arrive
     */
    public TransportParameters forZeroRtt() {
        return toBuilder()
                .originalDestinationConnectionId(null)
                .initialSourceConnectionId(null)
                .retrySourceConnectionId(null)
                .statelessResetToken(null)
                .preferredAddress(null)
                .minAckDelay(-1)
                .ackDelayExponent(DEFAULT_ACK_DELAY_EXPONENT)
                .maxAckDelay(DEFAULT_MAX_ACK_DELAY)
                .build();
    }

    /**
     * Whether a server whose parameters these are may accept 0-RTT from a client that remembers
     * {@code remembered} (RFC 9000 section 7.4.1): none of the limits the client may use in 0-RTT
     * is smaller now than then.
     *
     * @param remembered the parameters the server had when it issued the ticket
     * @return true if 0-RTT data within the remembered limits is within these
     */
    public boolean allowsResumptionFrom(TransportParameters remembered) {
        return remembered.activeConnectionIdLimit <= activeConnectionIdLimit
                && remembered.initialMaxData <= initialMaxData
                && remembered.initialMaxStreamDataBidiLocal <= initialMaxStreamDataBidiLocal
                && remembered.initialMaxStreamDataBidiRemote <= initialMaxStreamDataBidiRemote
                && remembered.initialMaxStreamDataUni <= initialMaxStreamDataUni
                && remembered.initialMaxStreamsBidi <= initialMaxStreamsBidi
                && remembered.initialMaxStreamsUni <= initialMaxStreamsUni
                && remembered.maxDatagramFrameSize <= maxDatagramFrameSize
                && (!remembered.greaseQuicBit || greaseQuicBit);
    }

    /**
     * Checks, on a client whose 0-RTT data the server accepted, that the server's new parameters
     * allow all it may have sent under the remembered ones (quinn's {@code validate_resumption_from}).
     *
     * @param remembered the parameters the client used for 0-RTT
     * @throws QuicException {@code PROTOCOL_VIOLATION} if the server lowered a limit
     */
    public void validateResumptionFrom(TransportParameters remembered) throws QuicException {
        if (!allowsResumptionFrom(remembered)) {
            throw new QuicException(QuicException.PROTOCOL_VIOLATION,
                    "0-RTT accepted with incompatible transport parameters");
        }
    }

    /**
     * The encoded length.
     *
     * @return the bytes {@link #encode(ByteBuffer)} writes
     */
    public int encodedLength() {
        int n = connectionIdLength(ORIGINAL_DESTINATION_CONNECTION_ID, originalDestinationConnectionId)
                + integerLength(MAX_IDLE_TIMEOUT, maxIdleTimeout, 0)
                + (statelessResetToken == null ? 0 : 2 + StatelessResetToken.LENGTH)
                + integerLength(MAX_UDP_PAYLOAD_SIZE, maxUdpPayloadSize, DEFAULT_MAX_UDP_PAYLOAD_SIZE)
                + integerLength(INITIAL_MAX_DATA, initialMaxData, 0)
                + integerLength(INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, initialMaxStreamDataBidiLocal, 0)
                + integerLength(INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, initialMaxStreamDataBidiRemote, 0)
                + integerLength(INITIAL_MAX_STREAM_DATA_UNI, initialMaxStreamDataUni, 0)
                + integerLength(INITIAL_MAX_STREAMS_BIDI, initialMaxStreamsBidi, 0)
                + integerLength(INITIAL_MAX_STREAMS_UNI, initialMaxStreamsUni, 0)
                + integerLength(ACK_DELAY_EXPONENT, ackDelayExponent, DEFAULT_ACK_DELAY_EXPONENT)
                + integerLength(MAX_ACK_DELAY, maxAckDelay, DEFAULT_MAX_ACK_DELAY)
                + (disableActiveMigration ? 2 : 0)
                + (preferredAddress == null ? 0
                        : 1 + VarInt.size(preferredAddress.encodedLength()) + preferredAddress.encodedLength())
                + integerLength(ACTIVE_CONNECTION_ID_LIMIT, activeConnectionIdLimit, DEFAULT_ACTIVE_CONNECTION_ID_LIMIT)
                + connectionIdLength(INITIAL_SOURCE_CONNECTION_ID, initialSourceConnectionId)
                + connectionIdLength(RETRY_SOURCE_CONNECTION_ID, retrySourceConnectionId)
                + (versionInformation == null ? 0
                        : 1 + VarInt.size(versionInformation.encodedLength()) + versionInformation.encodedLength())
                + integerLength(MAX_DATAGRAM_FRAME_SIZE, maxDatagramFrameSize, 0)
                + (greaseQuicBit ? VarInt.size(GREASE_QUIC_BIT) + 1 : 0)
                + (minAckDelay < 0 ? 0 : VarInt.size(MIN_ACK_DELAY) + 1 + VarInt.size(minAckDelay));
        for (UnknownParameter p : unknownParameters) {
            int len = p.value().length;
            n += VarInt.size(p.id()) + VarInt.size(len) + len;
        }
        return n;
    }

    private static int integerLength(int id, long value, long defaultValue) {
        return value == defaultValue ? 0 : VarInt.size(id) + 1 + VarInt.size(value);
    }

    private static int connectionIdLength(int id, ConnectionId cid) {
        return cid == null ? 0 : VarInt.size(id) + 1 + cid.length();
    }

    /**
     * Encodes the parameters, in ID order with unknown parameters last.
     *
     * @return the encoded bytes, the {@code quic_transport_parameters} TLS extension value
     */
    public byte[] encode() {
        ByteBuffer out = ByteBuffer.allocate(encodedLength());
        encode(out);
        return out.array();
    }

    /**
     * Encodes the parameters at the buffer's position.
     *
     * @param out the buffer
     * @throws java.nio.BufferOverflowException if the buffer has too little room
     */
    public void encode(ByteBuffer out) {
        writeConnectionId(out, ORIGINAL_DESTINATION_CONNECTION_ID, originalDestinationConnectionId);
        writeInteger(out, MAX_IDLE_TIMEOUT, maxIdleTimeout, 0);
        if (statelessResetToken != null) {
            VarInt.write(out, STATELESS_RESET_TOKEN);
            VarInt.write(out, StatelessResetToken.LENGTH);
            statelessResetToken.writeTo(out);
        }
        writeInteger(out, MAX_UDP_PAYLOAD_SIZE, maxUdpPayloadSize, DEFAULT_MAX_UDP_PAYLOAD_SIZE);
        writeInteger(out, INITIAL_MAX_DATA, initialMaxData, 0);
        writeInteger(out, INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, initialMaxStreamDataBidiLocal, 0);
        writeInteger(out, INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, initialMaxStreamDataBidiRemote, 0);
        writeInteger(out, INITIAL_MAX_STREAM_DATA_UNI, initialMaxStreamDataUni, 0);
        writeInteger(out, INITIAL_MAX_STREAMS_BIDI, initialMaxStreamsBidi, 0);
        writeInteger(out, INITIAL_MAX_STREAMS_UNI, initialMaxStreamsUni, 0);
        writeInteger(out, ACK_DELAY_EXPONENT, ackDelayExponent, DEFAULT_ACK_DELAY_EXPONENT);
        writeInteger(out, MAX_ACK_DELAY, maxAckDelay, DEFAULT_MAX_ACK_DELAY);
        if (disableActiveMigration) {
            VarInt.write(out, DISABLE_ACTIVE_MIGRATION);
            VarInt.write(out, 0);
        }
        if (preferredAddress != null) {
            VarInt.write(out, PREFERRED_ADDRESS);
            VarInt.write(out, preferredAddress.encodedLength());
            preferredAddress.encode(out);
        }
        writeInteger(out, ACTIVE_CONNECTION_ID_LIMIT, activeConnectionIdLimit, DEFAULT_ACTIVE_CONNECTION_ID_LIMIT);
        writeConnectionId(out, INITIAL_SOURCE_CONNECTION_ID, initialSourceConnectionId);
        writeConnectionId(out, RETRY_SOURCE_CONNECTION_ID, retrySourceConnectionId);
        if (versionInformation != null) {
            VarInt.write(out, VERSION_INFORMATION);
            VarInt.write(out, versionInformation.encodedLength());
            versionInformation.encode(out);
        }
        writeInteger(out, MAX_DATAGRAM_FRAME_SIZE, maxDatagramFrameSize, 0);
        if (greaseQuicBit) {
            VarInt.write(out, GREASE_QUIC_BIT);
            VarInt.write(out, 0);
        }
        if (minAckDelay >= 0) {
            VarInt.write(out, MIN_ACK_DELAY);
            VarInt.write(out, VarInt.size(minAckDelay));
            VarInt.write(out, minAckDelay);
        }
        for (UnknownParameter p : unknownParameters) {
            byte[] value = p.value();
            VarInt.write(out, p.id());
            VarInt.write(out, value.length);
            out.put(value);
        }
    }

    /**
     * Decodes and validates the peer's transport parameters.
     *
     * @param in the encoded parameters between position and limit; the position moves to the
     *     limit on success
     * @param sentByServer whether the peer is the server, which allows the server-only parameters
     * @return the parameters, with defaults for those absent
     * @throws QuicException with {@code TRANSPORT_PARAMETER_ERROR} if the parameters are
     *     malformed, duplicated, out of range or not allowed from the peer's role
     */
    public static TransportParameters decode(ByteBuffer in, boolean sentByServer) throws QuicException {
        Builder b = new Builder();
        Set<Long> seen = new HashSet<>();
        try {
            while (in.hasRemaining()) {
                long id = VarInt.read(in);
                long length = VarInt.read(in);
                if (length > in.remaining()) {
                    throw error("parameter 0x" + Long.toHexString(id) + " longer than the extension");
                }
                if (!seen.add(id)) {
                    throw error("duplicate parameter 0x" + Long.toHexString(id));
                }
                ByteBuffer value = in.slice(in.position(), (int) length);
                in.position(in.position() + (int) length);
                decodeParameter(b, id, value);
                if (value.hasRemaining()) {
                    throw error("parameter 0x" + Long.toHexString(id) + " has trailing bytes");
                }
            }
        } catch (BufferUnderflowException | IllegalArgumentException e) {
            throw error("malformed transport parameters");
        }
        TransportParameters p = b.build();
        p.validate(sentByServer);
        return p;
    }

    /**
     * Decodes and validates the peer's transport parameters from an array.
     *
     * @param encoded the encoded parameters
     * @param sentByServer whether the peer is the server
     * @return the parameters
     * @throws QuicException with {@code TRANSPORT_PARAMETER_ERROR} if they are invalid
     */
    public static TransportParameters decode(byte[] encoded, boolean sentByServer) throws QuicException {
        return decode(ByteBuffer.wrap(encoded), sentByServer);
    }

    private static void decodeParameter(Builder b, long id, ByteBuffer v) throws QuicException {
        if (id == MIN_ACK_DELAY) {
            b.minAckDelay = readInteger(v);
            return;
        }
        if (id > Integer.MAX_VALUE) {
            b.unknownParameters.add(new UnknownParameter(id, remaining(v)));
            return;
        }
        switch ((int) id) {
            case ORIGINAL_DESTINATION_CONNECTION_ID -> b.originalDestinationConnectionId = readConnectionId(v);
            case MAX_IDLE_TIMEOUT -> b.maxIdleTimeout = readInteger(v);
            case STATELESS_RESET_TOKEN -> {
                if (v.remaining() != StatelessResetToken.LENGTH) {
                    throw error("stateless_reset_token is not 16 bytes");
                }
                b.statelessResetToken = StatelessResetToken.read(v);
            }
            case MAX_UDP_PAYLOAD_SIZE -> b.maxUdpPayloadSize = readInteger(v);
            case INITIAL_MAX_DATA -> b.initialMaxData = readInteger(v);
            case INITIAL_MAX_STREAM_DATA_BIDI_LOCAL -> b.initialMaxStreamDataBidiLocal = readInteger(v);
            case INITIAL_MAX_STREAM_DATA_BIDI_REMOTE -> b.initialMaxStreamDataBidiRemote = readInteger(v);
            case INITIAL_MAX_STREAM_DATA_UNI -> b.initialMaxStreamDataUni = readInteger(v);
            case INITIAL_MAX_STREAMS_BIDI -> b.initialMaxStreamsBidi = readInteger(v);
            case INITIAL_MAX_STREAMS_UNI -> b.initialMaxStreamsUni = readInteger(v);
            case ACK_DELAY_EXPONENT -> b.ackDelayExponent = readInteger(v);
            case MAX_ACK_DELAY -> b.maxAckDelay = readInteger(v);
            case DISABLE_ACTIVE_MIGRATION -> b.disableActiveMigration = readFlag(v);
            case PREFERRED_ADDRESS -> {
                PreferredAddress a = PreferredAddress.decode(v);
                if (a == null) {
                    throw error("preferred_address has no address");
                }
                b.preferredAddress = a;
            }
            case ACTIVE_CONNECTION_ID_LIMIT -> b.activeConnectionIdLimit = readInteger(v);
            case INITIAL_SOURCE_CONNECTION_ID -> b.initialSourceConnectionId = readConnectionId(v);
            case RETRY_SOURCE_CONNECTION_ID -> b.retrySourceConnectionId = readConnectionId(v);
            case VERSION_INFORMATION -> {
                if (v.remaining() < 4 || v.remaining() % 4 != 0) {
                    throw error("version_information length " + v.remaining());
                }
                int chosen = v.getInt();
                List<Integer> available = new ArrayList<>();
                while (v.hasRemaining()) {
                    available.add(v.getInt());
                }
                b.versionInformation = new VersionInformation(chosen, available);
            }
            case MAX_DATAGRAM_FRAME_SIZE -> b.maxDatagramFrameSize = readInteger(v);
            case GREASE_QUIC_BIT -> b.greaseQuicBit = readFlag(v);
            default -> b.unknownParameters.add(new UnknownParameter(id, remaining(v)));
        }
    }

    private void validate(boolean sentByServer) throws QuicException {
        if (ackDelayExponent > MAX_ACK_DELAY_EXPONENT) {
            throw error("ack_delay_exponent " + ackDelayExponent + " above 20");
        }
        if (maxAckDelay >= MAX_ACK_DELAY_LIMIT) {
            throw error("max_ack_delay " + maxAckDelay + " not below 2^14");
        }
        if (activeConnectionIdLimit < DEFAULT_ACTIVE_CONNECTION_ID_LIMIT) {
            throw error("active_connection_id_limit " + activeConnectionIdLimit + " below 2");
        }
        if (maxUdpPayloadSize < MIN_UDP_PAYLOAD_SIZE) {
            throw error("max_udp_payload_size " + maxUdpPayloadSize + " below 1200");
        }
        if (initialMaxStreamsBidi > MAX_STREAM_COUNT || initialMaxStreamsUni > MAX_STREAM_COUNT) {
            throw error("initial_max_streams above 2^60");
        }
        if (minAckDelay >= 0 && minAckDelay > maxAckDelay * 1000) {
            throw error("min_ack_delay above max_ack_delay");
        }
        if (!sentByServer && (originalDestinationConnectionId != null || statelessResetToken != null
                || preferredAddress != null || retrySourceConnectionId != null)) {
            throw error("client sent a server-only transport parameter");
        }
        if (preferredAddress != null && preferredAddress.connectionId().isEmpty()) {
            throw error("preferred_address with an empty connection ID");
        }
        if (versionInformation != null) {
            if (versionInformation.chosenVersion() == 0 || versionInformation.availableVersions().contains(0)) {
                throw error("version_information with version 0");
            }
            if (!sentByServer && !versionInformation.availableVersions().contains(versionInformation.chosenVersion())) {
                throw error("version_information chosen version not among the available versions");
            }
        }
    }

    /**
     * Authenticates the connection IDs of the handshake (RFC 9000 section 7.3): both endpoints
     * must send {@code initial_source_connection_id} matching the Source Connection ID of their
     * first Initial; a server must send {@code original_destination_connection_id}, and {@code
     * retry_source_connection_id} if and only if it sent a Retry.
     *
     * @param sentByServer whether these are the server's parameters
     * @param peerInitialSourceId the Source Connection ID of the peer's first Initial packet
     * @param originalDestinationId for a server's parameters, the Destination Connection ID of the
     *     client's first Initial; ignored for a client's
     * @param retrySourceId for a server's parameters, the Source Connection ID of the Retry the
     *     client processed, or null if none; ignored for a client's
     * @throws QuicException with {@code TRANSPORT_PARAMETER_ERROR} if a parameter is missing,
     *     unexpected or different
     */
    public void authenticateConnectionIds(boolean sentByServer, ConnectionId peerInitialSourceId,
            ConnectionId originalDestinationId, ConnectionId retrySourceId) throws QuicException {
        if (initialSourceConnectionId == null || !initialSourceConnectionId.equals(peerInitialSourceId)) {
            throw error("initial_source_connection_id missing or different");
        }
        if (!sentByServer) {
            return;
        }
        if (originalDestinationConnectionId == null || !originalDestinationConnectionId.equals(originalDestinationId)) {
            throw error("original_destination_connection_id missing or different");
        }
        if (!Objects.equals(retrySourceConnectionId, retrySourceId)) {
            throw error("retry_source_connection_id missing, unexpected or different");
        }
    }

    private static QuicException error(String reason) {
        return new QuicException(QuicException.TRANSPORT_PARAMETER_ERROR, reason);
    }

    private static long readInteger(ByteBuffer v) {
        return VarInt.read(v);
    }

    private static boolean readFlag(ByteBuffer v) throws QuicException {
        if (v.hasRemaining()) {
            throw error("flag parameter with a value");
        }
        return true;
    }

    private static ConnectionId readConnectionId(ByteBuffer v) throws QuicException {
        if (v.remaining() > ConnectionId.MAX_LENGTH) {
            throw error("connection ID longer than 20 bytes");
        }
        return ConnectionId.read(v, v.remaining());
    }

    private static byte[] remaining(ByteBuffer v) {
        byte[] b = new byte[v.remaining()];
        v.get(b);
        return b;
    }

    private static void writeInteger(ByteBuffer out, int id, long value, long defaultValue) {
        if (value != defaultValue) {
            VarInt.write(out, id);
            VarInt.write(out, VarInt.size(value));
            VarInt.write(out, value);
        }
    }

    private static void writeConnectionId(ByteBuffer out, int id, ConnectionId cid) {
        if (cid != null) {
            VarInt.write(out, id);
            VarInt.write(out, cid.length());
            cid.writeTo(out);
        }
    }

    /** Builds {@link TransportParameters}, starting from the defaults. Not thread-safe. */
    public static final class Builder {
        private ConnectionId originalDestinationConnectionId;
        private long maxIdleTimeout;
        private StatelessResetToken statelessResetToken;
        private long maxUdpPayloadSize = DEFAULT_MAX_UDP_PAYLOAD_SIZE;
        private long initialMaxData;
        private long initialMaxStreamDataBidiLocal;
        private long initialMaxStreamDataBidiRemote;
        private long initialMaxStreamDataUni;
        private long initialMaxStreamsBidi;
        private long initialMaxStreamsUni;
        private long ackDelayExponent = DEFAULT_ACK_DELAY_EXPONENT;
        private long maxAckDelay = DEFAULT_MAX_ACK_DELAY;
        private boolean disableActiveMigration;
        private PreferredAddress preferredAddress;
        private long activeConnectionIdLimit = DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
        private ConnectionId initialSourceConnectionId;
        private ConnectionId retrySourceConnectionId;
        private long maxDatagramFrameSize;
        private boolean greaseQuicBit;
        private long minAckDelay = -1;
        private VersionInformation versionInformation;
        private final List<UnknownParameter> unknownParameters = new ArrayList<>();

        private Builder() {}

        private Builder(TransportParameters p) {
            originalDestinationConnectionId = p.originalDestinationConnectionId;
            maxIdleTimeout = p.maxIdleTimeout;
            statelessResetToken = p.statelessResetToken;
            maxUdpPayloadSize = p.maxUdpPayloadSize;
            initialMaxData = p.initialMaxData;
            initialMaxStreamDataBidiLocal = p.initialMaxStreamDataBidiLocal;
            initialMaxStreamDataBidiRemote = p.initialMaxStreamDataBidiRemote;
            initialMaxStreamDataUni = p.initialMaxStreamDataUni;
            initialMaxStreamsBidi = p.initialMaxStreamsBidi;
            initialMaxStreamsUni = p.initialMaxStreamsUni;
            ackDelayExponent = p.ackDelayExponent;
            maxAckDelay = p.maxAckDelay;
            disableActiveMigration = p.disableActiveMigration;
            preferredAddress = p.preferredAddress;
            activeConnectionIdLimit = p.activeConnectionIdLimit;
            initialSourceConnectionId = p.initialSourceConnectionId;
            retrySourceConnectionId = p.retrySourceConnectionId;
            maxDatagramFrameSize = p.maxDatagramFrameSize;
            greaseQuicBit = p.greaseQuicBit;
            minAckDelay = p.minAckDelay;
            versionInformation = p.versionInformation;
            unknownParameters.addAll(p.unknownParameters);
        }

        /**
         * Sets {@code original_destination_connection_id}.
         *
         * @param v the connection ID, or null
         * @return this builder
         */
        public Builder originalDestinationConnectionId(ConnectionId v) {
            originalDestinationConnectionId = v;
            return this;
        }

        /**
         * Sets {@code max_idle_timeout}.
         *
         * @param v milliseconds, 0 to disable
         * @return this builder
         */
        public Builder maxIdleTimeout(long v) {
            maxIdleTimeout = v;
            return this;
        }

        /**
         * Sets {@code stateless_reset_token}.
         *
         * @param v the token, or null
         * @return this builder
         */
        public Builder statelessResetToken(StatelessResetToken v) {
            statelessResetToken = v;
            return this;
        }

        /**
         * Sets {@code max_udp_payload_size}.
         *
         * @param v bytes
         * @return this builder
         */
        public Builder maxUdpPayloadSize(long v) {
            maxUdpPayloadSize = v;
            return this;
        }

        /**
         * Sets {@code initial_max_data}.
         *
         * @param v bytes
         * @return this builder
         */
        public Builder initialMaxData(long v) {
            initialMaxData = v;
            return this;
        }

        /**
         * Sets {@code initial_max_stream_data_bidi_local}.
         *
         * @param v bytes
         * @return this builder
         */
        public Builder initialMaxStreamDataBidiLocal(long v) {
            initialMaxStreamDataBidiLocal = v;
            return this;
        }

        /**
         * Sets {@code initial_max_stream_data_bidi_remote}.
         *
         * @param v bytes
         * @return this builder
         */
        public Builder initialMaxStreamDataBidiRemote(long v) {
            initialMaxStreamDataBidiRemote = v;
            return this;
        }

        /**
         * Sets {@code initial_max_stream_data_uni}.
         *
         * @param v bytes
         * @return this builder
         */
        public Builder initialMaxStreamDataUni(long v) {
            initialMaxStreamDataUni = v;
            return this;
        }

        /**
         * Sets {@code initial_max_streams_bidi}.
         *
         * @param v the stream count
         * @return this builder
         */
        public Builder initialMaxStreamsBidi(long v) {
            initialMaxStreamsBidi = v;
            return this;
        }

        /**
         * Sets {@code initial_max_streams_uni}.
         *
         * @param v the stream count
         * @return this builder
         */
        public Builder initialMaxStreamsUni(long v) {
            initialMaxStreamsUni = v;
            return this;
        }

        /**
         * Sets {@code ack_delay_exponent}.
         *
         * @param v the exponent
         * @return this builder
         */
        public Builder ackDelayExponent(long v) {
            ackDelayExponent = v;
            return this;
        }

        /**
         * Sets {@code max_ack_delay}.
         *
         * @param v milliseconds
         * @return this builder
         */
        public Builder maxAckDelay(long v) {
            maxAckDelay = v;
            return this;
        }

        /**
         * Sets {@code disable_active_migration}.
         *
         * @param v whether active migration is disabled
         * @return this builder
         */
        public Builder disableActiveMigration(boolean v) {
            disableActiveMigration = v;
            return this;
        }

        /**
         * Sets {@code preferred_address}.
         *
         * @param v the address, or null
         * @return this builder
         */
        public Builder preferredAddress(PreferredAddress v) {
            preferredAddress = v;
            return this;
        }

        /**
         * Sets {@code active_connection_id_limit}.
         *
         * @param v the limit
         * @return this builder
         */
        public Builder activeConnectionIdLimit(long v) {
            activeConnectionIdLimit = v;
            return this;
        }

        /**
         * Sets {@code initial_source_connection_id}.
         *
         * @param v the connection ID, or null
         * @return this builder
         */
        public Builder initialSourceConnectionId(ConnectionId v) {
            initialSourceConnectionId = v;
            return this;
        }

        /**
         * Sets {@code retry_source_connection_id}.
         *
         * @param v the connection ID, or null
         * @return this builder
         */
        public Builder retrySourceConnectionId(ConnectionId v) {
            retrySourceConnectionId = v;
            return this;
        }

        /**
         * Sets {@code max_datagram_frame_size}.
         *
         * @param v bytes, 0 for no DATAGRAM support
         * @return this builder
         */
        public Builder maxDatagramFrameSize(long v) {
            maxDatagramFrameSize = v;
            return this;
        }

        /**
         * Sets {@code grease_quic_bit}.
         *
         * @param v whether a cleared Fixed Bit is accepted
         * @return this builder
         */
        public Builder greaseQuicBit(boolean v) {
            greaseQuicBit = v;
            return this;
        }

        /**
         * Sets {@code min_ack_delay}.
         *
         * @param v microseconds, or -1 to omit
         * @return this builder
         */
        public Builder minAckDelay(long v) {
            minAckDelay = v;
            return this;
        }

        /**
         * Sets {@code version_information}.
         *
         * @param v the version information, or null
         * @return this builder
         */
        public Builder versionInformation(VersionInformation v) {
            versionInformation = v;
            return this;
        }

        /**
         * Adds an uninterpreted parameter, such as a GREASE one from {@link
         * UnknownParameter#grease}.
         *
         * @param v the parameter
         * @return this builder
         */
        public Builder addUnknownParameter(UnknownParameter v) {
            unknownParameters.add(Objects.requireNonNull(v));
            return this;
        }

        /**
         * Builds the parameters.
         *
         * @return the parameters
         * @throws IllegalArgumentException if a value is outside the varint range
         */
        public TransportParameters build() {
            return new TransportParameters(originalDestinationConnectionId, maxIdleTimeout, statelessResetToken,
                    maxUdpPayloadSize, initialMaxData, initialMaxStreamDataBidiLocal, initialMaxStreamDataBidiRemote,
                    initialMaxStreamDataUni, initialMaxStreamsBidi, initialMaxStreamsUni, ackDelayExponent,
                    maxAckDelay, disableActiveMigration, preferredAddress, activeConnectionIdLimit,
                    initialSourceConnectionId, retrySourceConnectionId, maxDatagramFrameSize, greaseQuicBit,
                    minAckDelay, versionInformation, unknownParameters);
        }
    }
}
