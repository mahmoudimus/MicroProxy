/*
 * Ported from quinn-proto src/packet.rs (PartialDecode, ProtectedHeader::decode and
 * PartialDecode::finish) (Apache-2.0), with QUIC version 2 type bits (RFC 9369).
 */
package io.github.mahmoudimus.quic.packet;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.VarInt;
import io.github.mahmoudimus.quic.crypto.DirectionalKeys;
import io.github.mahmoudimus.quic.crypto.HeaderKey;
import io.github.mahmoudimus.quic.crypto.PacketKey;
import io.github.mahmoudimus.quic.crypto.RetryIntegrity;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * A packet whose unprotected header fields are parsed but whose packet number and payload are
 * still protected: quinn's {@code PartialDecode}. The version, type and connection IDs are enough
 * to pick the keys; the {@linkplain #sampleOffset() sample offset} is where header protection
 * samples. Removing protection works in place on the datagram buffer:
 *
 * <pre>{@code
 * ProtectedPacket p = ProtectedPacket.parse(datagram, localIdLength);
 * PacketHeader.Numbered h = p.removeHeaderProtection(keys.remote().header(), largestReceived);
 * Packet packet = p.decrypt(keys.remote().packet()); // null if authentication failed
 * }</pre>
 *
 * <p>A Retry or Version Negotiation packet is fully decoded by {@link #parse}; see {@link
 * #header()}.
 *
 * <p>Instances are single-use and not thread-safe; they share content with the datagram buffer.
 */
public final class ProtectedPacket {

    private static final int MIN_SAMPLE_SPAN = 4 + HeaderKey.SAMPLE_LENGTH;

    private final ByteBuffer buffer;
    private final int start;
    private final int end;
    private final PacketType type;
    private final QuicVersion version;
    private final ConnectionId destinationId;
    private final ConnectionId sourceId;
    private final byte[] token;
    private final int packetNumberOffset;
    private PacketHeader header;
    private int payloadOffset = -1;

    private ProtectedPacket(ByteBuffer buffer, int start, int end, PacketType type, QuicVersion version,
            ConnectionId destinationId, ConnectionId sourceId, byte[] token, int packetNumberOffset, PacketHeader header) {
        this.buffer = buffer;
        this.start = start;
        this.end = end;
        this.type = type;
        this.version = version;
        this.destinationId = destinationId;
        this.sourceId = sourceId;
        this.token = token;
        this.packetNumberOffset = packetNumberOffset;
        this.header = header;
    }

    /**
     * Parses the packet at the buffer's position, requiring the Fixed Bit.
     *
     * @param datagram the datagram; on success its position moves to the end of this packet,
     *     which for short headers, Retry and Version Negotiation is the buffer's limit
     * @param shortHeaderIdLength the length of this endpoint's connection IDs, which short headers
     *     do not encode
     * @return the packet
     * @throws UnsupportedVersionException for a long header of a version other than 1 and 2
     * @throws PacketDecodeException if the header is malformed; the position is then unchanged
     */
    public static ProtectedPacket parse(ByteBuffer datagram, int shortHeaderIdLength) throws PacketDecodeException {
        return parse(datagram, shortHeaderIdLength, false);
    }

    /**
     * Parses the packet at the buffer's position.
     *
     * @param datagram the datagram; on success its position moves to the end of this packet
     * @param shortHeaderIdLength the length of this endpoint's connection IDs
     * @param allowClearFixedBit whether to accept a cleared Fixed Bit, as an endpoint that sent the
     *     {@code grease_quic_bit} transport parameter must (RFC 9287)
     * @return the packet
     * @throws UnsupportedVersionException for a long header of a version other than 1 and 2
     * @throws PacketDecodeException if the header is malformed; the position is then unchanged
     */
    public static ProtectedPacket parse(ByteBuffer datagram, int shortHeaderIdLength, boolean allowClearFixedBit)
            throws PacketDecodeException {
        int start = datagram.position();
        try {
            ProtectedPacket p = decode(datagram.duplicate(), shortHeaderIdLength, allowClearFixedBit);
            datagram.position(p.end);
            return p;
        } catch (BufferUnderflowException e) {
            throw new PacketDecodeException("unexpected end of packet at offset " + start);
        }
    }

    /**
     * Splits a datagram into its coalesced packets (RFC 9000 section 12.2). Parsing stops, and
     * the rest of the datagram is ignored, at the first packet after the first that fails to
     * parse or carries a different Destination Connection ID.
     *
     * @param datagram the datagram between its position and limit; the buffer's position is not
     *     changed, but protection is later removed in its content
     * @param shortHeaderIdLength the length of this endpoint's connection IDs
     * @param allowClearFixedBit whether to accept a cleared Fixed Bit (RFC 9287)
     * @return the packets, at least one
     * @throws PacketDecodeException if the first packet cannot be parsed
     */
    public static List<ProtectedPacket> splitDatagram(ByteBuffer datagram, int shortHeaderIdLength,
            boolean allowClearFixedBit) throws PacketDecodeException {
        ByteBuffer in = datagram.duplicate();
        List<ProtectedPacket> packets = new ArrayList<>();
        ProtectedPacket first = parse(in, shortHeaderIdLength, allowClearFixedBit);
        packets.add(first);
        while (in.hasRemaining()) {
            ProtectedPacket next;
            try {
                next = parse(in, shortHeaderIdLength, allowClearFixedBit);
            } catch (PacketDecodeException e) {
                break;
            }
            if (!next.destinationId.equals(first.destinationId)) {
                break;
            }
            packets.add(next);
        }
        return packets;
    }

    private static ProtectedPacket decode(ByteBuffer in, int shortIdLength, boolean allowClearFixedBit)
            throws PacketDecodeException {
        int start = in.position();
        int first = in.get() & 0xff;
        if ((first & PacketHeader.LONG_HEADER_FORM) == 0) {
            if (!allowClearFixedBit && (first & PacketHeader.FIXED_BIT) == 0) {
                throw new PacketDecodeException("fixed bit unset");
            }
            ConnectionId dcid = ConnectionId.read(in, shortIdLength);
            int pnOffset = in.position();
            int end = in.limit();
            checkSample(pnOffset, end);
            return new ProtectedPacket(in, start, end, PacketType.ONE_RTT, null, dcid, null, null, pnOffset, null);
        }

        int wireVersion = in.getInt();
        byte[] dcid = readLongId(in);
        byte[] scid = readLongId(in);
        if (wireVersion == 0) {
            if (dcid.length > ConnectionId.MAX_LENGTH || scid.length > ConnectionId.MAX_LENGTH) {
                throw new PacketDecodeException("connection ID too long");
            }
            if (in.remaining() % 4 != 0) {
                throw new PacketDecodeException("Version Negotiation versions not a multiple of 4 bytes");
            }
            List<Integer> versions = new ArrayList<>(in.remaining() / 4);
            while (in.hasRemaining()) {
                versions.add(in.getInt());
            }
            PacketHeader vn = new PacketHeader.VersionNegotiation(ConnectionId.of(dcid), ConnectionId.of(scid), versions);
            return new ProtectedPacket(in, start, in.limit(), PacketType.VERSION_NEGOTIATION, null,
                    ConnectionId.of(dcid), ConnectionId.of(scid), null, -1, vn);
        }
        QuicVersion version = QuicVersion.forWireValue(wireVersion);
        if (version == null) {
            throw new UnsupportedVersionException(wireVersion, dcid, scid);
        }
        if (dcid.length > ConnectionId.MAX_LENGTH || scid.length > ConnectionId.MAX_LENGTH) {
            throw new PacketDecodeException("connection ID too long");
        }
        if (!allowClearFixedBit && (first & PacketHeader.FIXED_BIT) == 0) {
            throw new PacketDecodeException("fixed bit unset");
        }
        ConnectionId destination = ConnectionId.of(dcid);
        ConnectionId source = ConnectionId.of(scid);
        PacketType type = PacketType.fromLongTypeBits(version, first >>> 4);
        if (type == PacketType.RETRY) {
            int tokenLength = in.remaining() - RetryIntegrity.TAG_LENGTH;
            if (tokenLength < 0) {
                throw new PacketDecodeException("Retry packet too short for its integrity tag");
            }
            byte[] retryToken = new byte[tokenLength];
            in.get(retryToken);
            byte[] tag = new byte[RetryIntegrity.TAG_LENGTH];
            in.get(tag);
            PacketHeader retry = new PacketHeader.Retry(version, destination, source, retryToken, tag);
            return new ProtectedPacket(in, start, in.limit(), type, version, destination, source, retryToken, -1, retry);
        }
        byte[] initialToken = null;
        if (type == PacketType.INITIAL) {
            long tokenLength = VarInt.read(in);
            if (tokenLength > in.remaining()) {
                throw new PacketDecodeException("token out of bounds");
            }
            initialToken = new byte[(int) tokenLength];
            in.get(initialToken);
        }
        long length = VarInt.read(in);
        if (length > in.remaining()) {
            throw new PacketDecodeException("packet too short to contain payload length");
        }
        int pnOffset = in.position();
        int end = pnOffset + (int) length;
        checkSample(pnOffset, end);
        return new ProtectedPacket(in, start, end, type, version, destination, source, initialToken, pnOffset, null);
    }

    private static byte[] readLongId(ByteBuffer in) {
        int len = in.get() & 0xff;
        if (in.remaining() < len) {
            throw new BufferUnderflowException();
        }
        byte[] id = new byte[len];
        in.get(id);
        return id;
    }

    private static void checkSample(int pnOffset, int end) throws PacketDecodeException {
        if (end - pnOffset < MIN_SAMPLE_SPAN) {
            throw new PacketDecodeException("packet too short to extract header protection sample");
        }
    }

    /**
     * The packet type.
     *
     * @return the type
     */
    public PacketType type() {
        return type;
    }

    /**
     * The QUIC version of a long header.
     *
     * @return the version, or null for short headers and Version Negotiation
     */
    public QuicVersion version() {
        return version;
    }

    /**
     * The Destination Connection ID.
     *
     * @return the connection ID
     */
    public ConnectionId destinationId() {
        return destinationId;
    }

    /**
     * The Source Connection ID of a long header.
     *
     * @return the connection ID, or null for short headers
     */
    public ConnectionId sourceId() {
        return sourceId;
    }

    /**
     * The token of an Initial or Retry packet.
     *
     * @return a copy of the token, or null for other types
     */
    public byte[] token() {
        return token == null ? null : token.clone();
    }

    /**
     * The index of the first byte of this packet in the datagram buffer.
     *
     * @return the absolute start index
     */
    public int start() {
        return start;
    }

    /**
     * The index just past this packet in the datagram buffer.
     *
     * @return the absolute end index
     */
    public int end() {
        return end;
    }

    /**
     * The packet length, header and tag included.
     *
     * @return {@code end() - start()}
     */
    public int length() {
        return end - start;
    }

    /**
     * The index of the (protected) packet number.
     *
     * @return the absolute index, or -1 for Retry and Version Negotiation
     */
    public int packetNumberOffset() {
        return packetNumberOffset;
    }

    /**
     * The index of the header protection sample: four bytes past the start of the packet number.
     *
     * @return the absolute index, or -1 for Retry and Version Negotiation
     */
    public int sampleOffset() {
        return packetNumberOffset < 0 ? -1 : packetNumberOffset + 4;
    }

    /**
     * A view of the whole packet, header protection included or removed as it stands.
     *
     * @return a new buffer over {@code [start(), end())}
     */
    public ByteBuffer bytes() {
        return buffer.slice(start, end - start);
    }

    /**
     * The decoded header: available at once for Retry and Version Negotiation packets, and for
     * protected packets after {@link #removeHeaderProtection}.
     *
     * @return the header, or null before header protection is removed
     */
    public PacketHeader header() {
        return header;
    }

    /**
     * Checks the integrity tag of a Retry packet (RFC 9001 section 5.8).
     *
     * @param originalDestinationId the Destination Connection ID of the client's first Initial
     * @return true if the tag is valid
     * @throws IllegalStateException if this is not a Retry packet
     */
    public boolean verifyRetry(ConnectionId originalDestinationId) {
        if (type != PacketType.RETRY) {
            throw new IllegalStateException(type + " is not a Retry packet");
        }
        return RetryIntegrity.verify(version, originalDestinationId, bytes());
    }

    /**
     * Removes header protection in place and recovers the full packet number.
     *
     * @param key the header protection key of the packet's level (it is the same for both key
     *     phases)
     * @param largestPacketNumber the largest packet number successfully processed in this
     *     packet number space, or -1 if none
     * @return the header; for short headers it carries the key phase that picks the packet key
     * @throws IllegalStateException if the packet is not protected or protection was already
     *     removed
     */
    public PacketHeader.Numbered removeHeaderProtection(HeaderKey key, long largestPacketNumber) {
        if (packetNumberOffset < 0) {
            throw new IllegalStateException(type + " packets have no header protection");
        }
        if (payloadOffset >= 0) {
            throw new IllegalStateException("header protection already removed");
        }
        int pnLength = key.unprotect(buffer, start, packetNumberOffset);
        long truncated = PacketNumber.readProtected(buffer, packetNumberOffset, pnLength);
        long number = PacketNumber.decode(largestPacketNumber, truncated, pnLength);
        int first = buffer.get(start) & 0xff;
        PacketHeader.Numbered h = switch (type) {
            case INITIAL -> new PacketHeader.Initial(version, destinationId, sourceId, token, number, pnLength);
            case ZERO_RTT -> new PacketHeader.ZeroRtt(version, destinationId, sourceId, number, pnLength);
            case HANDSHAKE -> new PacketHeader.Handshake(version, destinationId, sourceId, number, pnLength);
            default -> new PacketHeader.Short((first & PacketHeader.SPIN_BIT) != 0,
                    (first & PacketHeader.KEY_PHASE_BIT) != 0, destinationId, number, pnLength);
        };
        header = h;
        payloadOffset = packetNumberOffset + pnLength;
        return h;
    }

    /**
     * Opens the payload in place, once header protection is removed. After authentication
     * succeeds, the reserved header bits must be zero (RFC 9000 section 17).
     *
     * @param key the packet key for the packet's level and, for 1-RTT, its key phase
     * @return the packet, or null if it failed authentication (drop it; its payload bytes are
     *     then unspecified)
     * @throws QuicException with {@code PROTOCOL_VIOLATION} if an authenticated packet has
     *     reserved bits set
     * @throws IllegalStateException if header protection was not removed first
     */
    public Packet decrypt(PacketKey key) throws QuicException {
        if (payloadOffset < 0) {
            throw new IllegalStateException("remove header protection first");
        }
        int plainEnd = key.open(((PacketHeader.Numbered) header).packetNumber(), buffer, start, payloadOffset, end);
        if (plainEnd < 0) {
            return null;
        }
        int first = buffer.get(start) & 0xff;
        int reserved = type == PacketType.ONE_RTT ? PacketHeader.SHORT_RESERVED_BITS : PacketHeader.LONG_RESERVED_BITS;
        if ((first & reserved) != 0) {
            throw new QuicException(QuicException.PROTOCOL_VIOLATION, "reserved header bits set");
        }
        return new Packet((PacketHeader.Numbered) header, buffer.slice(payloadOffset, plainEnd - payloadOffset));
    }

    /**
     * Removes header and payload protection in one step, for levels without key phases.
     *
     * @param keys the receiver's keys for the packet's level ({@link
     *     io.github.mahmoudimus.quic.crypto.Keys#remote()})
     * @param largestPacketNumber the largest packet number processed in this space, or -1
     * @return the packet, or null if it failed authentication
     * @throws QuicException with {@code PROTOCOL_VIOLATION} if reserved bits are set
     */
    public Packet unprotect(DirectionalKeys keys, long largestPacketNumber) throws QuicException {
        removeHeaderProtection(keys.header(), largestPacketNumber);
        return decrypt(keys.packet());
    }
}
