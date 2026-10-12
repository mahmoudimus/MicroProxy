/*
 * Ported from quinn-proto src/packet.rs (Header, InitialHeader and Header::encode) (Apache-2.0),
 * with QUIC version 2 type bits (RFC 9369).
 */
package io.github.mahmoudimus.quic.packet;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.VarInt;
import io.github.mahmoudimus.quic.crypto.RetryIntegrity;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * A decoded QUIC packet header (RFC 9000 section 17), or one to encode. Protected packets carry a
 * full packet number and the length it is sent with; Retry and Version Negotiation packets have
 * none.
 *
 * <p>{@link #encode(ByteBuffer)} writes the header with the packet number unprotected and, for
 * long headers, a two-byte Length placeholder; {@link PacketProtection#protect} fills it in.
 * Records are immutable; byte-array components are copied in and out.
 */
public sealed interface PacketHeader permits PacketHeader.Numbered, PacketHeader.Retry, PacketHeader.VersionNegotiation {

    /** The Header Form bit, set in long headers. */
    int LONG_HEADER_FORM = 0x80;
    /** The Fixed Bit, set in every version 1 and 2 packet unless greased (RFC 9287). */
    int FIXED_BIT = 0x40;
    /** The latency spin bit of short headers. */
    int SPIN_BIT = 0x20;
    /** The reserved bits of long headers, zero once header protection is removed. */
    int LONG_RESERVED_BITS = 0x0c;
    /** The reserved bits of short headers, zero once header protection is removed. */
    int SHORT_RESERVED_BITS = 0x18;
    /** The Key Phase bit of short headers. */
    int KEY_PHASE_BIT = 0x04;

    /**
     * The packet type.
     *
     * @return the type
     */
    PacketType type();

    /**
     * The Destination Connection ID.
     *
     * @return the connection ID
     */
    ConnectionId destinationId();

    /**
     * Writes the header at the buffer's position.
     *
     * @param out the buffer
     * @return where the fields landed
     * @throws java.nio.BufferOverflowException if the buffer has too little room
     */
    HeaderLayout encode(ByteBuffer out);

    /** A header of a protected packet, with a packet number. */
    sealed interface Numbered extends PacketHeader permits Initial, ZeroRtt, Handshake, Short {

        /**
         * The full packet number.
         *
         * @return 0 to 2<sup>62</sup>-1
         */
        long packetNumber();

        /**
         * The number of packet number bytes on the wire.
         *
         * @return 1 to 4
         */
        int packetNumberLength();
    }

    /**
     * An Initial packet header (RFC 9000 section 17.2.2).
     *
     * @param version the QUIC version
     * @param destinationId the Destination Connection ID
     * @param sourceId the Source Connection ID
     * @param token the address validation token, empty if none
     * @param packetNumber the full packet number
     * @param packetNumberLength the packet number length on the wire, 1 to 4
     */
    record Initial(QuicVersion version, ConnectionId destinationId, ConnectionId sourceId, byte[] token,
            long packetNumber, int packetNumberLength) implements Numbered {

        /**
         * An Initial header.
         *
         * @param version the QUIC version
         * @param destinationId the Destination Connection ID
         * @param sourceId the Source Connection ID
         * @param token the address validation token, empty if none
         * @param packetNumber the full packet number
         * @param packetNumberLength the packet number length on the wire, 1 to 4
         */
        public Initial {
            Objects.requireNonNull(version, "version");
            Objects.requireNonNull(destinationId, "destinationId");
            Objects.requireNonNull(sourceId, "sourceId");
            token = token.clone();
            checkNumber(packetNumber, packetNumberLength);
        }

        @Override
        public PacketType type() {
            return PacketType.INITIAL;
        }

        /**
         * The token.
         *
         * @return a copy of the token bytes
         */
        @Override
        public byte[] token() {
            return token.clone();
        }

        @Override
        public HeaderLayout encode(ByteBuffer out) {
            int start = out.position();
            writeLongPrefix(out, PacketType.INITIAL, version, packetNumberLength - 1, destinationId, sourceId);
            VarInt.write(out, token.length);
            out.put(token);
            return finishLong(out, start, packetNumber, packetNumberLength);
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Initial i && version == i.version && destinationId.equals(i.destinationId)
                    && sourceId.equals(i.sourceId) && Arrays.equals(token, i.token)
                    && packetNumber == i.packetNumber && packetNumberLength == i.packetNumberLength;
        }

        @Override
        public int hashCode() {
            return Objects.hash(version, destinationId, sourceId, Arrays.hashCode(token), packetNumber, packetNumberLength);
        }

        @Override
        public String toString() {
            return "Initial[version=" + version + ", destinationId=" + destinationId + ", sourceId=" + sourceId
                    + ", token=" + HexFormat.of().formatHex(token) + ", packetNumber=" + packetNumber
                    + ", packetNumberLength=" + packetNumberLength + "]";
        }
    }

    /**
     * A 0-RTT packet header (RFC 9000 section 17.2.3).
     *
     * @param version the QUIC version
     * @param destinationId the Destination Connection ID
     * @param sourceId the Source Connection ID
     * @param packetNumber the full packet number
     * @param packetNumberLength the packet number length on the wire, 1 to 4
     */
    record ZeroRtt(QuicVersion version, ConnectionId destinationId, ConnectionId sourceId, long packetNumber,
            int packetNumberLength) implements Numbered {

        /**
         * A 0-RTT header.
         *
         * @param version the QUIC version
         * @param destinationId the Destination Connection ID
         * @param sourceId the Source Connection ID
         * @param packetNumber the full packet number
         * @param packetNumberLength the packet number length on the wire, 1 to 4
         */
        public ZeroRtt {
            Objects.requireNonNull(version, "version");
            Objects.requireNonNull(destinationId, "destinationId");
            Objects.requireNonNull(sourceId, "sourceId");
            checkNumber(packetNumber, packetNumberLength);
        }

        @Override
        public PacketType type() {
            return PacketType.ZERO_RTT;
        }

        @Override
        public HeaderLayout encode(ByteBuffer out) {
            int start = out.position();
            writeLongPrefix(out, PacketType.ZERO_RTT, version, packetNumberLength - 1, destinationId, sourceId);
            return finishLong(out, start, packetNumber, packetNumberLength);
        }
    }

    /**
     * A Handshake packet header (RFC 9000 section 17.2.4).
     *
     * @param version the QUIC version
     * @param destinationId the Destination Connection ID
     * @param sourceId the Source Connection ID
     * @param packetNumber the full packet number
     * @param packetNumberLength the packet number length on the wire, 1 to 4
     */
    record Handshake(QuicVersion version, ConnectionId destinationId, ConnectionId sourceId, long packetNumber,
            int packetNumberLength) implements Numbered {

        /**
         * A Handshake header.
         *
         * @param version the QUIC version
         * @param destinationId the Destination Connection ID
         * @param sourceId the Source Connection ID
         * @param packetNumber the full packet number
         * @param packetNumberLength the packet number length on the wire, 1 to 4
         */
        public Handshake {
            Objects.requireNonNull(version, "version");
            Objects.requireNonNull(destinationId, "destinationId");
            Objects.requireNonNull(sourceId, "sourceId");
            checkNumber(packetNumber, packetNumberLength);
        }

        @Override
        public PacketType type() {
            return PacketType.HANDSHAKE;
        }

        @Override
        public HeaderLayout encode(ByteBuffer out) {
            int start = out.position();
            writeLongPrefix(out, PacketType.HANDSHAKE, version, packetNumberLength - 1, destinationId, sourceId);
            return finishLong(out, start, packetNumber, packetNumberLength);
        }
    }

    /**
     * A short (1-RTT) packet header (RFC 9000 section 17.3.1). It carries no version: the
     * connection's version applies.
     *
     * @param spin the latency spin bit
     * @param keyPhase the key phase bit
     * @param destinationId the Destination Connection ID
     * @param packetNumber the full packet number
     * @param packetNumberLength the packet number length on the wire, 1 to 4
     */
    record Short(boolean spin, boolean keyPhase, ConnectionId destinationId, long packetNumber,
            int packetNumberLength) implements Numbered {

        /**
         * A short header.
         *
         * @param spin the latency spin bit
         * @param keyPhase the key phase bit
         * @param destinationId the Destination Connection ID
         * @param packetNumber the full packet number
         * @param packetNumberLength the packet number length on the wire, 1 to 4
         */
        public Short {
            Objects.requireNonNull(destinationId, "destinationId");
            checkNumber(packetNumber, packetNumberLength);
        }

        @Override
        public PacketType type() {
            return PacketType.ONE_RTT;
        }

        @Override
        public HeaderLayout encode(ByteBuffer out) {
            int start = out.position();
            out.put((byte) (FIXED_BIT | (spin ? SPIN_BIT : 0) | (keyPhase ? KEY_PHASE_BIT : 0) | (packetNumberLength - 1)));
            destinationId.writeTo(out);
            int pnOffset = out.position();
            PacketNumber.write(out, packetNumber, packetNumberLength);
            return new HeaderLayout(start, -1, pnOffset, packetNumberLength, out.position());
        }
    }

    /**
     * A Retry packet (RFC 9000 section 17.2.5): the whole packet, since it has no payload beyond
     * the token and the integrity tag. The four unused bits of the first byte are encoded as ones,
     * as in the RFC 9001 and RFC 9369 samples.
     *
     * @param version the QUIC version
     * @param destinationId the Destination Connection ID (the client's Source Connection ID)
     * @param sourceId the Source Connection ID the server chose
     * @param token the Retry token
     * @param integrityTag the 16-byte Retry Integrity Tag
     */
    record Retry(QuicVersion version, ConnectionId destinationId, ConnectionId sourceId, byte[] token,
            byte[] integrityTag) implements PacketHeader {

        /**
         * A Retry packet.
         *
         * @param version the QUIC version
         * @param destinationId the Destination Connection ID
         * @param sourceId the Source Connection ID
         * @param token the Retry token
         * @param integrityTag the 16-byte Retry Integrity Tag
         */
        public Retry {
            Objects.requireNonNull(version, "version");
            Objects.requireNonNull(destinationId, "destinationId");
            Objects.requireNonNull(sourceId, "sourceId");
            token = token.clone();
            if (integrityTag.length != RetryIntegrity.TAG_LENGTH) {
                throw new IllegalArgumentException("Retry integrity tag length " + integrityTag.length);
            }
            integrityTag = integrityTag.clone();
        }

        /**
         * A Retry packet with its integrity tag computed for the client's original Destination
         * Connection ID.
         *
         * @param version the QUIC version
         * @param destinationId the Destination Connection ID (the client's Source Connection ID)
         * @param sourceId the Source Connection ID the server chose
         * @param token the Retry token
         * @param originalDestinationId the Destination Connection ID of the client's Initial
         * @return the Retry packet
         */
        public static Retry create(QuicVersion version, ConnectionId destinationId, ConnectionId sourceId,
                byte[] token, ConnectionId originalDestinationId) {
            ByteBuffer buf = ByteBuffer.allocate(7 + destinationId.length() + sourceId.length() + token.length);
            writeLongPrefix(buf, PacketType.RETRY, version, 0x0f, destinationId, sourceId);
            buf.put(token);
            byte[] tag = RetryIntegrity.tag(version, originalDestinationId, buf.flip());
            return new Retry(version, destinationId, sourceId, token, tag);
        }

        @Override
        public PacketType type() {
            return PacketType.RETRY;
        }

        /**
         * The Retry token.
         *
         * @return a copy of the token
         */
        @Override
        public byte[] token() {
            return token.clone();
        }

        /**
         * The Retry Integrity Tag.
         *
         * @return a copy of the 16-byte tag
         */
        @Override
        public byte[] integrityTag() {
            return integrityTag.clone();
        }

        @Override
        public HeaderLayout encode(ByteBuffer out) {
            int start = out.position();
            writeLongPrefix(out, PacketType.RETRY, version, 0x0f, destinationId, sourceId);
            out.put(token);
            out.put(integrityTag);
            return new HeaderLayout(start, -1, -1, 0, out.position());
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Retry r && version == r.version && destinationId.equals(r.destinationId)
                    && sourceId.equals(r.sourceId) && Arrays.equals(token, r.token)
                    && Arrays.equals(integrityTag, r.integrityTag);
        }

        @Override
        public int hashCode() {
            return Objects.hash(version, destinationId, sourceId, Arrays.hashCode(token), Arrays.hashCode(integrityTag));
        }

        @Override
        public String toString() {
            HexFormat hex = HexFormat.of();
            return "Retry[version=" + version + ", destinationId=" + destinationId + ", sourceId=" + sourceId
                    + ", token=" + hex.formatHex(token) + ", integrityTag=" + hex.formatHex(integrityTag) + "]";
        }
    }

    /**
     * A Version Negotiation packet (RFC 9000 section 17.2.1): the whole packet. The first byte is
     * encoded as {@code 0xc0}, with the bit that the Fixed Bit occupies in other packets set, as
     * RFC 9000 recommends for multiplexing.
     *
     * @param destinationId the Destination Connection ID (the client's Source Connection ID)
     * @param sourceId the Source Connection ID (the client's Destination Connection ID)
     * @param versions the supported version numbers
     */
    record VersionNegotiation(ConnectionId destinationId, ConnectionId sourceId, List<Integer> versions)
            implements PacketHeader {

        /**
         * A Version Negotiation packet.
         *
         * @param destinationId the Destination Connection ID
         * @param sourceId the Source Connection ID
         * @param versions the supported version numbers
         */
        public VersionNegotiation {
            Objects.requireNonNull(destinationId, "destinationId");
            Objects.requireNonNull(sourceId, "sourceId");
            versions = List.copyOf(versions);
        }

        @Override
        public PacketType type() {
            return PacketType.VERSION_NEGOTIATION;
        }

        @Override
        public HeaderLayout encode(ByteBuffer out) {
            int start = out.position();
            out.put((byte) (LONG_HEADER_FORM | FIXED_BIT));
            out.putInt(0);
            out.put((byte) destinationId.length());
            destinationId.writeTo(out);
            out.put((byte) sourceId.length());
            sourceId.writeTo(out);
            for (int v : versions) {
                out.putInt(v);
            }
            return new HeaderLayout(start, -1, -1, 0, out.position());
        }
    }

    private static void checkNumber(long packetNumber, int packetNumberLength) {
        if (packetNumber < 0 || packetNumber > PacketNumber.MAX) {
            throw new IllegalArgumentException("packet number " + packetNumber);
        }
        if (packetNumberLength < 1 || packetNumberLength > 4) {
            throw new IllegalArgumentException("packet number length " + packetNumberLength);
        }
    }

    private static void writeLongPrefix(ByteBuffer out, PacketType type, QuicVersion version, int lowBits,
            ConnectionId destinationId, ConnectionId sourceId) {
        out.put((byte) (LONG_HEADER_FORM | FIXED_BIT | type.longTypeBits(version) << 4 | lowBits));
        out.putInt(version.wireValue());
        out.put((byte) destinationId.length());
        destinationId.writeTo(out);
        out.put((byte) sourceId.length());
        sourceId.writeTo(out);
    }

    private static HeaderLayout finishLong(ByteBuffer out, int start, long packetNumber, int packetNumberLength) {
        int lengthOffset = out.position();
        // Placeholder: PacketProtection.protect writes the real value in these two bytes.
        out.putShort((short) 0x4000);
        int pnOffset = out.position();
        PacketNumber.write(out, packetNumber, packetNumberLength);
        return new HeaderLayout(start, lengthOffset, pnOffset, packetNumberLength, out.position());
    }
}
