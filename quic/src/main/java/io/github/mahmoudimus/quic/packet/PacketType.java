/*
 * Ported from quinn-proto src/packet.rs (LongHeaderType, LongType and SpaceId) (Apache-2.0), with
 * the QUIC version 2 type bits of RFC 9369 section 3.2.
 */
package io.github.mahmoudimus.quic.packet;

import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.QuicVersion;

/**
 * The QUIC packet types (RFC 9000 section 17). Long header types carry two type bits whose values
 * differ between version 1 and version 2.
 */
public enum PacketType {
    /** Initial (long header), carrying the first CRYPTO data and an optional token. */
    INITIAL(EncryptionLevel.INITIAL, 0),
    /** 0-RTT (long header), early application data. */
    ZERO_RTT(EncryptionLevel.ZERO_RTT, 1),
    /** Handshake (long header). */
    HANDSHAKE(EncryptionLevel.HANDSHAKE, 2),
    /** Retry (long header), unprotected except for its integrity tag. */
    RETRY(null, 3),
    /** Version Negotiation (long header with version 0), unprotected. */
    VERSION_NEGOTIATION(null, -1),
    /** 1-RTT (short header). */
    ONE_RTT(EncryptionLevel.ONE_RTT, -1);

    private final EncryptionLevel level;
    private final int v1Bits;

    PacketType(EncryptionLevel level, int v1Bits) {
        this.level = level;
        this.v1Bits = v1Bits;
    }

    /**
     * The encryption level whose keys protect this packet type.
     *
     * @return the level, or null for Retry and Version Negotiation packets
     */
    public EncryptionLevel level() {
        return level;
    }

    /**
     * Whether the packet has header and payload protection and a packet number.
     *
     * @return false for Retry and Version Negotiation packets
     */
    public boolean isProtected() {
        return level != null;
    }

    /**
     * Whether the packet uses a long header.
     *
     * @return true for every type but {@link #ONE_RTT}
     */
    public boolean isLongHeader() {
        return this != ONE_RTT;
    }

    /**
     * The two Long Packet Type bits of this type in a version.
     *
     * @param version the QUIC version
     * @return 0 to 3
     * @throws IllegalStateException for {@link #ONE_RTT} and {@link #VERSION_NEGOTIATION}
     */
    public int longTypeBits(QuicVersion version) {
        if (v1Bits < 0) {
            throw new IllegalStateException(this + " has no long packet type");
        }
        return version == QuicVersion.V2 ? (v1Bits + 1) & 0x03 : v1Bits;
    }

    /**
     * The long header type for two type bits in a version.
     *
     * @param version the QUIC version
     * @param bits the Long Packet Type bits, 0 to 3
     * @return {@link #INITIAL}, {@link #ZERO_RTT}, {@link #HANDSHAKE} or {@link #RETRY}
     */
    public static PacketType fromLongTypeBits(QuicVersion version, int bits) {
        int v1 = version == QuicVersion.V2 ? (bits + 3) & 0x03 : bits & 0x03;
        return switch (v1) {
            case 0 -> INITIAL;
            case 1 -> ZERO_RTT;
            case 2 -> HANDSHAKE;
            default -> RETRY;
        };
    }
}
