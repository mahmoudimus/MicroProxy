/*
 * Ported from quinn-proto src/packet.rs (PacketDecodeError::UnsupportedVersion) and src/endpoint.rs
 * (the Version Negotiation response) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.packet;

import java.io.Serial;
import java.nio.ByteBuffer;

/**
 * A long header packet of a version this endpoint does not speak. A server answers it with a
 * Version Negotiation packet ({@link #versionNegotiation}) when the datagram is at least 1200
 * bytes (RFC 9000 section 6.1). The connection IDs follow the version-independent invariants (RFC
 * 8999), so they may be up to 255 bytes long.
 */
public final class UnsupportedVersionException extends PacketDecodeException {

    @Serial
    private static final long serialVersionUID = 1L;

    /** The version number in the packet. */
    private final int version;
    /** The Destination Connection ID. */
    private final byte[] destinationId;
    /** The Source Connection ID. */
    private final byte[] sourceId;

    /**
     * An unsupported version.
     *
     * @param version the version number in the packet
     * @param destinationId the packet's Destination Connection ID
     * @param sourceId the packet's Source Connection ID
     */
    public UnsupportedVersionException(int version, byte[] destinationId, byte[] sourceId) {
        super(String.format("unsupported version 0x%08x", version));
        this.version = version;
        this.destinationId = destinationId.clone();
        this.sourceId = sourceId.clone();
    }

    /**
     * The version number in the packet.
     *
     * @return the 32-bit version
     */
    public int version() {
        return version;
    }

    /**
     * The packet's Destination Connection ID.
     *
     * @return a copy of its 0 to 255 bytes
     */
    public byte[] destinationId() {
        return destinationId.clone();
    }

    /**
     * The packet's Source Connection ID.
     *
     * @return a copy of its 0 to 255 bytes
     */
    public byte[] sourceId() {
        return sourceId.clone();
    }

    /**
     * The Version Negotiation packet that answers this packet: the connection IDs swapped and the
     * supported versions listed (RFC 9000 section 17.2.1).
     *
     * @param supportedVersions the version numbers to offer, often with a reserved one added
     * @return the packet bytes
     */
    public byte[] versionNegotiation(int... supportedVersions) {
        ByteBuffer out = ByteBuffer.allocate(7 + destinationId.length + sourceId.length + 4 * supportedVersions.length);
        out.put((byte) 0xc0);
        out.putInt(0);
        out.put((byte) sourceId.length).put(sourceId);
        out.put((byte) destinationId.length).put(destinationId);
        for (int v : supportedVersions) {
            out.putInt(v);
        }
        return out.array();
    }
}
