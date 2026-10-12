/*
 * Ported from quinn-proto src/packet.rs (PartialEncode::finish) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.packet;

import io.github.mahmoudimus.quic.crypto.DirectionalKeys;
import io.github.mahmoudimus.quic.crypto.HeaderKey;
import io.github.mahmoudimus.quic.crypto.PacketKey;
import java.nio.ByteBuffer;

/**
 * Applies packet protection (RFC 9001 section 5) to an encoded packet in place: fills in the
 * Length field, seals the payload and then masks the header. Removing protection is {@link
 * ProtectedPacket#unprotect}.
 *
 * <p>All methods are static; thread confinement follows from the keys passed in.
 */
public final class PacketProtection {

    /**
     * The longest long header packet, from the packet number to the end of the tag, that the
     * two-byte Length field this module writes can describe.
     */
    public static final int MAX_LONG_PACKET_REMAINDER = (1 << 14) - 1;

    private PacketProtection() {}

    /**
     * The fewest payload bytes a packet needs so that the header protection sample, which starts
     * four bytes after the packet number, lies within the ciphertext and tag.
     *
     * @param packetNumberLength the packet number length, 1 to 4
     * @return the minimum plaintext payload length
     */
    public static int minPayloadLength(int packetNumberLength) {
        return Math.max(0, 4 + HeaderKey.SAMPLE_LENGTH - PacketKey.TAG_LENGTH - packetNumberLength);
    }

    /**
     * Protects an encoded packet in place. The header was written by {@link
     * PacketHeader#encode} at {@code layout}, followed by the plaintext payload up to {@code
     * payloadEnd}; the buffer needs 16 bytes of capacity after it for the tag. Indexes are
     * absolute; the buffer's position and limit are not changed.
     *
     * @param packet the packet buffer
     * @param layout where the header's fields are
     * @param payloadEnd the index just past the plaintext payload
     * @param packetNumber the full packet number in the header
     * @param keys the sender's keys for the packet's level
     * @return the index just past the protected packet
     * @throws IllegalArgumentException if the payload is shorter than {@link #minPayloadLength}
     *     or too long for the Length field, or the header is not a protected one
     */
    public static int protect(ByteBuffer packet, HeaderLayout layout, int payloadEnd, long packetNumber,
            DirectionalKeys keys) {
        int pnOffset = layout.packetNumberOffset();
        if (pnOffset < 0) {
            throw new IllegalArgumentException("Retry and Version Negotiation packets are not protected");
        }
        int payloadLength = payloadEnd - layout.payloadOffset();
        if (payloadLength < minPayloadLength(layout.packetNumberLength())) {
            throw new IllegalArgumentException("payload of " + payloadLength + " bytes is too short to sample");
        }
        int end = payloadEnd + PacketKey.TAG_LENGTH;
        if (layout.lengthOffset() >= 0) {
            int length = end - pnOffset;
            if (length > MAX_LONG_PACKET_REMAINDER) {
                throw new IllegalArgumentException("packet too long for a two-byte Length: " + length);
            }
            packet.putShort(layout.lengthOffset(), (short) (0x4000 | length));
        }
        keys.packet().seal(packetNumber, packet, layout.start(), layout.payloadOffset(), payloadEnd);
        keys.header().protect(packet, layout.start(), pnOffset);
        return end;
    }
}
