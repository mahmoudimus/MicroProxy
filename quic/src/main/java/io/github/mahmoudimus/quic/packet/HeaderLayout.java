/*
 * Ported from quinn-proto src/packet.rs (PartialEncode) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.packet;

/**
 * Where an encoded header's fields sit in the packet buffer, so that protection can fill in the
 * Length field and mask the packet number once the payload is written. All offsets are absolute
 * buffer indexes.
 *
 * @param start the index of the first header byte
 * @param lengthOffset the index of the two-byte Length field, or -1 for headers without one
 * @param packetNumberOffset the index of the packet number, or -1 for unprotected packets
 * @param packetNumberLength the packet number length, 1 to 4, or 0 for unprotected packets
 * @param payloadOffset the index just past the header, where the payload starts
 */
public record HeaderLayout(int start, int lengthOffset, int packetNumberOffset, int packetNumberLength, int payloadOffset) {

    /**
     * The header length.
     *
     * @return {@code payloadOffset - start}
     */
    public int headerLength() {
        return payloadOffset - start;
    }
}
