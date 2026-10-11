/*
 * Ported from quinn-proto src/packet.rs (Packet) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.packet;

import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * A packet with protection removed: its full header and its plaintext payload of frames.
 *
 * @param header the header, with the recovered packet number
 * @param payload the plaintext frames: a view into the datagram buffer, valid as long as the
 *     buffer is not reused
 */
public record Packet(PacketHeader.Numbered header, ByteBuffer payload) {

    /**
     * A packet.
     *
     * @param header the header
     * @param payload the plaintext payload
     */
    public Packet {
        Objects.requireNonNull(header, "header");
        payload = payload.slice();
    }

    /**
     * The payload, as an independent view whose position the caller may move.
     *
     * @return a duplicate of the payload view
     */
    @Override
    public ByteBuffer payload() {
        return payload.duplicate();
    }
}
