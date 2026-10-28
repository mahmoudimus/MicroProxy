/*
 * Ported from quinn-proto src/connection/packet_builder.rs and src/packet.rs (Header::encode and
 * PartialEncode::finish) (Apache-2.0), reduced to building and protecting packets.
 */
package io.github.mahmoudimus.quic.packet;

import io.github.mahmoudimus.quic.crypto.DirectionalKeys;
import io.github.mahmoudimus.quic.crypto.PacketKey;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * Builds a datagram of one or more coalesced packets: write a header, fill the frame space, then
 * pad and protect. A client's Initial datagram must reach {@value #MIN_INITIAL_DATAGRAM} bytes
 * (RFC 9000 section 14.1), which {@link #finish(int)} pads to.
 *
 * <pre>{@code
 * PacketBuilder b = new PacketBuilder(ByteBuffer.allocate(1500), 1500);
 * ByteBuffer frames = b.begin(new PacketHeader.Initial(V1, dcid, scid, new byte[0], 0, 1), keys.local());
 * Frame.Crypto.encode(frames, 0, clientHello, frames.remaining());
 * b.finish(PacketBuilder.MIN_INITIAL_DATAGRAM);
 * ByteBuffer datagram = b.datagram();
 * }</pre>
 *
 * <p>Instances are not thread-safe.
 */
public final class PacketBuilder {

    /** The smallest datagram that may carry a client's Initial packet (RFC 9000 section 14.1). */
    public static final int MIN_INITIAL_DATAGRAM = 1200;

    private final ByteBuffer buffer;
    private final int datagramStart;
    private final int datagramLimit;
    private PacketHeader.Numbered header;
    private DirectionalKeys keys;
    private HeaderLayout layout;
    private ByteBuffer frames;

    /**
     * A builder that writes from the buffer's position.
     *
     * @param buffer the datagram buffer; packets are written from its position on
     * @param maxDatagramSize the largest datagram to build, such as the path MTU's UDP payload
     */
    public PacketBuilder(ByteBuffer buffer, int maxDatagramSize) {
        this.buffer = buffer.duplicate();
        this.datagramStart = buffer.position();
        this.datagramLimit = Math.min(buffer.limit(), datagramStart + maxDatagramSize);
        this.buffer.limit(datagramLimit);
    }

    /**
     * Starts a packet after any already finished in this datagram.
     *
     * @param header the header, with the packet number to send
     * @param keys the sender's keys for the header's level
     * @return the frame space: a buffer whose position is where frames go and whose limit leaves
     *     room for the AEAD tag; write frames at its position
     * @throws IllegalStateException if a packet is already in progress
     * @throws BufferOverflowException if the header does not fit; the builder is unchanged
     */
    public ByteBuffer begin(PacketHeader.Numbered header, DirectionalKeys keys) {
        if (this.header != null) {
            throw new IllegalStateException("finish the current packet first");
        }
        Objects.requireNonNull(header, "header");
        Objects.requireNonNull(keys, "keys");
        int mark = buffer.position();
        try {
            layout = header.encode(buffer);
        } catch (BufferOverflowException e) {
            buffer.position(mark);
            throw e;
        }
        this.header = header;
        this.keys = keys;
        int limit = datagramLimit - PacketKey.TAG_LENGTH;
        if (layout.lengthOffset() >= 0) {
            limit = Math.min(limit, layout.packetNumberOffset() + PacketProtection.MAX_LONG_PACKET_REMAINDER
                    - PacketKey.TAG_LENGTH);
        }
        frames = buffer.duplicate().limit(Math.max(limit, buffer.position()));
        return frames;
    }

    /**
     * The frame space left in the current packet.
     *
     * @return the bytes that frames may still use
     */
    public int remaining() {
        return frames == null ? 0 : frames.remaining();
    }

    /**
     * Finishes the current packet: pads it so that header protection can sample it and, if
     * {@code minDatagramSize} asks for it, so that the datagram reaches that size; then protects
     * it.
     *
     * @param minDatagramSize the size the datagram must reach with this packet, or 0
     * @return the index just past the protected packet
     * @throws IllegalStateException if no packet is in progress or the padding does not fit
     */
    public int finish(int minDatagramSize) {
        return finish(minDatagramSize, null);
    }

    /**
     * {@link #finish(int)}, letting {@code rewrite} lay the plaintext payload out again before it is
     * protected: it gets the payload, padding included, from its position to its limit, and must
     * keep its length.
     *
     * @param minDatagramSize the size the datagram must reach with this packet, or 0
     * @param rewrite the rewrite, or null for none
     * @return the index just past the protected packet
     */
    public int finish(int minDatagramSize, java.util.function.Consumer<ByteBuffer> rewrite) {
        if (header == null) {
            throw new IllegalStateException("no packet in progress");
        }
        int payloadEnd = frames.position();
        int minPayloadEnd = layout.payloadOffset() + PacketProtection.minPayloadLength(layout.packetNumberLength());
        int wanted = Math.max(minPayloadEnd, datagramStart + minDatagramSize - PacketKey.TAG_LENGTH);
        if (wanted > frames.limit()) {
            throw new IllegalStateException("no room to pad the packet to " + (wanted - datagramStart) + " bytes");
        }
        while (payloadEnd < wanted) {
            frames.put(payloadEnd++, (byte) 0); // PADDING frames
        }
        if (rewrite != null) {
            rewrite.accept(buffer.duplicate().limit(payloadEnd).position(layout.payloadOffset()).slice());
        }
        int end = PacketProtection.protect(buffer, layout, payloadEnd, header.packetNumber(), keys);
        buffer.position(end);
        header = null;
        keys = null;
        layout = null;
        frames = null;
        return end;
    }

    /**
     * Finishes the current packet without padding beyond what header protection needs.
     *
     * @return the index just past the protected packet
     */
    public int finish() {
        return finish(0);
    }

    /**
     * Pads the datagram with zero bytes after its last finished packet, up to {@code minDatagramSize}:
     * bytes a receiver discards as not a packet, as neqo pads its Initial datagrams.
     *
     * @param minDatagramSize the size the datagram must reach
     * @return the index just past the padding
     * @throws IllegalStateException if a packet is in progress or the padding does not fit
     */
    public int padAfter(int minDatagramSize) {
        if (header != null) throw new IllegalStateException("a packet is in progress");
        int end = datagramStart + minDatagramSize;
        if (end > buffer.limit()) throw new IllegalStateException("no room to pad the datagram to " + minDatagramSize + " bytes");
        while (buffer.position() < end) buffer.put((byte) 0);
        return buffer.position();
    }

    /**
     * The datagram built so far: every finished packet.
     *
     * @return a view from the first packet to the end of the last finished one
     */
    public ByteBuffer datagram() {
        return buffer.duplicate().limit(buffer.position()).position(datagramStart).slice();
    }
}
