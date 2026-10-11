/*
 * Ported from quinn-proto src/connection/assembler.rs (Chunk) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * A run of received stream or CRYPTO data and its offset in the stream.
 *
 * @param offset the stream offset of the first byte
 * @param bytes the data, between its position and limit; a view, not a copy
 */
public record Chunk(long offset, ByteBuffer bytes) {

    /**
     * A chunk.
     *
     * @param offset the stream offset of the first byte
     * @param bytes the data
     */
    public Chunk {
        Objects.requireNonNull(bytes, "bytes");
    }

    /**
     * The number of bytes.
     *
     * @return {@code bytes.remaining()}
     */
    public int length() {
        return bytes.remaining();
    }

    /**
     * The stream offset just past the chunk.
     *
     * @return {@code offset + length()}
     */
    public long end() {
        return offset + bytes.remaining();
    }

    /**
     * A copy of the bytes.
     *
     * @return a new array
     */
    public byte[] toByteArray() {
        byte[] out = new byte[bytes.remaining()];
        bytes.duplicate().get(out);
        return out;
    }
}
