/*
 * Ported from quinn-proto src/shared.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

/**
 * A QUIC connection ID (RFC 9000 section 5.1): 0 to 20 opaque bytes with value semantics.
 *
 * <p>Instances are immutable and thread-safe; the bytes are copied in and out.
 */
public final class ConnectionId implements Comparable<ConnectionId> {

    /** The longest connection ID QUIC version 1 and 2 allow, in bytes. */
    public static final int MAX_LENGTH = 20;

    /** The zero-length connection ID. */
    public static final ConnectionId EMPTY = new ConnectionId(new byte[0]);

    private final byte[] bytes;

    private ConnectionId(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * A connection ID with a copy of some bytes.
     *
     * @param bytes 0 to {@link #MAX_LENGTH} bytes
     * @return the connection ID
     * @throws IllegalArgumentException if there are more than {@link #MAX_LENGTH} bytes
     */
    public static ConnectionId of(byte... bytes) {
        return of(bytes, 0, bytes.length);
    }

    /**
     * A connection ID with a copy of part of an array.
     *
     * @param bytes the array
     * @param offset the first byte
     * @param length the length, 0 to {@link #MAX_LENGTH}
     * @return the connection ID
     * @throws IllegalArgumentException if the length is out of range
     * @throws IndexOutOfBoundsException if the range is outside the array
     */
    public static ConnectionId of(byte[] bytes, int offset, int length) {
        if (length < 0 || length > MAX_LENGTH) {
            throw new IllegalArgumentException("connection ID length " + length);
        }
        if (length == 0) {
            return EMPTY;
        }
        return new ConnectionId(Arrays.copyOfRange(bytes, offset, Math.addExact(offset, length)));
    }

    /**
     * Reads a connection ID of known length at the buffer's position.
     *
     * @param in the buffer; its position moves past the connection ID
     * @param length the length, 0 to {@link #MAX_LENGTH}
     * @return the connection ID
     * @throws IllegalArgumentException if the length is out of range
     * @throws BufferUnderflowException if fewer than {@code length} bytes remain
     */
    public static ConnectionId read(ByteBuffer in, int length) {
        if (length < 0 || length > MAX_LENGTH) {
            throw new IllegalArgumentException("connection ID length " + length);
        }
        if (in.remaining() < length) {
            throw new BufferUnderflowException();
        }
        if (length == 0) {
            return EMPTY;
        }
        byte[] b = new byte[length];
        in.get(b);
        return new ConnectionId(b);
    }

    /**
     * A random connection ID. Use a {@link java.security.SecureRandom} for IDs sent on the wire.
     *
     * @param random the source of randomness
     * @param length the length, 0 to {@link #MAX_LENGTH}
     * @return the connection ID
     * @throws IllegalArgumentException if the length is out of range
     */
    public static ConnectionId random(Random random, int length) {
        if (length < 0 || length > MAX_LENGTH) {
            throw new IllegalArgumentException("connection ID length " + length);
        }
        byte[] b = new byte[length];
        random.nextBytes(b);
        return length == 0 ? EMPTY : new ConnectionId(b);
    }

    /**
     * The length in bytes.
     *
     * @return 0 to {@link #MAX_LENGTH}
     */
    public int length() {
        return bytes.length;
    }

    /**
     * Whether this is the zero-length connection ID.
     *
     * @return true if the length is zero
     */
    public boolean isEmpty() {
        return bytes.length == 0;
    }

    /**
     * One byte of the ID.
     *
     * @param index the index, below {@link #length()}
     * @return the byte
     */
    public byte get(int index) {
        return bytes[index];
    }

    /**
     * A copy of the bytes.
     *
     * @return a new array
     */
    public byte[] toByteArray() {
        return bytes.clone();
    }

    /**
     * Writes the bytes, without a length prefix.
     *
     * @param out the buffer, written at its position
     */
    public void writeTo(ByteBuffer out) {
        out.put(bytes);
    }

    /**
     * Writes the bytes into an array, without a length prefix.
     *
     * @param out the array
     * @param offset where to write
     * @return the offset just past the bytes
     */
    public int writeTo(byte[] out, int offset) {
        System.arraycopy(bytes, 0, out, offset, bytes.length);
        return offset + bytes.length;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ConnectionId other && Arrays.equals(bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    /** Orders by length, then by unsigned bytes. */
    @Override
    public int compareTo(ConnectionId o) {
        int c = Integer.compare(bytes.length, o.bytes.length);
        return c != 0 ? c : Arrays.compareUnsigned(bytes, o.bytes);
    }

    /** The bytes in lowercase hexadecimal. */
    @Override
    public String toString() {
        return HexFormat.of().formatHex(bytes);
    }
}
