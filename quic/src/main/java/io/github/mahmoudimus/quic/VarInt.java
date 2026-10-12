/*
 * Ported from quinn-proto src/varint.rs and src/coding.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * QUIC variable-length integers (RFC 9000 section 16): values below 2<sup>62</sup>, encoded in 1,
 * 2, 4 or 8 bytes with the length in the two most significant bits of the first byte.
 *
 * <p>Values are carried as {@code long}s. The writers always use the shortest encoding; the reader
 * accepts any encoding, as RFC 9000 requires, so callers that need the shortest form (frame types)
 * compare {@link #size(long)} with the bytes consumed.
 *
 * <p>All methods are static and thread-safe.
 */
public final class VarInt {

    /** The largest encodable value, 2<sup>62</sup>-1. */
    public static final long MAX = (1L << 62) - 1;

    /** The longest encoding, in bytes. */
    public static final int MAX_SIZE = 8;

    private VarInt() {}

    /**
     * The length of the shortest encoding of a value.
     *
     * @param value the value, from 0 to {@link #MAX}
     * @return 1, 2, 4 or 8
     * @throws IllegalArgumentException if the value is negative or above {@link #MAX}
     */
    public static int size(long value) {
        if (value < 0) {
            throw new IllegalArgumentException("negative varint " + value);
        } else if (value < (1L << 6)) {
            return 1;
        } else if (value < (1L << 14)) {
            return 2;
        } else if (value < (1L << 30)) {
            return 4;
        } else if (value <= MAX) {
            return 8;
        }
        throw new IllegalArgumentException("varint out of range " + value);
    }

    /**
     * The length of an encoding, read from its first byte.
     *
     * @param firstByte the first byte of the encoding
     * @return 1, 2, 4 or 8
     */
    public static int sizeOf(byte firstByte) {
        return 1 << ((firstByte & 0xff) >>> 6);
    }

    /**
     * The largest value that encodes in at most {@code size} bytes.
     *
     * @param size 1, 2, 4 or 8
     * @return the largest value of that size
     * @throws IllegalArgumentException for any other size
     */
    public static long maxForSize(int size) {
        return switch (size) {
            case 1 -> (1L << 6) - 1;
            case 2 -> (1L << 14) - 1;
            case 4 -> (1L << 30) - 1;
            case 8 -> MAX;
            default -> throw new IllegalArgumentException("varint size " + size);
        };
    }

    /**
     * Writes a value in its shortest encoding.
     *
     * @param out the buffer, written at its position
     * @param value the value, from 0 to {@link #MAX}
     * @throws IllegalArgumentException if the value is out of range
     * @throws BufferOverflowException if the buffer has too little room
     */
    public static void write(ByteBuffer out, long value) {
        writeWithSize(out, value, size(value));
    }

    /**
     * Writes a value in a chosen encoding length, which may be longer than necessary (as the
     * two-byte Length field of a long header is, so that it can be patched once the payload is
     * known).
     *
     * @param out the buffer, written at its position
     * @param value the value
     * @param size the encoding length: 1, 2, 4 or 8, at least {@link #size(long)}
     * @throws IllegalArgumentException if the value does not fit in {@code size} bytes
     * @throws BufferOverflowException if the buffer has too little room
     */
    public static void writeWithSize(ByteBuffer out, long value, int size) {
        if (value < 0 || value > maxForSize(size)) {
            throw new IllegalArgumentException("varint " + value + " does not fit in " + size + " bytes");
        }
        switch (size) {
            case 1 -> out.put((byte) value);
            case 2 -> out.putShort((short) (0x4000 | value));
            case 4 -> out.putInt((int) (0x8000_0000L | value));
            default -> out.putLong(0xc000_0000_0000_0000L | value);
        }
    }

    /**
     * Writes a value in its shortest encoding into an array.
     *
     * @param out the array
     * @param offset where to write
     * @param value the value, from 0 to {@link #MAX}
     * @return the offset just past the encoding
     * @throws IllegalArgumentException if the value is out of range
     * @throws IndexOutOfBoundsException if the array has too little room
     */
    public static int write(byte[] out, int offset, long value) {
        ByteBuffer buf = ByteBuffer.wrap(out, offset, out.length - offset);
        write(buf, value);
        return buf.position();
    }

    /**
     * The shortest encoding of a value.
     *
     * @param value the value, from 0 to {@link #MAX}
     * @return a new array of {@link #size(long)} bytes
     * @throws IllegalArgumentException if the value is out of range
     */
    public static byte[] encode(long value) {
        byte[] out = new byte[size(value)];
        write(ByteBuffer.wrap(out), value);
        return out;
    }

    /**
     * Reads a value at the buffer's position, in any of the four encodings.
     *
     * @param in the buffer; its position moves past the encoding
     * @return the value, from 0 to {@link #MAX}
     * @throws BufferUnderflowException if the buffer ends inside the encoding (the position is
     *     then unchanged)
     */
    public static long read(ByteBuffer in) {
        if (!in.hasRemaining()) {
            throw new BufferUnderflowException();
        }
        int pos = in.position();
        byte first = in.get(pos);
        int size = sizeOf(first);
        if (in.remaining() < size) {
            throw new BufferUnderflowException();
        }
        long value = first & 0x3f;
        for (int i = 1; i < size; i++) {
            value = (value << 8) | (in.get(pos + i) & 0xff);
        }
        in.position(pos + size);
        return value;
    }
}
