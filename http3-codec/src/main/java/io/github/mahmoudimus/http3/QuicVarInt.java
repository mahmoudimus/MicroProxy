package io.github.mahmoudimus.http3;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * QUIC variable-length integers (RFC 9000 §16), which HTTP/3 uses for frame types, lengths,
 * settings, stream types, push IDs and error codes. The two most significant bits of the first
 * byte give the length (1, 2, 4 or 8 bytes); the rest is the value, big-endian, from 0 to
 * 2^62 - 1.
 *
 * <p>Writing always uses the shortest encoding. Reading accepts any encoding, including
 * non-minimal ones, as RFC 9000 requires.
 */
public final class QuicVarInt {

    /** The largest value, 2^62 - 1. */
    public static final long MAX_VALUE = (1L << 62) - 1;

    /** The longest encoding, in bytes. */
    public static final int MAX_LENGTH = 8;

    private QuicVarInt() {}

    /** The length of the shortest encoding of {@code value}. */
    public static int length(long value) {
        check(value);
        if (value < (1L << 6)) return 1;
        if (value < (1L << 14)) return 2;
        if (value < (1L << 30)) return 4;
        return 8;
    }

    /** The total length of an encoding, from its first byte. */
    public static int lengthOf(int firstByte) {
        return 1 << ((firstByte & 0xff) >>> 6);
    }

    /** The shortest encoding of {@code value}. */
    public static byte[] encode(long value) {
        byte[] b = new byte[length(value)];
        write(value, b, 0);
        return b;
    }

    /**
     * Writes the shortest encoding of {@code value} at {@code offset}.
     *
     * @return the offset just past it
     * @throws IndexOutOfBoundsException if it does not fit
     */
    public static int write(long value, byte[] dst, int offset) {
        int n = length(value);
        Objects.checkFromIndexSize(offset, n, dst.length);
        long v = value | ((long) Integer.numberOfTrailingZeros(n) << (8 * n - 2));
        for (int i = n - 1; i >= 0; i--) {
            dst[offset + i] = (byte) v;
            v >>>= 8;
        }
        return offset + n;
    }

    public static void write(long value, OutputStream out) throws IOException {
        out.write(encode(value));
    }

    /**
     * Writes the shortest encoding of {@code value} at the buffer's position.
     *
     * @throws BufferOverflowException if it does not fit; nothing is written then
     */
    public static void write(long value, ByteBuffer buf) {
        int n = length(value);
        if (buf.remaining() < n) throw new BufferOverflowException();
        long v = value | ((long) Integer.numberOfTrailingZeros(n) << (8 * n - 2));
        for (int i = n - 1; i >= 0; i--) buf.put((byte) (v >>> (8 * i)));
    }

    /**
     * Reads one integer.
     *
     * @return the value, or -1 if the stream ended before its first byte
     * @throws EOFException if the stream ends inside it
     */
    public static long read(InputStream in) throws IOException {
        int first = in.read();
        if (first < 0) return -1;
        int n = lengthOf(first);
        long v = first & 0x3f;
        for (int i = 1; i < n; i++) {
            int b = in.read();
            if (b < 0) throw new EOFException("stream ended inside a variable-length integer");
            v = (v << 8) | b;
        }
        return v;
    }

    /**
     * Reads one integer from the buffer's position.
     *
     * @return the value, with the position moved past it; or -1, with the position unchanged, if
     *     the buffer does not hold all of it
     */
    public static long read(ByteBuffer buf) {
        if (!buf.hasRemaining()) return -1;
        int pos = buf.position();
        int first = buf.get(pos) & 0xff;
        int n = lengthOf(first);
        if (buf.remaining() < n) return -1;
        long v = first & 0x3f;
        for (int i = 1; i < n; i++) v = (v << 8) | (buf.get(pos + i) & 0xff);
        buf.position(pos + n);
        return v;
    }

    /**
     * Reads one integer from {@code src[offset..end)}.
     *
     * @return the value, or -1 if the range does not hold all of it; {@link #lengthOf(int)} of the
     *     first byte tells how many bytes it took
     */
    public static long read(byte[] src, int offset, int end) {
        if (offset >= end) return -1;
        int first = src[offset] & 0xff;
        int n = lengthOf(first);
        if (end - offset < n) return -1;
        long v = first & 0x3f;
        for (int i = 1; i < n; i++) v = (v << 8) | (src[offset + i] & 0xff);
        return v;
    }

    private static void check(long value) {
        if (value < 0 || value > MAX_VALUE) {
            throw new IllegalArgumentException("variable-length integer out of range 0 to 2^62-1: " + value);
        }
    }
}
