// Ported from rustls src/msgs/codec.rs (the Codec encoders and LengthPrefixedBuffer) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import java.util.Arrays;

/**
 * A growable buffer for TLS encodings. Length-prefixed structures are written by {@link
 * #open(int)}, which reserves the prefix, and {@link #close(int)}, which fills it in.
 */
final class Writer {

    private byte[] buf = new byte[256];
    private int len;

    private void ensure(int n) {
        if (len + n > buf.length) {
            buf = Arrays.copyOf(buf, Math.max(buf.length * 2, len + n));
        }
    }

    Writer u8(int v) {
        ensure(1);
        buf[len++] = (byte) v;
        return this;
    }

    Writer u16(int v) {
        ensure(2);
        buf[len++] = (byte) (v >>> 8);
        buf[len++] = (byte) v;
        return this;
    }

    Writer u24(int v) {
        ensure(3);
        buf[len++] = (byte) (v >>> 16);
        buf[len++] = (byte) (v >>> 8);
        buf[len++] = (byte) v;
        return this;
    }

    Writer u32(long v) {
        ensure(4);
        buf[len++] = (byte) (v >>> 24);
        buf[len++] = (byte) (v >>> 16);
        buf[len++] = (byte) (v >>> 8);
        buf[len++] = (byte) v;
        return this;
    }

    Writer bytes(byte[] b) {
        ensure(b.length);
        System.arraycopy(b, 0, buf, len, b.length);
        len += b.length;
        return this;
    }

    Writer vector8(byte[] b) {
        return u8(checkLength(b.length, 1)).bytes(b);
    }

    Writer vector16(byte[] b) {
        return u16(checkLength(b.length, 2)).bytes(b);
    }

    Writer vector24(byte[] b) {
        return u24(checkLength(b.length, 3)).bytes(b);
    }

    /**
     * Reserves a length prefix of {@code width} bytes.
     *
     * @return the marker to pass to {@link #close(int)}
     */
    int open(int width) {
        ensure(width);
        int marker = (width << 24) | len;
        len += width;
        return marker;
    }

    /** Writes the length of everything since {@link #open(int)} into its prefix. */
    void close(int marker) {
        int width = marker >>> 24;
        int at = marker & 0xffffff;
        int n = checkLength(len - at - width, width);
        for (int i = 0; i < width; i++) {
            buf[at + i] = (byte) (n >>> (8 * (width - 1 - i)));
        }
    }

    private static int checkLength(int n, int width) {
        if (n >= 1 << (8 * width)) {
            throw new IllegalArgumentException("length " + n + " does not fit in " + width + " bytes");
        }
        return n;
    }

    int length() {
        return len;
    }

    byte[] toByteArray() {
        return Arrays.copyOf(buf, len);
    }
}
