// Ported from rustls src/msgs/codec.rs (Reader, and the length-prefixed reads of its Codec
// implementations) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.QuicException;
import java.util.Arrays;

/**
 * A bounds-checked cursor over a TLS-encoded message. Every read past the end, and every length
 * prefix that overruns its enclosing structure, fails with a {@code decode_error} alert, so a
 * decoder built on it can only fail with a {@link QuicException}.
 */
final class Reader {

    private final byte[] buf;
    private final int limit;
    private int pos;

    Reader(byte[] buf) {
        this(buf, 0, buf.length);
    }

    private Reader(byte[] buf, int offset, int length) {
        this.buf = buf;
        this.pos = offset;
        this.limit = offset + length;
    }

    int remaining() {
        return limit - pos;
    }

    boolean hasRemaining() {
        return pos < limit;
    }

    private void need(int n, String what) throws QuicException {
        if (n < 0 || remaining() < n) {
            throw TlsAlert.decodeError("truncated " + what);
        }
    }

    int u8(String what) throws QuicException {
        need(1, what);
        return buf[pos++] & 0xff;
    }

    int u16(String what) throws QuicException {
        need(2, what);
        int v = ((buf[pos] & 0xff) << 8) | (buf[pos + 1] & 0xff);
        pos += 2;
        return v;
    }

    int u24(String what) throws QuicException {
        need(3, what);
        int v = ((buf[pos] & 0xff) << 16) | ((buf[pos + 1] & 0xff) << 8) | (buf[pos + 2] & 0xff);
        pos += 3;
        return v;
    }

    long u32(String what) throws QuicException {
        need(4, what);
        long v = ((long) (buf[pos] & 0xff) << 24)
                | ((buf[pos + 1] & 0xff) << 16)
                | ((buf[pos + 2] & 0xff) << 8)
                | (buf[pos + 3] & 0xff);
        pos += 4;
        return v;
    }

    byte[] bytes(int n, String what) throws QuicException {
        need(n, what);
        byte[] out = Arrays.copyOfRange(buf, pos, pos + n);
        pos += n;
        return out;
    }

    /** All the bytes left. */
    byte[] rest() {
        byte[] out = Arrays.copyOfRange(buf, pos, limit);
        pos = limit;
        return out;
    }

    /** An opaque vector with a one-byte length, {@code opaque x<min..2^8-1>}. */
    byte[] vector8(int min, String what) throws QuicException {
        return checkedMin(bytes(u8(what), what), min, what);
    }

    /** An opaque vector with a two-byte length, {@code opaque x<min..2^16-1>}. */
    byte[] vector16(int min, String what) throws QuicException {
        return checkedMin(bytes(u16(what), what), min, what);
    }

    /** An opaque vector with a three-byte length, {@code opaque x<min..2^24-1>}. */
    byte[] vector24(int min, String what) throws QuicException {
        return checkedMin(bytes(u24(what), what), min, what);
    }

    private static byte[] checkedMin(byte[] v, int min, String what) throws QuicException {
        if (v.length < min) {
            throw TlsAlert.decodeError(what + " is shorter than " + min + " bytes");
        }
        return v;
    }

    /** A reader over the next {@code n} bytes, which this reader skips. */
    Reader sub(int n, String what) throws QuicException {
        need(n, what);
        Reader sub = new Reader(buf, pos, n);
        pos += n;
        return sub;
    }

    Reader sub8(String what) throws QuicException {
        return sub(u8(what), what);
    }

    Reader sub16(String what) throws QuicException {
        return sub(u16(what), what);
    }

    Reader sub24(String what) throws QuicException {
        return sub(u24(what), what);
    }

    /** Fails unless every byte has been read. */
    void expectEnd(String what) throws QuicException {
        if (hasRemaining()) {
            throw TlsAlert.decodeError("trailing data in " + what);
        }
    }

    /** A list of two-byte values in a vector with a two-byte length, such as supported groups. */
    int[] u16List16(int minItems, String what) throws QuicException {
        Reader list = sub16(what);
        if ((list.remaining() & 1) != 0) {
            throw TlsAlert.decodeError(what + " has an odd length");
        }
        int[] out = new int[list.remaining() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = list.u16(what);
        }
        if (out.length < minItems) {
            throw TlsAlert.decodeError(what + " is empty");
        }
        return out;
    }
}
