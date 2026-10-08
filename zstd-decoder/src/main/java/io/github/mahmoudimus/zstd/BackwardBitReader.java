package io.github.mahmoudimus.zstd;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

/**
 * Reads a backward bitstream (RFC 8878 section 4.1): written forwards, read from the end. The
 * last byte's highest set bit marks the end; bits are consumed from the most significant end
 * towards the start. Reading past the start yields zeros and leaves {@link #position()}
 * negative, which callers check to detect overflow.
 */
final class BackwardBitReader {

    private static final VarHandle LONG_LE = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);

    private final byte[] buf;
    private final int start;
    private final int end;
    private long position;

    BackwardBitReader(byte[] buf, int start, int end) throws ZstdException {
        if (end <= start) {
            throw ZstdException.corrupt("empty bitstream");
        }
        int last = buf[end - 1] & 0xff;
        if (last == 0) {
            throw ZstdException.corrupt("bitstream has no end mark");
        }
        this.buf = buf;
        this.start = start;
        this.end = end;
        this.position = (long) (end - start) * 8 - (8 - highBit(last));
    }

    /** Bits not yet read; negative once the reader has read past the start. */
    long position() {
        return position;
    }

    /** Reads {@code n} bits (0 to 56). */
    long read(int n) {
        if (n == 0) {
            return 0;
        }
        position -= n;
        long p = position;
        if (p >= 0) {
            return extract((int) p, n);
        }
        if (p + n <= 0) {
            return 0;
        }
        return extract(0, (int) (p + n)) << (int) -p;
    }

    private long extract(int bit, int n) {
        int index = start + (bit >>> 3);
        long word;
        if (index + 8 <= end) {
            word = (long) LONG_LE.get(buf, index);
        } else {
            word = 0;
            for (int i = index, shift = 0; i < end; i++, shift += 8) {
                word |= (buf[i] & 0xffL) << shift;
            }
        }
        return (word >>> (bit & 7)) & ((1L << n) - 1);
    }

    static int highBit(int value) {
        return 31 - Integer.numberOfLeadingZeros(value);
    }
}
