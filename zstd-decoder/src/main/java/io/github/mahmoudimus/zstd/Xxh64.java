package io.github.mahmoudimus.zstd;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

/** Streaming XXH64 with seed 0, for frame checksums. */
final class Xxh64 {

    private static final long P1 = 0x9E3779B185EBCA87L;
    private static final long P2 = 0xC2B2AE3D27D4EB4FL;
    private static final long P3 = 0x165667B19E3779F9L;
    private static final long P4 = 0x85EBCA77C2B2AE63L;
    private static final long P5 = 0x27D4EB2F165667C5L;
    private static final VarHandle LONG_LE = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);
    private static final VarHandle INT_LE = MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);

    private long v1 = P1 + P2;
    private long v2 = P2;
    private long v3 = 0;
    private long v4 = -P1;
    private long total;
    private final byte[] pending = new byte[32];
    private int pendingSize;

    void update(byte[] b, int off, int len) {
        total += len;
        if (pendingSize > 0) {
            int take = Math.min(len, 32 - pendingSize);
            System.arraycopy(b, off, pending, pendingSize, take);
            pendingSize += take;
            off += take;
            len -= take;
            if (pendingSize < 32) return;
            stripe(pending, 0);
            pendingSize = 0;
        }
        while (len >= 32) {
            stripe(b, off);
            off += 32;
            len -= 32;
        }
        System.arraycopy(b, off, pending, 0, len);
        pendingSize = len;
    }

    private void stripe(byte[] b, int off) {
        v1 = round(v1, (long) LONG_LE.get(b, off));
        v2 = round(v2, (long) LONG_LE.get(b, off + 8));
        v3 = round(v3, (long) LONG_LE.get(b, off + 16));
        v4 = round(v4, (long) LONG_LE.get(b, off + 24));
    }

    long digest() {
        long h;
        if (total >= 32) {
            h = Long.rotateLeft(v1, 1) + Long.rotateLeft(v2, 7) + Long.rotateLeft(v3, 12) + Long.rotateLeft(v4, 18);
            h = merge(h, v1);
            h = merge(h, v2);
            h = merge(h, v3);
            h = merge(h, v4);
        } else {
            h = P5;
        }
        h += total;
        int i = 0;
        for (; i + 8 <= pendingSize; i += 8) {
            h ^= round(0, (long) LONG_LE.get(pending, i));
            h = Long.rotateLeft(h, 27) * P1 + P4;
        }
        if (i + 4 <= pendingSize) {
            h ^= ((int) INT_LE.get(pending, i) & 0xFFFFFFFFL) * P1;
            h = Long.rotateLeft(h, 23) * P2 + P3;
            i += 4;
        }
        for (; i < pendingSize; i++) {
            h ^= (pending[i] & 0xffL) * P5;
            h = Long.rotateLeft(h, 11) * P1;
        }
        h ^= h >>> 33;
        h *= P2;
        h ^= h >>> 29;
        h *= P3;
        h ^= h >>> 32;
        return h;
    }

    private static long round(long acc, long input) {
        acc += input * P2;
        acc = Long.rotateLeft(acc, 31);
        return acc * P1;
    }

    private static long merge(long acc, long value) {
        acc ^= round(0, value);
        return acc * P1 + P4;
    }
}
