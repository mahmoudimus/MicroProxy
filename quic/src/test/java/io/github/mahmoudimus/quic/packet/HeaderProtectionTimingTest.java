package io.github.mahmoudimus.quic.packet;

import static org.junit.jupiter.api.Assertions.*;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.crypto.HeaderKey;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Random;
import org.junit.jupiter.api.Test;

/** Fixed-address integration checks; these assertions do not measure JVM timing. */
class HeaderProtectionTimingTest {
    private static byte[] contents(ByteBuffer buffer) {
        byte[] bytes = new byte[buffer.capacity()];
        buffer.duplicate().clear().get(bytes);
        return bytes;
    }

    @Test
    void everyLengthPreservesWireBytesAndBufferState() {
        Random random = new Random(0x512ab3L);
        for (CipherSuite suite : CipherSuite.values()) {
            for (int length = 1; length <= 4; length++) {
                for (int kind = 0; kind < 4; kind++) {
                    for (ByteOrder order : new ByteOrder[]{ByteOrder.BIG_ENDIAN, ByteOrder.LITTLE_ENDIAN}) {
                        ByteBuffer buffer = kind == 0 ? ByteBuffer.allocate(64) : kind == 2 ? ByteBuffer.allocate(80) : ByteBuffer.allocateDirect(80);
                        if (kind >= 2) {
                            buffer.position(7).limit(71);
                            buffer = buffer.slice();
                        } else if (kind == 1) {
                            buffer.limit(64);
                            buffer = buffer.slice();
                        }
                        buffer.order(order);
                        byte[] original = new byte[64];
                        random.nextBytes(original);
                        int start = 3, pn = 11;
                        original[start] = (byte) ((kind % 2 == 0 ? 0xc0 : 0x40) | (length - 1));
                        buffer.put(original).position(17).limit(50).mark();
                        HeaderKey key = HeaderKey.of(suite, new byte[suite.keyLength()]);
                        byte[] sample = java.util.Arrays.copyOfRange(original, pn + 4, pn + 20);
                        byte[] mask = key.mask(sample);
                        byte[] protectedBytes = original.clone();
                        protectedBytes[start] ^= (byte) (mask[0] & ((original[start] & 0x80) != 0 ? 15 : 31));
                        for (int i = 0; i < length; i++) protectedBytes[pn + i] ^= mask[i + 1];
                        key.protect(buffer, start, pn);
                        assertArrayEquals(protectedBytes, contents(buffer));
                        assertEquals(length, key.unprotect(buffer, start, pn));
                        assertArrayEquals(original, contents(buffer), "following ciphertext must stay unchanged");
                        assertEquals(17, buffer.position());
                        assertEquals(50, buffer.limit());
                        assertSame(order, buffer.order());
                        assertDoesNotThrow(buffer::reset);
                    }
                }
            }
        }
    }

    @Test
    void rejectionBeforeWritesPreservesPacketBytes() {
        HeaderKey key = HeaderKey.of(CipherSuite.TLS_AES_128_GCM_SHA256, new byte[16]);
        ByteBuffer shortPacket = ByteBuffer.allocate(20);
        byte[] before = contents(shortPacket);
        assertThrows(IndexOutOfBoundsException.class, () -> key.unprotect(shortPacket, 0, 1));
        assertArrayEquals(before, contents(shortPacket));
        ByteBuffer readOnly = ByteBuffer.allocate(32).asReadOnlyBuffer();
        assertThrows(java.nio.ReadOnlyBufferException.class, () -> key.unprotect(readOnly, 0, 1));
        assertArrayEquals(new byte[32], contents(readOnly));
    }

    @Test
    void fixedPrefixReadDoesNotDependOnBufferByteOrder() {
        for (ByteOrder order : new ByteOrder[]{ByteOrder.BIG_ENDIAN, ByteOrder.LITTLE_ENDIAN}) {
            ByteBuffer buffer = ByteBuffer.wrap(new byte[]{9, (byte) 0x80, 0x23, (byte) 0xfe, 0x45, 8}).order(order);
            buffer.position(5).mark();
            for (int length = 1; length <= 4; length++) {
                long expected = PacketNumber.read(buffer.duplicate().position(1), length);
                assertEquals(expected, PacketNumber.readProtected(buffer, 1, length));
                assertEquals(5, buffer.position());
                assertDoesNotThrow(buffer::reset);
            }
        }
    }

    private static long referenceDecode(long largest, long truncated, int length) {
        long expected = largest + 1, win = 1L << (8 * length), half = win / 2;
        long candidate = (expected & ~(win - 1)) | (truncated & (win - 1));
        if (candidate <= expected - half && candidate < (1L << 62) - win) return candidate + win;
        if (candidate > expected + half && candidate >= win) return candidate - win;
        return candidate;
    }

    @Test
    void reconstructionPreservesAllSignedOverflowAndWindowEdges() {
        long[] boundary = {-1, 0, 1, 127, 128, 255, 256, (1L << 62) - 1,
                1L << 62, Long.MAX_VALUE, Long.MIN_VALUE, Long.MIN_VALUE + 1};
        Random random = new Random(0x773bb9L);
        for (int length = 1; length <= 4; length++) {
            for (long largest : boundary) for (long truncated : boundary) {
                assertEquals(referenceDecode(largest, truncated, length), PacketNumber.decode(largest, truncated, length));
            }
            for (int i = 0; i < 20_000; i++) {
                long largest = random.nextLong(), truncated = random.nextLong();
                assertEquals(referenceDecode(largest, truncated, length), PacketNumber.decode(largest, truncated, length));
            }
        }
    }
}
