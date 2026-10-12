/*
 * Ported from quinn-proto src/connection/assembler.rs (tests) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

class AssemblerTest {

    private static ByteBuffer b(String s) {
        return ByteBuffer.wrap(s.getBytes(StandardCharsets.US_ASCII));
    }

    private static String next(Assembler x, int size) {
        Chunk c = x.read(size, true);
        return c == null ? null : new String(c.toByteArray(), StandardCharsets.US_ASCII);
    }

    private static Chunk chunk(long offset, String s) {
        return new Chunk(offset, b(s));
    }

    private static Chunk nextUnordered(Assembler x) {
        Chunk c = x.read(Integer.MAX_VALUE, false);
        return c == null ? null : new Chunk(c.offset(), ByteBuffer.wrap(c.toByteArray()));
    }

    private static Chunk nextOrdered(Assembler x) {
        Chunk c = x.read(Integer.MAX_VALUE, true);
        return c == null ? null : new Chunk(c.offset(), ByteBuffer.wrap(c.toByteArray()));
    }

    @Test
    void assembleOrdered() {
        Assembler x = new Assembler();
        assertNull(next(x, 32));
        x.insert(0, b("123"), 3);
        assertEquals("1", next(x, 1));
        assertEquals("23", next(x, 3));
        x.insert(3, b("456"), 3);
        assertEquals("456", next(x, 32));
        x.insert(6, b("789"), 3);
        x.insert(9, b("10"), 2);
        assertEquals("789", next(x, 32));
        assertEquals("10", next(x, 32));
        assertNull(next(x, 32));
    }

    @Test
    void assembleUnordered() {
        Assembler x = new Assembler();
        assertTrue(x.ensureOrdering(false));
        x.insert(3, b("456"), 3);
        assertNull(next(x, 32));
        x.insert(0, b("123"), 3);
        assertEquals(chunk(0, "123"), nextUnordered(x));
        assertEquals(chunk(3, "456"), nextUnordered(x));
        assertNull(nextUnordered(x));
    }

    @Test
    void unorderedAfterOrderedReadDropsAStaleDuplicate() {
        Assembler x = new Assembler();
        x.insert(0, b("abc"), 3);
        x.insert(0, b("abc"), 3);
        assertEquals("abc", next(x, 3));
        assertEquals(3, x.bytesRead());
        x.ensureOrdering(false);
        assertNull(x.read(Integer.MAX_VALUE, false));
        assertEquals(3, x.bytesRead());
    }

    @Test
    void orderedReadAfterUnorderedIsRefused() {
        Assembler x = new Assembler();
        assertTrue(x.ensureOrdering(false));
        assertFalse(x.ensureOrdering(true));
        assertTrue(x.ensureOrdering(false));
    }

    @Test
    void assembleDuplicate() {
        Assembler x = new Assembler();
        x.insert(0, b("123"), 3);
        x.insert(0, b("123"), 3);
        assertEquals("123", next(x, 32));
        assertNull(next(x, 32));
    }

    @Test
    void assembleDuplicateCompact() {
        Assembler x = new Assembler();
        x.insert(0, b("123"), 3);
        x.insert(0, b("123"), 3);
        x.defragment(0);
        assertEquals("123", next(x, 32));
        assertNull(next(x, 32));
    }

    @Test
    void assembleContained() {
        Assembler x = new Assembler();
        x.insert(0, b("12345"), 5);
        x.insert(1, b("234"), 3);
        assertEquals("12345", next(x, 32));
        assertNull(next(x, 32));
    }

    @Test
    void assembleContainedCompact() {
        Assembler x = new Assembler();
        x.insert(0, b("12345"), 5);
        x.insert(1, b("234"), 3);
        x.defragment(0);
        assertEquals("12345", next(x, 32));
        assertNull(next(x, 32));
    }

    @Test
    void assembleContains() {
        Assembler x = new Assembler();
        x.insert(1, b("234"), 3);
        x.insert(0, b("12345"), 5);
        assertEquals("12345", next(x, 32));
        assertNull(next(x, 32));
    }

    @Test
    void assembleContainsCompact() {
        Assembler x = new Assembler();
        x.insert(1, b("234"), 3);
        x.insert(0, b("12345"), 5);
        x.defragment(0);
        assertEquals("12345", next(x, 32));
        assertNull(next(x, 32));
    }

    @Test
    void assembleOverlapping() {
        Assembler x = new Assembler();
        x.insert(0, b("123"), 3);
        x.insert(1, b("234"), 3);
        assertEquals("123", next(x, 32));
        assertEquals("4", next(x, 32));
        assertNull(next(x, 32));
    }

    @Test
    void assembleOverlappingCompact() {
        Assembler x = new Assembler();
        x.insert(0, b("123"), 4);
        x.insert(1, b("234"), 4);
        x.defragment(0);
        assertEquals("1234", next(x, 32));
        assertNull(next(x, 32));
    }

    @Test
    void assembleComplex() {
        Assembler x = new Assembler();
        x.insert(0, b("1"), 1);
        x.insert(2, b("3"), 1);
        x.insert(4, b("5"), 1);
        x.insert(0, b("123456"), 6);
        assertEquals("123456", next(x, 32));
        assertNull(next(x, 32));
    }

    @Test
    void assembleComplexCompact() {
        Assembler x = new Assembler();
        x.insert(0, b("1"), 1);
        x.insert(2, b("3"), 1);
        x.insert(4, b("5"), 1);
        x.insert(0, b("123456"), 6);
        x.defragment(0);
        assertEquals("123456", next(x, 32));
        assertNull(next(x, 32));
    }

    @Test
    void assembleOld() {
        Assembler x = new Assembler();
        x.insert(0, b("1234"), 4);
        assertEquals("1234", next(x, 32));
        x.insert(0, b("1234"), 4);
        assertNull(next(x, 32));
    }

    @Test
    void compact() {
        Assembler x = new Assembler();
        x.insert(0, b("abc"), 4);
        x.insert(3, b("def"), 4);
        x.insert(9, b("jkl"), 4);
        x.insert(12, b("mno"), 4);
        x.defragment(0);
        assertEquals(chunk(0, "abcdef"), nextUnordered(x));
        assertEquals(chunk(9, "jklmno"), nextUnordered(x));
    }

    @Test
    void defragWithMissingPrefix() {
        Assembler x = new Assembler();
        x.insert(3, b("def"), 3);
        x.defragment(0);
        assertEquals(chunk(3, "def"), nextUnordered(x));
    }

    @Test
    void defragReadChunk() {
        Assembler x = new Assembler();
        x.insert(3, b("def"), 4);
        x.insert(0, b("abc"), 4);
        x.insert(7, b("hij"), 4);
        x.insert(11, b("lmn"), 4);
        x.defragment(0);
        assertEquals(chunk(0, "abcdef"), nextOrdered(x));
        x.insert(5, b("fghijklmn"), 9);
        assertEquals(chunk(6, "ghijklmn"), nextOrdered(x));
        x.insert(13, b("nopq"), 4);
        assertEquals(chunk(14, "opq"), nextOrdered(x));
        x.insert(15, b("pqrs"), 4);
        assertEquals(chunk(17, "rs"), nextOrdered(x));
        assertNull(nextOrdered(x));
    }

    @Test
    void unorderedHappyPath() {
        Assembler x = new Assembler();
        x.ensureOrdering(false);
        x.insert(0, b("abc"), 3);
        assertEquals(chunk(0, "abc"), nextUnordered(x));
        assertNull(nextUnordered(x));
        x.insert(3, b("def"), 3);
        assertEquals(chunk(3, "def"), nextUnordered(x));
        assertNull(nextUnordered(x));
    }

    @Test
    void unorderedDedup() {
        Assembler x = new Assembler();
        x.ensureOrdering(false);
        x.insert(3, b("def"), 3);
        assertEquals(chunk(3, "def"), nextUnordered(x));
        assertNull(nextUnordered(x));
        x.insert(0, b("a"), 1);
        x.insert(0, b("abcdefghi"), 9);
        x.insert(0, b("abcd"), 4);
        assertEquals(chunk(0, "a"), nextUnordered(x));
        assertEquals(chunk(1, "bc"), nextUnordered(x));
        assertEquals(chunk(6, "ghi"), nextUnordered(x));
        assertNull(nextUnordered(x));
        x.insert(8, b("ijkl"), 4);
        assertEquals(chunk(9, "jkl"), nextUnordered(x));
        assertNull(nextUnordered(x));
        x.insert(12, b("mno"), 3);
        assertEquals(chunk(12, "mno"), nextUnordered(x));
        assertNull(nextUnordered(x));
        x.insert(2, b("cde"), 3);
        assertNull(nextUnordered(x));
    }

    @Test
    void chunksDedup() {
        Assembler x = new Assembler();
        x.insert(3, b("def"), 3);
        assertNull(nextOrdered(x));
        x.insert(0, b("a"), 1);
        x.insert(1, b("bcdefghi"), 9);
        x.insert(0, b("abcd"), 4);
        assertEquals(chunk(0, "abcd"), nextOrdered(x));
        assertEquals(chunk(4, "efghi"), nextOrdered(x));
        assertNull(nextOrdered(x));
        x.insert(8, b("ijkl"), 4);
        assertEquals(chunk(9, "jkl"), nextOrdered(x));
        assertNull(nextOrdered(x));
        x.insert(12, b("mno"), 3);
        assertEquals(chunk(12, "mno"), nextOrdered(x));
        assertNull(nextOrdered(x));
        x.insert(2, b("cde"), 3);
        assertNull(nextOrdered(x));
    }

    @Test
    void orderedEagerDiscard() {
        Assembler x = new Assembler();
        x.insert(0, b("abc"), 3);
        assertEquals(1, x.chunkCount());
        assertEquals(chunk(0, "abc"), nextOrdered(x));
        x.insert(0, b("ab"), 2);
        assertEquals(0, x.chunkCount());
        x.insert(2, b("cd"), 2);
        assertArrayEquals(new long[] {3, 1}, x.front());
    }

    @Test
    void orderedInsertUnorderedRead() {
        Assembler x = new Assembler();
        x.insert(0, b("abc"), 3);
        x.insert(0, b("abc"), 3);
        x.ensureOrdering(false);
        Chunk c = x.read(3, false);
        assertEquals(chunk(0, "abc"), new Chunk(c.offset(), ByteBuffer.wrap(c.toByteArray())));
        assertNull(x.read(3, false));
    }

    @Test
    void orderedLosslessStreamIsNotRejected() {
        int frameLen = 32;
        Assembler x = new Assembler();
        ByteBuffer data = ByteBuffer.allocate(frameLen);
        for (long offset = 0; offset < 2L * Assembler.COMPACT_THRESHOLD * frameLen; offset += frameLen) {
            assertTrue(x.insert(offset, data, frameLen), "contiguous lossless data must not be rejected");
        }
    }

    @Test
    void defragRespectsMaxChunksAtRoundingBoundary() {
        Assembler x = new Assembler();
        ByteBuffer data = ByteBuffer.allocate(Assembler.MIN_RETAINED_CHUNK_SIZE);
        long offset = 0;
        for (int i = 0; i < Assembler.MAX_CHUNKS; i++) {
            assertTrue(x.insert(offset, data, data.remaining()));
            offset += data.remaining();
        }
        assertTrue(x.insert(offset, b("x"), 1));
        x.defragment(0);
        assertTrue(x.chunkCount() <= Assembler.MAX_CHUNKS);
    }

    @Test
    void boundedChunksUnderLowOverAllocation() {
        Assembler x = new Assembler();
        long offset = 1; // withhold offset 0 so an ordered reader can never drain anything
        boolean result = true;
        for (int i = 0; i < Assembler.MAX_CHUNKS * 8; i++) {
            result = x.insert(offset, b("gap"), 3);
            if (!result) {
                break;
            }
            offset += 3 + 1;
        }
        assertFalse(result);
        assertTrue(x.chunkCount() <= Assembler.COMPACT_THRESHOLD + 1, "chunk count " + x.chunkCount());
    }

    @Test
    void boundedChunksUnorderedOverlapFlood() {
        Assembler x = new Assembler();
        x.ensureOrdering(false);
        long top = 1_000_000;
        x.insert(top, b("ab"), 2);
        for (long k = 0; k < 4L * Assembler.MAX_CHUNKS; k++) {
            assertTrue(x.insert(top - k - 1, b("ab"), 2));
            assertTrue(x.chunkCount() <= Assembler.COMPACT_THRESHOLD + 1, "chunk count at k=" + k);
        }
    }

    @Test
    void boundedChunksDuplicateFlood() {
        Assembler x = new Assembler();
        for (long i = 0; i < Assembler.MAX_CHUNKS; i++) {
            assertTrue(x.insert(1 + i * 4, b("abc"), 3));
        }
        int maxLen = x.chunkCount();
        for (int i = 0; i < 3 * Assembler.MAX_CHUNKS; i++) {
            assertTrue(x.insert(1, b("abc"), 3), "duplicate flood must not be rejected");
            maxLen = Math.max(maxLen, x.chunkCount());
            assertTrue(x.chunkCount() <= Assembler.COMPACT_THRESHOLD + 1);
        }
        assertTrue(maxLen > Assembler.MAX_CHUNKS, "buffer compacted on every frame (max " + maxLen + ")");
    }

    @Test
    void assembleRandom() {
        randomStream(true);
    }

    @Test
    void assembleRandomUnordered() {
        randomStream(false);
    }

    /** Fragments arriving retransmitted and shuffled must still read back as the exact stream. */
    private static void randomStream(boolean ordered) {
        int len = 2048;
        Random rng = new Random(0xdeadbeefL);
        byte[] stream = new byte[len];
        rng.nextBytes(stream);
        for (int round = 0; round < 64; round++) {
            List<int[]> frags = new ArrayList<>();
            int at = 0;
            while (at < len) {
                int size = Math.min(1 + rng.nextInt(32), len - at);
                frags.add(new int[] {at, size});
                at += size;
            }
            // Retransmits are refragmented from scratch, overlapping the originals arbitrarily
            int originals = frags.size();
            for (int i = 0; i < originals / 4; i++) {
                int start = rng.nextInt(len);
                int end = Math.min(start + 1 + rng.nextInt(64), len);
                int p = start;
                while (p < end) {
                    int size = Math.min(1 + rng.nextInt(32), end - p);
                    frags.add(new int[] {p, size});
                    p += size;
                }
            }
            Collections.shuffle(frags, rng);
            Assembler x = new Assembler();
            if (!ordered) {
                x.ensureOrdering(false);
            }
            boolean[] delivered = new boolean[len];
            for (int[] f : frags) {
                byte[] copy = new byte[f[1]];
                System.arraycopy(stream, f[0], copy, 0, f[1]);
                assertTrue(x.insert(f[0], ByteBuffer.wrap(copy), f[1]));
                assertTrue(x.isSorted());
                if (rng.nextInt(3) == 0) {
                    drain(x, 1 + rng.nextInt(64), ordered, stream, delivered);
                }
            }
            drain(x, Integer.MAX_VALUE, ordered, stream, delivered);
            for (boolean d : delivered) {
                assertTrue(d, "stream did not fully assemble");
            }
        }
    }

    private static void drain(Assembler x, int max, boolean ordered, byte[] stream, boolean[] delivered) {
        Chunk c;
        while ((c = x.read(max, ordered)) != null) {
            int start = (int) c.offset();
            byte[] got = c.toByteArray();
            byte[] want = new byte[got.length];
            System.arraycopy(stream, start, want, 0, got.length);
            assertArrayEquals(want, got);
            for (int i = start; i < start + got.length; i++) {
                assertFalse(delivered[i], "offset " + i + " delivered twice");
                delivered[i] = true;
            }
            assertTrue(x.isSorted());
        }
    }

    @Test
    void orderedPartialOverlap() {
        Assembler x = new Assembler();
        x.insert(0, b("0123456789"), 10);
        x.insert(2, b("23456789abcdef"), 14);
        assertEquals("01234", next(x, 5));
        assertTrue(x.isSorted());
        ByteArrayOutputStream got = new ByteArrayOutputStream();
        got.writeBytes("01234".getBytes(StandardCharsets.US_ASCII));
        Chunk c;
        while ((c = x.read(Integer.MAX_VALUE, true)) != null) {
            got.writeBytes(c.toByteArray());
        }
        assertEquals("0123456789abcdef", got.toString(StandardCharsets.US_ASCII));
    }

    @Test
    void defragMixedOrder() {
        Assembler x = new Assembler();
        x.insert(0, b("a"), 4096); // too badly utilized to be marked defragmented
        x.insert(1, b("bcdefghij"), 9);
        x.defragment(0);
        assertTrue(x.isSorted());
        ByteArrayOutputStream got = new ByteArrayOutputStream();
        Chunk c;
        while ((c = x.read(Integer.MAX_VALUE, true)) != null) {
            got.writeBytes(c.toByteArray());
        }
        assertEquals("abcdefghij", got.toString(StandardCharsets.US_ASCII));
    }

    @Test
    void insertDoesNotMoveTheCallersBuffer() {
        Assembler x = new Assembler();
        ByteBuffer data = b("hello");
        x.insert(0, data);
        assertEquals(0, data.position());
        assertEquals(5, data.remaining());
    }
}
