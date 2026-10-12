/*
 * Ported from quinn-proto src/range_set/tests.rs and src/range_set/btree_range_set.rs (tests)
 * (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class RangeSetTest {

    private static long[] elts(RangeSet set) {
        return set.elements().toArray();
    }

    @Test
    void mergeAndSplit() {
        RangeSet set = new RangeSet();
        assertTrue(set.insert(0, 2));
        assertTrue(set.contains(0));
        assertTrue(set.insert(2, 4));
        assertTrue(set.contains(3));
        assertFalse(set.insert(1, 3));
        assertEquals(1, set.size());
        assertArrayEquals(new long[] {0, 1, 2, 3}, elts(set));
        assertFalse(set.contains(4));
        assertTrue(set.remove(2, 3));
        assertEquals(2, set.size());
        assertFalse(set.contains(2));
        assertArrayEquals(new long[] {0, 1, 3}, elts(set));
    }

    @Test
    void doubleMergeExact() {
        RangeSet set = new RangeSet();
        assertTrue(set.insert(0, 2));
        assertTrue(set.insert(4, 6));
        assertEquals(2, set.size());
        assertTrue(set.insert(2, 4));
        assertEquals(1, set.size());
        assertArrayEquals(new long[] {0, 1, 2, 3, 4, 5}, elts(set));
    }

    @Test
    void singleMergeLow() {
        RangeSet set = new RangeSet();
        assertTrue(set.insert(0, 2));
        assertTrue(set.insert(4, 6));
        assertTrue(set.insert(2, 3));
        assertEquals(2, set.size());
        assertArrayEquals(new long[] {0, 1, 2, 4, 5}, elts(set));
    }

    @Test
    void singleMergeHigh() {
        RangeSet set = new RangeSet();
        assertTrue(set.insert(0, 2));
        assertTrue(set.insert(4, 6));
        assertTrue(set.insert(3, 4));
        assertEquals(2, set.size());
        assertArrayEquals(new long[] {0, 1, 3, 4, 5}, elts(set));
    }

    @Test
    void doubleMergeWide() {
        RangeSet set = new RangeSet();
        assertTrue(set.insert(0, 2));
        assertTrue(set.insert(4, 6));
        assertTrue(set.insert(1, 5));
        assertEquals(1, set.size());
        assertArrayEquals(new long[] {0, 1, 2, 3, 4, 5}, elts(set));
    }

    @Test
    void doubleRemove() {
        RangeSet set = new RangeSet();
        assertTrue(set.insert(0, 2));
        assertTrue(set.insert(4, 6));
        assertTrue(set.remove(1, 5));
        assertEquals(2, set.size());
        assertArrayEquals(new long[] {0, 5}, elts(set));
    }

    @Test
    void insertMultiple() {
        RangeSet set = new RangeSet();
        assertTrue(set.insert(0, 1));
        assertTrue(set.insert(2, 3));
        assertTrue(set.insert(4, 5));
        assertTrue(set.insert(0, 5));
        assertEquals(1, set.size());
    }

    @Test
    void removeMultiple() {
        RangeSet set = new RangeSet();
        assertTrue(set.insert(0, 1));
        assertTrue(set.insert(2, 3));
        assertTrue(set.insert(4, 5));
        assertTrue(set.remove(0, 5));
        assertTrue(set.isEmpty());
    }

    @Test
    void doubleInsert() {
        RangeSet set = new RangeSet();
        assertTrue(set.insert(0, 2));
        assertFalse(set.insert(0, 2));
        assertTrue(set.insert(2, 4));
        assertFalse(set.insert(2, 4));
        assertFalse(set.insert(0, 4));
        assertFalse(set.insert(1, 2));
        assertFalse(set.insert(1, 3));
        assertFalse(set.insert(1, 4));
        assertEquals(1, set.size());
    }

    @Test
    void skipEmptyRanges() {
        RangeSet set = new RangeSet();
        assertFalse(set.insert(2, 2));
        assertFalse(set.insert(4, 4));
        assertFalse(set.insert(0, 0));
        assertEquals(0, set.size());
    }

    @Test
    void minMax() {
        RangeSet set = new RangeSet();
        set.insert(1, 3);
        set.insert(4, 5);
        set.insert(6, 10);
        assertEquals(1, set.min());
        assertEquals(9, set.max());
    }

    @Test
    void compareInsertToReference() {
        int max = 50;
        for (int start = 0; start <= max; start++) {
            for (int end = 0; end <= max; end++) {
                RangeSet set = initialSet();
                boolean[] ref = initialReference(max);
                assertEquals(refInsert(ref, start, end), set.insert(start, end), "insert " + start + ".." + end);
                assertSame(ref, set);
            }
        }
    }

    @Test
    void compareRemoveToReference() {
        int max = 50;
        for (int start = 0; start <= max; start++) {
            for (int end = 0; end <= max; end++) {
                RangeSet set = initialSet();
                boolean[] ref = initialReference(max);
                assertEquals(refRemove(ref, start, end), set.remove(start, end), "remove " + start + ".." + end);
                assertSame(ref, set);
            }
        }
    }

    @Test
    void compareReplaceToReference() {
        int max = 50;
        for (int start = 0; start <= max; start++) {
            for (int end = start; end <= max; end++) {
                RangeSet set = initialSet();
                boolean[] ref = initialReference(max);
                List<RangeSet.Range> overlaps = set.replace(start, end);
                long overlapCount = overlaps.stream().mapToLong(RangeSet.Range::length).sum();
                long expected = IntStream.range(start, end).filter(i -> ref[i]).count();
                assertEquals(expected, overlapCount, "replace " + start + ".." + end);
                for (RangeSet.Range r : overlaps) {
                    for (long i = r.start(); i < r.end(); i++) {
                        assertTrue(ref[(int) i]);
                    }
                }
                refInsert(ref, start, end);
                assertSame(ref, set);
            }
        }
    }

    @Test
    void replaceContained() {
        RangeSet set = new RangeSet();
        set.insert(2, 4);
        assertEquals(List.of(new RangeSet.Range(2, 4)), set.replace(1, 5));
        assertEquals(1, set.size());
        assertEquals(new RangeSet.Range(1, 5), set.peekMin());
    }

    @Test
    void replaceContains() {
        RangeSet set = new RangeSet();
        set.insert(1, 5);
        assertEquals(List.of(new RangeSet.Range(2, 4)), set.replace(2, 4));
        assertEquals(1, set.size());
        assertEquals(new RangeSet.Range(1, 5), set.peekMin());
    }

    @Test
    void replacePred() {
        RangeSet set = new RangeSet();
        set.insert(2, 4);
        assertEquals(List.of(new RangeSet.Range(3, 4)), set.replace(3, 5));
        assertEquals(new RangeSet.Range(2, 5), set.peekMin());
    }

    @Test
    void replaceSucc() {
        RangeSet set = new RangeSet();
        set.insert(2, 4);
        assertEquals(List.of(new RangeSet.Range(2, 3)), set.replace(1, 3));
        assertEquals(new RangeSet.Range(1, 4), set.peekMin());
    }

    @Test
    void replaceExactPred() {
        RangeSet set = new RangeSet();
        set.insert(2, 4);
        assertEquals(List.of(), set.replace(4, 6));
        assertEquals(1, set.size());
        assertEquals(new RangeSet.Range(2, 6), set.peekMin());
    }

    @Test
    void replaceExactSucc() {
        RangeSet set = new RangeSet();
        set.insert(2, 4);
        assertEquals(List.of(), set.replace(0, 2));
        assertEquals(1, set.size());
        assertEquals(new RangeSet.Range(0, 4), set.peekMin());
    }

    @Test
    void replaceEmpty() {
        RangeSet set = new RangeSet();
        set.replace(3, 3);
        set.replace(6, 10);
        set.replace(5, 5);
        set.replace(2, 7);
        assertEquals("[2..10]", set.toString());
    }

    @Test
    void descendingIteration() {
        RangeSet set = new RangeSet();
        set.insert(0, 2);
        set.insert(5, 7);
        set.insert(9, 10);
        StringBuilder sb = new StringBuilder();
        for (RangeSet.Range r : set.descending()) {
            sb.append(r.start()).append('-').append(r.end()).append(' ');
        }
        assertEquals("9-10 5-7 0-2 ", sb.toString());
        assertEquals(new RangeSet.Range(0, 2), set.popMin());
        assertEquals(2, set.size());
    }

    private static RangeSet initialSet() {
        RangeSet set = new RangeSet();
        int[][] ranges = {{2, 6}, {10, 14}, {14, 14}, {18, 19}, {20, 21}, {22, 24}, {26, 30}, {34, 38}, {42, 44}};
        for (int[] r : ranges) {
            set.insert(r[0], r[1]);
        }
        return set;
    }

    private static boolean[] initialReference(int max) {
        boolean[] ref = new boolean[max];
        int[][] ranges = {{2, 6}, {10, 14}, {14, 14}, {18, 19}, {20, 21}, {22, 24}, {26, 30}, {34, 38}, {42, 44}};
        for (int[] r : ranges) {
            refInsert(ref, r[0], r[1]);
        }
        return ref;
    }

    private static boolean refInsert(boolean[] ref, int start, int end) {
        boolean changed = false;
        for (int i = start; i < end; i++) {
            changed |= !ref[i];
            ref[i] = true;
        }
        return changed;
    }

    private static boolean refRemove(boolean[] ref, int start, int end) {
        boolean changed = false;
        for (int i = start; i < end; i++) {
            changed |= ref[i];
            ref[i] = false;
        }
        return changed;
    }

    private static void assertSame(boolean[] ref, RangeSet set) {
        int runs = 0;
        boolean last = false;
        for (boolean b : ref) {
            if (b && !last) {
                runs++;
            }
            last = b;
        }
        assertEquals(runs, set.size());
        assertEquals(runs == 0, set.isEmpty());
        assertArrayEquals(IntStream.range(0, ref.length).filter(i -> ref[i]).asLongStream().toArray(), elts(set));
    }
}
