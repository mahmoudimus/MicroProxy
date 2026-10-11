/*
 * Ported from quinn-proto src/range_set/btree_range_set.rs and src/range_set/array_range_set.rs
 * (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.TreeMap;
import java.util.stream.LongStream;

/**
 * A set of non-negative {@code long} values stored as disjoint, non-adjacent half-open ranges, for
 * long runs with random insertion and removal: received packet numbers, ACK ranges, received and
 * acknowledged stream offsets.
 *
 * <p>Adjacent and overlapping ranges are always merged, so iteration yields the smallest possible
 * set of ranges, in ascending order.
 *
 * <p><b>Threads.</b> Not thread-safe; a set belongs to one connection, which serializes access.
 */
public final class RangeSet implements Iterable<RangeSet.Range> {

    /**
     * A half-open range {@code [start, end)}.
     *
     * @param start the first value in the range
     * @param end one past the last value in the range
     */
    public record Range(long start, long end) {

        /**
         * The number of values in the range.
         *
         * @return {@code end - start}, or zero for an empty range
         */
        public long length() {
            return Math.max(0, end - start);
        }

        /**
         * Whether the range holds no values.
         *
         * @return true if {@code end <= start}
         */
        public boolean isEmpty() {
            return end <= start;
        }
    }

    /** Start of each range to its exclusive end. */
    private final TreeMap<Long, Long> map;

    /** An empty set. */
    public RangeSet() {
        map = new TreeMap<>();
    }

    /**
     * A copy of another set.
     *
     * @param other the set to copy
     */
    public RangeSet(RangeSet other) {
        map = new TreeMap<>(other.map);
    }

    /**
     * Whether a value is in the set.
     *
     * @param x the value
     * @return true if a range contains it
     */
    public boolean contains(long x) {
        Map.Entry<Long, Long> pred = map.floorEntry(x);
        return pred != null && pred.getValue() > x;
    }

    /**
     * Adds one value.
     *
     * @param x the value
     * @return true if the set changed
     */
    public boolean insertOne(long x) {
        return insert(x, x + 1);
    }

    /**
     * Adds the values {@code [start, end)}, merging with overlapping and adjacent ranges.
     *
     * @param start the first value
     * @param end one past the last value
     * @return true if the set changed; false for an empty range or one already contained
     */
    public boolean insert(long start, long end) {
        if (end <= start) {
            return false;
        }
        Map.Entry<Long, Long> pred = map.floorEntry(start);
        if (pred != null) {
            if (pred.getValue() >= end) {
                return false; // wholly contained
            } else if (pred.getValue() >= start) {
                map.remove(pred.getKey());
                start = pred.getKey(); // extend the overlapping predecessor
            }
        }
        Map.Entry<Long, Long> next;
        while ((next = map.higherEntry(start)) != null && next.getKey() <= end) {
            map.remove(next.getKey());
            end = Math.max(end, next.getValue());
        }
        map.put(start, end);
        return true;
    }

    /**
     * Removes the values {@code [start, end)}.
     *
     * @param start the first value
     * @param end one past the last value
     * @return true if the set changed
     */
    public boolean remove(long start, long end) {
        if (end <= start) {
            return false;
        }
        boolean before = false;
        Map.Entry<Long, Long> pred = map.floorEntry(start);
        if (pred != null && pred.getValue() > start) {
            long ps = pred.getKey();
            long pe = pred.getValue();
            map.remove(ps);
            if (ps < start) {
                map.put(ps, start);
            }
            if (pe > end) {
                map.put(end, pe);
                return true; // cannot overlap anything else
            }
            before = true;
        }
        boolean after = false;
        Map.Entry<Long, Long> next;
        while ((next = map.higherEntry(start)) != null && next.getKey() < end) {
            after = true;
            map.remove(next.getKey());
            if (next.getValue() > end) {
                map.put(end, next.getValue());
                break;
            }
        }
        return before || after;
    }

    /**
     * Adds {@code [start, end)} and returns the parts of it that were already present, in ascending
     * order. Used to deduplicate stream data received out of order.
     *
     * @param start the first value
     * @param end one past the last value
     * @return the intersection of the previous set with the range
     */
    public List<Range> replace(long start, long end) {
        List<Range> overlaps = new ArrayList<>();
        if (end <= start) {
            return overlaps;
        }
        Map.Entry<Long, Long> pred = map.floorEntry(start);
        if (pred != null && pred.getValue() >= start) {
            map.remove(pred.getKey());
            long replacedEnd = Math.min(end, pred.getValue());
            if (start != replacedEnd) {
                overlaps.add(new Range(start, replacedEnd));
            }
            start = Math.min(start, pred.getKey());
            end = Math.max(end, pred.getValue());
        }
        Map.Entry<Long, Long> next;
        while ((next = map.higherEntry(start)) != null && next.getKey() <= end) {
            map.remove(next.getKey());
            long replacedEnd = Math.min(end, next.getValue());
            if (next.getKey() != replacedEnd) {
                overlaps.add(new Range(next.getKey(), replacedEnd));
            }
            end = Math.max(end, next.getValue());
        }
        map.put(start, end);
        return overlaps;
    }

    /**
     * Adds every value of another set.
     *
     * @param other the values to add
     */
    public void add(RangeSet other) {
        for (Map.Entry<Long, Long> e : other.map.entrySet()) {
            insert(e.getKey(), e.getValue());
        }
    }

    /**
     * Removes every value of another set.
     *
     * @param other the values to remove
     */
    public void subtract(RangeSet other) {
        for (Map.Entry<Long, Long> e : other.map.entrySet()) {
            remove(e.getKey(), e.getValue());
        }
    }

    /**
     * Whether the set is empty.
     *
     * @return true if it holds no values
     */
    public boolean isEmpty() {
        return map.isEmpty();
    }

    /**
     * The number of disjoint ranges.
     *
     * @return the range count
     */
    public int size() {
        return map.size();
    }

    /**
     * The smallest value.
     *
     * @return the start of the first range
     * @throws NoSuchElementException if the set is empty
     */
    public long min() {
        return map.firstKey();
    }

    /**
     * The largest value.
     *
     * @return one less than the end of the last range
     * @throws NoSuchElementException if the set is empty
     */
    public long max() {
        return map.lastEntry().getValue() - 1;
    }

    /**
     * The first range.
     *
     * @return the lowest range, or null if the set is empty
     */
    public Range peekMin() {
        Map.Entry<Long, Long> e = map.firstEntry();
        return e == null ? null : new Range(e.getKey(), e.getValue());
    }

    /**
     * Removes and returns the first range.
     *
     * @return the lowest range, or null if the set is empty
     */
    public Range popMin() {
        Map.Entry<Long, Long> e = map.pollFirstEntry();
        return e == null ? null : new Range(e.getKey(), e.getValue());
    }

    /** Removes every value. */
    public void clear() {
        map.clear();
    }

    /**
     * The ranges in ascending order.
     *
     * @return an iterator that does not support removal
     */
    @Override
    public Iterator<Range> iterator() {
        return rangeIterator(map.entrySet().iterator());
    }

    /**
     * The ranges in descending order, as ACK frames list them.
     *
     * @return the ranges, highest first
     */
    public Iterable<Range> descending() {
        return () -> rangeIterator(map.descendingMap().entrySet().iterator());
    }

    /**
     * Every value, in ascending order.
     *
     * @return the values
     */
    public LongStream elements() {
        return map.entrySet().stream().flatMapToLong(e -> LongStream.range(e.getKey(), e.getValue()));
    }

    private static Iterator<Range> rangeIterator(Iterator<Map.Entry<Long, Long>> it) {
        return new Iterator<>() {
            @Override
            public boolean hasNext() {
                return it.hasNext();
            }

            @Override
            public Range next() {
                Map.Entry<Long, Long> e = it.next();
                return new Range(e.getKey(), e.getValue());
            }
        };
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof RangeSet other && map.equals(other.map);
    }

    @Override
    public int hashCode() {
        return map.hashCode();
    }

    /** The ranges, as {@code [a..b, c..d]}. */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("[");
        for (Map.Entry<Long, Long> e : map.entrySet()) {
            if (sb.length() > 1) {
                sb.append(", ");
            }
            sb.append(e.getKey()).append("..").append(e.getValue());
        }
        return sb.append(']').toString();
    }
}
