package io.github.mahmoudimus.http3;

/**
 * A QPACK dynamic table (RFC 9204 §3.2): a FIFO of fields bounded by a capacity in octets, with
 * absolute indexing (the first entry ever inserted is 0, §3.2.4). It evicts whatever it is told
 * to; deciding what may be evicted is the encoder's job (§2.1.1).
 */
final class QpackDynamicTable {

    private HeaderField[] ring = new HeaderField[8];
    private int oldest; // ring slot of the oldest entry
    private int length;
    private long size;
    private long capacity;
    private long insertCount;

    /** The total number of entries ever inserted: the absolute index the next one gets. */
    long insertCount() {
        return insertCount;
    }

    /** The absolute index of the oldest entry still present (equal to the insert count when empty). */
    long firstIndex() {
        return insertCount - length;
    }

    int length() {
        return length;
    }

    /** The sum of the entries' sizes. */
    long size() {
        return size;
    }

    long capacity() {
        return capacity;
    }

    /** Whether the entry with this absolute index is present. */
    boolean contains(long absoluteIndex) {
        return absoluteIndex >= firstIndex() && absoluteIndex < insertCount;
    }

    /** The entry with this absolute index, which must be present. */
    HeaderField get(long absoluteIndex) {
        if (!contains(absoluteIndex)) throw new IndexOutOfBoundsException("no dynamic table entry " + absoluteIndex);
        return ring[(int) ((oldest + (absoluteIndex - firstIndex())) % ring.length)];
    }

    /** Adds an entry no larger than the capacity, evicting the oldest entries to make room (§3.2.2). */
    void add(HeaderField field) {
        long entrySize = field.size();
        if (entrySize > capacity) throw new IllegalStateException("entry larger than the table capacity");
        while (size + entrySize > capacity) evictOldest();
        if (length == ring.length) grow();
        ring[(oldest + length) % ring.length] = field;
        length++;
        size += entrySize;
        insertCount++;
    }

    /** Changes the capacity, evicting the oldest entries until the table fits (§3.2.2). */
    void setCapacity(long capacity) {
        this.capacity = capacity;
        while (size > capacity) evictOldest();
    }

    void evictOldest() {
        size -= ring[oldest].size();
        ring[oldest] = null;
        oldest = (oldest + 1) % ring.length;
        length--;
    }

    private void grow() {
        HeaderField[] bigger = new HeaderField[ring.length * 2];
        for (int i = 0; i < length; i++) bigger[i] = ring[(oldest + i) % ring.length];
        ring = bigger;
        oldest = 0;
    }
}
