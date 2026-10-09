package io.github.mahmoudimus.http2;

import java.util.Arrays;

/**
 * An HPACK dynamic table (RFC 7541 §2.3.2, §4): a FIFO of fields bounded by a size in octets.
 * Index 1 is the newest entry.
 */
final class DynamicTable {

    private HeaderField[] ring = new HeaderField[8];
    private int head; // where the next entry goes
    private int length;
    private int size;
    private int capacity;

    DynamicTable(int capacity) {
        this.capacity = capacity;
    }

    int length() {
        return length;
    }

    /** The sum of the entries' sizes. */
    int size() {
        return size;
    }

    /** The maximum size. */
    int capacity() {
        return capacity;
    }

    /** The entry at {@code index}, 1 being the newest. */
    HeaderField get(int index) {
        if (index < 1 || index > length) throw new IndexOutOfBoundsException(index);
        return ring[(head - index + ring.length) % ring.length];
    }

    /** Adds an entry, evicting old ones; one larger than the capacity empties the table (§4.4). */
    void add(HeaderField field) {
        int entrySize = field.size();
        if (entrySize > capacity) {
            clear();
            return;
        }
        while (size + entrySize > capacity) evict();
        if (length == ring.length) grow();
        ring[head] = field;
        head = (head + 1) % ring.length;
        length++;
        size += entrySize;
    }

    /** Changes the maximum size, evicting entries that no longer fit (§4.3). */
    void setCapacity(int capacity) {
        this.capacity = capacity;
        while (size > capacity) evict();
    }

    private void evict() {
        int tail = (head - length + ring.length) % ring.length;
        size -= ring[tail].size();
        ring[tail] = null;
        length--;
    }

    private void clear() {
        Arrays.fill(ring, null);
        head = 0;
        length = 0;
        size = 0;
    }

    private void grow() {
        HeaderField[] bigger = new HeaderField[ring.length * 2];
        for (int i = 0; i < length; i++) {
            bigger[length - 1 - i] = get(i + 1);
        }
        ring = bigger;
        head = length;
    }
}
