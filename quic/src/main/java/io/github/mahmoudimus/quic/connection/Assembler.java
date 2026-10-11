/*
 * Ported from quinn-proto src/connection/assembler.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Reassembles STREAM or CRYPTO frame data that arrives out of order, duplicated or overlapping,
 * into the stream's bytes (RFC 9000 section 2.2).
 *
 * <p>Data is read either in order, as a byte stream, or unordered, as chunks with their offsets.
 * A stream starts ordered; it may switch to unordered reads once, but never back.
 *
 * <p><b>Bounded buffering.</b> Inserted buffers are kept as views, not copied, and their backing
 * allocation is accounted for: when a peer's small or gapped frames pin much more memory than the
 * data they carry, or the number of buffered pieces grows past a bound, the assembler copies the
 * pieces into fresh compact buffers. A peer that keeps more than {@value #MAX_CHUNKS} separate
 * pieces after compaction makes {@link #insert} fail. The total buffered is bounded by flow control,
 * which the caller enforces.
 *
 * <p><b>Threads.</b> Not thread-safe; an assembler belongs to one stream of one connection, which
 * serializes access.
 */
public final class Assembler {

    /**
     * The most separate pieces kept for one stream. An insert fails only if compaction cannot get
     * the count back down to this.
     */
    public static final int MAX_CHUNKS = 1024;

    /** Defragmented pieces smaller than this are copied again on every compaction. */
    static final int MIN_RETAINED_CHUNK_SIZE = 128;

    /** The piece count past which an insert compacts before deciding whether to reject. */
    static final int COMPACT_THRESHOLD = 2 * MAX_CHUNKS;

    /** Buffered pieces, ordered by offset with longer pieces first at equal offsets. */
    private final List<Buffer> data = new ArrayList<>();
    /** Bytes buffered, counting duplicates in ordered mode. */
    private long buffered;
    /** Estimated bytes allocated behind the buffered views; never less than {@code buffered}. */
    private long allocated;
    /** Bytes the application has read; in ordered mode, the read offset. */
    private long bytesRead;
    /** One past the highest offset received. */
    private long end;
    /** Offsets received, once in unordered mode; null while ordered. */
    private RangeSet recvd;

    /** An empty, ordered assembler. */
    public Assembler() {}

    /** Discards everything and returns to the initial, ordered state. */
    public void reinit() {
        data.clear();
        buffered = 0;
        allocated = 0;
        bytesRead = 0;
        end = 0;
        recvd = null;
    }

    /**
     * Selects ordered or unordered reads. Switching to unordered is allowed once; an ordered read
     * after that is not.
     *
     * @param ordered whether the next reads are ordered
     * @return false if {@code ordered} is requested after an unordered read
     */
    public boolean ensureOrdering(boolean ordered) {
        if (ordered && recvd != null) {
            return false;
        } else if (!ordered && recvd == null) {
            if (!data.isEmpty()) {
                defragment(bytesRead);
            }
            RangeSet r = new RangeSet();
            r.insert(0, bytesRead);
            for (Buffer chunk : data) {
                r.insert(chunk.offset, chunk.end());
            }
            recvd = r;
        }
        return true;
    }

    /**
     * Whether reads are ordered.
     *
     * @return false once {@link #ensureOrdering(boolean) ensureOrdering(false)} has been called
     */
    public boolean isOrdered() {
        return recvd == null;
    }

    /**
     * Takes the next chunk.
     *
     * @param maxLength the most bytes to return
     * @param ordered true for the bytes at the read offset, false for any buffered chunk
     * @return the chunk, or null if nothing (in order) is buffered
     */
    public Chunk read(int maxLength, boolean ordered) {
        if (ordered) {
            while (!data.isEmpty() && data.get(0).end() <= bytesRead) {
                Buffer front = data.remove(0); // ends before the read offset
                buffered -= front.length();
                allocated -= front.allocationSize;
            }
            if (data.isEmpty() || data.get(0).offset > bytesRead) {
                return null; // the next buffer starts after the read offset
            }
        }
        if (data.isEmpty()) {
            return null;
        }
        Buffer front = data.remove(0);
        if (ordered && bytesRead >= front.offset) {
            int skip = (int) (bytesRead - front.offset);
            front.advance(skip);
            buffered -= skip;
        }
        Chunk chunk;
        if (maxLength < front.length()) {
            // Take a prefix and reinsert the remainder
            ByteBuffer prefix = front.bytes.slice(front.bytes.position(), maxLength);
            chunk = new Chunk(front.offset, prefix);
            front.advance(maxLength);
            int idx = 0;
            while (idx < data.size() && compare(data.get(idx), front) < 0) {
                idx++;
            }
            data.add(idx, front);
        } else {
            allocated -= front.allocationSize;
            chunk = new Chunk(front.offset, front.bytes);
        }
        bytesRead += chunk.length();
        buffered -= chunk.length();
        return chunk;
    }

    /**
     * Copies fragmented pieces into new compact buffers, merging contiguous ones, so that small
     * views stop pinning large allocations. Bytes before {@code start} count as delivered and are
     * dropped.
     */
    void defragment(long start) {
        long minChunkSize = Math.max(ceilDiv(buffered, MAX_CHUNKS), MIN_RETAINED_CHUNK_SIZE);
        List<Buffer> buffers = new ArrayList<>(data);
        data.clear();
        buffered = 0;
        long fragmentedBuffered = 0;
        long offset = start;
        for (Buffer chunk : buffers) {
            chunk.tryMarkDefragment(offset);
            int size = chunk.length();
            offset = chunk.offset + size;
            buffered += size;
            if (!chunk.defragmented || size < minChunkSize) {
                fragmentedBuffered += size;
            }
        }
        allocated = buffered;
        ByteBuffer buffer = ByteBuffer.allocate((int) fragmentedBuffered);
        int bufferStart = 0; // position in `buffer` where the accumulating piece starts
        long pieceOffset = 0;
        for (Buffer chunk : buffers) {
            if (chunk.length() == 0) {
                continue; // emptied by tryMarkDefragment
            }
            int pieceLength = buffer.position() - bufferStart;
            if (chunk.defragmented && chunk.length() >= minChunkSize) {
                // The accumulated piece starts before this one, so it goes first
                if (pieceLength > 0) {
                    data.add(Buffer.defragmented(pieceOffset, buffer.slice(bufferStart, pieceLength)));
                    bufferStart = buffer.position();
                }
                pieceOffset = chunk.end();
                data.add(chunk);
                continue;
            }
            // Overlap was resolved by tryMarkDefragment
            if (chunk.offset != pieceOffset + pieceLength) {
                if (pieceLength > 0) {
                    data.add(Buffer.defragmented(pieceOffset, buffer.slice(bufferStart, pieceLength)));
                    bufferStart = buffer.position();
                }
                pieceOffset = chunk.offset;
            }
            buffer.put(chunk.bytes.duplicate());
        }
        int pieceLength = buffer.position() - bufferStart;
        if (pieceLength > 0) {
            data.add(Buffer.defragmented(pieceOffset, buffer.slice(bufferStart, pieceLength)));
        }
    }

    /**
     * Adds received data. The assembler keeps a view of {@code bytes}, so the caller must not
     * reuse its contents afterwards; copy data out of a reusable packet buffer first.
     *
     * @param offset the stream offset of the first byte
     * @param bytes the data, between its position and limit; the buffer itself is not changed
     * @param allocationSize the size of the allocation behind {@code bytes}, at least its length;
     *     pass the length for a buffer that holds only this data
     * @return false if the stream is fragmented into too many pieces, which only a misbehaving
     *     peer causes
     */
    public boolean insert(long offset, ByteBuffer bytes, int allocationSize) {
        ByteBuffer view = bytes.slice();
        if (allocationSize < view.remaining()) {
            throw new IllegalArgumentException("allocationSize " + allocationSize + " < " + view.remaining());
        }
        end = Math.max(end, offset + view.remaining());
        if (recvd != null) {
            // Discard duplicate data
            for (RangeSet.Range duplicate : recvd.replace(offset, offset + view.remaining())) {
                if (duplicate.start() > offset) {
                    int n = (int) (duplicate.start() - offset);
                    Buffer buffer = new Buffer(offset, view.slice(view.position(), n), allocationSize);
                    buffered += buffer.length();
                    allocated += buffer.allocationSize;
                    insertOrdered(buffer);
                    offset = duplicate.start();
                    view.position(view.position() + n);
                }
                view.position(view.position() + (int) (duplicate.end() - offset));
                offset = duplicate.end();
            }
        } else if (offset < bytesRead) {
            if (offset + view.remaining() <= bytesRead) {
                return true;
            }
            int diff = (int) (bytesRead - offset);
            offset += diff;
            view.position(view.position() + diff);
        }
        // No early return when empty: the dedup loop above may already have added pieces
        if (view.hasRemaining()) {
            Buffer buffer = new Buffer(offset, view.slice(), allocationSize);
            buffered += buffer.length();
            allocated += buffer.allocationSize;
            insertOrdered(buffer);
        }
        // `buffered` counts duplicates, so `end - bytesRead` bounds the unique bytes buffered;
        // duplicates past a proportion of the window then cause a compaction.
        long unique = Math.min(buffered, end - bytesRead);
        long overAllocation = allocated - unique;
        // A malicious peer could send one-byte frames, each pinning a whole packet buffer; this
        // limits over-allocation in proportion to the data. Small gapped frames keep it low, so
        // the piece count is bounded too.
        long threshold = Math.max(32768, unique * 3 / 2);
        if (overAllocation > threshold || data.size() > COMPACT_THRESHOLD) {
            defragment(0);
            return data.size() <= MAX_CHUNKS;
        }
        return true;
    }

    /**
     * Adds received data held in a buffer of its own; see {@link #insert(long, ByteBuffer, int)}.
     *
     * @param offset the stream offset of the first byte
     * @param bytes the data, between its position and limit
     * @return false if the stream is fragmented into too many pieces
     */
    public boolean insert(long offset, ByteBuffer bytes) {
        return insert(offset, bytes, bytes.remaining());
    }

    /**
     * The number of bytes the application has read.
     *
     * @return in ordered mode, the read offset
     */
    public long bytesRead() {
        return bytesRead;
    }

    /**
     * One past the highest offset received.
     *
     * @return the high-water mark
     */
    public long end() {
        return end;
    }

    /** Discards all buffered data, keeping the read offset. */
    public void clear() {
        data.clear();
        buffered = 0;
        allocated = 0;
    }

    /** The number of buffered pieces, for tests. */
    int chunkCount() {
        return data.size();
    }

    /** Whether the pieces are sorted, for tests. */
    boolean isSorted() {
        for (int i = 1; i < data.size(); i++) {
            if (compare(data.get(i - 1), data.get(i)) > 0) {
                return false;
            }
        }
        return true;
    }

    /** The first piece's offset and length, for tests. */
    long[] front() {
        return data.isEmpty() ? null : new long[] {data.get(0).offset, data.get(0).length()};
    }

    /** O(1) for a piece in order or below everything buffered, otherwise a shifting insert. */
    private void insertOrdered(Buffer buffer) {
        if (data.isEmpty() || compare(data.get(data.size() - 1), buffer) <= 0) {
            data.add(buffer);
            return;
        }
        if (compare(buffer, data.get(0)) <= 0) {
            data.add(0, buffer);
            return;
        }
        int lo = 0;
        int hi = data.size();
        while (lo < hi) { // first index whose piece sorts after `buffer`
            int mid = (lo + hi) >>> 1;
            if (compare(data.get(mid), buffer) <= 0) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        data.add(lo, buffer);
    }

    /** Ascending offset, longer pieces first at equal offsets. */
    private static int compare(Buffer a, Buffer b) {
        int c = Long.compare(a.offset, b.offset);
        return c != 0 ? c : Integer.compare(b.length(), a.length());
    }

    private static long ceilDiv(long a, long b) {
        return (a + b - 1) / b;
    }

    /** A buffered piece: a view of received bytes and the allocation behind it. */
    private static final class Buffer {
        long offset;
        ByteBuffer bytes;
        /** The allocation behind {@code bytes} if not defragmented, else its length. */
        int allocationSize;
        boolean defragmented;

        Buffer(long offset, ByteBuffer bytes, int allocationSize) {
            this.offset = offset;
            this.bytes = bytes;
            this.allocationSize = allocationSize;
        }

        static Buffer defragmented(long offset, ByteBuffer bytes) {
            Buffer b = new Buffer(offset, bytes, bytes.remaining());
            b.defragmented = true;
            return b;
        }

        int length() {
            return bytes.remaining();
        }

        long end() {
            return offset + bytes.remaining();
        }

        void advance(int n) {
            bytes.position(bytes.position() + n);
            offset += n;
        }

        /** Drops data before {@code start}; marks the piece defragmented if well utilized. */
        void tryMarkDefragment(long start) {
            long duplicate = Math.max(0, start - offset);
            offset = Math.max(offset, start);
            if (duplicate >= length()) {
                bytes = ByteBuffer.allocate(0);
                defragmented = true;
                allocationSize = 0;
                return;
            }
            bytes.position(bytes.position() + (int) duplicate);
            defragmented = defragmented || (long) length() * 6 / 5 >= allocationSize;
            if (defragmented) {
                allocationSize = length();
            }
        }
    }
}
