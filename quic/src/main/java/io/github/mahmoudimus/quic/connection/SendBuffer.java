/*
 * Ported from quinn-proto src/connection/send_buffer.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.VarInt;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;

/**
 * The outgoing data of one stream that is not yet acknowledged: what the application wrote, what
 * has been sent, what was deemed lost and must be sent again, and which ranges the peer has
 * acknowledged.
 *
 * <p>Data stays buffered until every byte before it is acknowledged, so a selectively acknowledged
 * range keeps its storage until the gap before it closes.
 *
 * <p><b>Threads.</b> Not thread-safe; a buffer belongs to one stream of one connection, which
 * serializes access.
 */
public final class SendBuffer {

    /**
     * The range {@link #pollTransmit(int)} chose to send next.
     *
     * @param start the first stream offset
     * @param end one past the last stream offset
     * @param encodeLength whether the STREAM frame needs a Length field; false when the data
     *     fills the rest of the packet
     */
    public record Transmit(long start, long end, boolean encodeLength) {}

    /** Data written but not yet acknowledged, which may or may not have been sent. */
    private final ArrayDeque<ByteBuffer> unackedSegments = new ArrayDeque<>();
    /** Total length of {@code unackedSegments}. */
    private long unackedLength;
    /** Acknowledged bytes trimmed from the first segment's view but still in its allocation. */
    private long frontTrimmed;
    /** The offset the next write starts at, just past the end of the unacknowledged data. */
    private long offset;
    /** The first offset never sent. */
    private long unsent;
    /** Acknowledged ranges not yet released because they do not start at the oldest offset. */
    private final RangeSet acks = new RangeSet();
    /** Sent ranges deemed lost. */
    private final RangeSet retransmits = new RangeSet();

    /** An empty buffer at offset zero. */
    public SendBuffer() {}

    /**
     * Appends data to the end of the stream. The buffer keeps a view of {@code data}; the caller
     * must not change its contents afterwards.
     *
     * @param data the bytes between the position and limit; the buffer itself is not changed
     */
    public void write(ByteBuffer data) {
        ByteBuffer view = data.slice();
        unackedLength += view.remaining();
        offset += view.remaining();
        unackedSegments.addLast(view);
    }

    /**
     * Records that the peer acknowledged a range, releasing any acknowledged prefix.
     *
     * @param start the first acknowledged offset
     * @param end one past the last acknowledged offset
     */
    public void ack(long start, long end) {
        // Clamp to the data that is still tracked
        long base = offset - unackedLength;
        acks.insert(Math.max(base, start), Math.max(base, end));
        while (!acks.isEmpty() && acks.min() == offset - unackedLength) {
            RangeSet.Range prefix = acks.popMin();
            long toAdvance = prefix.length();
            unackedLength -= toAdvance;
            while (toAdvance > 0) {
                ByteBuffer front = unackedSegments.peekFirst();
                if (front.remaining() <= toAdvance) {
                    toAdvance -= front.remaining();
                    unackedSegments.pollFirst();
                    frontTrimmed = 0;
                } else {
                    front.position(front.position() + (int) toAdvance);
                    frontTrimmed += toAdvance;
                    toAdvance = 0;
                }
            }
        }
    }

    /**
     * Chooses the next range to send, lost data first, and records it as sent.
     *
     * <p>{@code maxLength} includes the space for the STREAM frame's Offset and Length fields; it
     * must be at least 16 so that both fit at their largest.
     *
     * @param maxLength the bytes available for the offset, length and data
     * @return the range to send, empty when there is nothing (but perhaps a FIN) to send
     */
    public Transmit pollTransmit(int maxLength) {
        if (maxLength < 16) {
            throw new IllegalArgumentException("maxLength " + maxLength + " < 16");
        }
        long max = maxLength;
        boolean encodeLength = false;
        RangeSet.Range range = retransmits.popMin();
        if (range != null) {
            // Retransmit sent data; offset zero needs no Offset field
            if (range.start() != 0) {
                max -= VarInt.size(range.start());
            }
            if (range.length() < max) {
                encodeLength = true;
                max -= 8;
            }
            long end = Math.min(range.end(), saturatingAdd(max, range.start()));
            if (end != range.end()) {
                retransmits.insert(end, range.end());
            }
            return new Transmit(range.start(), end, encodeLength);
        }
        // Transmit new data
        if (unsent != 0) {
            max -= VarInt.size(unsent);
        }
        if (offset - unsent < max) {
            encodeLength = true;
            max -= 8;
        }
        long end = Math.min(offset, saturatingAdd(max, unsent));
        Transmit result = new Transmit(unsent, end, encodeLength);
        unsent = end;
        return result;
    }

    /**
     * The data of a range. The data may be stored in pieces, so the result can be a prefix of the
     * range; call again from the next offset for the rest.
     *
     * @param start the first offset, which must still be buffered
     * @param end one past the last offset
     * @return a read-only view of a prefix of the range, empty if {@code start} is not buffered
     */
    public ByteBuffer get(long start, long end) {
        long segmentOffset = offset - unackedLength;
        for (ByteBuffer segment : unackedSegments) {
            int len = segment.remaining();
            if (start >= segmentOffset && start < segmentOffset + len) {
                int from = (int) (start - segmentOffset);
                int to = (int) Math.min(end - segmentOffset, len);
                return segment.slice(segment.position() + from, to - from).asReadOnlyBuffer();
            }
            segmentOffset += len;
        }
        return ByteBuffer.allocate(0);
    }

    /** Releases all data while keeping the final offset, for RESET_STREAM. */
    public void discard() {
        unackedSegments.clear();
        unackedLength = 0;
        frontTrimmed = 0;
        unsent = offset;
        acks.clear();
        retransmits.clear();
    }

    /**
     * Queues a sent but unacknowledged range to be sent again.
     *
     * @param start the first lost offset
     * @param end one past the last lost offset, at most the first unsent offset
     */
    public void retransmit(long start, long end) {
        if (end > unsent) {
            throw new IllegalArgumentException("unsent data can't be lost");
        }
        retransmits.insert(start, end);
    }

    /** Marks everything unsent again, after the server rejected 0-RTT data. */
    public void retransmitAllForZeroRtt() {
        unsent = 0;
    }

    /**
     * The offset the next write starts at.
     *
     * @return the total bytes written
     */
    public long offset() {
        return offset;
    }

    /**
     * Whether every written byte has been acknowledged.
     *
     * @return true if nothing is unacknowledged
     */
    public boolean isFullyAcked() {
        return unackedLength == 0;
    }

    /**
     * Whether there is data to send, new or lost. There may be unacknowledged data even when
     * there is not.
     *
     * @return true if {@link #pollTransmit(int)} would return data
     */
    public boolean hasUnsentData() {
        return unsent != offset || !retransmits.isEmpty();
    }

    /**
     * The bytes still held from application writes, including acknowledged bytes that cannot be
     * released yet.
     *
     * @return the retained bytes
     */
    public long buffered() {
        return unackedLength + frontTrimmed;
    }

    /** The unacknowledged bytes, concatenated, for tests. */
    byte[] unackedBytes() {
        ByteBuffer out = ByteBuffer.allocate((int) unackedLength);
        for (ByteBuffer s : unackedSegments) {
            out.put(s.duplicate());
        }
        return out.array();
    }

    /** Whether no acknowledged ranges wait for a gap to close, for tests. */
    boolean acksEmpty() {
        return acks.isEmpty();
    }

    private static long saturatingAdd(long a, long b) {
        long r = a + b;
        return ((a ^ r) & (b ^ r)) < 0 ? Long.MAX_VALUE : r;
    }
}
