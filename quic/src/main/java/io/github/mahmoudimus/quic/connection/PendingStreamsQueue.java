/*
 * Ported from quinn-proto src/connection/streams/mod.rs (PendingStreamsQueue, PendingStream)
 * (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.util.ArrayList;
import java.util.List;
import java.util.PriorityQueue;

/**
 * Streams with data to send, highest priority first and round-robin among equal priorities. Not
 * thread-safe; owned by {@link StreamsState}.
 */
final class PendingStreamsQueue {

    /**
     * A queued stream.
     *
     * @param priority higher goes first
     * @param recency the tie-breaker: higher goes first, and each push takes a lower value, so a
     *     requeued stream goes after the others of its priority
     * @param id the stream
     */
    record Entry(int priority, long recency, StreamId id) {}

    private final PriorityQueue<Entry> streams = new PriorityQueue<>((a, b) -> {
        int c = Integer.compare(b.priority, a.priority);
        return c != 0 ? c : Long.compare(b.recency, a.recency);
    });
    /** A partly written stream to finish first when fairness is off. */
    private Entry next;
    private long recency = Long.MAX_VALUE;

    /** Reinserts a stream that still has data, to be written next (no fairness). */
    void reinsertPending(StreamId id, int priority) {
        if (next != null) {
            throw new IllegalStateException("a stream is already reinserted");
        }
        next = new Entry(priority, recency, id);
    }

    /** Queues a stream after the others of the same priority. */
    void pushPending(StreamId id, int priority) {
        recency--;
        streams.add(new Entry(priority, recency, id));
    }

    Entry pop() {
        if (next != null) {
            Entry e = next;
            next = null;
            return e;
        }
        return streams.poll();
    }

    void clear() {
        next = null;
        streams.clear();
    }

    List<Entry> entries() {
        List<Entry> all = new ArrayList<>(streams.size() + 1);
        if (next != null) {
            all.add(next);
        }
        all.addAll(streams);
        return all;
    }

    int size() {
        return streams.size() + (next != null ? 1 : 0);
    }
}
