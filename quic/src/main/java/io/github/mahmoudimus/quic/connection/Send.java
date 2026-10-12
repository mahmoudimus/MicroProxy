/*
 * Ported from quinn-proto src/connection/streams/send.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.nio.ByteBuffer;

/** The sending part of a stream. Owned by {@link StreamsState}; not thread-safe. */
final class Send {

    /** The peer's stream-level flow control limit (MAX_STREAM_DATA). */
    long maxData;
    SendState state = SendState.READY;
    final SendBuffer pending = new SendBuffer();
    int priority;
    /** Whether the application finished the stream. */
    boolean finished;
    /** Whether the FIN has been acknowledged. */
    boolean finishAcked;
    /** Whether a frame with the FIN bit must be sent, even without new data. */
    boolean finPending;
    /** Whether the stream is on {@link StreamsState}'s list of streams blocked by the connection. */
    boolean connectionBlocked;
    /** The {@code maxData} a STREAM_DATA_BLOCKED was last queued for, or -1. */
    long dataBlockedLimit = -1;
    /** The error code of a STOP_SENDING received, or -1. */
    long stopReason = -1;

    Send(long maxData) {
        this.maxData = maxData;
    }

    boolean isReset() {
        return state == SendState.RESET_SENT;
    }

    /** Whether the application may still write: open, not finished and not reset. */
    boolean isWritable() {
        return !finished && !isReset();
    }

    void finish() throws StreamException {
        if (stopReason >= 0) {
            throw new StreamException(StreamException.Kind.STOPPED, stopReason);
        } else if (isWritable()) {
            finished = true;
            finPending = true;
        } else {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
    }

    /**
     * Takes data from a source, up to the stream's flow control credit and {@code limit}.
     *
     * @return {bytes, whole chunks consumed}
     */
    long[] write(Source source, long limit) throws StreamException {
        if (!isWritable()) {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
        if (stopReason >= 0) {
            throw new StreamException(StreamException.Kind.STOPPED, stopReason);
        }
        long budget = maxData - pending.offset();
        if (budget == 0) {
            throw new StreamException(StreamException.Kind.BLOCKED);
        }
        long remaining = Math.min(limit, budget);
        long bytes = 0;
        long chunks = 0;
        while (true) {
            ByteBuffer chunk = source.popChunk((int) Math.min(remaining, Integer.MAX_VALUE));
            chunks += source.lastConsumed();
            if (!chunk.hasRemaining()) {
                break;
            }
            bytes += chunk.remaining();
            remaining -= chunk.remaining();
            pending.write(chunk);
        }
        return new long[] {bytes, chunks};
    }

    /** Abandons the stream after a local reset; a no-op once reset. */
    void reset() {
        if (!isReset()) {
            state = SendState.RESET_SENT;
            pending.discard();
            finPending = false;
        }
    }

    /** Handles STOP_SENDING; true if this frame stopped the stream. */
    boolean tryStop(long errorCode) {
        if (stopReason < 0) {
            stopReason = errorCode;
            return true;
        }
        return false;
    }

    /** Handles an acknowledged frame; true if the stream is finished and fully acknowledged. */
    boolean ack(StreamMeta frame) {
        pending.ack(frame.start(), frame.end());
        if (finished && !isReset()) {
            finishAcked |= frame.fin();
            return finishAcked && pending.isFullyAcked();
        }
        return false;
    }

    /** Handles a raised MAX_STREAM_DATA; true if the stream was blocked by the old limit. */
    boolean increaseMaxData(long offset) {
        if (offset <= maxData || !isWritable()) {
            return false;
        }
        boolean wasBlocked = pending.offset() == maxData;
        maxData = offset;
        return wasBlocked;
    }

    long offset() {
        return pending.offset();
    }

    boolean isPending() {
        return pending.hasUnsentData() || finPending;
    }

    /** A source of data for {@link #write}, consumed a chunk at a time. */
    interface Source {

        /** The next chunk of at most {@code limit} bytes, empty when exhausted or at the limit. */
        ByteBuffer popChunk(int limit);

        /** How many whole source chunks the last {@link #popChunk} consumed. */
        int lastConsumed();
    }

    /** Copies from one buffer, so the caller may reuse it; ported from quinn's {@code ByteSlice}. */
    static final class CopyingSource implements Source {
        private final ByteBuffer data;
        private int consumed;

        CopyingSource(ByteBuffer data) {
            this.data = data;
        }

        @Override
        public ByteBuffer popChunk(int limit) {
            int n = Math.min(limit, data.remaining());
            consumed = 0;
            if (n == 0) {
                return ByteBuffer.allocate(0);
            }
            byte[] copy = new byte[n];
            data.get(copy);
            consumed = data.hasRemaining() ? 0 : 1;
            return ByteBuffer.wrap(copy);
        }

        @Override
        public int lastConsumed() {
            return consumed;
        }
    }

    /**
     * Takes views of caller-owned chunks without copying; a partly taken chunk is advanced. Ported
     * from quinn's {@code BytesArray}.
     */
    static final class ChunksSource implements Source {
        private final ByteBuffer[] chunks;
        private int index;
        private int consumed;

        ChunksSource(ByteBuffer[] chunks) {
            this.chunks = chunks;
        }

        @Override
        public ByteBuffer popChunk(int limit) {
            consumed = 0;
            // Skips empty chunks while still counting them as consumed
            while (index < chunks.length) {
                ByteBuffer chunk = chunks[index];
                if (chunk.remaining() <= limit) {
                    ByteBuffer view = chunk.slice();
                    chunk.position(chunk.limit());
                    index++;
                    consumed++;
                    if (!view.hasRemaining()) {
                        continue;
                    }
                    return view;
                } else if (limit > 0) {
                    ByteBuffer view = chunk.slice(chunk.position(), limit);
                    chunk.position(chunk.position() + limit);
                    return view;
                } else {
                    break;
                }
            }
            return ByteBuffer.allocate(0);
        }

        @Override
        public int lastConsumed() {
            return consumed;
        }
    }
}
