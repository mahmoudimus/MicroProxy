/*
 * Ported from quinn-proto src/connection/streams/recv.rs (Chunks) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

/**
 * A read in progress on one stream, from {@link StreamsState#read}. Take chunks with {@link
 * #next(int)}, then call {@link #close()}: flow control credit for the bytes read is issued only
 * then, so a peer blocked on this stream stays blocked until the reader closes.
 *
 * <p>Use it with try-with-resources, within one locked section of the connection; it is not
 * thread-safe.
 */
public final class Chunks implements AutoCloseable {

    private static final int READABLE = 0;
    private static final int RESET = 1;
    private static final int FINISHED = 2;
    private static final int CLOSED = 3;

    private final StreamId id;
    private final boolean ordered;
    private final StreamsState streams;
    private final Recv recv;
    private final Retransmits retransmits;
    private int state = READABLE;
    private long resetCode;
    private long read;
    private boolean shouldTransmit;

    Chunks(StreamId id, boolean ordered, StreamsState streams, Recv recv, Retransmits retransmits) {
        this.id = id;
        this.ordered = ordered;
        this.streams = streams;
        this.recv = recv;
        this.retransmits = retransmits;
    }

    /**
     * The next chunk. In ordered mode chunks follow each other; otherwise their offsets say where
     * they belong.
     *
     * @param maxLength the most bytes to return
     * @return the chunk, or null at the end of the stream (the stream is then released)
     * @throws StreamException {@code BLOCKED} if no data is available yet, {@code RESET} if the peer
     *     reset the stream (the stream is then released)
     * @throws IllegalStateException after {@link #close()}
     */
    public Chunk next(int maxLength) throws StreamException {
        switch (state) {
            case RESET -> throw new StreamException(StreamException.Kind.RESET, resetCode);
            case FINISHED -> {
                return null;
            }
            case CLOSED -> throw new IllegalStateException("next() after close()");
            default -> {}
        }
        Chunk chunk = recv.assembler.read(maxLength, ordered);
        if (chunk != null) {
            read += chunk.length();
            return chunk;
        }
        if (recv.resetReceived) {
            state = RESET;
            resetCode = recv.resetErrorCode;
            streams.recv.remove(id);
            streams.streamRecvFreed(id);
            throw new StreamException(StreamException.Kind.RESET, resetCode);
        }
        if (recv.finalSize == recv.end && recv.finalSize >= 0 && recv.assembler.bytesRead() == recv.end) {
            state = FINISHED;
            streams.recv.remove(id);
            streams.streamRecvFreed(id);
            return null;
        }
        // Retrying harmlessly reaches here again until more data arrives
        throw new StreamException(StreamException.Kind.BLOCKED);
    }

    /**
     * The number of bytes read so far.
     *
     * @return bytes
     */
    public long bytesRead() {
        return read;
    }

    /**
     * Ends the read and issues flow control credit for what was read: MAX_STREAM_DATA, MAX_DATA and,
     * if the stream was released, MAX_STREAMS, queued as needed. Repeated calls do nothing.
     */
    @Override
    public void close() {
        if (state == CLOSED) {
            return;
        }
        int prior = state;
        state = CLOSED;
        // New stream credit once a released stream's state is gone
        boolean transmit = streams.queueMaxStreamId(retransmits);
        if (prior == READABLE) {
            // The stream may need stream-level credit
            boolean maxStreamData = recv.maxStreamData(streams.streamReceiveWindow)[1] != 0;
            transmit |= maxStreamData;
            if (maxStreamData) {
                retransmits.maxStreamData.add(id);
            }
        }
        // Connection-level credit for everything read, whatever the state
        boolean maxData = streams.addReadCredits(read);
        retransmits.maxData |= maxData;
        transmit |= maxData;
        shouldTransmit = transmit;
    }

    /**
     * Whether closing queued a frame that should be sent soon to unblock the peer.
     *
     * @return true after {@link #close()} queued MAX_DATA, MAX_STREAM_DATA or MAX_STREAMS
     */
    public boolean shouldTransmit() {
        return shouldTransmit;
    }
}
