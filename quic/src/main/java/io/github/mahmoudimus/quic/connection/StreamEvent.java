/*
 * Ported from quinn-proto src/connection/streams/mod.rs (StreamEvent) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

/**
 * Application events about streams, polled from {@link StreamsState#poll()}. They are hints: the
 * blocking stream layer wakes the matching readers and writers, which then retry.
 */
public sealed interface StreamEvent {

    /**
     * The peer opened one or more streams, which {@link StreamsState#accept(Dir)} now returns. A
     * separate {@link Readable} follows once data arrives.
     *
     * @param dir the directionality of the new streams
     */
    record Opened(Dir dir) implements StreamEvent {}

    /**
     * A stream probably has data, its end or a reset waiting to be read.
     *
     * @param id the stream
     */
    record Readable(StreamId id) implements StreamEvent {}

    /**
     * A stream that could not take more data might take some now, or was stopped. Only reported for
     * streams that are still open.
     *
     * @param id the stream
     */
    record Writable(StreamId id) implements StreamEvent {}

    /**
     * A finished stream's data, FIN included, has all been acknowledged.
     *
     * @param id the stream
     */
    record Finished(StreamId id) implements StreamEvent {}

    /**
     * The peer sent STOP_SENDING: it no longer wants the stream's data.
     *
     * @param id the stream
     * @param errorCode the application error code the peer gave
     */
    record Stopped(StreamId id, long errorCode) implements StreamEvent {}

    /**
     * The peer raised the stream limit, so at least one more stream of this directionality may be
     * opened.
     *
     * @param dir the directionality
     */
    record Available(Dir dir) implements StreamEvent {}
}
