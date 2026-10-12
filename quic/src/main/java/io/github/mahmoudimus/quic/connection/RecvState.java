/*
 * Ported from quinn-proto src/connection/streams/recv.rs (RecvState), extended to the full RFC
 * 9000 section 3.2 state machine (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

/**
 * The states of the receiving part of a stream (RFC 9000 section 3.2, figure 3).
 *
 * <pre>
 *   RECV --STREAM with FIN--&gt; SIZE_KNOWN --all data received--&gt; DATA_RECVD --app read all--&gt; DATA_READ
 *     |                          |                                |
 *     +-------- RESET_STREAM ----+--------------------------------+--&gt; RESET_RECVD --app read reset--&gt; RESET_READ
 * </pre>
 *
 * <p>The terminal states {@link #DATA_READ} and {@link #RESET_READ} are reached when the
 * application has seen the end of the stream or its reset: {@link StreamsState} then forgets the
 * stream.
 */
public enum RecvState {
    /** Receiving data; the final size is unknown. */
    RECV,
    /** A frame with the FIN bit fixed the final size; some data is still missing. */
    SIZE_KNOWN,
    /** Every byte up to the final size has arrived. */
    DATA_RECVD,
    /** The application has read all the data. */
    DATA_READ,
    /** The peer reset the stream. */
    RESET_RECVD,
    /** The application has seen the reset. */
    RESET_READ
}
