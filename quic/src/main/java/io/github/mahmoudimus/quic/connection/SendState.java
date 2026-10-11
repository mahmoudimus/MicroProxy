/*
 * Ported from quinn-proto src/connection/streams/send.rs (SendState), extended to the full RFC
 * 9000 section 3.1 state machine (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

/**
 * The states of the sending part of a stream (RFC 9000 section 3.1, figure 2).
 *
 * <pre>
 *   READY --first STREAM / STREAM_DATA_BLOCKED sent--&gt; SEND --STREAM with FIN sent--&gt; DATA_SENT
 *     |                                                 |                                |
 *     +----------------- reset by the application ------+--------------------------------+
 *                                    |                                                   |
 *                                    v                                       all data acknowledged
 *                               RESET_SENT --RESET_STREAM acknowledged--&gt; RESET_RECVD   v
 *                                                                                  DATA_RECVD
 * </pre>
 *
 * <p>The terminal states {@link #DATA_RECVD} and {@link #RESET_RECVD} are reached when the stream's
 * send state is released: {@link StreamsState} then forgets the stream, after reporting {@link
 * StreamEvent.Finished} for {@code DATA_RECVD}.
 */
public enum SendState {
    /** Open, but no STREAM or STREAM_DATA_BLOCKED frame has been sent yet. */
    READY,
    /** Sending data; the application may still write, or has finished but the FIN is unsent. */
    SEND,
    /** The FIN has been sent; only retransmissions remain. */
    DATA_SENT,
    /** Every byte and the FIN were acknowledged. */
    DATA_RECVD,
    /** The application reset the stream and RESET_STREAM was queued. */
    RESET_SENT,
    /** The peer acknowledged RESET_STREAM. */
    RESET_RECVD
}
