/*
 * Ported from quinn-proto src/connection/timer.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

/** The timers of a connection, kept in a {@link TimerTable}. */
public enum Timer {
    /** Time-threshold loss detection, or the probe timeout (RFC 9002 section 6.2). */
    LOSS_DETECTION,
    /** The idle timeout (RFC 9000 section 10.1): the connection is silently closed. */
    IDLE,
    /** The end of the closing or draining period (RFC 9000 section 10.2): the connection is gone. */
    CLOSE,
    /** When old keys (0-RTT or the previous 1-RTT generation) are discarded. */
    KEY_DISCARD,
    /**
     * When a server's validation of the peer's new path is abandoned, and the connection goes back
     * to the previous path.
     */
    PATH_VALIDATION,
    /** When a client sends its probe of a new path again, or gives up on it. */
    PATH_PROBE,
    /** When to send a PING to keep the connection alive. */
    KEEP_ALIVE,
    /** When pacing allows the next packet. */
    PACING,
    /** When to retire old connection IDs and push new ones with NEW_CONNECTION_ID. */
    PUSH_NEW_CID,
    /** When an ACK is due because {@code max_ack_delay} expired (RFC 9000 section 13.2.1). */
    MAX_ACK_DELAY
}
