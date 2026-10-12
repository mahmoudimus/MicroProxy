/*
 * Ported from quinn-proto src/lib.rs (Dir) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

/** Whether a stream carries data in both directions or only from its initiator (RFC 9000 section 2.1). */
public enum Dir {
    /** Bidirectional: data flows both ways. */
    BI,
    /** Unidirectional: data flows from the initiator only. */
    UNI
}
