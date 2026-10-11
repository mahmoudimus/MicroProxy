package io.github.mahmoudimus.quic;

/**
 * The four QUIC encryption levels (RFC 9001 section 4), each with its own keys. Initial, Handshake
 * and 1-RTT packets also have their own packet number spaces; 0-RTT shares 1-RTT's.
 */
public enum EncryptionLevel {
    /** Keys derived from the client's first Destination Connection ID. */
    INITIAL,
    /** Early data keys, from a resumed session. */
    ZERO_RTT,
    /** Keys from the TLS handshake secrets. */
    HANDSHAKE,
    /** Keys from the TLS application traffic secrets. */
    ONE_RTT
}
