/*
 * Ported from quinn-proto src/packet.rs (SpaceId) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.EncryptionLevel;

/**
 * The three packet number spaces (RFC 9000 section 12.3). They are ordered: Initial, then
 * Handshake, then application data.
 */
public enum SpaceId {
    /** Initial packets. */
    INITIAL,
    /** Handshake packets. */
    HANDSHAKE,
    /** 0-RTT and 1-RTT packets, which share a space. */
    DATA;

    /**
     * The space of an encryption level.
     *
     * @param level the level
     * @return {@link #DATA} for 0-RTT and 1-RTT
     */
    public static SpaceId of(EncryptionLevel level) {
        return switch (level) {
            case INITIAL -> INITIAL;
            case HANDSHAKE -> HANDSHAKE;
            case ZERO_RTT, ONE_RTT -> DATA;
        };
    }
}
