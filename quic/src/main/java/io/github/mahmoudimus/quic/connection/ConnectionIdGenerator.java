/*
 * Ported from quinn-proto src/cid_generator.rs (ConnectionIdGenerator) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.ConnectionId;

/**
 * Generates the connection IDs an endpoint issues. IDs must not let an observer link them to
 * other IDs of the same connection (RFC 9000 section 5.1): they need high entropy, from
 * cryptographic randomness or encryption.
 */
public interface ConnectionIdGenerator {

    /**
     * A new connection ID.
     *
     * @return an ID of {@link #cidLength()} bytes
     */
    ConnectionId generateCid();

    /**
     * Whether an ID could have come from this generator, to drop stray packets cheaply. False
     * positives are allowed.
     *
     * @param cid the ID
     * @return true by default
     */
    default boolean validate(ConnectionId cid) {
        return true;
    }

    /**
     * The length of the IDs, which the endpoint needs to parse short headers.
     *
     * @return 0 to 20 bytes
     */
    int cidLength();

    /**
     * How long an ID lives before it is retired and replaced.
     *
     * @return nanoseconds, or -1 for forever
     */
    long cidLifetime();
}
