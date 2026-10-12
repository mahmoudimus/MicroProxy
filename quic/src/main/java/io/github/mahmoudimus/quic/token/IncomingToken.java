/*
 * Ported from quinn-proto src/token.rs (IncomingToken) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.token;

import io.github.mahmoudimus.quic.ConnectionId;
import java.util.Objects;

/**
 * What the token in a client's first Initial packet establishes.
 *
 * @param retrySourceId the Source Connection ID of the server's Retry, which the server echoes in
 *     {@code retry_source_connection_id}, or null without a Retry token
 * @param originalDestinationId the Destination Connection ID of the client's first Initial, for
 *     {@code original_destination_connection_id}
 * @param validated whether the client's address is validated, lifting the anti-amplification
 *     limit
 */
public record IncomingToken(ConnectionId retrySourceId, ConnectionId originalDestinationId, boolean validated) {

    /**
     * The result of validating a token.
     *
     * @param retrySourceId the Retry's Source Connection ID, or null
     * @param originalDestinationId the original Destination Connection ID
     * @param validated whether the address is validated
     */
    public IncomingToken {
        Objects.requireNonNull(originalDestinationId, "originalDestinationId");
    }

    /**
     * No usable token: the address is not validated.
     *
     * @param destinationId the Destination Connection ID of the Initial packet
     * @return the result
     */
    public static IncomingToken unvalidated(ConnectionId destinationId) {
        return new IncomingToken(null, destinationId, false);
    }
}
