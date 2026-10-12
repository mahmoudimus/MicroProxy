/*
 * Ported from quinn-proto src/token.rs (TokenPayload) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.token;

import io.github.mahmoudimus.quic.ConnectionId;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.Objects;

/** What an address validation token says, encrypted so that only the server can read it. */
public sealed interface TokenPayload {

    /**
     * When the token was issued, to whole seconds.
     *
     * @return the time
     */
    Instant issued();

    /**
     * A token sent in a Retry packet (RFC 9000 section 8.1.2), bound to the client's address and
     * port, and short-lived since the client returns it at once.
     *
     * @param address the client's address and port
     * @param originalDestinationId the Destination Connection ID of the client's first Initial
     * @param issued when the token was issued
     */
    record Retry(InetSocketAddress address, ConnectionId originalDestinationId, Instant issued) implements TokenPayload {

        /**
         * A Retry payload.
         *
         * @param address the client's resolved address and port
         * @param originalDestinationId the original Destination Connection ID
         * @param issued when issued; fractions of a second are dropped
         */
        public Retry {
            Objects.requireNonNull(address.getAddress(), "address must be resolved");
            Objects.requireNonNull(originalDestinationId, "originalDestinationId");
            issued = Instant.ofEpochSecond(issued.getEpochSecond());
        }
    }

    /**
     * A token sent in a NEW_TOKEN frame (RFC 9000 section 8.1.3), for a later connection. It is
     * bound to the client's IP address only, since the port likely changes.
     *
     * @param ip the client's IP address
     * @param issued when the token was issued
     */
    record Validation(InetAddress ip, Instant issued) implements TokenPayload {

        /**
         * A validation payload.
         *
         * @param ip the client's IP address
         * @param issued when issued; fractions of a second are dropped
         */
        public Validation {
            Objects.requireNonNull(ip, "ip");
            issued = Instant.ofEpochSecond(issued.getEpochSecond());
        }
    }
}
