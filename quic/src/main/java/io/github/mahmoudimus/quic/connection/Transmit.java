/*
 * Ported from quinn-proto src/lib.rs (Transmit) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * A datagram a {@link Connection} wants sent: usually to the peer's address on the current path,
 * but a PATH_CHALLENGE or PATH_RESPONSE may go to another address, or (on a client probing a new
 * path, {@link Connection#probePath}) from another local address.
 *
 * @param datagram the datagram, from position 0 to its length
 * @param destination where to send it
 * @param source the local address to send it from, or null for the endpoint's default
 */
public record Transmit(ByteBuffer datagram, InetSocketAddress destination, InetSocketAddress source) {

    /**
     * A datagram to send.
     *
     * @param datagram the datagram
     * @param destination where to send it
     * @param source the local address to send it from, or null for the endpoint's default
     */
    public Transmit {
        Objects.requireNonNull(datagram, "datagram");
        Objects.requireNonNull(destination, "destination");
    }
}
