/*
 * Ported from quinn-proto src/shared.rs (EndpointEventInner) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.StatelessResetToken;
import java.net.InetSocketAddress;

/**
 * What a {@link Connection} tells its {@link Endpoint}, through {@link
 * Connection#pollEndpointEvent()}: routing changes. The I/O layer passes each one to {@link
 * Endpoint#handleEvent(Connection, EndpointEvent)}.
 */
public sealed interface EndpointEvent {

    /**
     * The connection issued a local connection ID; packets for it must reach the connection.
     *
     * @param cid the connection ID
     */
    record CidIssued(io.github.mahmoudimus.quic.ConnectionId cid) implements EndpointEvent {}

    /**
     * The peer retired a local connection ID; it no longer routes to the connection.
     *
     * @param cid the connection ID
     */
    record CidRetired(io.github.mahmoudimus.quic.ConnectionId cid) implements EndpointEvent {}

    /**
     * The peer's current stateless reset token, which lets a reset with a random connection ID reach
     * the connection.
     *
     * @param remote the peer's address
     * @param token the token
     */
    record ResetToken(InetSocketAddress remote, StatelessResetToken token) implements EndpointEvent {}

    /** The connection is gone and holds no state the endpoint must keep; this is the last event. */
    record Drained() implements EndpointEvent {}
}
