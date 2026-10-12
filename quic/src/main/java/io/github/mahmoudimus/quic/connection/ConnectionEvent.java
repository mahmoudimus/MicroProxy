/*
 * Ported from quinn-proto src/connection/mod.rs (Event) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.net.InetSocketAddress;

/**
 * What a {@link Connection} tells its application, through {@link Connection#pollEvent()}.
 */
public sealed interface ConnectionEvent {

    /**
     * The handshake has progressed far enough that the ALPN protocol and, on a server, the client's
     * server name are known.
     */
    record HandshakeDataReady() implements ConnectionEvent {}

    /** The handshake completed: streams and datagrams can flow. */
    record Connected() implements ConnectionEvent {}

    /** The handshake is confirmed (RFC 9001 section 4.1.2). */
    record HandshakeConfirmed() implements ConnectionEvent {}

    /**
     * The connection ended; this is the last event.
     *
     * @param reason why
     */
    record ConnectionLost(ConnectionError reason) implements ConnectionEvent {}

    /**
     * Something happened on a stream.
     *
     * @param event what
     */
    record Stream(StreamEvent event) implements ConnectionEvent {}

    /** One or more DATAGRAM frames arrived; read them with {@link Connection#receiveDatagram()}. */
    record DatagramReceived() implements ConnectionEvent {}

    /**
     * The path packets are sent on changed: the server followed the client to a new address (and
     * validates it), went back to the previous path after a failed validation, or the client
     * switched to a path it probed ({@link Connection#probePath}, or the server's preferred
     * address).
     *
     * @param remote the peer's address on the path
     * @param local the local address on the path, or null for the endpoint's default
     */
    record PathUpdated(InetSocketAddress remote, InetSocketAddress local) implements ConnectionEvent {}

    /**
     * A client's probe of a new path got no PATH_RESPONSE in time: the connection stays on its
     * path.
     *
     * @param remote the address probed
     * @param local the local address probed from, or null for the endpoint's default
     */
    record PathProbeFailed(InetSocketAddress remote, InetSocketAddress local) implements ConnectionEvent {}
}
