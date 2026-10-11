/*
 * Ported from quinn-proto src/shared.rs and src/lib.rs (Side) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

/** The role of an endpoint in a connection. */
public enum Side {
    /** The endpoint that initiated the connection. */
    CLIENT,
    /** The endpoint that accepted the connection. */
    SERVER;

    /**
     * The other side.
     *
     * @return {@link #SERVER} for {@link #CLIENT} and the reverse
     */
    public Side opposite() {
        return this == CLIENT ? SERVER : CLIENT;
    }

    /**
     * Whether this is the server.
     *
     * @return true for {@link #SERVER}
     */
    public boolean isServer() {
        return this == SERVER;
    }

    /**
     * Whether this is the client.
     *
     * @return true for {@link #CLIENT}
     */
    public boolean isClient() {
        return this == CLIENT;
    }
}
