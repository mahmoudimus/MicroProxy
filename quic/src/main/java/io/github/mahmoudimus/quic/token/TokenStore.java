/*
 * Ported from quinn-proto src/token.rs (TokenStore, NoneTokenStore) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.token;

/**
 * Where a client keeps the address validation tokens servers send in NEW_TOKEN frames (RFC 9000
 * section 8.1.3), by server name, to present in the first Initial of a later connection so the
 * server can skip its Retry round trip.
 *
 * <p>A token must never be handed out twice: reusing one would let observers link connections
 * (RFC 9000 section 8.1.3). Implementations must be thread-safe.
 */
public interface TokenStore {

    /** A store that keeps nothing. */
    TokenStore NONE = new TokenStore() {
        @Override
        public void put(String serverName, byte[] token) {}

        @Override
        public byte[] take(String serverName) {
            return null;
        }
    };

    /**
     * Keeps a token for later, one-time use.
     *
     * @param serverName the server it came from
     * @param token the token
     */
    void put(String serverName, byte[] token);

    /**
     * Takes a token for a server, removing it.
     *
     * @param serverName the server
     * @return the token, or null if there is none
     */
    byte[] take(String serverName);
}
