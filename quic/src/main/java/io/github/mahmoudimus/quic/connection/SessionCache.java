package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.tls.ClientSessionMemoryCache;
import io.github.mahmoudimus.quic.tls.ClientSessionStore;
import io.github.mahmoudimus.quic.token.TokenMemoryCache;
import io.github.mahmoudimus.quic.token.TokenStore;
import java.util.Objects;

/**
 * What a client remembers about servers between connections: TLS session tickets, for resumption
 * and 0-RTT (each ticket also carries the server's transport parameters, which 0-RTT data must keep
 * within), and NEW_TOKEN tokens, which let a server skip its Retry round trip. Both are kept by
 * server name (or by address when there is none) and handed out once.
 *
 * <p>Share one cache among the connections to the same servers; it is thread-safe.
 *
 * @param tickets the session tickets
 * @param tokens the address validation tokens
 */
public record SessionCache(ClientSessionStore tickets, TokenStore tokens) {

    /**
     * A cache.
     *
     * @param tickets the session tickets
     * @param tokens the address validation tokens
     */
    public SessionCache {
        Objects.requireNonNull(tickets, "tickets");
        Objects.requireNonNull(tokens, "tokens");
    }

    /**
     * A bounded in-memory cache for 256 servers: up to 8 tickets and 2 tokens each.
     *
     * @return a new cache
     */
    public static SessionCache memory() {
        return new SessionCache(new ClientSessionMemoryCache(), new TokenMemoryCache());
    }

    /**
     * A cache that remembers nothing: every connection makes a full handshake.
     *
     * @return the cache
     */
    public static SessionCache none() {
        return new SessionCache(ClientSessionStore.NONE, TokenStore.NONE);
    }
}
