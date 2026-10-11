// Ported from rustls src/client/config.rs (the ClientSessionStore trait, for TLS 1.3 tickets) and
// src/client/handy.rs (NoClientSessionStorage) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

/**
 * Where a client keeps session tickets between connections, by server. Each ticket is handed out
 * once ({@link #take}), as RFC 8446 appendix C.4 recommends, so that connections cannot be linked
 * by their tickets and a server may treat tickets as single-use.
 *
 * <p>Implementations must be thread-safe: the connections of a client share a store.
 */
public interface ClientSessionStore {

    /** A store that keeps nothing, so every connection makes a full handshake. */
    ClientSessionStore NONE = new ClientSessionStore() {
        @Override
        public void put(String key, SessionTicket ticket) {}

        @Override
        public SessionTicket take(String key) {
            return null;
        }
    };

    /**
     * Keeps a ticket.
     *
     * @param key the server it is for: its name, or another key the caller uses consistently
     * @param ticket the ticket
     */
    void put(String key, SessionTicket ticket);

    /**
     * Takes the newest ticket for a server, removing it.
     *
     * @param key the server
     * @return the ticket, or null if there is none
     */
    SessionTicket take(String key);
}
