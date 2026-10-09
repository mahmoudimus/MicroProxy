package org.microproxy.impl;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * The server connections of one client connection's HTTP/2 streams. An HTTP/1.1 server connection
 * carries one exchange at a time, so a stream takes an idle one for its exchange ({@link #take})
 * and gives it back afterwards ({@link #release}); concurrent streams use different connections,
 * made as they are needed. Idle connections are kept per target, at most as many as streams may
 * run at once; more are closed (or returned to the shared pool they came from).
 *
 * <p>Thread-safe: streams take and release connections from their own threads, and a connection
 * that closes removes itself from any thread.
 */
final class StreamServerConnections {

    /** Every connection owned: in use by a stream, or idle. */
    private final Set<ServerConnection> owned = ConcurrentHashMap.newKeySet();
    /** Idle connections per key, most recently used first. */
    private final Map<String, ConcurrentLinkedDeque<ServerConnection>> idle = new ConcurrentHashMap<>();
    private final int maxIdlePerKey;

    StreamServerConnections(int maxIdlePerKey) {
        this.maxIdlePerKey = maxIdlePerKey;
    }

    /** Takes an idle, open connection for {@code key} for one exchange; null if there is none. */
    ServerConnection take(String key) {
        ConcurrentLinkedDeque<ServerConnection> deque = idle.get(key);
        if (deque == null) return null;
        ServerConnection c;
        while ((c = deque.pollFirst()) != null) {
            if (c.isOpen()) return c;
            owned.remove(c);
        }
        return null;
    }

    /** Owns a connection just made (or leased) for a stream's exchange. */
    void add(ServerConnection c) {
        owned.add(c);
    }

    /** A stream's exchange is done with {@code c}, which is open and reusable. */
    void release(ServerConnection c) {
        if (!owned.contains(c)) {
            // Closed (and forgotten) meanwhile.
            return;
        }
        ConcurrentLinkedDeque<ServerConnection> deque = idle.computeIfAbsent(c.key, k -> new ConcurrentLinkedDeque<>());
        if (deque.size() >= maxIdlePerKey) {
            owned.remove(c);
            giveUp(c);
            return;
        }
        deque.addFirst(c);
    }

    /** Forgets a connection that closed. */
    void remove(ServerConnection c) {
        if (owned.remove(c)) {
            ConcurrentLinkedDeque<ServerConnection> deque = idle.get(c.key);
            if (deque != null) deque.remove(c);
        }
    }

    /**
     * The client connection is closing: idle pooled connections go back to the pool, the others
     * close (streams still using one fail).
     */
    void releaseAll() {
        for (ServerConnection c : List.copyOf(owned)) {
            ConcurrentLinkedDeque<ServerConnection> deque = idle.get(c.key);
            boolean wasIdle = deque != null && deque.remove(c);
            owned.remove(c);
            if (wasIdle && c.pool != null && !c.inExchange && c.isOpen()) {
                c.pool.release(c);
            } else {
                c.close();
            }
        }
    }

    /** Connections owned now, idle or in use (for tests). */
    int size() {
        return owned.size();
    }

    private static void giveUp(ServerConnection c) {
        if (c.pool != null && c.isOpen()) {
            c.pool.release(c);
        } else {
            c.close();
        }
    }
}
