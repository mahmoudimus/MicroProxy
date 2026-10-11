// Ported from rustls src/client/handy.rs (ClientSessionMemoryCache: per-server deques of TLS 1.3
// tickets, the oldest dropped first and the newest taken first) and src/limited_cache.rs (the
// bounded map of servers, evicting the server added first) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A bounded, in-memory {@link ClientSessionStore}: up to a number of servers, each with up to
 * {@value #MAX_TICKETS_PER_SERVER} tickets. A full cache forgets the server added first; a full
 * server entry forgets its oldest ticket. Tickets are taken newest first, and only once.
 *
 * <p>Thread-safe: a {@link ReentrantLock} guards the map.
 */
public final class ClientSessionMemoryCache implements ClientSessionStore {

    /** The tickets kept per server, as rustls keeps. */
    public static final int MAX_TICKETS_PER_SERVER = 8;
    /** The default number of servers. */
    public static final int DEFAULT_MAX_SERVERS = 256;

    private final int maxServers;
    private final ReentrantLock lock = new ReentrantLock();
    private final LinkedHashMap<String, ArrayDeque<SessionTicket>> servers = new LinkedHashMap<>();

    /** A cache for {@value #DEFAULT_MAX_SERVERS} servers. */
    public ClientSessionMemoryCache() {
        this(DEFAULT_MAX_SERVERS);
    }

    /**
     * A cache.
     *
     * @param maxServers the most servers to remember; 0 remembers none
     */
    public ClientSessionMemoryCache(int maxServers) {
        if (maxServers < 0) {
            throw new IllegalArgumentException("maxServers " + maxServers);
        }
        this.maxServers = maxServers;
    }

    @Override
    public void put(String key, SessionTicket ticket) {
        if (maxServers == 0 || key == null || ticket == null) {
            return;
        }
        lock.lock();
        try {
            ArrayDeque<SessionTicket> tickets = servers.get(key);
            if (tickets == null) {
                if (servers.size() >= maxServers) {
                    Iterator<Map.Entry<String, ArrayDeque<SessionTicket>>> oldest = servers.entrySet().iterator();
                    oldest.next();
                    oldest.remove();
                }
                tickets = new ArrayDeque<>(MAX_TICKETS_PER_SERVER);
                servers.put(key, tickets);
            }
            if (tickets.size() >= MAX_TICKETS_PER_SERVER) {
                tickets.pollFirst();
            }
            tickets.addLast(ticket);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public SessionTicket take(String key) {
        if (key == null) {
            return null;
        }
        lock.lock();
        try {
            ArrayDeque<SessionTicket> tickets = servers.get(key);
            if (tickets == null) {
                return null;
            }
            SessionTicket t = tickets.pollLast();
            if (tickets.isEmpty()) {
                servers.remove(key);
            }
            return t;
        } finally {
            lock.unlock();
        }
    }

    /**
     * The number of tickets kept for a server.
     *
     * @param key the server
     * @return the count
     */
    public int size(String key) {
        lock.lock();
        try {
            ArrayDeque<SessionTicket> tickets = servers.get(key);
            return tickets == null ? 0 : tickets.size();
        } finally {
            lock.unlock();
        }
    }
}
