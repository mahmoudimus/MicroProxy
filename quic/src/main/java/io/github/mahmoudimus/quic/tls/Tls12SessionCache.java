package io.github.mahmoudimus.quic.tls;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The TLS 1.2 sessions a client resumes with their tickets (RFC 5077), by server, at most 256
 * servers' worth, the least recently used going first. A session is taken when offered and kept
 * again once the server has issued its next ticket or resumed it.
 */
final class Tls12SessionCache {

    private static final int MAX_SERVERS = 256;

    private final Map<String, Tls12ClientHandshake.Session> sessions = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Tls12ClientHandshake.Session> eldest) {
            return size() > MAX_SERVERS;
        }
    };

    synchronized void put(String key, Tls12ClientHandshake.Session session) {
        sessions.put(key, session);
    }

    synchronized Tls12ClientHandshake.Session take(String key) {
        return sessions.remove(key);
    }
}
