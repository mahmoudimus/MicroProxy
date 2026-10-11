/*
 * Ported from quinn-proto src/token_memory_cache.rs (TokenMemoryCache: up to N tokens per server
 * name for a bounded number of server names, the least recently used name evicted) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.token;

import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A bounded, in-memory {@link TokenStore}: up to a number of server names, each with a queue of up
 * to a number of tokens. Storing a token for a full queue drops its oldest; storing one for a new
 * name when the cache is full evicts the least recently used name. Tokens are taken oldest first.
 *
 * <p>Thread-safe: a {@link ReentrantLock} guards the map.
 */
public final class TokenMemoryCache implements TokenStore {

    private final int maxServerNames;
    private final int maxTokensPerServer;
    private final ReentrantLock lock = new ReentrantLock();
    /** Server names in access order, least recently used first. */
    private final LinkedHashMap<String, ArrayDeque<byte[]>> entries = new LinkedHashMap<>(16, 0.75f, true);

    /** A cache with quinn's defaults: 256 server names, 2 tokens each. */
    public TokenMemoryCache() {
        this(256, 2);
    }

    /**
     * A cache.
     *
     * @param maxServerNames the most server names to remember; 0 keeps nothing
     * @param maxTokensPerServer the most tokens per server name; 0 keeps nothing
     */
    public TokenMemoryCache(int maxServerNames, int maxTokensPerServer) {
        if (maxServerNames < 0 || maxTokensPerServer < 0) {
            throw new IllegalArgumentException("negative limit");
        }
        this.maxServerNames = maxServerNames;
        this.maxTokensPerServer = maxTokensPerServer;
    }

    @Override
    public void put(String serverName, byte[] token) {
        if (maxServerNames == 0 || maxTokensPerServer == 0 || serverName == null || token == null) {
            return;
        }
        lock.lock();
        try {
            ArrayDeque<byte[]> tokens = entries.get(serverName);
            if (tokens == null) {
                if (entries.size() >= maxServerNames) {
                    Iterator<Map.Entry<String, ArrayDeque<byte[]>>> lru = entries.entrySet().iterator();
                    lru.next();
                    lru.remove();
                }
                tokens = new ArrayDeque<>();
                entries.put(serverName, tokens);
            }
            if (tokens.size() >= maxTokensPerServer) {
                tokens.pollFirst();
            }
            tokens.addLast(token.clone());
        } finally {
            lock.unlock();
        }
    }

    @Override
    public byte[] take(String serverName) {
        if (serverName == null) {
            return null;
        }
        lock.lock();
        try {
            ArrayDeque<byte[]> tokens = entries.get(serverName);
            if (tokens == null) {
                return null;
            }
            byte[] token = tokens.pollFirst();
            if (tokens.isEmpty()) {
                entries.remove(serverName);
            }
            return token;
        } finally {
            lock.unlock();
        }
    }
}
