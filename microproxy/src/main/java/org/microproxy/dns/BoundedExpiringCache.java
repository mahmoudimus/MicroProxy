package org.microproxy.dns;

import java.time.Clock;
import java.util.LinkedHashMap;

/**
 * Small, strictly bounded LRU cache. Every access discards expired entries, including unrelated
 * names. The bounded scan avoids a second expiry index or a maintenance thread; no DNS or
 * cryptographic work occurs under this cache's lock.
 */
final class BoundedExpiringCache<K, V> {
    private record Entry<V>(V value, long expiresAtMillis) {}

    private final LinkedHashMap<K, Entry<V>> entries = new LinkedHashMap<>(16, 0.75f, true);
    private final int capacity;
    private final Clock clock;

    BoundedExpiringCache(int capacity, Clock clock) {
        if (capacity < 0) throw new IllegalArgumentException("cache capacity must not be negative");
        this.capacity = capacity;
        this.clock = clock;
    }

    synchronized V get(K key) {
        evictExpired();
        Entry<V> entry = entries.get(key);
        return entry == null ? null : entry.value();
    }

    synchronized void put(K key, V value, long expiresAtMillis) {
        evictExpired();
        entries.remove(key);
        if (capacity == 0 || expiresAtMillis <= clock.millis()) return;
        while (entries.size() >= capacity) entries.pollFirstEntry();
        entries.put(key, new Entry<>(value, expiresAtMillis));
    }

    synchronized void evictExpired() {
        long now = clock.millis();
        entries.values().removeIf(entry -> entry.expiresAtMillis() <= now);
    }
}
