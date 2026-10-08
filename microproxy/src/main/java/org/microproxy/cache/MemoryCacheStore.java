package org.microproxy.cache;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/** Keeps responses in memory, evicting the least recently used URLs beyond a size limit. */
public final class MemoryCacheStore implements CacheStore {

    private final long maxSize;
    private final ReentrantLock lock = new ReentrantLock();
    private final LinkedHashMap<String, List<CachedResponse>> entries = new LinkedHashMap<>(16, 0.75f, true);
    private long size;
    private int count;

    /** @param maxSize the most {@link CachedResponse#weight()} to hold, in bytes */
    public MemoryCacheStore(long maxSize) {
        if (maxSize <= 0) throw new IllegalArgumentException("maxSize must be positive");
        this.maxSize = maxSize;
    }

    @Override
    public List<CachedResponse> get(String key) {
        lock.lock();
        try {
            List<CachedResponse> variants = entries.get(key);
            return variants == null ? List.of() : List.copyOf(variants);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void put(CachedResponse response) {
        if (response.weight() > maxSize) return;
        lock.lock();
        try {
            List<CachedResponse> variants = entries.computeIfAbsent(response.key(), k -> new ArrayList<>(1));
            for (Iterator<CachedResponse> it = variants.iterator(); it.hasNext(); ) {
                CachedResponse old = it.next();
                if (old.vary().equals(response.vary())) {
                    it.remove();
                    size -= old.weight();
                    count--;
                }
            }
            variants.addFirst(response);
            size += response.weight();
            count++;
            Iterator<Map.Entry<String, List<CachedResponse>>> lru = entries.entrySet().iterator();
            while (size > maxSize && lru.hasNext()) {
                Map.Entry<String, List<CachedResponse>> eldest = lru.next();
                if (eldest.getKey().equals(response.key()) && entries.size() > 1) continue;
                for (CachedResponse r : eldest.getValue()) {
                    size -= r.weight();
                    count--;
                }
                lru.remove();
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void remove(String key) {
        lock.lock();
        try {
            List<CachedResponse> variants = entries.remove(key);
            if (variants != null) {
                for (CachedResponse r : variants) {
                    size -= r.weight();
                    count--;
                }
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long size() {
        lock.lock();
        try {
            return size;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public int count() {
        lock.lock();
        try {
            return count;
        } finally {
            lock.unlock();
        }
    }
}
