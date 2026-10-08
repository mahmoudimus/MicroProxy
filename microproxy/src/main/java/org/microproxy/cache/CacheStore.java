package org.microproxy.cache;

import java.util.List;

/**
 * Where {@link HttpCache} keeps responses. Implementations must be safe for concurrent use; {@link
 * MemoryCacheStore} and {@link DiskCacheStore} are provided.
 */
public interface CacheStore {

    /** The stored variants for {@code key} (a URL), most recently stored first; empty if none. */
    List<CachedResponse> get(String key);

    /** Stores {@code response}, replacing the variant of its key with the same {@code vary} values. */
    void put(CachedResponse response);

    /** Removes every variant stored for {@code key}. */
    void remove(String key);

    /** The total {@link CachedResponse#weight()} of what is stored. */
    long size();

    /** The number of stored responses (variants). */
    int count();
}
