package org.microproxy.cache;

import java.util.List;

/**
 * Where {@link HttpCache} keeps responses. Implementations must be safe for concurrent use; {@link
 * MemoryCacheStore} and {@link DiskCacheStore} are provided.
 */
public interface CacheStore {

    /**
     * The stored variants for {@code key} (a URL), most recently stored first; empty if none.
     *
     * @param key the URL whose variants to retrieve
     * @return the stored variants for {@code key} (a URL), most recently stored first; empty if none
     */
    List<CachedResponse> get(String key);

    /**
     * Stores {@code response}, replacing the variant of its key with the same {@code vary} values.
     *
     * @param response the response being handled
     */
    void put(CachedResponse response);

    /**
     * Removes every variant stored for {@code key}.
     *
     * @param key the URL whose variants to remove
     */
    void remove(String key);

    /** {@return the total {@link CachedResponse#weight()} of what is stored} */
    long size();

    /** {@return the number of stored responses (variants)} */
    int count();
}
