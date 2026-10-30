package org.microproxy.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

class BoundedExpiringCacheTest {
    @Test
    void evictsLeastRecentlyUsedAndExpiresUnrelatedEntries() throws Exception {
        var clock = new DnssecResourceLimitsTest.MutableClock(1000);
        var cache = new BoundedExpiringCache<String, String>(2, clock);
        cache.put("first", "a", 2000);
        cache.put("second", "b", 3000);
        assertEquals("a", cache.get("first"));
        cache.put("third", "c", 4000);
        assertNull(cache.get("second"));
        clock.millis = 2000;
        assertEquals("c", cache.get("third"));
        assertEquals(1, retained(cache));
        assertNull(cache.get("first"));
    }

    @Test
    void expiredEntriesAreRemovedBeforeFreshEntriesAndZeroTtlIsNotCached() throws Exception {
        var clock = new DnssecResourceLimitsTest.MutableClock(1000);
        var cache = new BoundedExpiringCache<String, String>(2, clock);
        cache.put("fresh", "a", 4000);
        cache.put("old", "b", 2000);
        clock.millis = 2000;
        cache.put("new", "c", 4000);
        assertEquals("a", cache.get("fresh"));
        cache.put("new", "expired replacement", 2000);
        assertNull(cache.get("new"));
        assertEquals(1, retained(cache));
    }

    @Test
    void concurrentInsertionsNeverExceedCapacity() throws Exception {
        var clock = new DnssecResourceLimitsTest.MutableClock(1000);
        var cache = new BoundedExpiringCache<Integer, Integer>(8, clock);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var tasks = new ArrayList<Callable<Void>>();
            for (int i = 0; i < 64; i++) {
                int key = i;
                tasks.add(() -> {
                    for (int j = 0; j < 8; j++) {
                        cache.put(key, key, 2000);
                        synchronized (cache) {
                            assertTrue(retained(cache) <= 8);
                        }
                        cache.get(key);
                    }
                    return null;
                });
            }
            for (var result : executor.invokeAll(tasks)) result.get();
        }
        assertEquals(8, retained(cache));
        clock.millis = 2000;
        assertNull(cache.get(-1));
        assertEquals(0, retained(cache));
    }

    @Test
    void zeroCapacityDisablesRetention() throws Exception {
        var cache = new BoundedExpiringCache<String, String>(0, new DnssecResourceLimitsTest.MutableClock(1000));
        cache.put("key", "value", 2000);
        assertNull(cache.get("key"));
        assertEquals(0, retained(cache));
    }

    private static int retained(Object cache) throws Exception {
        Field entries = cache.getClass().getDeclaredField("entries");
        entries.setAccessible(true);
        return ((Map<?, ?>) entries.get(cache)).size();
    }
}
