package org.microproxy.cache;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.http.HttpHeaders;

class CacheStoreTest {

    private static CachedResponse response(String key, String lang, String body, long time) {
        HttpHeaders h = new HttpHeaders();
        h.set("Content-Type", "text/plain");
        h.set("Cache-Control", "max-age=60");
        h.set("Connection", "keep-alive");
        Map<String, String> vary = new HashMap<>();
        if (lang != null) vary.put("accept-language", lang);
        return new CachedResponse(key, vary, 200, "OK", h, body.getBytes(StandardCharsets.UTF_8), time, time);
    }

    @Test
    void hopByHopFieldsAreNotStored() {
        assertEquals(null, response("http://a/", null, "x", 1).headers().get("Connection"));
    }

    @Test
    void memoryStoreKeepsVariantsAndEvictsLeastRecentlyUsed() {
        MemoryCacheStore store = new MemoryCacheStore(3 * response("http://x/0", null, "y".repeat(100), 0).weight());
        store.put(response("http://x/1", "en", "a".repeat(100), 1));
        store.put(response("http://x/1", "fr", "b".repeat(100), 2));
        assertEquals(2, store.get("http://x/1").size());
        assertEquals("fr", store.get("http://x/1").get(0).vary().get("accept-language"));
        store.put(response("http://x/1", "fr", "c".repeat(100), 3));
        assertEquals(2, store.count());
        store.put(response("http://x/2", null, "d".repeat(100), 4));
        store.get("http://x/1");
        store.put(response("http://x/3", null, "e".repeat(100), 5));
        // x/2 was least recently used.
        assertEquals(List.of(), store.get("http://x/2"));
        assertEquals(2, store.get("http://x/1").size());
        store.remove("http://x/1");
        assertEquals(1, store.count());
        assertTrue(store.size() > 0);
    }

    @Test
    void diskStoreSurvivesRestartsAndEvicts(@TempDir Path dir) throws IOException {
        long weight = response("http://x/0", null, "y".repeat(1000), 0).weight();
        DiskCacheStore store = new DiskCacheStore(dir, 3 * weight);
        store.put(response("http://x/1", "en", "a".repeat(1000), 1));
        store.put(response("http://x/1", "fr", "b".repeat(1000), 2));
        store.put(response("http://x/2", null, "c".repeat(1000), 3));
        assertEquals(3, store.count());

        DiskCacheStore reopened = new DiskCacheStore(dir, 3 * weight);
        assertEquals(3, reopened.count());
        List<CachedResponse> variants = reopened.get("http://x/1");
        assertEquals(2, variants.size());
        assertEquals("fr", variants.get(0).vary().get("accept-language"));
        assertArrayEquals("b".repeat(1000).getBytes(StandardCharsets.UTF_8), variants.get(0).body());
        assertEquals("max-age=60", variants.get(0).headers().get("Cache-Control"));

        reopened.get("http://x/2");
        reopened.put(response("http://x/3", null, "d".repeat(1000), 4));
        assertEquals(3, reopened.count());
        assertEquals(1, reopened.get("http://x/1").size());
        reopened.remove("http://x/2");
        try (var files = Files.list(dir)) {
            assertEquals(2, files.count());
        }
    }

    @Test
    void damagedFilesAreDropped(@TempDir Path dir) throws IOException {
        DiskCacheStore store = new DiskCacheStore(dir, 1 << 20);
        store.put(response("http://x/1", null, "a", 1));
        try (var files = Files.list(dir)) {
            Path file = files.findFirst().orElseThrow();
            Files.write(file, new byte[] {1, 2, 3});
        }
        Files.write(dir.resolve("leftover.entry.7.tmp"), new byte[] {1});
        DiskCacheStore reopened = new DiskCacheStore(dir, 1 << 20);
        assertEquals(0, reopened.count());
        try (var files = Files.list(dir)) {
            assertEquals(0, files.count());
        }
    }
}
