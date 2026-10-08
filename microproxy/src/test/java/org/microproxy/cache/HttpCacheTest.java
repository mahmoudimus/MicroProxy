package org.microproxy.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.HttpFiltersSourceAdapter;
import org.microproxy.HttpProxyServer;
import org.microproxy.http.HttpObject;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;

class HttpCacheTest {

    /** A clock tests move forward by hand. */
    static final class MutableClock extends Clock {
        final AtomicLong millis = new AtomicLong(System.currentTimeMillis());

        void advance(Duration d) {
            millis.addAndGet(d.toMillis());
        }

        @Override
        public long millis() {
            return millis.get();
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis());
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }

    private final Map<String, AtomicInteger> hits = new ConcurrentHashMap<>();
    private final MutableClock clock = new MutableClock();
    private MemoryCacheStore store;
    private HttpServer origin;
    private HttpProxyServer proxy;
    private HttpCache cache;

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(this::handle);
        store = new MemoryCacheStore(1 << 20);
        start(HttpCache.builder().store(store).clock(clock).maxEntrySize(4096));
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private void start(HttpCache.Builder builder) {
        if (proxy != null) proxy.abort();
        cache = builder.build();
        // The JDK's server stamps responses with the real time; restamp them with the test clock,
        // ahead of the cache, so ages are not skewed.
        HttpFiltersSource restamp = new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(org.microproxy.http.HttpRequest originalRequest, FlowContext ctx) {
                return new HttpFilters() {
                    @Override
                    public HttpObject serverToProxyResponse(HttpObject o) {
                        if (o instanceof org.microproxy.http.HttpResponse r) {
                            r.headers().set("Date", CachedResponse.formatDate(clock.millis()));
                        }
                        return o;
                    }
                };
            }
        };
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(restamp).withHttpCache(cache).start();
    }

    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        int n = hits.computeIfAbsent(path, k -> new AtomicInteger()).incrementAndGet();
        exchange.getRequestBody().readAllBytes();
        var h = exchange.getResponseHeaders();
        String body = path + " #" + n;
        int status = 200;
        String inm = exchange.getRequestHeaders().getFirst("If-None-Match");
        switch (path) {
            case "/fresh" -> h.set("Cache-Control", "max-age=60");
            case "/no-store" -> h.set("Cache-Control", "no-store, max-age=60");
            case "/private" -> h.set("Cache-Control", "private, max-age=60");
            case "/etag", "/stale-ok", "/must-revalidate" -> {
                h.set("ETag", "\"v1\"");
                h.set("Cache-Control", path.equals("/must-revalidate") ? "max-age=10, must-revalidate" : "max-age=10");
                if ("\"v1\"".equals(inm)) status = 304;
            }
            case "/vary" -> {
                h.set("Cache-Control", "max-age=60");
                h.set("Vary", "Accept-Language");
                body += " " + exchange.getRequestHeaders().getFirst("Accept-Language");
            }
            case "/heuristic" -> h.set("Last-Modified", CachedResponse.formatDate(clock.millis() - Duration.ofDays(10).toMillis()));
            case "/big" -> {
                h.set("Cache-Control", "max-age=60");
                body = "x".repeat(10_000);
            }
            case "/cookie" -> {
                h.set("Cache-Control", "max-age=60");
                h.set("Set-Cookie", "session=1");
            }
            case "/error" -> {
                h.set("Cache-Control", "max-age=10, stale-if-error=600");
                if (n > 1) status = 500;
            }
            default -> h.set("Cache-Control", "max-age=60");
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        if (status == 304) {
            exchange.sendResponseHeaders(304, -1);
        } else {
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
        }
        exchange.close();
    }

    private HttpResponse<String> fetch(String path, String... headers) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url(origin, path))).timeout(Duration.ofSeconds(20));
        if (headers.length > 0) b.headers(headers);
        return send(client(proxy), b.build());
    }

    private int originHits(String path) {
        return hits.getOrDefault(path, new AtomicInteger()).get();
    }

    private static String cacheStatus(HttpResponse<?> r) {
        return r.headers().firstValue("cache-status").orElse("");
    }

    @Test
    void freshResponsesAreServedFromTheCache() {
        HttpResponse<String> first = fetch("/fresh");
        assertEquals("/fresh #1", first.body());
        assertTrue(cacheStatus(first).contains("fwd=miss; stored"), cacheStatus(first));
        clock.advance(Duration.ofSeconds(30));
        HttpResponse<String> second = fetch("/fresh");
        assertEquals("/fresh #1", second.body());
        assertTrue(cacheStatus(second).startsWith("MicroProxy; hit"), cacheStatus(second));
        assertEquals("30", second.headers().firstValue("age").orElseThrow());
        assertEquals(1, originHits("/fresh"));
        clock.advance(Duration.ofSeconds(31));
        assertEquals("/fresh #2", fetch("/fresh").body());
        assertEquals(2, cache.stats().stores());
        assertEquals(1, cache.stats().hits());
    }

    @Test
    void requestDirectivesAreHonoured() {
        fetch("/fresh");
        clock.advance(Duration.ofSeconds(20));
        assertEquals("/fresh #2", fetch("/fresh", "Cache-Control", "max-age=10").body());
        assertEquals("/fresh #3", fetch("/fresh", "Cache-Control", "no-cache").body());
        assertEquals("/fresh #4", fetch("/fresh", "Pragma", "no-cache").body());
        assertEquals("/fresh #4", fetch("/fresh", "Cache-Control", "min-fresh=30").body());
        assertEquals("/fresh #5", fetch("/fresh", "Cache-Control", "min-fresh=61").body());
        HttpResponse<String> onlyIfCached = fetch("/missing", "Cache-Control", "only-if-cached");
        assertEquals(504, onlyIfCached.statusCode());
        assertEquals(0, originHits("/missing"));
        clock.advance(Duration.ofSeconds(100));
        assertEquals("/fresh #5", fetch("/fresh", "Cache-Control", "max-stale=60").body());
        assertTrue(cacheStatus(fetch("/fresh", "Cache-Control", "max-stale")).contains("stale"));
    }

    @Test
    void uncacheableResponsesAreNotStored() {
        for (String path : new String[] {"/no-store", "/private", "/cookie", "/big"}) {
            fetch(path);
            fetch(path);
            assertEquals(2, originHits(path), path);
        }
        assertEquals(10_000, fetch("/big").body().length());
        fetch("/fresh", "Authorization", "Basic dXNlcjpwdw==");
        fetch("/fresh", "Authorization", "Basic dXNlcjpwdw==");
        assertEquals(2, originHits("/fresh"));
        fetch("/fresh", "Cache-Control", "no-store");
        fetch("/fresh");
        assertEquals(4, originHits("/fresh"));
    }

    @Test
    void staleEntriesAreRevalidated() {
        assertEquals("/etag #1", fetch("/etag").body());
        clock.advance(Duration.ofSeconds(20));
        HttpResponse<String> revalidated = fetch("/etag");
        assertEquals(200, revalidated.statusCode());
        assertEquals("/etag #1", revalidated.body());
        assertTrue(cacheStatus(revalidated).contains("fwd=stale; fwd-status=304"), cacheStatus(revalidated));
        assertEquals(2, originHits("/etag"));
        // The 304 refreshed the entry.
        assertEquals("/etag #1", fetch("/etag").body());
        assertEquals(2, originHits("/etag"));
        assertEquals(1, cache.stats().revalidations());
    }

    @Test
    void heuristicFreshnessUsesLastModified() {
        fetch("/heuristic");
        clock.advance(Duration.ofHours(12));
        assertEquals("/heuristic #1", fetch("/heuristic").body());
        clock.advance(Duration.ofHours(13));
        assertEquals("/heuristic #2", fetch("/heuristic").body());
    }

    @Test
    void variantsAreKeptPerVaryValue() {
        assertEquals("/vary #1 en", fetch("/vary", "Accept-Language", "en").body());
        assertEquals("/vary #2 fr", fetch("/vary", "Accept-Language", "fr").body());
        assertEquals("/vary #1 en", fetch("/vary", "Accept-Language", "en").body());
        assertEquals("/vary #2 fr", fetch("/vary", "Accept-Language", "fr").body());
        assertEquals("/vary #3 null", fetch("/vary").body());
        assertEquals(3, store.count());
    }

    @Test
    void unsafeRequestsInvalidate() {
        fetch("/fresh");
        send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/fresh")))
                .POST(HttpRequest.BodyPublishers.ofString("x")).build());
        assertEquals("/fresh #3", fetch("/fresh").body());
    }

    @Test
    void headIsAnsweredFromAStoredGet() {
        fetch("/fresh");
        HttpResponse<String> head = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/fresh")))
                .method("HEAD", HttpRequest.BodyPublishers.noBody()).build());
        assertEquals(200, head.statusCode());
        assertEquals("", head.body());
        assertEquals(String.valueOf("/fresh #1".length()), head.headers().firstValue("content-length").orElseThrow());
        assertEquals(1, originHits("/fresh"));
    }

    @Test
    void staleEntriesCoverForAnUnreachableServer() {
        fetch("/stale-ok");
        fetch("/must-revalidate");
        clock.advance(Duration.ofMinutes(5));
        origin.stop(0);
        HttpResponse<String> stale = fetch("/stale-ok");
        assertEquals(200, stale.statusCode());
        assertEquals("/stale-ok #1", stale.body());
        assertTrue(cacheStatus(stale).contains("server-unreachable"), cacheStatus(stale));
        assertEquals(502, fetch("/must-revalidate").statusCode());
        assertEquals(502, fetch("/never-cached").statusCode());
    }

    @Test
    void serverErrorsAreReplacedWithinStaleIfError() {
        assertEquals("/error #1", fetch("/error").body());
        clock.advance(Duration.ofSeconds(60));
        HttpResponse<String> r = fetch("/error");
        assertEquals(200, r.statusCode());
        assertEquals("/error #1", r.body());
        clock.advance(Duration.ofHours(1));
        assertEquals(500, fetch("/error").statusCode());
    }

    @Test
    void offlineModeAnswersOnlyFromTheCache() {
        fetch("/fresh");
        fetch("/etag");
        clock.advance(Duration.ofDays(30));
        start(HttpCache.builder().store(store).clock(clock).offline(true));
        assertEquals("/fresh #1", fetch("/fresh").body());
        assertEquals("/etag #1", fetch("/etag", "Cache-Control", "no-cache").body());
        HttpResponse<String> miss = fetch("/missing");
        assertEquals(504, miss.statusCode());
        assertEquals(1, originHits("/fresh"));
        assertEquals(0, originHits("/missing"));
        HttpResponse<String> post = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/fresh")))
                .POST(HttpRequest.BodyPublishers.ofString("x")).build());
        assertEquals(504, post.statusCode());
        assertFalse(hits.containsKey("/missing"));
    }
}
