package org.microproxy.cache;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.ProxyFailure;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpUtil;
import org.microproxy.http.HttpVersion;

/**
 * A shared HTTP cache (RFC 9111) that can also keep a site usable offline.
 *
 * <pre>{@code
 * HttpCache cache = HttpCache.builder()
 *         .store(new DiskCacheStore(Path.of("cache"), 1L << 30))
 *         .build();
 * MicroProxy.bootstrap().withHttpCache(cache).start();
 * }</pre>
 *
 * <p>What it does:
 *
 * <ul>
 *   <li><b>Storing:</b> complete responses to {@code GET}, up to {@link Builder#maxEntrySize}, that
 *       are storable for a shared cache: not {@code no-store} or {@code private}, not to requests
 *       with {@code Authorization} (unless {@code public}, {@code s-maxage} or {@code
 *       must-revalidate}), not {@code Vary: *}, and not setting cookies unless {@code public}.
 *   <li><b>Freshness:</b> from {@code s-maxage}, {@code max-age}, {@code Expires}, or 10% of the
 *       time since {@code Last-Modified} (at most a day); ages follow the RFC's calculation,
 *       including {@code Age} and response delay. Request directives {@code max-age}, {@code
 *       min-fresh}, {@code max-stale}, {@code no-cache}, {@code no-store} and {@code
 *       only-if-cached} are honoured.
 *   <li><b>Validation:</b> stale entries with an {@code ETag} or {@code Last-Modified} are
 *       revalidated with a conditional request; a {@code 304} refreshes the entry and the client
 *       gets the stored response.
 *   <li><b>Variants:</b> {@code Vary} is matched on normalized request field values; each URL may
 *       have several stored variants. {@code HEAD} is answered from a stored {@code GET}.
 *   <li><b>Invalidation:</b> a successful unsafe request ({@code POST}, {@code PUT}, ...) removes
 *       the stored responses for its URL and for same-origin {@code Location} / {@code
 *       Content-Location}.
 *   <li><b>Unreachable servers:</b> when the server cannot be reached (the proxy would answer
 *       {@code 502} or {@code 504}) a stale entry is served instead, unless it says {@code
 *       must-revalidate}, {@code proxy-revalidate}, {@code no-cache} or {@code s-maxage}. A server
 *       error ({@code 5xx}) is replaced by a stale entry only within its {@code stale-if-error}
 *       window. Intercepted HTTPS keeps working: a {@code CONNECT} to an unreachable server is
 *       still intercepted so cached pages can be served inside it.
 *   <li><b>Offline mode</b> ({@link Builder#offline}): requests are answered only from the cache,
 *       whatever their age and directives; anything not stored gets {@code 504}.
 * </ul>
 *
 * <p>Responses carry a {@code Cache-Status} field (RFC 9211), e.g. {@code MicroProxy; hit} or
 * {@code MicroProxy; fwd=miss; stored}. Not implemented: {@code stale-while-revalidate}, partial
 * content ({@code Range} requests bypass the cache), and caching of {@code POST} responses.
 *
 * <p>Install it with {@link org.microproxy.HttpProxyServerBootstrap#withHttpCache}, which runs it
 * after all other filters: they see requests before the cache answers them, and the cache stores
 * responses as they leave the other filters.
 */
public final class HttpCache implements HttpFiltersSource {

    /** Statuses cacheable by default, so a heuristic lifetime may apply (RFC 9110 section 15.1). */
    static final Set<Integer> HEURISTIC_STATUSES = Set.of(200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501);
    /** Statuses this cache stores (with explicit freshness, or heuristically for the set above). */
    private static final Set<Integer> STORABLE_STATUSES = Set.of(200, 203, 204, 300, 301, 302, 307, 308, 404, 405, 410,
            414, 501);
    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS", "TRACE");

    private final CacheStore store;
    private final int maxEntrySize;
    private final boolean shared;
    private final boolean offline;
    private final boolean serveStaleOnError;
    private final double heuristicFraction;
    private final long maxHeuristicMillis;
    private final Clock clock;
    private final String name;

    private final AtomicLong hits = new AtomicLong();
    private final AtomicLong misses = new AtomicLong();
    private final AtomicLong stores = new AtomicLong();
    private final AtomicLong revalidations = new AtomicLong();
    private final AtomicLong staleServed = new AtomicLong();

    private HttpCache(Builder b) {
        this.store = Objects.requireNonNullElseGet(b.store, () -> new MemoryCacheStore(64L << 20));
        this.maxEntrySize = b.maxEntrySize;
        this.shared = b.shared;
        this.offline = b.offline;
        this.serveStaleOnError = b.serveStaleOnError;
        this.heuristicFraction = b.heuristicFraction;
        this.maxHeuristicMillis = b.maxHeuristicFreshness.toMillis();
        this.clock = b.clock;
        this.name = b.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Options for {@link HttpCache}. */
    public static final class Builder {
        private CacheStore store;
        private int maxEntrySize = 8 << 20;
        private boolean shared = true;
        private boolean offline;
        private boolean serveStaleOnError = true;
        private double heuristicFraction = 0.1;
        private Duration maxHeuristicFreshness = Duration.ofDays(1);
        private Clock clock = Clock.systemUTC();
        private String name = "MicroProxy";

        private Builder() {}

        /** Where responses are kept (default: 64 MiB in memory). */
        public Builder store(CacheStore store) {
            this.store = Objects.requireNonNull(store);
            return this;
        }

        /** The largest response body stored (default 8 MiB); larger ones stream past. */
        public Builder maxEntrySize(int bytes) {
            if (bytes <= 0) throw new IllegalArgumentException("maxEntrySize must be positive");
            this.maxEntrySize = bytes;
            return this;
        }

        /** Whether the rules for shared caches apply (default true). False makes a private cache. */
        public Builder shared(boolean shared) {
            this.shared = shared;
            return this;
        }

        /** Answer only from the cache, never contacting servers (default false). */
        public Builder offline(boolean offline) {
            this.offline = offline;
            return this;
        }

        /** Serve stale entries when servers cannot be reached (default true). */
        public Builder serveStaleOnError(boolean serveStaleOnError) {
            this.serveStaleOnError = serveStaleOnError;
            return this;
        }

        /** The heuristic lifetime: this fraction of the time since {@code Last-Modified}, at most {@code max}. */
        public Builder heuristic(double fraction, Duration max) {
            if (fraction < 0 || fraction > 1) throw new IllegalArgumentException("fraction must be between 0 and 1");
            this.heuristicFraction = fraction;
            this.maxHeuristicFreshness = Objects.requireNonNull(max);
            return this;
        }

        /** The clock for ages and freshness (for tests). */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock);
            return this;
        }

        /** The cache's name in {@code Cache-Status} (default "MicroProxy"). */
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }

        public HttpCache build() {
            return new HttpCache(this);
        }
    }

    /**
     * A response made by the cache: a stored response, or its own {@code 504}. The proxy reports
     * these to trackers as {@link org.microproxy.ResponseSource#CACHE}.
     */
    public static final class Answer extends DefaultFullHttpResponse {
        Answer(HttpResponseStatus status, byte[] content) {
            super(HttpVersion.HTTP_1_1, status, content);
        }
    }

    /** Counters since the cache was created. */
    // @value-candidate: becomes a value class in the valhalla build profile
    public record Stats(long hits, long misses, long stores, long revalidations, long staleServed) {}

    public Stats stats() {
        return new Stats(hits.get(), misses.get(), stores.get(), revalidations.get(), staleServed.get());
    }

    public CacheStore store() {
        return store;
    }

    public boolean isOffline() {
        return offline;
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        return new Filters(flowContext);
    }

    // ---------------------------------------------------------------------------------------

    private final class Filters implements HttpFilters {
        private final FlowContext ctx;
        private HttpRequest request;
        private String key;
        private boolean cacheable;
        private boolean head;
        private CacheControl requestCc = CacheControl.NONE;
        private CachedResponse candidate;
        private boolean validatorsAdded;
        private boolean answered;
        private boolean sawServerResponse;
        private long requestTime;

        Filters(FlowContext ctx) {
            this.ctx = ctx;
        }

        @Override
        public boolean proxyToServerAllowOfflineMitm() {
            return offline || serveStaleOnError;
        }

        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            if (!(httpObject instanceof HttpRequest req)) return null;
            request = req;
            HttpMethod method = req.method();
            if (method.equals(HttpMethod.CONNECT)) return null;
            key = absoluteUrl(req, ctx);
            requestTime = clock.millis();
            head = method.equals(HttpMethod.HEAD);
            boolean get = method.equals(HttpMethod.GET);
            if ((!get && !head) || req.headers().contains("Range")) {
                return offline ? answer(gatewayTimeout("offline mode: only cached GET requests are served"), "fwd=bypass; detail=offline") : null;
            }
            cacheable = get;
            requestCc = CacheControl.of(req.headers(), true);
            CachedResponse stored = select(store.get(key), req);
            if (stored != null && shared && req.headers().contains("Authorization")
                    && !allowsAuthorized(stored.cacheControl())) {
                stored = null;
            }
            long now = clock.millis();
            if (stored == null) {
                misses.incrementAndGet();
                if (offline) return answer(gatewayTimeout("offline mode: not in the cache"), "fwd=miss; detail=offline");
                if (requestCc.has("only-if-cached")) return answer(gatewayTimeout("not in the cache"), "fwd=miss; detail=only-if-cached");
                return null;
            }
            if (offline) {
                hits.incrementAndGet();
                return serve(stored, now, "hit; detail=offline");
            }
            long age = stored.currentAge(now);
            long lifetime = lifetime(stored);
            CacheControl responseCc = stored.cacheControl();
            if (!requestCc.has("no-cache") && !responseCc.has("no-cache")) {
                long maxAge = requestCc.seconds("max-age");
                long minFresh = requestCc.seconds("min-fresh");
                boolean acceptable = (maxAge < 0 || age <= maxAge * 1000)
                        && (minFresh < 0 || lifetime - age >= minFresh * 1000);
                if (acceptable && lifetime > age) {
                    hits.incrementAndGet();
                    return serve(stored, now, "hit; ttl=" + (lifetime - age) / 1000);
                }
                long maxStale = requestCc.secondsOrAny("max-stale");
                if (acceptable && maxStale >= 0 && !revalidationRequired(responseCc)
                        && (maxStale == Long.MAX_VALUE || age - lifetime <= maxStale * 1000)) {
                    hits.incrementAndGet();
                    staleServed.incrementAndGet();
                    return serve(stored, now, "hit; detail=stale");
                }
            }
            if (requestCc.has("only-if-cached")) {
                return answer(gatewayTimeout("only a stale response is cached"), "fwd=stale; detail=only-if-cached");
            }
            candidate = stored;
            if (!isConditional(req)) {
                String etag = stored.header("ETag");
                String lastModified = stored.header("Last-Modified");
                if (etag != null) req.headers().set("If-None-Match", etag);
                if (lastModified != null) req.headers().set("If-Modified-Since", lastModified);
                validatorsAdded = etag != null || lastModified != null;
            }
            misses.incrementAndGet();
            return null;
        }

        @Override
        public int responseBufferSizeInBytes(HttpResponse response) {
            if (!cacheable || !storable(response)) return 0;
            return HttpUtil.getContentLength(response, -1) > maxEntrySize ? 0 : maxEntrySize;
        }

        @Override
        public HttpObject serverToProxyResponse(HttpObject httpObject) {
            if (!(httpObject instanceof HttpResponse res) || request == null || key == null) return httpObject;
            sawServerResponse = true;
            long now = clock.millis();
            int status = res.status().code();
            String method = request.method().name();
            if (!SAFE_METHODS.contains(method)) {
                if (status < 400) invalidate(res);
                return httpObject;
            }
            if (!cacheable && !head) return httpObject;
            if (status == 304 && candidate != null && validatorsAdded) {
                CachedResponse updated = candidate.revalidated(res.headers(), requestTime, now);
                if (cacheable && storable(updated.toResponse(now, false))) store.put(updated);
                revalidations.incrementAndGet();
                answered = true;
                return tag(updated.toResponse(now, head), "fwd=stale; fwd-status=304");
            }
            if (status >= 500 && candidate != null && withinStaleIfError(candidate, now)) {
                staleServed.incrementAndGet();
                answered = true;
                return tag(candidate.toResponse(now, head), "fwd=stale; fwd-status=" + status + "; detail=stale-if-error");
            }
            String fwd = candidate != null ? "fwd=stale" : "fwd=miss";
            if (cacheable && res instanceof FullHttpResponse full && storable(full)
                    && full.content().length <= maxEntrySize) {
                store.put(new CachedResponse(key, varyValues(full, request), status, full.status().reasonPhrase(),
                        full.headers(), full.content(), requestTime, now));
                stores.incrementAndGet();
                return tag(res, fwd + "; stored");
            }
            return tag(res, fwd);
        }

        @Override
        public HttpResponse proxyToServerFailure(ProxyFailure failure) {
            if (!answered && !sawServerResponse && candidate != null) {
                int status = failure.status().code();
                if ((status == 502 || status == 504) && serveStaleOnError && !requestCc.has("no-cache")
                        && !revalidationRequired(candidate.cacheControl())) {
                    staleServed.incrementAndGet();
                    hits.incrementAndGet();
                    answered = true;
                    return tag(candidate.toResponse(clock.millis(), head), "hit; detail=server-unreachable");
                }
            }
            return null;
        }

        private HttpResponse serve(CachedResponse stored, long now, String status) {
            return answer(stored.toResponse(now, head), status);
        }

        private HttpResponse answer(FullHttpResponse response, String status) {
            answered = true;
            tag(response, status);
            return response;
        }

        /** Whether the stored response may be used for a request with {@code Authorization}. */
        private boolean allowsAuthorized(CacheControl cc) {
            return cc.has("public") || cc.has("s-maxage") || cc.has("must-revalidate");
        }

        private boolean storable(HttpResponse res) {
            if (!STORABLE_STATUSES.contains(res.status().code())) return false;
            if (requestCc.has("no-store")) return false;
            CacheControl cc = CacheControl.of(res.headers(), false);
            if (cc.has("no-store") || (shared && cc.has("private"))) return false;
            if (shared && request.headers().contains("Authorization") && !allowsAuthorized(cc)) return false;
            if (varyNames(res.headers()).contains("*")) return false;
            if (res.headers().contains("Set-Cookie") && !cc.has("public")) return false;
            boolean explicit = cc.has("max-age") || (shared && cc.has("s-maxage")) || cc.has("public")
                    || res.headers().contains("Expires");
            return explicit || HEURISTIC_STATUSES.contains(res.status().code());
        }

        private boolean withinStaleIfError(CachedResponse stored, long now) {
            long window = Math.max(stored.cacheControl().seconds("stale-if-error"), requestCc.seconds("stale-if-error"));
            if (window < 0) return false;
            long staleness = stored.currentAge(now) - lifetime(stored);
            return staleness <= window * 1000;
        }

        private void invalidate(HttpResponse res) {
            store.remove(key);
            for (String field : List.of("Location", "Content-Location")) {
                String value = res.headers().get(field);
                if (value == null) continue;
                try {
                    URI base = URI.create(key);
                    URI target = base.resolve(value.strip());
                    if (Objects.equals(base.getScheme(), target.getScheme())
                            && Objects.equals(base.getRawAuthority(), target.getRawAuthority())) {
                        store.remove(target.toString());
                    }
                } catch (IllegalArgumentException e) {
                    // Not a usable URL; nothing to invalidate.
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------

    private long lifetime(CachedResponse r) {
        return r.freshnessLifetime(shared, heuristicFraction, maxHeuristicMillis);
    }

    /** Directives that forbid serving the response stale, even when the server is unreachable. */
    private boolean revalidationRequired(CacheControl cc) {
        return cc.has("must-revalidate") || cc.has("no-cache")
                || (shared && (cc.has("proxy-revalidate") || cc.has("s-maxage")));
    }

    private <T extends HttpResponse> T tag(T response, String status) {
        response.headers().add("Cache-Status", name + "; " + status);
        return response;
    }

    private static FullHttpResponse gatewayTimeout(String reason) {
        byte[] body = ("504 Gateway Timeout: " + reason + "\n").getBytes(StandardCharsets.UTF_8);
        FullHttpResponse r = new Answer(HttpResponseStatus.valueOf(504), body);
        r.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=utf-8");
        r.headers().set("Content-Length", String.valueOf(body.length));
        return r;
    }

    private static boolean isConditional(HttpRequest req) {
        HttpHeaders h = req.headers();
        return h.contains("If-None-Match") || h.contains("If-Modified-Since") || h.contains("If-Match")
                || h.contains("If-Unmodified-Since") || h.contains("If-Range");
    }

    static List<String> varyNames(HttpHeaders headers) {
        return headers.getAllElements("Vary").stream().map(s -> s.strip().toLowerCase(Locale.ROOT)).toList();
    }

    /** The request's values for the fields the response varies on. */
    static Map<String, String> varyValues(HttpResponse response, HttpRequest request) {
        Map<String, String> values = new HashMap<>();
        for (String name : varyNames(response.headers())) {
            values.put(name, normalized(request.headers(), name));
        }
        return values;
    }

    private static String normalized(HttpHeaders headers, String name) {
        List<String> all = headers.getAll(name);
        if (all.isEmpty()) return null;
        return String.join(", ", all).strip().replaceAll("\\s+", " ");
    }

    /** The most recently stored variant that matches the request. */
    static CachedResponse select(List<CachedResponse> variants, HttpRequest request) {
        for (CachedResponse r : variants) {
            boolean match = true;
            for (Map.Entry<String, String> e : r.vary().entrySet()) {
                if (!Objects.equals(e.getValue(), normalized(request.headers(), e.getKey()))) {
                    match = false;
                    break;
                }
            }
            if (match) return r;
        }
        return null;
    }

    static String absoluteUrl(HttpRequest request, FlowContext ctx) {
        String uri = request.uri();
        String lower = uri.toLowerCase(Locale.ROOT);
        if (lower.startsWith("http://") || lower.startsWith("https://")) {
            return uri;
        }
        String host = request.headers().get(HttpHeaderNames.HOST, "");
        String scheme = ctx != null && ctx.getClientSslSession() != null ? "https" : "http";
        return scheme + "://" + host + (uri.startsWith("/") ? uri : "/" + uri);
    }
}
