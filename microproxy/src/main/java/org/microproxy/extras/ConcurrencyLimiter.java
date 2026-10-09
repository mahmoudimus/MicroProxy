package org.microproxy.extras;

import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiFunction;
import java.util.function.Function;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersBuilder.Body;
import org.microproxy.HttpFiltersSource;
import org.microproxy.ResponseSource;
import org.microproxy.SelectiveFilters;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/**
 * Limits how many exchanges run at once per key: per client address by default, or per user,
 * per target host, or anything else a {@linkplain Builder#key key function} derives from the
 * request and its client connection. Requests over the limit wait in a bounded queue, or are
 * answered with {@code 429 Too Many Requests}.
 *
 * <pre>{@code
 * ConcurrencyLimiter limiter = ConcurrencyLimiter.builder()
 *         .key(ConcurrencyLimiter.byUser())        // default: the client's IP address
 *         .permits(8)                               // per key
 *         .permits(user -> user.equals("batch") ? 32 : null)   // null: the default
 *         .queue(16, Duration.ofSeconds(2))         // up to 16 wait up to 2 s each
 *         .build();
 * MicroProxy.bootstrap().plusFiltersSource(limiter).start();
 * }</pre>
 *
 * <p>How a permit is held:
 *
 * <ul>
 *   <li>It is taken in {@link HttpFilters#clientToProxyRequest} for the request head, which runs
 *       after proxy authentication, so {@link #byUser()} sees the authenticated user and
 *       requests refused with {@code 407} are never counted. Place the limiter first among the
 *       filters ({@code HttpFiltersChain.of(limiter, ...)}) so that later filters do no work for
 *       refused requests; an earlier filter that answers a request itself means the limiter never
 *       sees it.
 *   <li>It is released exactly once, in {@link HttpFilters#exchangeEnded}: after the response
 *       has been written, or when the exchange was abandoned (client disconnected, server failed,
 *       a filter answered or aborted, the proxy stopped).
 *   <li>A {@code CONNECT} that becomes a byte tunnel, and a request upgraded with {@code 101}
 *       (WebSocket), hold their permit until the tunnel closes. With {@link
 *       Builder#countTunnels(boolean) countTunnels(false)} {@code CONNECT}s are not counted at all
 *       and an upgraded request gives its permit back once the {@code 101} has been sent. An
 *       intercepted (MITM) {@code CONNECT} holds its permit only until interception starts; the
 *       requests inside the session are counted one by one.
 *   <li>As a safety net, a permit held for longer than {@link Builder#permitTimeout} (10 minutes
 *       by default) is reclaimed and logged at {@code WARNING}. Tunnels are exempt once
 *       established: they end when either side closes or goes idle.
 * </ul>
 *
 * <p>A key's bookkeeping is dropped as soon as none of its permits are in use and nobody waits,
 * so the number of keys tracked is bounded by the number of exchanges in progress. Per-key
 * rejection counts in {@link #snapshot()} therefore cover the key's current busy period; the
 * totals cover the limiter's lifetime.
 *
 * <p>The limiter only reads request heads ({@link SelectiveFilters}), so bodies keep the proxy's
 * fast path. Waiting blocks only the client connection's virtual thread.
 */
public final class ConcurrencyLimiter implements HttpFiltersSource {

    private static final System.Logger LOG = System.getLogger(ConcurrencyLimiter.class.getName());

    /** Called for every request over the limit, refused or (in shadow mode) let through. */
    @FunctionalInterface
    public interface RejectListener {
        void rejected(String key, HttpRequest request, FlowContext flow);
    }

    /** Makes the answer to a refused request; {@code null} sends the default {@code 429}. */
    @FunctionalInterface
    public interface Responder {
        HttpResponse respond(String key, HttpRequest request, FlowContext flow);
    }

    /**
     * One key's state.
     *
     * @param permits how many exchanges with this key may run at once
     * @param inUse exchanges running now (in shadow mode this may exceed {@code permits})
     * @param waiting requests queued for a permit
     * @param rejected requests over the limit since the key became busy
     */
    public record KeyStats(int permits, int inUse, int waiting, long rejected) {}

    /**
     * The limiter's state at one moment.
     *
     * @param keys the keys with permits in use or requests waiting, sorted by key
     * @param inUse permits in use, over all keys
     * @param waiting requests waiting, over all keys
     * @param acquired permits granted since the limiter was built
     * @param rejected requests over the limit since the limiter was built (refused, or let through
     *     in shadow mode)
     * @param reclaimed permits reclaimed by the {@linkplain Builder#permitTimeout safety net}
     */
    public record Snapshot(Map<String, KeyStats> keys, int inUse, int waiting, long acquired, long rejected,
            long reclaimed) {}

    private final BiFunction<HttpRequest, FlowContext, String> keyFunction;
    private final int permits;
    private final Function<String, Integer> permitsPerKey;
    private final int maxWaiting;
    private final long maxWaitNanos;
    private final boolean shadow;
    private final boolean countTunnels;
    private final Duration retryAfter;
    private final Responder responder;
    private final RejectListener onReject;
    private final long permitTimeoutNanos;

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();
    private final Set<Permit> outstanding = ConcurrentHashMap.newKeySet();
    private final LongAdder acquired = new LongAdder();
    private final LongAdder rejected = new LongAdder();
    private final LongAdder reclaimed = new LongAdder();
    private final AtomicLong nextSweep = new AtomicLong(System.nanoTime());

    private ConcurrencyLimiter(Builder b) {
        keyFunction = b.key;
        permits = b.permits;
        permitsPerKey = b.permitsPerKey;
        maxWaiting = b.maxWaiting;
        maxWaitNanos = b.maxWait.toNanos();
        shadow = b.shadow;
        countTunnels = b.countTunnels;
        retryAfter = b.retryAfter;
        responder = b.responder;
        onReject = b.onReject;
        permitTimeoutNanos = b.permitTimeout.toNanos();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Keys requests by the client's IP address (the default). */
    public static BiFunction<HttpRequest, FlowContext, String> byClientIp() {
        return (request, flow) -> clientIp(flow);
    }

    /**
     * Keys requests by the authenticated user ({@code flow.getClientDetails().getUserName()}),
     * or by the client's IP address for clients that did not authenticate.
     */
    public static BiFunction<HttpRequest, FlowContext, String> byUser() {
        return (request, flow) -> {
            String user = flow.getClientDetails().getUserName();
            return user != null ? user : clientIp(flow);
        };
    }

    /**
     * Keys requests by the host they go to, lower-cased and without the port: the {@code CONNECT}
     * target, the absolute URI's host, or the {@code Host} header (inside intercepted sessions).
     */
    public static BiFunction<HttpRequest, FlowContext, String> byTargetHost() {
        return (request, flow) -> targetHost(request);
    }

    private static String clientIp(FlowContext flow) {
        InetSocketAddress address = flow.getClientAddress();
        if (address == null) return "unknown";
        return address.getAddress() != null ? address.getAddress().getHostAddress() : address.getHostString();
    }

    static String targetHost(HttpRequest request) {
        String authority;
        String uri = request.uri();
        if (HttpMethod.CONNECT.equals(request.method())) {
            authority = uri;
        } else {
            int scheme = uri.indexOf("://");
            if (scheme > 0 && uri.indexOf('/') > scheme) {
                int start = scheme + 3;
                int end = start;
                while (end < uri.length() && "/?#".indexOf(uri.charAt(end)) < 0) end++;
                authority = uri.substring(start, end);
                int at = authority.lastIndexOf('@');
                if (at >= 0) authority = authority.substring(at + 1);
            } else {
                authority = request.headers().get(HttpHeaderNames.HOST, "");
            }
        }
        String host;
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            host = close > 0 ? authority.substring(0, close + 1) : authority;
        } else {
            int colon = authority.lastIndexOf(':');
            host = colon >= 0 && authority.indexOf(':') == colon ? authority.substring(0, colon) : authority;
        }
        return host.strip().toLowerCase(Locale.ROOT);
    }

    /** The permits per key unless {@link Builder#permits(Function)} says otherwise. */
    public int permits() {
        return permits;
    }

    /** Whether requests over the limit are only counted and reported, never refused. */
    public boolean shadow() {
        return shadow;
    }

    /** Whether {@code CONNECT} tunnels hold a permit (see the class documentation). */
    public boolean countTunnels() {
        return countTunnels;
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        if (!countTunnels && HttpMethod.CONNECT.equals(originalRequest.method())) {
            return null;
        }
        return new Exchange(flowContext);
    }

    /** The current state, per key and in total. Also reclaims expired permits. */
    public Snapshot snapshot() {
        sweep(System.nanoTime(), true);
        Map<String, KeyStats> keys = new TreeMap<>();
        int inUse = 0;
        int waiting = 0;
        for (Entry e : entries.values()) {
            e.lock.lock();
            try {
                if (e.removed) continue;
                keys.put(e.key, new KeyStats(e.permits, e.inUse, e.waiting, e.rejected));
                inUse += e.inUse;
                waiting += e.waiting;
            } finally {
                e.lock.unlock();
            }
        }
        return new Snapshot(java.util.Collections.unmodifiableMap(keys), inUse, waiting, acquired.sum(),
                rejected.sum(), reclaimed.sum());
    }

    // ---------------------------------------------------------------------------------------
    // Permits
    // ---------------------------------------------------------------------------------------

    /** One key's permits. Guarded by {@link #lock}; removed from the map once idle. */
    private static final class Entry {
        final String key;
        final int permits;
        final ReentrantLock lock = new ReentrantLock();
        final Condition released = lock.newCondition();
        int inUse;
        int waiting;
        long rejected;
        /** Taken out of the map: callers that still hold it must look the key up again. */
        boolean removed;

        Entry(String key, int permits) {
            this.key = key;
            this.permits = permits;
        }
    }

    /** A granted permit, released at most once (by its exchange or the safety net). */
    private final class Permit {
        final Entry entry;
        final long acquiredAt = System.nanoTime();
        final String request;
        final AtomicBoolean released = new AtomicBoolean();
        /** An established tunnel, exempt from the safety net. */
        volatile boolean tunnel;

        Permit(Entry entry, String request) {
            this.entry = entry;
            this.request = request;
        }

        /** Gives the permit back; false if it already was. */
        boolean release() {
            if (!released.compareAndSet(false, true)) return false;
            outstanding.remove(this);
            Entry e = entry;
            e.lock.lock();
            try {
                e.inUse = Math.max(0, e.inUse - 1);
                e.released.signal();
                removeIfIdle(e);
            } finally {
                e.lock.unlock();
            }
            return true;
        }
    }

    private int permitsFor(String key) {
        if (permitsPerKey != null) {
            try {
                Integer n = permitsPerKey.apply(key);
                if (n != null) return Math.max(0, n);
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "permits function failed for key " + key + "; using the default", e);
            }
        }
        return permits;
    }

    private Entry entryFor(String key) {
        Entry e = entries.get(key);
        if (e != null) return e;
        // Asked outside computeIfAbsent: it is the caller's code.
        Entry created = new Entry(key, permitsFor(key));
        e = entries.putIfAbsent(key, created);
        return e != null ? e : created;
    }

    private void removeIfIdle(Entry e) {
        // Under e.lock: acquirers check `removed` under the same lock, so none can slip in.
        if (e.inUse == 0 && e.waiting == 0 && !e.removed) {
            e.removed = true;
            entries.remove(e.key, e);
        }
    }

    /**
     * Takes a permit for {@code key}, waiting in the queue if allowed. Returns null when the
     * request is refused; in shadow mode always returns a permit.
     */
    Permit acquire(String key, HttpRequest request, FlowContext flow) {
        sweep(System.nanoTime(), false);
        String description = request.method() + " " + request.uri();
        boolean over = false;
        Permit permit = null;
        while (true) {
            Entry e = entryFor(key);
            e.lock.lock();
            try {
                if (e.removed) continue;
                if (e.inUse < e.permits) {
                    e.inUse++;
                    permit = new Permit(e, description);
                } else if (shadow) {
                    e.inUse++;
                    e.rejected++;
                    over = true;
                    permit = new Permit(e, description);
                } else {
                    if (e.waiting < maxWaiting && maxWaitNanos > 0) {
                        e.waiting++;
                        try {
                            long remaining = maxWaitNanos;
                            while (e.inUse >= e.permits && remaining > 0) {
                                remaining = e.released.awaitNanos(remaining);
                            }
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        } finally {
                            e.waiting--;
                        }
                        if (e.inUse < e.permits) {
                            e.inUse++;
                            permit = new Permit(e, description);
                        }
                    }
                    if (permit == null) {
                        e.rejected++;
                        over = true;
                        removeIfIdle(e);
                    }
                }
            } finally {
                e.lock.unlock();
            }
            break;
        }
        if (over) {
            rejected.increment();
            if (LOG.isLoggable(Level.DEBUG)) {
                LOG.log(Level.DEBUG, "[conn " + flow.getConnectionId() + "] over the concurrency limit for "
                        + key + (shadow ? " (shadow mode: let through): " : ": ") + description);
            }
            if (onReject != null) {
                try {
                    onReject.rejected(key, request, flow);
                } catch (RuntimeException ex) {
                    LOG.log(Level.WARNING, "onReject listener failed", ex);
                }
            }
        }
        if (permit != null) {
            acquired.increment();
            outstanding.add(permit);
        }
        return permit;
    }

    /** Reclaims permits held longer than the permit timeout; at most every so often unless forced. */
    private void sweep(long now, boolean force) {
        if (permitTimeoutNanos <= 0 || outstanding.isEmpty()) return;
        long due = nextSweep.get();
        if (!force && now - due < 0) return;
        long interval = Math.max(TimeUnit.MILLISECONDS.toNanos(10),
                Math.min(permitTimeoutNanos / 4, TimeUnit.SECONDS.toNanos(1)));
        if (!nextSweep.compareAndSet(due, now + interval) && !force) return;
        for (Permit p : outstanding) {
            if (!p.tunnel && now - p.acquiredAt > permitTimeoutNanos && p.release()) {
                reclaimed.increment();
                LOG.log(Level.WARNING, "reclaimed a concurrency permit for " + p.entry.key + " held for "
                        + TimeUnit.NANOSECONDS.toMillis(now - p.acquiredAt) + " ms by " + p.request
                        + "; its exchange never ended (a leak, or a request slower than permitTimeout)");
            }
        }
    }

    private HttpResponse rejection(String key, HttpRequest request, FlowContext flow) {
        if (responder != null) {
            try {
                HttpResponse custom = responder.respond(key, request, flow);
                if (custom != null) return custom;
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "concurrency limit responder failed; sending the default 429", e);
            }
        }
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                HttpResponseStatus.TOO_MANY_REQUESTS, "Too Many Requests\n");
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=utf-8");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().length);
        if (retryAfter != null) {
            response.headers().set("Retry-After", Long.toString(Math.max(0, (retryAfter.toMillis() + 999) / 1000)));
        }
        return response;
    }

    /** The limiter's filters for one exchange. */
    private final class Exchange implements SelectiveFilters {
        private final FlowContext flow;
        private Permit permit;
        private boolean connect;

        Exchange(FlowContext flow) {
            this.flow = flow;
        }

        @Override
        public boolean sees(Body stream) {
            return false;
        }

        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            if (!(httpObject instanceof HttpRequest request) || permit != null) return null;
            connect = HttpMethod.CONNECT.equals(request.method());
            if (connect && !countTunnels) return null;
            String key;
            try {
                key = keyFunction.apply(request, flow);
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "concurrency limit key function failed; not limiting this request", e);
                return null;
            }
            if (key == null) return null;
            Permit p = acquire(key, request, flow);
            if (p == null) return rejection(key, request, flow);
            permit = p;
            return null;
        }

        @Override
        public void proxyToClientResponseSent(HttpResponse response, ResponseSource source) {
            Permit p = permit;
            if (p == null) return;
            int code = response.status().code();
            if (code == 101 || (connect && code / 100 == 2)) {
                // A tunnel from now on: it ends when a side closes or goes idle.
                if (countTunnels) {
                    p.tunnel = true;
                } else {
                    p.release();
                }
            }
        }

        @Override
        public void exchangeEnded(boolean completed) {
            Permit p = permit;
            if (p != null) p.release();
        }
    }

    /** Configures a {@link ConcurrencyLimiter}. */
    public static final class Builder {
        private BiFunction<HttpRequest, FlowContext, String> key = byClientIp();
        private int permits = 16;
        private Function<String, Integer> permitsPerKey;
        private int maxWaiting;
        private Duration maxWait = Duration.ZERO;
        private boolean shadow;
        private boolean countTunnels = true;
        private Duration retryAfter = Duration.ofSeconds(1);
        private Responder responder;
        private RejectListener onReject;
        private Duration permitTimeout = Duration.ofMinutes(10);

        private Builder() {}

        /**
         * What requests are counted by: the client's IP address by default ({@link #byClientIp()}),
         * or {@link #byUser()}, {@link #byTargetHost()} or any function of the request head and
         * client connection. A {@code null} key leaves the request unlimited.
         */
        public Builder key(BiFunction<HttpRequest, FlowContext, String> key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }

        /** Exchanges per key that may run at once (default 16); 0 refuses every request. */
        public Builder permits(int permits) {
            if (permits < 0) throw new IllegalArgumentException("negative permits: " + permits);
            this.permits = permits;
            return this;
        }

        /**
         * Permits for particular keys; {@code null} means {@link #permits(int)}. Asked when a key
         * becomes busy, and kept until it is idle again.
         */
        public Builder permits(Function<String, Integer> permitsPerKey) {
            this.permitsPerKey = Objects.requireNonNull(permitsPerKey);
            return this;
        }

        /**
         * Lets up to {@code maxWaiting} requests per key wait up to {@code maxWait} each for a
         * permit before they are refused. The default, 0, refuses at once.
         */
        public Builder queue(int maxWaiting, Duration maxWait) {
            if (maxWaiting < 0) throw new IllegalArgumentException("negative queue length: " + maxWaiting);
            if (maxWait.isNegative()) throw new IllegalArgumentException("negative wait: " + maxWait);
            this.maxWaiting = maxWaiting;
            this.maxWait = maxWait;
            return this;
        }

        /**
         * Counts and reports requests over the limit ({@link #onReject}, {@link #snapshot()}) but
         * lets them through, to try a limit out before enforcing it.
         */
        public Builder shadow(boolean shadow) {
            this.shadow = shadow;
            return this;
        }

        /**
         * Whether a {@code CONNECT} tunnel (and an upgraded WebSocket connection) holds its permit
         * for its lifetime (default true). With false, {@code CONNECT}s are not counted and
         * upgraded connections give their permit back once the {@code 101} has been sent; requests
         * inside intercepted sessions are counted either way.
         */
        public Builder countTunnels(boolean countTunnels) {
            this.countTunnels = countTunnels;
            return this;
        }

        /** The {@code Retry-After} of the default {@code 429}, rounded up to seconds; null for none. Default 1 s. */
        public Builder retryAfter(Duration retryAfter) {
            if (retryAfter != null && retryAfter.isNegative()) throw new IllegalArgumentException("negative Retry-After");
            this.retryAfter = retryAfter;
            return this;
        }

        /** Answers refused requests instead of the default plain-text {@code 429}. */
        public Builder response(Responder responder) {
            this.responder = Objects.requireNonNull(responder);
            return this;
        }

        /** Called for every request over the limit (also in shadow mode), on its connection's thread. */
        public Builder onReject(RejectListener listener) {
            this.onReject = Objects.requireNonNull(listener);
            return this;
        }

        /**
         * Reclaims (and logs) a permit held for longer than this, in case an exchange never ends;
         * default 10 minutes, {@link Duration#ZERO} to turn the safety net off. Established
         * tunnels are exempt. Set it above the slowest exchange you expect.
         */
        public Builder permitTimeout(Duration permitTimeout) {
            if (permitTimeout.isNegative()) throw new IllegalArgumentException("negative permit timeout");
            this.permitTimeout = permitTimeout;
            return this;
        }

        public ConcurrencyLimiter build() {
            return new ConcurrencyLimiter(this);
        }
    }
}
