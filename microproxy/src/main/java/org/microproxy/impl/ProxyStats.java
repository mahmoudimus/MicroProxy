package org.microproxy.impl;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyAdapter;
import org.microproxy.ClientHello;
import org.microproxy.FlowRecord;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpFiltersSource;
import org.microproxy.ResponseFlag;
import org.microproxy.ServerState;
import org.microproxy.cache.HttpCache;
import org.microproxy.extras.ConcurrencyLimiter;
import org.microproxy.stats.Counter;
import org.microproxy.stats.Gauge;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.stats.TagExtractor;

/**
 * The proxy's own metrics, with Envoy's names, resolved once from its {@link StatsRegistry} and
 * kept in fields: per listener ({@link HttpStats}, {@link ListenerStats}), per cluster ({@link
 * ClusterStats}, which server connections keep) and process-wide. The proxy counts at its own
 * call sites (a connection accepted or closed, an exchange started or ended, a server connected),
 * never through {@link org.microproxy.ActivityTracker}s.
 *
 * <p>With metrics off the registry is {@link StatsRegistry#NOOP}: every metric here does nothing
 * and {@link #enabled} is false, which guards the few call sites that would otherwise read a clock.
 * The per-protocol stats (HTTP/2 and HTTP/3 codecs, QUIC, SOCKS, MASQUE, tunnels, WebSockets, the
 * hooks) hang off this class the same way ({@link ProtocolStats}, {@link QuicStats}).
 */
final class ProxyStats {

    final StatsRegistry registry;
    /** Whether metrics are kept: false for {@link StatsRegistry#NOOP}, whose metrics do nothing. */
    final boolean enabled;
    /** {@code http.<prefix>.*}: the proxy's requests and client connections. */
    final HttpStats http;
    /** {@code listener.<address>.*}, once the listener is bound; until then (and without metrics) no-ops. */
    private volatile ListenerStats listener;
    /** {@code tls_inspector.*}: what the ClientHellos the proxy reads before deciding on a session offer. */
    final TlsInspectorStats tlsInspector;
    final ClusterStats direct;
    final ClusterStats cache;
    final ClusterStats replay;
    /** {@code listener_manager.listener_stopped}: listeners closed. */
    final Counter listenerStopped;
    private final ClusterTable clusters;
    /** {@code http2.downstream.*} and {@code http2.upstream.*}. */
    final ProtocolStats.Http2Stats http2Downstream;
    final ProtocolStats.Http2Stats http2Upstream;
    /** {@code http3.downstream.*} and {@code http3.upstream.*}. */
    final ProtocolStats.Http3Stats http3Downstream;
    final ProtocolStats.Http3Stats http3Upstream;
    final ProtocolStats.QuicFlowStats transparentQuic;
    final ProtocolStats.SocksStats socks;
    final ProtocolStats.MasqueStats masque;
    final ProtocolStats.TunnelStats tunnel;
    final ProtocolStats.WebSocketStats webSocket;
    final ProtocolStats.Hooks hooks;
    /**
     * The {@link QuicStats} of each QUIC scope, made on first use by code that runs QUIC: plain
     * objects here, so that this class needs nothing of the optional {@code quic} module.
     */
    private final Map<String, Object> quicScopes = new ConcurrentHashMap<>();

    ProxyStats(StatsRegistry registry, String listenerName) {
        this.registry = registry;
        this.enabled = registry.enabled();
        this.http = new HttpStats(registry, TagExtractor.sanitize(listenerName));
        this.listener = new ListenerStats(StatsRegistry.NOOP, "-");
        this.tlsInspector = new TlsInspectorStats(registry);
        this.direct = new ClusterStats(registry, "direct");
        this.cache = new ClusterStats(registry, "cache");
        this.replay = new ClusterStats(registry, "replay");
        this.listenerStopped = registry.counter("listener_manager.listener_stopped", "Listeners closed");
        this.clusters = new ClusterTable(registry);
        this.http2Downstream = new ProtocolStats.Http2Stats(registry, "downstream");
        this.http2Upstream = new ProtocolStats.Http2Stats(registry, "upstream");
        this.http3Downstream = new ProtocolStats.Http3Stats(registry, "downstream");
        this.http3Upstream = new ProtocolStats.Http3Stats(registry, "upstream");
        this.transparentQuic = new ProtocolStats.QuicFlowStats(registry, "quic_transparent");
        this.socks = new ProtocolStats.SocksStats(registry);
        this.masque = new ProtocolStats.MasqueStats(registry);
        this.tunnel = new ProtocolStats.TunnelStats(registry);
        this.webSocket = new ProtocolStats.WebSocketStats(registry);
        this.hooks = new ProtocolStats.Hooks(registry);
    }

    /** The object kept for QUIC scope {@code scope}, made by {@code make} the first time ({@link QuicStats#of}). */
    Object quicScope(String scope, java.util.function.Supplier<Object> make) {
        Object o = quicScopes.get(scope);
        return o != null ? o : quicScopes.computeIfAbsent(scope, k -> make.get());
    }

    /** What a cluster is: {@code direct}, {@code cache}, {@code replay}, a chained proxy, a server, or the overflow. */
    static final String DIRECT = "direct";
    static final String CACHE = "cache";
    static final String REPLAY = "replay";
    static final String CHAINED_PROXY = "chained_proxy";
    static final String HOST = "host";
    static final String OVERFLOW = "overflow";

    /** A cluster with stats of its own, and what it is. */
    record Cluster(String name, String kind) {}

    /** The clusters with stats now, for the admin listener: the fixed ones, then those met so far, by name. */
    List<Cluster> clusters() {
        List<Cluster> all = new ArrayList<>(List.of(new Cluster(direct.name, DIRECT), new Cluster(cache.name, CACHE),
                new Cluster(replay.name, REPLAY)));
        all.addAll(clusters.list());
        return all;
    }

    /** {@code listener.<address>.*} of the listener bound at {@code address}. */
    void bound(InetSocketAddress address) {
        listener = new ListenerStats(registry, listenerAddress(address));
    }

    ListenerStats listener() {
        return listener;
    }

    /**
     * Envoy's name for a listener address: {@code 0.0.0.0_8080}, or {@code [__1]_8080} for IPv6
     * (whose colons a flat name cannot have).
     */
    static String listenerAddress(InetSocketAddress address) {
        String host;
        if (address.getAddress() == null) {
            host = TagExtractor.sanitize(address.getHostString());
        } else if (address.getAddress() instanceof Inet6Address v6) {
            String literal = v6.getHostAddress();
            int scope = literal.indexOf('%');
            if (scope >= 0) literal = literal.substring(0, scope);
            host = "[" + literal.replace(':', '_') + "]";
        } else {
            host = address.getAddress().getHostAddress();
        }
        return host + "_" + address.getPort();
    }

    /**
     * The cluster of a server connection through {@code proxy} (null or {@link
     * ChainedProxyAdapter#FALLBACK_TO_DIRECT_CONNECTION} for a direct one) to {@code hostAndPort}:
     * {@code direct}, the server ({@code host_port}) with {@link StatsRegistry#perHostClusters()},
     * or the chained proxy ({@code host_port} of its address). Looked up once per connection, not
     * per request.
     */
    ClusterStats cluster(ChainedProxy proxy, String hostAndPort) {
        if (!enabled) return direct;
        if (proxy == null || proxy == ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION) {
            return registry.perHostClusters() && hostAndPort != null ? clusters.get(TagExtractor.sanitize(hostAndPort), HOST)
                    : direct;
        }
        InetSocketAddress address = proxy.getChainedProxyAddress();
        if (address == null) return clusters.get("chained_proxy", CHAINED_PROXY);
        return clusters.get(TagExtractor.sanitize(address.getHostString() + "_" + address.getPort()), CHAINED_PROXY);
    }

    /**
     * Registers the gauges and counters read from elsewhere: {@code server.*}, the shared pool's
     * ({@code connection_pool.*}), the cache's ({@code cache.*}) and the concurrency limiters'
     * ({@code concurrency_limit.*}) found among {@code filters}.
     */
    void registerServer(DefaultHttpProxyServer server, HttpCache httpCache, HttpFiltersSource filters) {
        if (!enabled) return;
        long started = System.nanoTime();
        MemoryMXBean memory = ManagementFactory.getMemoryMXBean();
        registry.gauge("server.uptime", "Seconds the proxy has been running",
                () -> (System.nanoTime() - started) / 1_000_000_000L);
        registry.gauge("server.live", "1 while the proxy is live, 0 once it drains or stops",
                () -> server.state() == ServerState.LIVE ? 1 : 0);
        registry.gauge("server.state", "0 live, 1 draining, 2 pre-initializing, 3 initializing, 4 stopped",
                () -> server.state().code());
        registry.gauge("listener_manager.total_listeners_active", "Listeners accepting connections",
                server::activeListeners);
        registry.gauge("listener_manager.total_listeners_draining", "Listeners accepting connections while the proxy drains",
                () -> server.state() == ServerState.DRAINING ? server.activeListeners() : 0);
        registry.gauge("server.concurrency", "Processors available to the JVM",
                () -> Runtime.getRuntime().availableProcessors());
        registry.gauge("server.memory_allocated", "Heap bytes in use", () -> memory.getHeapMemoryUsage().getUsed());
        registry.gauge("server.memory_heap_size", "Heap bytes committed", () -> memory.getHeapMemoryUsage().getCommitted());
        registry.gauge("server.total_connections", "Client connections open", server::getOpenConnectionCount);
        if (server.pool != null) {
            SharedConnectionPool pool = server.pool;
            registry.gauge("connection_pool.total_connections", "Pooled server connections, leased or idle",
                    () -> pool.metrics().totalConnections());
            registry.gauge("connection_pool.active_connections", "Pooled server connections leased",
                    () -> pool.metrics().activeConnections());
            registry.gauge("connection_pool.idle_connections", "Pooled server connections idle",
                    () -> pool.metrics().idleConnections());
            registry.counter("connection_pool.borrow", "Leases granted", () -> pool.metrics().borrowCount());
            registry.counter("connection_pool.return", "Connections returned to the pool", () -> pool.metrics().returnCount());
            registry.counter("connection_pool.eviction", "Idle connections closed by the pool",
                    () -> pool.metrics().evictionCount());
            registry.counter("connection_pool.validation_failure", "Idle connections found closed when about to be reused",
                    () -> pool.metrics().validationFailureCount());
        }
        if (httpCache != null) {
            registry.counter("cache.hits", "Requests answered from the cache without revalidation",
                    () -> httpCache.stats().hits());
            registry.counter("cache.misses", "Cache lookups without a usable entry", () -> httpCache.stats().misses());
            registry.counter("cache.stores", "Responses stored", () -> httpCache.stats().stores());
            registry.counter("cache.revalidations", "Cached responses revalidated", () -> httpCache.stats().revalidations());
            registry.counter("cache.stale_served", "Stale responses served", () -> httpCache.stats().staleServed());
        }
        List<ConcurrencyLimiter> limiters = new ArrayList<>();
        limiters(filters, limiters);
        for (int i = 0; i < limiters.size(); i++) {
            limiters.get(i).registerStats(registry, i == 0 ? "concurrency_limit" : "concurrency_limit_" + (i + 1));
        }
    }

    private static void limiters(HttpFiltersSource source, List<ConcurrencyLimiter> found) {
        if (source instanceof ConcurrencyLimiter limiter) {
            found.add(limiter);
        } else if (source instanceof HttpFiltersChain chain) {
            for (HttpFiltersSource s : chain.sources()) limiters(s, found);
        }
    }

    /** The response class of {@code status} (1 to 5), or 0 for none. */
    static int responseClass(int status) {
        int c = status / 100;
        return c >= 1 && c <= 5 ? c : 0;
    }

    // ---------------------------------------------------------------------------------------
    // http.<prefix>.*
    // ---------------------------------------------------------------------------------------

    /** {@code http.<prefix>.*}: requests and client connections, as Envoy's HTTP connection manager counts them. */
    static final class HttpStats {
        private static final ResponseFlag[] FLAGS = ResponseFlag.values();

        private final StatsRegistry registry;
        private final String prefix;
        final Counter rqTotal;
        final Gauge rqActive;
        /** {@code downstream_rq_<n>xx} by class; index 0 does nothing. */
        private final Counter[] rqClass = new Counter[6];
        final Histogram rqTime;
        final Counter rqHttp1;
        final Counter rqHttp2;
        final Counter rqHttp3;
        final Counter rqRxReset;
        final Counter rqTxReset;
        final Counter rqTooLarge;
        /** {@code downstream_rq_response_flag.<flag>}, by flag ordinal, made on first use. */
        private final AtomicReferenceArray<Counter> rqFlags = new AtomicReferenceArray<>(FLAGS.length);
        final Counter cxTotal;
        final Gauge cxActive;
        final Counter cxHttp1;
        final Counter cxHttp2;
        final Counter cxHttp3;
        final Counter cxSsl;
        final Counter cxDestroy;
        final Counter cxDestroyRemote;
        final Counter cxDestroyLocal;
        final Histogram cxLength;
        final Counter cxRxBytes;
        final Counter cxTxBytes;
        final Counter cxDrainClose;

        HttpStats(StatsRegistry registry, String name) {
            this.registry = registry;
            this.prefix = "http." + name + ".";
            rqTotal = registry.counter(prefix + "downstream_rq_total", "Requests from clients");
            rqActive = registry.gauge(prefix + "downstream_rq_active", "Requests from clients in progress");
            rqClass[0] = StatsRegistry.NOOP.counter("none");
            for (int c = 1; c <= 5; c++) {
                rqClass[c] = registry.counter(prefix + "downstream_rq_" + c + "xx", "Responses to clients by status class");
            }
            rqTime = registry.histogram(prefix + "downstream_rq_time",
                    "Milliseconds from a request's first byte to its response's last");
            rqHttp1 = registry.counter(prefix + "downstream_rq_http1_total", "HTTP/1 requests from clients");
            rqHttp2 = registry.counter(prefix + "downstream_rq_http2_total", "HTTP/2 requests from clients");
            rqHttp3 = registry.counter(prefix + "downstream_rq_http3_total", "HTTP/3 requests from clients");
            rqRxReset = registry.counter(prefix + "downstream_rq_rx_reset", "Requests the client reset");
            rqTxReset = registry.counter(prefix + "downstream_rq_tx_reset",
                    "Requests the proxy reset (or closed the connection of) after its response started");
            rqTooLarge = registry.counter(prefix + "downstream_rq_too_large", "Requests answered 413 by the proxy");
            cxTotal = registry.counter(prefix + "downstream_cx_total", "Client connections");
            cxActive = registry.gauge(prefix + "downstream_cx_active", "Client connections open");
            cxHttp1 = registry.counter(prefix + "downstream_cx_http1_total", "Client connections that carried HTTP/1");
            cxHttp2 = registry.counter(prefix + "downstream_cx_http2_total", "Client connections that carried HTTP/2");
            cxHttp3 = registry.counter(prefix + "downstream_cx_http3_total", "Client connections that carried HTTP/3");
            cxSsl = registry.counter(prefix + "downstream_cx_ssl_total", "Client connections that completed a TLS handshake");
            cxDestroy = registry.counter(prefix + "downstream_cx_destroy", "Client connections closed");
            cxDestroyRemote = registry.counter(prefix + "downstream_cx_destroy_remote", "Client connections the client closed");
            cxDestroyLocal = registry.counter(prefix + "downstream_cx_destroy_local", "Client connections the proxy closed");
            cxLength = registry.histogram(prefix + "downstream_cx_length_ms", "Milliseconds client connections were open");
            cxRxBytes = registry.counter(prefix + "downstream_cx_rx_bytes_total", "Bytes read from clients");
            cxTxBytes = registry.counter(prefix + "downstream_cx_tx_bytes_total", "Bytes written to clients");
            cxDrainClose = registry.counter(prefix + "downstream_cx_drain_close",
                    "Client connections drained: a response with Connection: close, or GOAWAY");
        }

        /** Counts a request whose exchange starts on a {@code kind} channel ({@code h1}, {@code h2} or {@code h3}). */
        void requestStarted(FlowRecord.Kind kind) {
            rqTotal.inc();
            rqActive.inc();
            protocol(kind).inc();
        }

        private Counter protocol(FlowRecord.Kind kind) {
            return kind == FlowRecord.Kind.HTTP2 ? rqHttp2 : kind == FlowRecord.Kind.HTTP3 ? rqHttp3 : rqHttp1;
        }

        /**
         * Counts the end of an exchange: the class of {@code status} (0 for no response), its time
         * ({@code nanos}, negative if unknown), and for a response of 400 or more, or none, each of
         * its response flags ({@code flagBits}, one bit per ordinal).
         *
         * @param started whether {@link #requestStarted} counted it (else it is counted now, as a
         *     request a transport answered itself)
         */
        void requestEnded(FlowRecord.Kind kind, boolean started, int status, long nanos, long flagBits) {
            if (!started) {
                rqTotal.inc();
                protocol(kind).inc();
            }
            rqClass[responseClass(status)].inc();
            if (nanos >= 0) rqTime.recordNanos(nanos);
            if (status >= 400 || status == 0) {
                for (int i = 0; flagBits != 0 && i < FLAGS.length; i++, flagBits >>>= 1) {
                    if ((flagBits & 1) != 0) flag(i).inc();
                }
            }
            // Last: a request no longer active has been counted in full.
            if (started) rqActive.dec();
        }

        /** {@code downstream_rq_response_flag.<flag>} of flag {@code ordinal}, made on first use. */
        Counter flag(int ordinal) {
            Counter c = rqFlags.get(ordinal);
            if (c == null) {
                c = registry.counter(prefix + "downstream_rq_response_flag." + FLAGS[ordinal].code(),
                        "Requests that ended with a 4xx or 5xx response, or none, by response flag");
                if (!rqFlags.compareAndSet(ordinal, null, c)) c = rqFlags.get(ordinal);
            }
            return c;
        }
    }

    // ---------------------------------------------------------------------------------------
    // listener.<address>.*
    // ---------------------------------------------------------------------------------------

    /** {@code listener.<address>.*}: the TCP listener's connections and TLS handshakes. */
    static final class ListenerStats {
        final Counter cxTotal;
        final Gauge cxActive;
        final Gauge preCxActive;
        final Counter cxDestroy;
        final Counter sslHandshake;
        final Counter sslConnectionError;

        ListenerStats(StatsRegistry registry, String address) {
            String p = "listener." + address + ".";
            cxTotal = registry.counter(p + "downstream_cx_total", "Connections accepted");
            cxActive = registry.gauge(p + "downstream_cx_active", "Connections open");
            preCxActive = registry.gauge(p + "downstream_pre_cx_active",
                    "Connections still being inspected (PROXY header, TLS handshake, protocol detection)");
            cxDestroy = registry.counter(p + "downstream_cx_destroy", "Connections closed");
            sslHandshake = registry.counter(p + "ssl.handshake", "TLS handshakes with clients that succeeded");
            sslConnectionError = registry.counter(p + "ssl.connection_error", "TLS handshakes with clients that failed");
        }
    }

    /** {@code tls_inspector.*}: the ClientHellos the proxy reads to decide on a session. */
    static final class TlsInspectorStats {
        final Counter tlsFound;
        final Counter tlsNotFound;
        final Counter sniFound;
        final Counter sniNotFound;
        final Counter alpnFound;
        final Counter alpnNotFound;
        final Counter clientHelloTooLarge;

        TlsInspectorStats(StatsRegistry registry) {
            tlsFound = registry.counter("tls_inspector.tls_found", "Connections that started with a TLS ClientHello");
            tlsNotFound = registry.counter("tls_inspector.tls_not_found", "Connections that did not start with TLS");
            sniFound = registry.counter("tls_inspector.sni_found", "ClientHellos with a server name");
            sniNotFound = registry.counter("tls_inspector.sni_not_found", "ClientHellos without a server name");
            alpnFound = registry.counter("tls_inspector.alpn_found", "ClientHellos with ALPN protocols");
            alpnNotFound = registry.counter("tls_inspector.alpn_not_found", "ClientHellos without ALPN protocols");
            clientHelloTooLarge = registry.counter("tls_inspector.client_hello_too_large", "ClientHellos too large to read");
        }

        /** Counts what a client's first bytes turned out to be: {@code hello}, or not TLS ({@code tooLarge} if it was). */
        void inspected(ClientHello hello, boolean tooLarge) {
            if (hello == null) {
                (tooLarge ? clientHelloTooLarge : tlsNotFound).inc();
                return;
            }
            tlsFound.inc();
            (hello.sni() != null ? sniFound : sniNotFound).inc();
            (hello.alpnProtocols().isEmpty() ? alpnNotFound : alpnFound).inc();
        }
    }

    // ---------------------------------------------------------------------------------------
    // cluster.<name>.*
    // ---------------------------------------------------------------------------------------

    /** {@code cluster.<name>.*}: connections and requests to one cluster (a route, or a server). */
    static final class ClusterStats {
        /** Counts nothing: the cluster of connections not (yet) counted, and of every one without metrics. */
        static final ClusterStats NOOP = new ClusterStats(StatsRegistry.NOOP, "-");

        final String name;
        final boolean enabled;
        final Counter cxTotal;
        final Gauge cxActive;
        final Counter cxConnectFail;
        final Counter cxConnectTimeout;
        final Histogram cxConnectMs;
        final Counter cxHttp1;
        final Counter cxHttp2;
        final Counter cxHttp3;
        final Counter cxDestroy;
        final Counter cxDestroyLocal;
        final Counter cxDestroyRemote;
        final Histogram cxLength;
        final Counter cxPoolOverflow;
        final Counter rqTotal;
        final Gauge rqActive;
        private final Counter[] rqClass = new Counter[6];
        final Histogram rqTime;
        final Counter rqRetry;
        final Counter rqTimeout;
        final Counter rqRxReset;
        final Counter sslHandshake;
        final Counter sslConnectionError;
        final Counter cxRxBytes;
        final Counter cxTxBytes;
        final Counter backoffEngaged;
        final Counter failover;
        final Gauge backoffActive;
        /** What the cluster is ({@link #CHAINED_PROXY}, {@link #HOST}), for the admin listener; null for the fixed ones. */
        volatile String kind;
        /** When it was last handed out, for {@link StatsRegistry.Overflow#LRU}. */
        volatile long lastUsed = System.nanoTime();
        private final List<String> names = new ArrayList<>();
        private final StatsRegistry registry;

        ClusterStats(StatsRegistry registry, String name) {
            this.registry = registry;
            this.name = name;
            this.enabled = registry.enabled();
            String p = "cluster." + name + ".";
            cxTotal = counter(p + "upstream_cx_total", "Connections made to the cluster");
            cxActive = gauge(p + "upstream_cx_active", "Connections to the cluster open");
            cxConnectFail = counter(p + "upstream_cx_connect_fail", "Connection attempts that failed");
            cxConnectTimeout = counter(p + "upstream_cx_connect_timeout", "Connection attempts that timed out");
            cxConnectMs = histogram(p + "upstream_cx_connect_ms", "Milliseconds to connect");
            cxHttp1 = counter(p + "upstream_cx_http1_total", "Connections that carried HTTP/1");
            cxHttp2 = counter(p + "upstream_cx_http2_total", "Connections that carried HTTP/2");
            cxHttp3 = counter(p + "upstream_cx_http3_total", "Connections that carried HTTP/3");
            cxDestroy = counter(p + "upstream_cx_destroy", "Connections closed");
            cxDestroyLocal = counter(p + "upstream_cx_destroy_local", "Connections the proxy closed");
            cxDestroyRemote = counter(p + "upstream_cx_destroy_remote", "Connections the server closed");
            cxLength = histogram(p + "upstream_cx_length_ms", "Milliseconds connections were open");
            cxPoolOverflow = counter(p + "upstream_cx_pool_overflow", "Requests refused for want of a pooled connection");
            rqTotal = counter(p + "upstream_rq_total", "Requests sent to the cluster");
            rqActive = gauge(p + "upstream_rq_active", "Requests to the cluster in progress");
            rqClass[0] = StatsRegistry.NOOP.counter("none");
            for (int c = 1; c <= 5; c++) {
                rqClass[c] = counter(p + "upstream_rq_" + c + "xx", "Responses from the cluster by status class");
            }
            rqTime = histogram(p + "upstream_rq_time", "Milliseconds from sending a request to the end of its response");
            rqRetry = counter(p + "upstream_rq_retry", "Requests sent again on a new connection");
            rqTimeout = counter(p + "upstream_rq_timeout", "Requests whose response did not come in time");
            rqRxReset = counter(p + "upstream_rq_rx_reset", "Requests the server reset or closed the connection of");
            sslHandshake = counter(p + "ssl.handshake", "TLS handshakes with the cluster that succeeded");
            sslConnectionError = counter(p + "ssl.connection_error", "TLS handshakes with the cluster that failed");
            cxRxBytes = counter(p + "upstream_cx_rx_bytes_total", "Bytes read from the cluster (decrypted, over TLS)");
            cxTxBytes = counter(p + "upstream_cx_tx_bytes_total", "Bytes written to the cluster (before encryption, over TLS)");
            backoffEngaged = counter(p + "backoff_engaged", "Waits before trying the cluster after earlier attempts failed");
            failover = counter(p + "failover", "Connection attempts that failed and moved on to the route's next choice");
            backoffActive = gauge(p + "backoff_active", "Requests waiting before they try the cluster (backing off)");
        }

        private Counter counter(String name, String help) {
            names.add(name);
            return registry.counter(name, help);
        }

        private Gauge gauge(String name, String help) {
            names.add(name);
            return registry.gauge(name, help);
        }

        private Histogram histogram(String name, String help) {
            names.add(name);
            return registry.histogram(name, help);
        }

        /** Forgets this cluster's metrics (evicted under {@link StatsRegistry.Overflow#LRU}). */
        void unregister() {
            for (String n : names) registry.remove(n);
        }

        /** Counts a connection made: {@code connectNanos} long, or -1 when the time is not known. */
        void connected(long connectNanos) {
            cxTotal.inc();
            cxActive.inc();
            if (connectNanos >= 0) cxConnectMs.recordNanos(connectNanos);
        }

        /** Counts a connection attempt that failed with {@code e}. */
        void connectFailed(Throwable e) {
            cxConnectFail.inc();
            for (Throwable t = e; t != null; t = t.getCause() == t ? null : t.getCause()) {
                if (t instanceof java.net.SocketTimeoutException) {
                    cxConnectTimeout.inc();
                    return;
                }
            }
        }

        /** Counts a connection closed after {@code nanos}, by the server ({@code remote}) or the proxy. */
        void closed(long nanos, boolean remote) {
            cxActive.dec();
            cxDestroy.inc();
            (remote ? cxDestroyRemote : cxDestroyLocal).inc();
            if (nanos >= 0) cxLength.recordNanos(nanos);
        }

        void requestStarted() {
            rqTotal.inc();
            rqActive.inc();
        }

        /** Counts the end of a request: the server's {@code status} (0 for none), after {@code nanos} (-1 if not known). */
        void requestEnded(int status, long nanos) {
            rqClass[responseClass(status)].inc();
            if (nanos >= 0) rqTime.recordNanos(nanos);
            rqActive.dec();
        }

        /** Counts a request answered without a server connection (from the cache, or a recording). */
        void answered(int status, long nanos) {
            rqTotal.inc();
            rqClass[responseClass(status)].inc();
            if (nanos >= 0) rqTime.recordNanos(nanos);
        }
    }

    /**
     * The clusters other than {@code direct}, {@code cache} and {@code replay}: at most {@link
     * StatsRegistry#maxClusters()}, past which new ones share {@code other} or evict the least
     * recently used. Lookups of a known cluster take no lock.
     */
    static final class ClusterTable {
        private final StatsRegistry registry;
        private final Map<String, ClusterStats> clusters = new ConcurrentHashMap<>();
        private final ReentrantLock lock = new ReentrantLock();
        private volatile ClusterStats other;

        ClusterTable(StatsRegistry registry) {
            this.registry = registry;
        }

        ClusterStats get(String name, String kind) {
            ClusterStats c = clusters.get(name);
            if (c != null) {
                c.lastUsed = System.nanoTime();
                return c;
            }
            lock.lock();
            try {
                c = clusters.get(name);
                if (c != null) return c;
                if (clusters.size() >= registry.maxClusters()) {
                    if (registry.clusterOverflow() == StatsRegistry.Overflow.OTHER) return other();
                    evictLeastRecentlyUsed();
                }
                c = new ClusterStats(registry, name);
                c.kind = kind;
                clusters.put(name, c);
                return c;
            } finally {
                lock.unlock();
            }
        }

        private ClusterStats other() {
            ClusterStats o = other;
            if (o == null) {
                o = new ClusterStats(registry, StatsRegistry.OTHER_CLUSTER);
                other = o;
            }
            return o;
        }

        private void evictLeastRecentlyUsed() {
            ClusterStats oldest = null;
            for (ClusterStats c : clusters.values()) {
                if (oldest == null || c.lastUsed - oldest.lastUsed < 0) oldest = c;
            }
            if (oldest != null && clusters.remove(oldest.name, oldest)) oldest.unregister();
        }

        /** The clusters with stats of their own now, and {@code other} once used, sorted by name. */
        List<Cluster> list() {
            List<Cluster> all = new ArrayList<>();
            for (ClusterStats c : clusters.values()) all.add(new Cluster(c.name, c.kind));
            all.sort(java.util.Comparator.comparing(Cluster::name));
            if (other != null) all.add(new Cluster(StatsRegistry.OTHER_CLUSTER, OVERFLOW));
            return all;
        }

        /** The clusters with stats of their own now, for tests. */
        int size() {
            return clusters.size();
        }
    }
}
