package org.microproxy.impl;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.System.Logger.Level;
import java.lang.management.ManagementFactory;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.microproxy.FlowTracer;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpFiltersSource;
import org.microproxy.PoolMetrics;
import org.microproxy.ServerState;
import org.microproxy.dns.DnssecHostResolver;
import org.microproxy.stats.Counter;
import org.microproxy.stats.Gauge;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.Metric;
import org.microproxy.stats.StatsFormatter;
import org.microproxy.stats.StatsRegistry;

/**
 * The admin listener: Envoy's admin API, reimplemented on the JDK's {@code com.sun.net.httpserver}
 * (module {@code jdk.httpserver}), on a listener of its own. Reads are {@code GET} (and {@code
 * HEAD}); what changes the proxy is {@code POST}; another method gets {@code 405}. With a token,
 * every path but {@code /ready} needs it. Bound to a loopback address, it answers only requests
 * whose {@code Host} is a loopback name or address (against DNS rebinding); it refuses every
 * {@code POST} that a browser made for a page ({@code Origin}).
 */
final class AdminServer {

    private static final System.Logger LOG = System.getLogger(AdminServer.class.getName());
    static final String TEXT = "text/plain; charset=utf-8";
    static final String JSON = "application/json";
    private static final Set<String> GET = Set.of("GET", "HEAD");
    private static final Set<String> POST = Set.of("POST");
    private static final Set<String> GET_POST = Set.of("GET", "HEAD", "POST");

    private final DefaultHttpProxyServer server;
    private final HttpServer http;
    private final ExecutorService executor;
    /** The token as bytes, for a comparison in constant time; null for none. */
    private final byte[] token;
    private final boolean tokenHasColon;
    /** Whether the listener is bound to a loopback address, so that only loopback hosts are answered. */
    private final boolean loopback;
    private final List<Endpoint> endpoints;

    /** An admin path: what it shows, the methods it takes and what answers it. */
    private record Endpoint(String path, String help, Set<String> methods, Handler handler) {}

    @FunctionalInterface
    private interface Handler {
        Reply handle(Map<String, String> params, String method);
    }

    /** An answer: its status, content type, body and extra headers, and what to do once it is sent (or null). */
    record Reply(int status, String contentType, String body, Map<String, String> headers, Runnable then) {
        Reply(int status, String contentType, String body, Map<String, String> headers) {
            this(status, contentType, body, headers, null);
        }

        static Reply text(int status, String body) {
            return new Reply(status, TEXT, body, Map.of());
        }

        static Reply json(Object value) {
            return new Reply(200, JSON, AdminJson.write(value), Map.of());
        }
    }

    private AdminServer(DefaultHttpProxyServer server, HttpServer http, ExecutorService executor, String token) {
        this.server = server;
        this.http = http;
        this.executor = executor;
        this.token = token == null ? null : token.getBytes(StandardCharsets.UTF_8);
        this.tokenHasColon = token != null && token.indexOf(':') >= 0;
        InetAddress bound = http.getAddress().getAddress();
        this.loopback = bound != null && bound.isLoopbackAddress();
        this.endpoints = List.of(
                new Endpoint("/", "this list of the admin's paths", GET, (p, m) -> Reply.text(200, help())),
                new Endpoint("/help", "the same", GET, (p, m) -> Reply.text(200, help())),
                new Endpoint("/stats", "the stats as name: value lines; ?filter=<regex> keeps the names it finds, "
                        + "?usedonly those with a value, ?format=json or prometheus", GET, (p, m) -> stats(p)),
                new Endpoint("/stats/prometheus", "the stats in Prometheus's text format 0.0.4; ?filter=, ?usedonly",
                        GET, (p, m) -> prometheus(p)),
                new Endpoint("/ready", "200 LIVE when ready for traffic, else 503 and the state "
                        + "(DRAINING, INITIALIZING, HEALTH_CHECK_FAILED); needs no token", GET, (p, m) -> ready()),
                new Endpoint("/server_info", "version, state, uptime, listeners, features, JVM and command line (JSON)",
                        GET, (p, m) -> Reply.json(serverInfo())),
                new Endpoint("/listeners", "the listeners, their addresses and protocols; ?format=json", GET,
                        (p, m) -> listeners(p)),
                new Endpoint("/clusters", "the upstream clusters, their stats, pool and health; ?format=json", GET,
                        (p, m) -> clusters(p)),
                new Endpoint("/config_dump", "the configuration in effect, secrets redacted (JSON)", GET,
                        (p, m) -> Reply.json(AdminConfigDump.dump(server, address()))),
                new Endpoint("/logging", "the loggers and their levels; POST ?level=<level> sets them all, "
                        + "POST ?<logger>=<level> one", GET_POST, this::logging),
                new Endpoint("/healthcheck/fail", "POST: fail the health check (/ready and the health-check path "
                        + "answer 503, and connections drain)", POST, (p, m) -> healthCheck(true)),
                new Endpoint("/healthcheck/ok", "POST: restore the health check", POST, (p, m) -> healthCheck(false)),
                new Endpoint("/drain_listeners", "POST: stop accepting connections; ?graceful drains for the drain "
                        + "time first; ?inboundonly is accepted (every proxy listener is inbound)", POST,
                        (p, m) -> drainListeners(p)),
                new Endpoint("/quitquitquit", "POST: stop the proxy gracefully", POST, (p, m) -> quit()));
    }

    /**
     * Starts the admin listener for {@code server} at {@code address}.
     *
     * @param token what requests must present, or null for nothing
     * @throws IOException if the address cannot be bound
     */
    static AdminServer start(DefaultHttpProxyServer server, InetSocketAddress address, String token) throws IOException {
        HttpServer http = HttpServer.create(address, 0);
        // Platform threads, not virtual ones: the JDK's server reads requests and writes responses
        // in synchronized methods (sun.net.httpserver.Request.ReadStream.read and WriteStream.write),
        // which on JDK 21 pin a virtual thread to its carrier while it blocks. A client sending its
        // request or reading the response slowly would hold a carrier, and a few such clients would
        // stall every virtual thread of the proxy. (Idle keep-alive connections wait in the server's
        // selector, holding no thread; JDK 24, with JEP 491, no longer pins there.) A small pool
        // bounds what the admin listener can take from the proxy.
        ExecutorService executor = Executors.newFixedThreadPool(4,
                Thread.ofPlatform().name(server.name + "-admin-", 0).daemon(true).factory());
        AdminServer admin = new AdminServer(server, http, executor, token);
        http.setExecutor(executor);
        http.createContext("/", admin::handle);
        http.start();
        return admin;
    }

    /** {@return the address the listener is bound to, with its port} */
    InetSocketAddress address() {
        return http.getAddress();
    }

    /** Closes the listener at once. */
    void stop() {
        http.stop(0);
        executor.shutdownNow();
    }

    // ---------------------------------------------------------------------------------------
    // Requests
    // ---------------------------------------------------------------------------------------

    private void handle(HttpExchange exchange) {
        try {
            Reply reply;
            try {
                reply = dispatch(exchange);
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "admin " + exchange.getRequestURI() + " failed", e);
                reply = Reply.text(500, "error: " + e + "\n");
            }
            try {
                send(exchange, reply);
            } finally {
                exchange.close();
                if (reply.then != null) reply.then.run();
            }
        } catch (IOException e) {
            LOG.log(Level.DEBUG, "admin client went away: " + e);
        }
    }

    private Reply dispatch(HttpExchange exchange) {
        Headers headers = exchange.getRequestHeaders();
        if (loopback && !loopbackHost(headers.getFirst("Host"))) {
            return Reply.text(403, "the admin listener is bound to a loopback address and answers loopback hosts only\n");
        }
        String path = exchange.getRequestURI().getPath();
        if (!"/ready".equals(path) && !authorized(headers.getFirst("Authorization"))) {
            Map<String, String> challenge = new LinkedHashMap<>();
            challenge.put("WWW-Authenticate", "Bearer realm=\"MicroProxy admin\"");
            return new Reply(401, TEXT, "the admin listener needs its token: Authorization: Bearer <token>\n", challenge);
        }
        Endpoint endpoint = endpoints.stream().filter(e -> e.path.equals(path)).findFirst().orElse(null);
        if (endpoint == null) return Reply.text(404, "invalid path: " + path + "\n\n" + help());
        String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
        if (!endpoint.methods.contains(method)) {
            String allowed = String.join(", ", new java.util.TreeSet<>(endpoint.methods));
            return new Reply(405, TEXT, path + " takes " + allowed + ", not " + method
                    + (endpoint.methods.equals(POST) ? ": it changes the proxy\n" : "\n"), Map.of("Allow", allowed));
        }
        if (method.equals("POST") && headers.containsKey("Origin")) {
            // A browser's request for a page, not an operator's: a form on any site can POST to localhost.
            return Reply.text(403, "requests made by web pages (with an Origin) are refused\n");
        }
        Map<String, String> params;
        try {
            params = params(exchange.getRequestURI().getRawQuery());
        } catch (IllegalArgumentException e) {
            return Reply.text(400, "bad query: " + e.getMessage() + "\n");
        }
        return endpoint.handler.handle(params, method);
    }

    /**
     * The query's parameters, percent-decoded, in their order; one without {@code =} has the value
     * {@code ""}. A {@code +} stays a plus, as a regular expression in {@code ?filter=} means it.
     */
    static Map<String, String> params(String rawQuery) {
        Map<String, String> params = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isEmpty()) return params;
        for (String pair : rawQuery.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            params.put(decode(eq < 0 ? pair : pair.substring(0, eq)), eq < 0 ? "" : decode(pair.substring(eq + 1)));
        }
        return params;
    }

    private static String decode(String s) {
        return URLDecoder.decode(s.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    /** Whether {@code host} (a Host header) names this machine's loopback: {@code localhost} or a loopback address. */
    static boolean loopbackHost(String host) {
        if (host == null) return true;
        String h = host.strip();
        if (h.startsWith("[")) {
            int end = h.indexOf(']');
            h = end < 0 ? h : h.substring(1, end);
        } else if (h.indexOf(':') >= 0 && h.indexOf(':') == h.lastIndexOf(':')) {
            h = h.substring(0, h.indexOf(':'));
        }
        h = h.toLowerCase(Locale.ROOT);
        if (h.equals("localhost") || h.endsWith(".localhost")) return true;
        // Only literals: a name is never resolved here.
        if (!h.matches("[0-9.]+|[0-9a-f:]+")) return false;
        try {
            return InetAddress.getByName(h).isLoopbackAddress();
        } catch (IOException e) {
            return false;
        }
    }

    /** Whether {@code authorization} carries the token, or none is needed. */
    private boolean authorized(String authorization) {
        if (token == null) return true;
        if (authorization == null) return false;
        String a = authorization.strip();
        int space = a.indexOf(' ');
        if (space < 0) return false;
        String scheme = a.substring(0, space);
        String credentials = a.substring(space + 1).strip();
        if (scheme.equalsIgnoreCase("Bearer")) return matches(credentials);
        if (!scheme.equalsIgnoreCase("Basic")) return false;
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(credentials), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (tokenHasColon) return matches(decoded);
        int colon = decoded.indexOf(':');
        return colon >= 0 && matches(decoded.substring(colon + 1));
    }

    private boolean matches(String presented) {
        return MessageDigest.isEqual(token, presented.getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange exchange, Reply reply) throws IOException {
        Headers h = exchange.getResponseHeaders();
        h.set("Content-Type", reply.contentType);
        h.set("Cache-Control", "no-cache, max-age=0");
        h.set("X-Content-Type-Options", "nosniff");
        reply.headers.forEach(h::add);
        if (reply.status == 401) h.add("WWW-Authenticate", "Basic realm=\"MicroProxy admin\", charset=\"UTF-8\"");
        byte[] body = reply.body.getBytes(StandardCharsets.UTF_8);
        boolean head = "HEAD".equalsIgnoreCase(exchange.getRequestMethod());
        exchange.sendResponseHeaders(reply.status, head || body.length == 0 ? -1 : body.length);
        if (!head && body.length > 0) {
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Endpoints
    // ---------------------------------------------------------------------------------------

    private String help() {
        StringBuilder sb = new StringBuilder("admin commands are:\n");
        for (Endpoint e : endpoints) sb.append("  ").append(e.path).append(": ").append(e.help).append('\n');
        return sb.toString();
    }

    private StatsRegistry registry() {
        return server.stats.registry;
    }

    /** The metrics {@code ?filter=} and {@code ?usedonly} keep; null (and a 400) for a bad regex. */
    private static Predicate<Metric> include(Map<String, String> params) {
        Predicate<Metric> include = m -> true;
        String filter = params.get("filter");
        if (filter != null && !filter.isEmpty()) {
            Pattern pattern = Pattern.compile(filter);
            include = m -> pattern.matcher(m.name()).find();
        }
        if (params.containsKey("usedonly")) include = include.and(StatsFormatter::used);
        return include;
    }

    private Reply stats(Map<String, String> params) {
        Predicate<Metric> include;
        try {
            include = include(params);
        } catch (PatternSyntaxException e) {
            return Reply.text(400, "invalid regex in filter: " + e.getDescription() + "\n");
        }
        return switch (params.getOrDefault("format", "text")) {
            case "text", "" -> Reply.text(200, StatsFormatter.text(registry(), include));
            case "json" -> new Reply(200, JSON, StatsFormatter.json(registry(), include), Map.of());
            case "prometheus" -> new Reply(200, StatsFormatter.PROMETHEUS_CONTENT_TYPE,
                    StatsFormatter.prometheus(registry(), include), Map.of());
            default -> Reply.text(400, "unknown format: " + params.get("format") + "; expected text, json or prometheus\n");
        };
    }

    private Reply prometheus(Map<String, String> params) {
        Map<String, String> p = new LinkedHashMap<>(params);
        p.put("format", "prometheus");
        return stats(p);
    }

    private Reply ready() {
        ServerState state = server.state();
        if (state == ServerState.LIVE && !server.isHealthCheckFailed()) return Reply.text(200, "LIVE\n");
        return Reply.text(503, (state == ServerState.LIVE ? "HEALTH_CHECK_FAILED" : state.name()) + "\n");
    }

    private Reply healthCheck(boolean fail) {
        server.setHealthCheckFailed(fail);
        return Reply.text(200, "OK\n");
    }

    private Reply drainListeners(Map<String, String> params) {
        if (params.containsKey("graceful")) {
            // drain() lasts the drain time: the answer does not wait for it.
            Thread.ofVirtual().name(server.name + "-drain").start(() -> server.drain(server.drainTime));
        } else {
            server.stopListeners();
        }
        return Reply.text(200, "OK\n");
    }

    private Reply quit() {
        // Once answered: stopping closes this listener. A platform thread, not a daemon: the JVM
        // lives until the proxy has stopped.
        return new Reply(200, TEXT, "OK\n", Map.of(),
                () -> Thread.ofPlatform().name(server.name + "-quit").start(server::stop));
    }

    private Reply logging(Map<String, String> params, String method) {
        if (method.equals("POST") && !params.isEmpty()) {
            try {
                AdminLogging.set(params);
            } catch (IllegalArgumentException e) {
                return Reply.text(400, e.getMessage() + "\n");
            } catch (IllegalStateException e) {
                return Reply.text(501, e.getMessage() + "\n");
            }
        }
        return Reply.text(200, AdminLogging.list());
    }

    // ---------------------------------------------------------------------------------------
    // /server_info, /listeners, /clusters
    // ---------------------------------------------------------------------------------------

    private Map<String, Object> serverInfo() {
        Map<String, Object> info = new LinkedHashMap<>();
        long uptime = (System.nanoTime() - server.startNanos) / 1_000_000_000L;
        info.put("version", version());
        info.put("state", server.state().name());
        info.put("health_check_failed", server.isHealthCheckFailed());
        info.put("uptime_current_epoch", uptime + "s");
        info.put("uptime_all_epochs", uptime + "s");
        info.put("name", server.name);
        info.put("open_connections", server.openConnections());
        info.put("listeners", listenerList());
        Map<String, Object> admin = new LinkedHashMap<>();
        admin.put("address", hostPort(address()));
        admin.put("token", token != null);
        info.put("admin", admin);
        info.put("drain", Map.of("time", server.drainTime.toString(), "strategy",
                server.drainStrategy.name().toLowerCase(Locale.ROOT)));
        info.put("features", features());
        Map<String, Object> jvm = new LinkedHashMap<>();
        jvm.put("version", Runtime.version().toString());
        jvm.put("vendor", System.getProperty("java.vendor"));
        jvm.put("vm", System.getProperty("java.vm.name"));
        jvm.put("os", System.getProperty("os.name") + " " + System.getProperty("os.version") + " "
                + System.getProperty("os.arch"));
        jvm.put("pid", ProcessHandle.current().pid());
        jvm.put("processors", Runtime.getRuntime().availableProcessors());
        jvm.put("max_heap_bytes", Runtime.getRuntime().maxMemory());
        jvm.put("uptime", ManagementFactory.getRuntimeMXBean().getUptime() / 1000 + "s");
        jvm.put("logging", AdminLogging.backend());
        info.put("jvm", jvm);
        info.put("command_line_options", AdminConfigDump.commandLine(server.config.commandLineOptions));
        return info;
    }

    /** The proxy's version, from the jar (as Maven filtered it), else its manifest, else {@code unknown}. */
    static String version() {
        try (InputStream in = AdminServer.class.getResourceAsStream("/org/microproxy/version.properties")) {
            if (in != null) {
                Properties p = new Properties();
                p.load(in);
                String v = p.getProperty("version", "");
                if (!v.isEmpty() && !v.startsWith("${")) return v;
            }
        } catch (IOException e) {
            // fall back
        }
        String v = AdminServer.class.getPackage().getImplementationVersion();
        return v != null ? v : "unknown";
    }

    /** What the proxy does, by Envoy-like feature name. */
    private Map<String, Object> features() {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("http1", true);
        // Served inside intercepted TLS and on the TLS listener: on by default, it is in use only
        // on a proxy that has either.
        f.put("h2", server.http2 && (server.mitmManager != null || server.sslContextSource != null));
        f.put("h2_upstream", server.http2Upstream);
        f.put("h2c", server.http2Cleartext);
        f.put("h3", server.http3);
        f.put("h3_upstream", server.http3Origins != null);
        f.put("quic", server.http3 || server.http3Origins != null || server.transparentQuicPort >= 0);
        f.put("transparent_quic", server.transparentQuicPort >= 0);
        f.put("masque", server.connectUdpTemplate != null);
        f.put("socks", server.socksServer || server.socksDetection);
        f.put("mitm", server.mitmManager != null);
        f.put("transparent", server.transparent);
        f.put("reverse_proxy", server.reverseProxy != null);
        f.put("tls_listener", server.sslContextSource != null);
        f.put("proxy_protocol", server.acceptProxyProtocol || server.sendProxyProtocol);
        f.put("proxy_authentication", server.proxyAuthenticator != null);
        f.put("chained_proxies", server.chainProxyManager != null);
        f.put("shared_pool", server.pool != null);
        f.put("cache", server.config.httpCache != null);
        f.put("replay", hasFilter(server.filtersSource, "org.microproxy.extras.ServerReplay"));
        f.put("scripting", hasFilter(server.filtersSource, "org.microproxy.starlark."));
        f.put("dnssec", server.serverResolver instanceof DnssecHostResolver);
        f.put("metrics", registry().enabled());
        f.put("tracing", server.tracer != FlowTracer.NOOP);
        f.put("health_check_path", server.healthCheckPath != null);
        return f;
    }

    /** Whether a filters source whose class name starts with {@code prefix} is among {@code source}'s. */
    static boolean hasFilter(HttpFiltersSource source, String prefix) {
        if (source == null) return false;
        if (source.getClass().getName().startsWith(prefix)) return true;
        if (source instanceof HttpFiltersChain chain) {
            for (HttpFiltersSource s : chain.sources()) {
                if (hasFilter(s, prefix)) return true;
            }
        }
        return false;
    }

    /** The proxy's listeners: the TCP one, and the HTTP/3 and transparent QUIC ones on UDP when present. */
    private List<Map<String, Object>> listenerList() {
        InetSocketAddress[] addresses = server.listenerAddresses();
        boolean accepting = !server.refusesNewConnections();
        List<Map<String, Object>> list = new ArrayList<>();
        List<String> tcp = new ArrayList<>();
        if (server.reverseProxy != null && server.reverseProxy.rawTcp()) {
            tcp.add("tcp");
        } else if (server.socksServer) {
            tcp.addAll(List.of("socks5", "socks4"));
        } else {
            if (server.sslContextSource != null) tcp.add("tls");
            tcp.add("http/1.1");
            if (server.sslContextSource != null && server.http2) tcp.add("h2");
            if (server.http2Cleartext) tcp.add("h2c");
            if (server.connectUdpTemplate != null) tcp.add("masque");
            if (server.socksDetection) tcp.addAll(List.of("socks5", "socks4"));
            if (server.transparent) tcp.add("transparent_tls");
        }
        if (server.acceptProxyProtocol) tcp.add("proxy_protocol");
        list.add(listener(server.name, "tcp", addresses[0], tcp, accepting));
        if (addresses[1] != null) {
            List<String> h3 = new ArrayList<>(List.of("quic", "h3"));
            if (server.connectUdpTemplate != null) h3.add("masque");
            list.add(listener(server.name + "_http3", "udp", addresses[1], h3, accepting));
        }
        if (addresses[2] != null) {
            list.add(listener(server.name + "_transparent_quic", "udp", addresses[2], List.of("quic", "h3", "relay"),
                    accepting));
        }
        return list;
    }

    private static Map<String, Object> listener(String name, String transport, InetSocketAddress address,
            List<String> protocols, boolean accepting) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", name);
        m.put("local_address", hostPort(address));
        m.put("transport", transport);
        m.put("protocols", protocols);
        m.put("accepting", accepting);
        return m;
    }

    private Reply listeners(Map<String, String> params) {
        List<Map<String, Object>> list = listenerList();
        if ("json".equals(params.get("format"))) return Reply.json(Map.of("listener_statuses", list));
        StringBuilder sb = new StringBuilder();
        for (Map<String, Object> l : list) {
            sb.append(l.get("name")).append("::").append(l.get("local_address")).append("::").append(l.get("transport"))
                    .append("::").append(String.join(",", castList(l.get("protocols"))))
                    .append((Boolean) l.get("accepting") ? "" : "::not_accepting").append('\n');
        }
        return Reply.text(200, sb.toString());
    }

    @SuppressWarnings("unchecked")
    private static List<String> castList(Object o) {
        return (List<String>) o;
    }

    /** The clusters with stats (the fixed ones when configured or used), with their stats, health and pool. */
    private List<Map<String, Object>> clusterList() {
        Map<String, Map<String, Object>> statsByCluster = new TreeMap<>();
        for (Metric m : registry().metrics()) {
            String name = m.name();
            if (!name.startsWith("cluster.")) continue;
            int dot = name.indexOf('.', 8);
            if (dot < 0) continue;
            Object value = switch (m) {
                case Counter c -> c.value();
                case Gauge g -> g.value();
                case Histogram h -> histogram(h.snapshot());
                default -> null;
            };
            statsByCluster.computeIfAbsent(name.substring(8, dot), k -> new TreeMap<>()).put(name.substring(dot + 1), value);
        }
        List<Map<String, Object>> list = new ArrayList<>();
        for (ProxyStats.Cluster c : server.stats.clusters()) {
            Map<String, Object> stats = statsByCluster.getOrDefault(c.name(), Map.of());
            boolean configured = switch (c.kind()) {
                case ProxyStats.CACHE -> server.config.httpCache != null;
                case ProxyStats.REPLAY -> hasFilter(server.filtersSource, "org.microproxy.extras.ServerReplay");
                default -> true;
            };
            if (!configured && stats.values().stream().noneMatch(v -> v instanceof Long l && l != 0)) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", c.name());
            m.put("type", c.kind());
            // The proxy runs no active health checks: every cluster is taken for healthy.
            m.put("health_flags", "healthy");
            if (c.kind().equals(ProxyStats.DIRECT)) {
                PoolMetrics pool = server.getServerConnectionPoolMetrics();
                if (pool != null) {
                    Map<String, Object> p = new LinkedHashMap<>();
                    p.put("total_connections", pool.totalConnections());
                    p.put("active_connections", pool.activeConnections());
                    p.put("idle_connections", pool.idleConnections());
                    p.put("borrow", pool.borrowCount());
                    p.put("return", pool.returnCount());
                    p.put("eviction", pool.evictionCount());
                    p.put("validation_failure", pool.validationFailureCount());
                    m.put("connection_pool", p);
                }
            }
            m.put("stats", stats);
            list.add(m);
        }
        return list;
    }

    private static Map<String, Object> histogram(Histogram.Snapshot s) {
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("count", s.count());
        if (s.count() > 0) {
            h.put("p50", Math.round(s.quantile(0.5) * 1000) / 1000.0);
            h.put("p99", Math.round(s.quantile(0.99) * 1000) / 1000.0);
        }
        return h;
    }

    private Reply clusters(Map<String, String> params) {
        List<Map<String, Object>> list = clusterList();
        if ("json".equals(params.get("format"))) return Reply.json(Map.of("cluster_statuses", list));
        StringBuilder sb = new StringBuilder();
        for (Map<String, Object> c : list) {
            String name = (String) c.get("name");
            sb.append(name).append("::type::").append(c.get("type")).append('\n');
            sb.append(name).append("::health_flags::").append(c.get("health_flags")).append('\n');
            if (c.get("connection_pool") instanceof Map<?, ?> pool) {
                pool.forEach((k, v) -> sb.append(name).append("::connection_pool::").append(k).append("::").append(v)
                        .append('\n'));
            }
            if (c.get("stats") instanceof Map<?, ?> stats) {
                stats.forEach((k, v) -> {
                    if (v instanceof Long) sb.append(name).append("::").append(k).append("::").append(v).append('\n');
                });
            }
        }
        return Reply.text(200, sb.toString());
    }

    /** {@code host:port}, an IPv6 host in brackets. */
    static String hostPort(InetSocketAddress address) {
        if (address == null) return null;
        InetAddress a = address.getAddress();
        String host = a == null ? address.getHostString() : a.getHostAddress();
        int scope = host.indexOf('%');
        if (scope >= 0) host = host.substring(0, scope);
        return (a instanceof Inet6Address ? "[" + host + "]" : host) + ":" + address.getPort();
    }
}
