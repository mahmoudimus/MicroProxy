package org.microproxy;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.ServiceLoader;
import org.microproxy.cache.DiskCacheStore;
import org.microproxy.cache.HttpCache;
import org.microproxy.cache.MemoryCacheStore;
import org.microproxy.dns.DnssecHostResolver;
import org.microproxy.extras.ActivityLogger;
import org.microproxy.extras.ConcurrencyLimiter;
import org.microproxy.extras.HttpLogger;
import org.microproxy.extras.LogFormat;
import org.microproxy.simd.Simd;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SslContexts;
import org.microproxy.warc.WarcRecorder;

/** Command-line entry point. Run with {@code --help} for options. */
public final class Launcher {

    private static final String USAGE = """
            Usage: java -jar microproxy.jar [options]

              --config <file>              properties file (see README); flags override it
              --port <port>                listen port (default 8080)
              --address <host:port>        listen address
              --server                     listen on all interfaces, not just loopback
              --name <name>                server name for logs and threads
              --transparent                do not add Via / strip hop-by-hop headers
              --idle-timeout <seconds>     idle connection timeout (default 70, 0 = none)
              --connect-timeout <millis>   outbound connect timeout (default 40000)
              --tls-handshake-timeout <millis>  longest TLS handshake (default 10000, 0 = none)
              --tls-protocols <list>       TLS versions allowed on every TLS connection
                                           (default TLSv1.3,TLSv1.2; "" = JDK defaults)
              --littleproxy-compat         behave like LittleProxy where MicroProxy differs
              --proxy-alias <alias>        name used in Via headers
              --throttle <read> <write>    global server bandwidth limits in bytes/s
              --chained-proxy-backoff <initial>[:<max>]  millis to wait between failed chained
                                           proxy attempts, doubling up to max (default 8 x initial;
                                           0 = no waiting, the default)
              --accept-proxy-protocol      require a PROXY protocol header on inbound connections
              --send-proxy-protocol        send a PROXY protocol v1 header upstream
              --upstream-proxy <url>       chain to http(s)://[user:pw@]host:port or socks5://...
              --upstream-https-proxy <url> different upstream for HTTPS / CONNECT
              --no-proxy <list>            hosts to reach directly (NO_PROXY syntax)
              --env-proxy                  take upstream proxies from http_proxy/https_proxy/no_proxy
              --strip-tracing-headers      remove traceparent, tracestate, baggage, B3 and other
                                           tracing headers from requests sent upstream
              --strip-request-headers <list>  also remove these comma-separated request headers
              --no-alt-svc-h3              remove h3 (HTTP/3, QUIC) alternatives from Alt-Svc
                                           response headers, so clients stay on TCP through the
                                           proxy (default with --mitm or --transparent)
              --keep-alt-svc-h3            pass Alt-Svc h3 alternatives on even with --mitm or
                                           --transparent
              --dnssec                     resolve server names with DNSSEC validation
              --dnssec-resolver <spec>     DoH URL or comma-separated resolver IPs for --dnssec
              --activity-log-format <fmt>  access log: CLF, ELF, JSON, JSON_EXTENDED, SQUID,
                                           W3C, LTSV, CSV, HAPROXY
              --log-http <level>           log whole requests and responses: basic, headers or
                                           body (to the System.Logger org.microproxy.http)
              --log-http-json              write --log-http as JSON lines (headers if no level)
              --shared-pool                share server connections between clients
              --max-concurrent-per-client <n>  exchanges each client IP may run at once; more
                                           get 429 (CONNECT tunnels count while open)
              --cache-dir <dir>            cache responses on disk (RFC 9111); survives restarts
              --cache-size <MB>            disk cache limit (default 1024)
              --cache-memory <MB>          cache responses in memory instead
              --offline                    answer only from the cache (needs --cache-dir or --cache-memory)
              --warc-dir <dir>             record traffic with servers as WARC files
              --mitm                       intercept HTTPS with a generated CA
              --mitm-ca <file.p12>         CA key store for --mitm (created if missing;
                                           default ./microproxy-ca.p12)
              --mitm-ca-password <pw>      key store password (default "microproxy")
              --mitm-trust-all             do not validate upstream server certificates
              --help                       show this help
            """;

    private static final String EXTENSION_HEADER = "\n  Options from extensions:\n";

    private Launcher() {}

    public static void main(String[] args) throws IOException {
        HttpProxyServer server = start(args, System.out);
        if (server != null) {
            Runtime.getRuntime().addShutdownHook(new Thread(server::stop, "microproxy-shutdown"));
        }
    }

    /** Parses {@code args} and starts the proxy; returns null if only help was printed. */
    static HttpProxyServer start(String[] args, PrintStream console) throws IOException {
        Parsed parsed = parse(args, console);
        if (parsed == null) return null;
        HttpProxyServer server = parsed.bootstrap().start();
        // Closed after the server's connections finish, so in-flight records are written.
        parsed.resources().forEach(server::closeOnStop);
        console.println("MicroProxy listening on " + server.getListenAddress());
        if (Simd.isVectorized()) {
            console.println("SIMD: " + Simd.ops().description());
        }
        return server;
    }

    /**
     * A parsed command line: the configured bootstrap, and resources (such as a WARC recorder) to
     * close when the server stops.
     */
    record Parsed(HttpProxyServerBootstrap bootstrap, List<AutoCloseable> resources) {}

    /** Parses {@code args} into a bootstrap without starting it; returns null if only help was printed. */
    static Parsed parse(String[] args, PrintStream console) throws IOException {
        Deque<String> queue = new ArrayDeque<>(List.of(args));
        List<LauncherExtension> extensions = ServiceLoader.load(LauncherExtension.class).stream()
                .map(ServiceLoader.Provider::get)
                .toList();
        String usage = usage(extensions);
        HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap();
        boolean mitm = false;
        boolean dnssec = false;
        String upstream = null;
        String upstreamHttps = null;
        String noProxy = null;
        boolean envProxy = false;
        String dnssecResolver = null;
        boolean mitmTrustAll = false;
        Path caPath = Path.of("microproxy-ca.p12");
        Path cacheDir = null;
        long cacheSizeMb = 1024;
        long cacheMemoryMb = 0;
        boolean offline = false;
        Path warcDir = null;
        HttpLogger.Level logHttp = null;
        boolean logHttpJson = false;
        int maxConcurrentPerClient = 0;
        List<AutoCloseable> resources = new ArrayList<>();
        String caPassword = "microproxy";
        if (queue.contains("--config")) {
            List<String> all = List.copyOf(queue);
            int i = all.indexOf("--config");
            if (i + 1 >= all.size()) throw new IllegalArgumentException("--config needs a value");
            Path config = Path.of(all.get(i + 1));
            if (!java.nio.file.Files.isRegularFile(config)) {
                throw new IllegalArgumentException("--config file not found: " + config.toAbsolutePath());
            }
            bootstrap = MicroProxy.bootstrapFromFile(config);
        }
        while (!queue.isEmpty()) {
            String arg = queue.poll();
            switch (arg) {
                case "--help", "-h" -> {
                    console.print(usage);
                    return null;
                }
                case "--config" -> value(queue, arg);
                case "--port" -> bootstrap.withPort(intValue(queue, arg));
                case "--address" -> {
                    String[] parts = value(queue, arg).split(":(?=[0-9]+$)");
                    bootstrap.withAddress(new InetSocketAddress(parts[0], parts.length > 1 ? Integer.parseInt(parts[1]) : 8080));
                }
                case "--server" -> bootstrap.withAllowLocalOnly(false);
                case "--name" -> bootstrap.withName(value(queue, arg));
                case "--transparent" -> bootstrap.withTransparent(true);
                case "--idle-timeout" -> bootstrap.withIdleConnectionTimeout(intValue(queue, arg));
                case "--connect-timeout" -> bootstrap.withConnectTimeout(intValue(queue, arg));
                case "--littleproxy-compat" -> bootstrap.withLittleProxyCompatibility(true);
                case "--tls-protocols" -> bootstrap.withTlsProtocols(value(queue, arg).split(","));
                case "--tls-handshake-timeout" -> bootstrap.withTlsHandshakeTimeout(Duration.ofMillis(longValue(queue, arg)));
                case "--proxy-alias" -> bootstrap.withProxyAlias(value(queue, arg));
                case "--throttle" -> bootstrap.withThrottling(longValue(queue, arg), longValue(queue, arg));
                case "--chained-proxy-backoff" -> chainedProxyBackoff(bootstrap, value(queue, arg), arg);
                case "--accept-proxy-protocol" -> bootstrap.withAcceptProxyProtocol(true);
                case "--send-proxy-protocol" -> bootstrap.withSendProxyProtocol(true);
                case "--upstream-proxy" -> upstream = value(queue, arg);
                case "--upstream-https-proxy" -> upstreamHttps = value(queue, arg);
                case "--no-proxy" -> noProxy = value(queue, arg);
                case "--env-proxy" -> envProxy = true;
                case "--strip-tracing-headers" -> bootstrap.withoutTracingHeadersUpstream();
                case "--strip-request-headers" -> bootstrap.plusStrippedRequestHeaders(value(queue, arg).split(","));
                case "--no-alt-svc-h3" -> bootstrap.withAltSvcH3Stripping(true);
                case "--keep-alt-svc-h3" -> bootstrap.withAltSvcH3Stripping(false);
                case "--dnssec" -> dnssec = true;
                case "--dnssec-resolver" -> {
                    dnssec = true;
                    dnssecResolver = value(queue, arg);
                }
                case "--activity-log-format" -> bootstrap.plusActivityTracker(new ActivityLogger(logFormat(value(queue, arg))));
                case "--log-http" -> logHttp = logHttpLevel(value(queue, arg));
                case "--log-http-json" -> logHttpJson = true;
                case "--shared-pool" -> bootstrap.withSharedServerConnectionPool(true);
                case "--max-concurrent-per-client" -> {
                    maxConcurrentPerClient = intValue(queue, arg);
                    if (maxConcurrentPerClient <= 0) {
                        throw new IllegalArgumentException(arg + " needs a positive number");
                    }
                }
                case "--cache-dir" -> cacheDir = Path.of(value(queue, arg));
                case "--cache-size" -> cacheSizeMb = longValue(queue, arg);
                case "--cache-memory" -> cacheMemoryMb = longValue(queue, arg);
                case "--offline" -> offline = true;
                case "--warc-dir" -> warcDir = Path.of(value(queue, arg));
                case "--mitm" -> mitm = true;
                case "--mitm-ca" -> caPath = Path.of(value(queue, arg));
                case "--mitm-ca-password" -> caPassword = value(queue, arg);
                case "--mitm-trust-all" -> mitmTrustAll = true;
                default -> {
                    if (extensions.stream().noneMatch(e -> e.parseOption(arg, queue))) {
                        throw new IllegalArgumentException("unknown option: " + arg + "\n\n" + usage);
                    }
                }
            }
        }
        if (upstream != null || upstreamHttps != null) {
            bootstrap.withChainProxyManager(
                    new UpstreamProxyManager(upstream, upstreamHttps, NoProxyRules.parse(noProxy)));
        } else if (envProxy) {
            UpstreamProxyManager fromEnv = UpstreamProxyManager.fromEnvironment(System.getenv());
            if (fromEnv != null) bootstrap.withChainProxyManager(fromEnv);
        }
        if (dnssec) {
            bootstrap.withServerResolver(dnssecResolver == null ? new DnssecHostResolver()
                    : DnssecHostResolver.builder().resolver(dnssecResolver).build());
        }
        if (mitm) {
            CertificateAuthority ca = CertificateAuthority.loadOrCreate(caPath, caPassword.toCharArray(), "MicroProxy CA");
            Path pem = caPath.resolveSibling(stripExtension(caPath.getFileName().toString()) + ".pem");
            ca.writeCertificatePem(pem);
            console.println("MITM enabled; trust the CA certificate in " + pem.toAbsolutePath());
            bootstrap.withManInTheMiddle(mitmTrustAll
                    ? new CertificateAuthorityMitmManager(ca, SslContexts.trustAll())
                    : new CertificateAuthorityMitmManager(ca));
        }
        if (maxConcurrentPerClient > 0) {
            // In place of a limiter from the properties file, else before the other filters, so
            // they do no work for refused requests; recorders and loggers added below still see those.
            bootstrap.withFiltersSource(withLimiter(bootstrap.getFiltersSource(),
                    ConcurrencyLimiter.builder().permits(maxConcurrentPerClient).build()));
        }
        if (warcDir != null) {
            // First among the filters, so it records messages before others change them.
            WarcRecorder recorder = WarcRecorder.builder(warcDir).build();
            bootstrap.withFiltersSource(HttpFiltersChain.of(recorder, bootstrap.getFiltersSource()));
            resources.add(recorder);
            console.println("Recording WARC files in " + warcDir.toAbsolutePath());
        }
        if (logHttp != null || logHttpJson) {
            HttpLogger fromConfig = findHttpLogger(bootstrap.getFiltersSource());
            HttpLogger.Level level = logHttp != null ? logHttp
                    : fromConfig != null ? fromConfig.level() : HttpLogger.Level.HEADERS;
            HttpLogger.Format format = logHttpJson ? HttpLogger.Format.JSON
                    : fromConfig != null ? fromConfig.format() : HttpLogger.Format.TEXT;
            // First among the filters, replacing one from the properties file.
            bootstrap.withFiltersSource(HttpFiltersChain.of(HttpLogger.builder().level(level).format(format).build(),
                    withoutHttpLoggers(bootstrap.getFiltersSource())));
            console.println("Logging requests and responses (" + level.name().toLowerCase(Locale.ROOT)
                    + (format == HttpLogger.Format.JSON ? ", JSON" : "") + ") to the System.Logger "
                    + HttpLogger.LOGGER_NAME);
        }
        if (cacheDir != null || cacheMemoryMb > 0) {
            HttpCache.Builder cache = HttpCache.builder().offline(offline);
            cache.store(cacheDir != null ? new DiskCacheStore(cacheDir, cacheSizeMb << 20)
                    : new MemoryCacheStore(cacheMemoryMb << 20));
            bootstrap.withHttpCache(cache.build());
            console.println("Caching " + (cacheDir != null ? "in " + cacheDir.toAbsolutePath() : "in memory")
                    + (offline ? " (offline: answering only from the cache)" : ""));
        } else if (offline) {
            throw new IllegalArgumentException("--offline needs --cache-dir or --cache-memory");
        }
        for (LauncherExtension extension : extensions) {
            extension.configure(bootstrap, console);
        }
        return new Parsed(bootstrap, List.copyOf(resources));
    }

    private static String usage(List<LauncherExtension> extensions) {
        if (extensions.isEmpty()) return USAGE;
        StringBuilder sb = new StringBuilder(USAGE).append(EXTENSION_HEADER);
        for (LauncherExtension extension : extensions) {
            sb.append(extension.usage().stripTrailing()).append('\n');
        }
        return sb.toString();
    }

    private static String value(Deque<String> queue, String option) {
        String v = queue.poll();
        if (v == null) throw new IllegalArgumentException(option + " needs a value");
        return v;
    }

    private static int intValue(Deque<String> queue, String option) {
        String v = value(queue, option);
        try {
            return Integer.parseInt(v.strip());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(option + " needs a number, got: " + v);
        }
    }

    private static long longValue(Deque<String> queue, String option) {
        String v = value(queue, option);
        try {
            return Long.parseLong(v.strip());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(option + " needs a number, got: " + v);
        }
    }

    /**
     * Applies {@code --chained-proxy-backoff <initial-ms>[:<max-ms>]}: the maximum defaults to 8 x
     * the initial wait, as {@code chained_proxy_backoff_max_ms} does, and 0 turns waiting off.
     */
    private static void chainedProxyBackoff(HttpProxyServerBootstrap bootstrap, String v, String option) {
        int colon = v.indexOf(':');
        long initial = millis(colon < 0 ? v : v.substring(0, colon), v, option);
        long max = colon < 0 ? initial * 8 : millis(v.substring(colon + 1), v, option);
        if (initial == 0) {
            if (colon >= 0) throw new IllegalArgumentException(option + " 0 turns the backoff off and takes no maximum, got: " + v);
            bootstrap.withChainedProxyRetryBackoff(null, null);
        } else if (max < initial) {
            throw new IllegalArgumentException(option + " maximum " + max + " ms is below the initial " + initial + " ms");
        } else {
            bootstrap.withChainedProxyRetryBackoff(Duration.ofMillis(initial), Duration.ofMillis(max));
        }
    }

    private static long millis(String part, String v, String option) {
        long ms;
        try {
            ms = Long.parseLong(part.strip());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(option + " needs a number, got: " + v);
        }
        // Bounded so that 8 x initial cannot overflow, and the Duration stays representable.
        if (ms < 0 || ms > Long.MAX_VALUE / 8 / 1_000_000) {
            throw new IllegalArgumentException(option + " needs a non-negative number, got: " + v);
        }
        return ms;
    }

    private static LogFormat logFormat(String name) {
        try {
            return LogFormat.valueOf(name.strip().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("unknown --activity-log-format: " + name + "; expected one of "
                    + java.util.Arrays.toString(LogFormat.values()));
        }
    }

    private static HttpLogger.Level logHttpLevel(String name) {
        try {
            return HttpLogger.Level.valueOf(name.strip().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("unknown --log-http: " + name + "; expected basic, headers or body");
        }
    }

    private static HttpLogger findHttpLogger(HttpFiltersSource source) {
        if (source instanceof HttpLogger logger) return logger;
        if (source instanceof HttpFiltersChain chain) {
            for (HttpFiltersSource s : chain.sources()) {
                if (s instanceof HttpLogger logger) return logger;
            }
        }
        return null;
    }

    private static HttpFiltersSource withoutHttpLoggers(HttpFiltersSource source) {
        if (source instanceof HttpLogger) return null;
        if (source instanceof HttpFiltersChain chain) {
            return HttpFiltersChain.of(chain.sources().stream().filter(s -> !(s instanceof HttpLogger))
                    .toArray(HttpFiltersSource[]::new));
        }
        return source;
    }

    /** {@code source} with {@code limiter} replacing its concurrency limiters, or first if it has none. */
    private static HttpFiltersSource withLimiter(HttpFiltersSource source, ConcurrencyLimiter limiter) {
        List<HttpFiltersSource> sources = source instanceof HttpFiltersChain chain
                ? new ArrayList<>(chain.sources()) : new ArrayList<>(List.of(source));
        int at = -1;
        for (int i = sources.size() - 1; i >= 0; i--) {
            if (sources.get(i) instanceof ConcurrencyLimiter) {
                sources.remove(i);
                at = i;
            }
        }
        sources.add(Math.max(at, 0), limiter);
        return HttpFiltersChain.of(sources.toArray(HttpFiltersSource[]::new));
    }

    private static String stripExtension(String name) {
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }
}
