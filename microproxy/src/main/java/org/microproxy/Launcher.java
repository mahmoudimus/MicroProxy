package org.microproxy;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.file.Path;
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
              --proxy-alias <alias>        name used in Via headers
              --throttle <read> <write>    global server bandwidth limits in bytes/s
              --accept-proxy-protocol      require a PROXY protocol header on inbound connections
              --send-proxy-protocol        send a PROXY protocol v1 header upstream
              --upstream-proxy <url>       chain to http(s)://[user:pw@]host:port or socks5://...
              --upstream-https-proxy <url> different upstream for HTTPS / CONNECT
              --no-proxy <list>            hosts to reach directly (NO_PROXY syntax)
              --env-proxy                  take upstream proxies from http_proxy/https_proxy/no_proxy
              --dnssec                     resolve server names with DNSSEC validation
              --dnssec-resolver <spec>     DoH URL or comma-separated resolver IPs for --dnssec
              --activity-log-format <fmt>  access log: CLF, ELF, JSON, SQUID, W3C, LTSV, CSV, HAPROXY
              --shared-pool                share server connections between clients
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
        List<AutoCloseable> resources = new ArrayList<>();
        String caPassword = "microproxy";
        if (queue.contains("--config")) {
            List<String> all = List.copyOf(queue);
            int i = all.indexOf("--config");
            if (i + 1 >= all.size()) throw new IllegalArgumentException("--config needs a value");
            bootstrap = MicroProxy.bootstrapFromFile(Path.of(all.get(i + 1)));
        }
        while (!queue.isEmpty()) {
            String arg = queue.poll();
            switch (arg) {
                case "--help", "-h" -> {
                    console.print(usage);
                    return null;
                }
                case "--config" -> value(queue, arg);
                case "--port" -> bootstrap.withPort(Integer.parseInt(value(queue, arg)));
                case "--address" -> {
                    String[] parts = value(queue, arg).split(":(?=[0-9]+$)");
                    bootstrap.withAddress(new InetSocketAddress(parts[0], parts.length > 1 ? Integer.parseInt(parts[1]) : 8080));
                }
                case "--server" -> bootstrap.withAllowLocalOnly(false);
                case "--name" -> bootstrap.withName(value(queue, arg));
                case "--transparent" -> bootstrap.withTransparent(true);
                case "--idle-timeout" -> bootstrap.withIdleConnectionTimeout(Integer.parseInt(value(queue, arg)));
                case "--connect-timeout" -> bootstrap.withConnectTimeout(Integer.parseInt(value(queue, arg)));
                case "--proxy-alias" -> bootstrap.withProxyAlias(value(queue, arg));
                case "--throttle" -> bootstrap.withThrottling(
                        Long.parseLong(value(queue, arg)), Long.parseLong(value(queue, arg)));
                case "--accept-proxy-protocol" -> bootstrap.withAcceptProxyProtocol(true);
                case "--send-proxy-protocol" -> bootstrap.withSendProxyProtocol(true);
                case "--upstream-proxy" -> upstream = value(queue, arg);
                case "--upstream-https-proxy" -> upstreamHttps = value(queue, arg);
                case "--no-proxy" -> noProxy = value(queue, arg);
                case "--env-proxy" -> envProxy = true;
                case "--dnssec" -> dnssec = true;
                case "--dnssec-resolver" -> {
                    dnssec = true;
                    dnssecResolver = value(queue, arg);
                }
                case "--activity-log-format" -> bootstrap.plusActivityTracker(new ActivityLogger(
                        LogFormat.valueOf(value(queue, arg).toUpperCase(Locale.ROOT))));
                case "--shared-pool" -> bootstrap.withSharedServerConnectionPool(true);
                case "--cache-dir" -> cacheDir = Path.of(value(queue, arg));
                case "--cache-size" -> cacheSizeMb = Long.parseLong(value(queue, arg));
                case "--cache-memory" -> cacheMemoryMb = Long.parseLong(value(queue, arg));
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
        if (warcDir != null) {
            // First among the filters, so it records messages before others change them.
            WarcRecorder recorder = WarcRecorder.builder(warcDir).build();
            bootstrap.withFiltersSource(HttpFiltersChain.of(recorder, bootstrap.getFiltersSource()));
            resources.add(recorder);
            console.println("Recording WARC files in " + warcDir.toAbsolutePath());
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
        HttpProxyServer server = bootstrap.start();
        // Closed after the server's connections finish, so in-flight records are written.
        resources.forEach(server::closeOnStop);
        console.println("MicroProxy listening on " + server.getListenAddress());
        if (Simd.isVectorized()) {
            console.println("SIMD: " + Simd.ops().description());
        }
        return server;
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

    private static String stripExtension(String name) {
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }
}
