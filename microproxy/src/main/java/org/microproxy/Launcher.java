package org.microproxy;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.ServiceLoader;
import org.microproxy.cache.DiskCacheStore;
import org.microproxy.cache.HttpCache;
import org.microproxy.cache.MemoryCacheStore;
import org.microproxy.contentviews.ContentViews;
import org.microproxy.contentviews.ProtoSchema;
import org.microproxy.dns.DnssecHostResolver;
import org.microproxy.extras.AccessLogFilter;
import org.microproxy.extras.AccessLogFormat;
import org.microproxy.extras.AccessLogWriter;
import org.microproxy.extras.ActivityLogger;
import org.microproxy.extras.AntiCache;
import org.microproxy.extras.BlockList;
import org.microproxy.extras.ClientReplay;
import org.microproxy.extras.ConcurrencyLimiter;
import org.microproxy.extras.FlowFilter;
import org.microproxy.extras.HarRecorder;
import org.microproxy.extras.HttpLogger;
import org.microproxy.extras.LogFormat;
import org.microproxy.extras.MapLocal;
import org.microproxy.extras.MapRemote;
import org.microproxy.extras.ModifyBody;
import org.microproxy.extras.ModifyHeaders;
import org.microproxy.extras.RecordedExchange;
import org.microproxy.extras.ServerReplay;
import org.microproxy.extras.StickyCookie;
import org.microproxy.simd.Simd;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.stats.StatsdSink;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.KeyStoreSslContextSource;
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
              --transparent                do not add Via / strip hop-by-hop headers, and route TLS
                                           that arrives without CONNECT by its SNI
              --transparent-tls-port <port>  port SNI-routed TLS and QUIC go to (default 443)
              --transparent-quic-port <port>  with --transparent, also take QUIC (UDP) redirected to
                                           this UDP port: route it by the SNI of its ClientHello,
                                           intercept HTTP/3 (with --mitm) or relay it untouched;
                                           needs the quic and http3-codec jars
              --transparent-quic-relay-idle-timeout <seconds>  close a relayed QUIC flow after this
                                           long without a datagram (default 60)
              --allow-requests-to-origin-server  accept origin-form requests, routed by Host (for
                                           transparent HTTP)
              --mode <mode>                regular, transparent, socks5 or
                                           reverse:<scheme>://<host>[:<port>] (scheme http, https
                                           or tcp; default https)
              --socks                      also serve SOCKS5 and SOCKS4(a) clients on the listener,
                                           told apart by their first byte
              --reverse <spec>             reverse proxy to one upstream: [scheme://]host[:port]
              --keep-host-header           in reverse mode, keep the client's Host
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
              --activity-log-format <fmt>  access log to the System.Logger: CLF, ELF, JSON,
                                           JSON_EXTENDED, SQUID, W3C, LTSV, CSV, HAPROXY, ENVOY
              --access-log <path|->        write an access log line per exchange or flow to a
                                           file, or - for standard output (Envoy's default
                                           format unless --access-log-format or -json says)
              --access-log-format <fmt>    a preset name, or an Envoy format string such as
                                           '%START_TIME% %REQ(:METHOD)% %RESPONSE_CODE% %RESPONSE_FLAGS%'
              --access-log-json <dict>     a JSON object of keys and Envoy format strings, one
                                           JSON line per exchange
              --access-log-filter <expr>   log only what passes, e.g. 'status>=500 ||
                                           response_flag' (repeatable: all must pass)
              --metrics                    keep Envoy-style stats (http.*, cluster.*, listener.*,
                                           server.*; see README) for Prometheus, statsd and scripts
              --statsd <host:port>         push the stats to statsd over UDP every 5 seconds
                                           (implies --metrics)
              --dogstatsd <host:port>      the same, with DogStatsD tags
              --stats-prefix <prefix>      prefix of exported stat names (default envoy:
                                           envoy_http_downstream_rq_total, envoy.http....)
              --stats-max-clusters <n>     clusters with stats of their own (default 100); more
                                           share cluster "other" unless --stats-cluster-lru
              --stats-cluster-lru          evict the least recently used cluster's stats instead
              --stats-per-host             a cluster per server of direct connections (host_port),
                                           not one "direct" cluster, bounded by --stats-max-clusters
              --admin-port <port>          serve Envoy's admin API (/stats, /stats/prometheus, /ready,
                                           /server_info, /config_dump, /drain_listeners, ...; see
                                           README) on this port of 127.0.0.1 (implies --metrics)
              --admin-address <host:port>  the same on another address, such as 0.0.0.0:9901 (then
                                           set --admin-token)
              --admin-token <token>        require this bearer token (or basic password) on every
                                           admin path but /ready
              --admin-token-file <file>    the same, read from the file's first line
              --drain-time <seconds>       how long a drain lasts, and how long stopping (SIGTERM)
                                           lets exchanges in progress finish (default 10)
              --drain-strategy <strategy>  gradual (default: more and more new requests are told to
                                           go elsewhere) or immediate (all at once)
              --health-check-path <path>   answer health checks on the proxy's listener: 200, or
                                           503 when failed (admin /healthcheck/fail) or draining
              --health-check-pass-through  forward a healthy health check to the server instead
              --log-http <level>           log whole requests and responses: basic, headers or
                                           body (to the System.Logger org.microproxy.http)
              --log-http-json              write --log-http as JSON lines (headers if no level)
              --log-http-view <name>       render logged bodies through content views: auto (the
                                           best view per body), or grpc, protobuf, json, msgpack,
                                           ... (body if no level)
              --proto-descriptors <file>   a protobuf FileDescriptorSet (protoc
                                           --descriptor_set_out) for field names in the protobuf
                                           and gRPC views (implies --log-http-view auto)
              --shared-pool                share server connections between clients
              --max-concurrent-per-client <n>  exchanges each client IP may run at once; more
                                           get 429 (CONNECT tunnels count while open)
              --cache-dir <dir>            cache responses on disk (RFC 9111); survives restarts
              --cache-size <MB>            disk cache limit (default 1024)
              --cache-memory <MB>          cache responses in memory instead
              --offline                    answer only from the cache (needs --cache-dir or --cache-memory)
              --warc-dir <dir>             record traffic with servers as WARC files
              --save-har <file>            record exchanges as a HAR file, written on exit
                                           (.zhar: zlib-compressed)
              --save-har-filter <filter>   record only the exchanges a filter expression matches
              --save-har-stream            write HAR entries as they complete, not on exit
              --save-har-max-body <bytes>  bytes kept of each body (default 1048576; 0 = none)
              --mitm                       intercept HTTPS with a generated CA
              --mitm-ca <file.p12>         CA key store for --mitm (created if missing;
                                           default ./microproxy-ca.p12)
              --mitm-ca-password <pw>      key store password (default "microproxy")
              --mitm-trust-all             do not validate upstream server certificates
              --ignore-hosts <regex>       tunnel TLS to matching host:port names (CONNECT target or
                                           SNI) untouched; repeatable
              --allow-hosts <regex>        intercept only TLS to matching host:port names; repeatable
              --tcp-hosts <regex>          relay matching hosts (target host or SNI) as raw TCP even
                                           when they look like HTTP; TLS is still intercepted;
                                           repeatable
              --quic-hosts <regex>         relay matching hosts' intercepted QUIC (server host or
                                           SNI) stream by stream through the QUIC hooks, even
                                           HTTP/3, and intercept their other QUIC; repeatable
              --quic-framing <rules>       cut intercepted QUIC streams into messages for the
                                           message hooks, by ALPN or host: key=framer pairs, such
                                           as doq=u16,myproto=varint,*=none; framers u16, u32,
                                           varint, lf, crlf, none, script (default doq=u16)
              --quic-max-message-size <n>  the largest QUIC message framed, in bytes (default
                                           1048576); a larger one resets its stream
              --quic-message-error-code <n>  the error code of that reset (default 2)
              --http2                      serve HTTP/2 on intercepted TLS and the proxy TLS listener;
                                           needs the http2-codec jar on the class path
              --http2-upstream             speak HTTP/2 to servers that offer it over TLS (ALPN
                                           h2), one shared connection per server; needs the
                                           http2-codec jar
              --http2-cleartext            serve HTTP/2 with prior knowledge (h2c) on the plain
                                           listener; needs the http2-codec jar
              --http2-max-streams <n>      concurrent HTTP/2 streams per client connection
                                           (default 100)
              --http2-coalesce             with --http2-upstream, let an HTTP/2 connection to a
                                           server carry requests for other names its certificate
                                           covers that resolve to its address, or that it names
                                           in an ORIGIN frame (RFC 9113 9.1.1, RFC 8336)
              --http3                      also serve HTTP/3 (QUIC) on the UDP port with the
                                           listener's number: in reverse mode, advertised with
                                           Alt-Svc on TCP responses; in forward mode next to the TLS
                                           listener (--listener-keystore), with CONNECT, WebSockets
                                           and CONNECT-UDP (MASQUE); needs the quic and http3-codec
                                           jars, and a certificate (--listener-keystore, or --mitm's
                                           CA in reverse mode)
              --http3-upstream             speak HTTP/3 to servers that advertise it (Alt-Svc h3),
                                           one shared QUIC connection per server, falling back to
                                           TCP; needs the quic and http3-codec jars
              --http3-upstream-hosts <regex>  reach matching host:port names over HTTP/3 without
                                           waiting for Alt-Svc (with --http3-upstream); repeatable
              --http3-max-streams <n>      concurrent HTTP/3 requests per client connection
                                           (default 100)
              --no-http3-alt-svc           with --http3, do not advertise it with Alt-Svc
              --http3-retry                validate QUIC clients' addresses with a Retry first
                                           (--http3 and --transparent-quic-port)
              --masque                     serve CONNECT-UDP (MASQUE) on the TCP listener, also
                                           without --http3: over HTTP/2 (--http2, --http2-cleartext)
                                           and as HTTP/1.1 Upgrade: connect-udp, in DATAGRAM
                                           capsules; a forward proxy with --http3 serves it there
                                           anyway; needs the quic and http3-codec jars
              --masque-udp-template <t>    the URI template of CONNECT-UDP requests (default
                                           /.well-known/masque/udp/{target_host}/{target_port}/)
              --masque-udp-idle-timeout <seconds>  close a CONNECT-UDP flow after this long without
                                           a datagram either way (default 60)
              --masque-max-udp-flows <n>   CONNECT-UDP flows at once (default 4096)
              --masque-max-udp-flows-per-connection <n>  CONNECT-UDP flows of one client connection
                                           (default 64)
              --masque-intercept-quic      decide on QUIC inside CONNECT-UDP flows as on transparent
                                           QUIC: intercept HTTP/3 (and other QUIC with the QUIC
                                           hooks) unless the host rules or hooks decline, else relay
              --masque-quic-ports <list>   the target ports whose flows --masque-intercept-quic
                                           inspects: comma-separated, or "any" (default 443)
              --http3-0rtt                 accept 0-RTT early data from resuming HTTP/3 clients
                                           (--http3, --transparent-quic-port and
                                           --masque-intercept-quic): replayable, so unsafe methods
                                           get 425 and the rest go on with Early-Data: 1
              --no-http3-upstream-0rtt     never send requests to HTTP/3 servers as 0-RTT data (by
                                           default GET, HEAD and OPTIONS without a body may go)
              --quic-congestion <name>     congestion control of the proxy's QUIC connections:
                                           cubic (default), newreno or bbr (experimental)
              --qlog-dir <dir>             write a qlog file (JSON-SEQ, .sqlog) per QUIC connection,
                                           to clients and to servers, into <dir> (for debugging)
              --qlog-max-files <n>         qlog files the directory keeps, the oldest deleted past
                                           it (default 1000)
              --listener-keystore <file>   serve TLS on the listener with this PKCS#12 or JKS key
                                           store's first key entry (HTTPS, HTTP/2 with --http2, and
                                           the certificate --http3 presents)
              --listener-keystore-password <pw>  the key store's password (default empty)

              Addons, as in mitmproxy (repeatable; a spec starts with its separator, here |):
              --map-local <spec>           answer from local files: [|filter]|url-regex|file-or-dir
              --map-remote <spec>          send requests elsewhere: [|filter]|url-regex|replacement
              --modify-body <spec>         replace in bodies: [|filter]|regex|[@]replacement
              --modify-headers <spec>      set headers: [|filter]|name|[@]value (empty removes)
              --block-list <spec>          answer |filter|status (444: close without a response)
              --anticache                  remove If-None-Match and If-Modified-Since from requests
              --stickycookie <filter>      add remembered cookies to requests the filter matches
              --server-replay <path>       answer from responses recorded in HAR or WARC files
                                           (a file or a directory of them)
              --server-replay-reuse        let each recording answer any number of times
              --server-replay-extra <x>    unmatched requests: forward (default), kill or a status
              --server-replay-kill-extra   the same as --server-replay-extra kill
              --server-replay-no-refresh   keep the recorded Date, Expires, Last-Modified and
                                           cookie expiry instead of shifting them to now
              --server-replay-ignore-content  match without comparing request bodies
              --server-replay-ignore-host  match without comparing hosts
              --server-replay-ignore-port  match without comparing ports
              --server-replay-ignore-params <list>  query parameters left out of the match
              --server-replay-ignore-payload-params <list>  form fields left out of the match
              --server-replay-use-headers <list>  request headers that must match too
              --client-replay <path>       send the requests recorded in HAR or WARC files
                                           through the proxy once it runs, then exit
              --client-replay-concurrency <n>  requests replayed at once (default 1)
              --keepserving                keep running after --client-replay

              --help                       show this help
            """;

    private static final String EXTENSION_HEADER = "\n  Options from extensions:\n";

    private Launcher() {}

    /**
     * Starts the proxy from command-line options.
     *
     * @param args the command-line arguments
     * @throws IOException if configuration cannot be read or the proxy cannot be started
     */
    public static void main(String[] args) throws IOException {
        HttpProxyServer server = start(args, System.out);
        if (server != null) {
            Runtime.getRuntime().addShutdownHook(shutdownHook(server, System.out));
        }
    }

    /**
     * The shutdown hook: on SIGTERM (or SIGINT, or {@code System.exit}) the proxy drains, then the
     * JVM exits. Stopping closes the listeners, tells clients to go away (idle connections close,
     * HTTP/2 and HTTP/3 ones get GOAWAY, HTTP/1 ones close after their exchange) and lets the
     * exchanges in progress finish for up to the drain time ({@code --drain-time}), as Envoy's
     * shutdown does; then whatever is left is closed. To keep accepting while a load balancer
     * forgets the proxy, drain first through the admin listener ({@code POST
     * /drain_listeners?graceful}).
     */
    static Thread shutdownHook(HttpProxyServer server, PrintStream console) {
        return new Thread(() -> shutdown(server, console), "microproxy-shutdown");
    }

    /** What the shutdown hook does: stops {@code server} gracefully, unless it has stopped already. */
    static void shutdown(HttpProxyServer server, PrintStream console) {
        if (server.state() == ServerState.STOPPED) return;
        console.println("MicroProxy stopping: draining for up to " + server.getDrainTime().toMillis() / 1000.0 + " s");
        server.stop();
    }

    /** Parses {@code args} and starts the proxy; returns null if only help was printed. */
    static HttpProxyServer start(String[] args, PrintStream console) throws IOException {
        Parsed parsed = parse(args, console);
        if (parsed == null) return null;
        HttpProxyServer server = parsed.bootstrap().start();
        // Closed after the server's connections finish, so in-flight records are written.
        parsed.resources().forEach(server::closeOnStop);
        for (AutoCloseable resource : parsed.resources()) {
            if (resource instanceof StatsdSink sink) sink.start();
        }
        console.println("MicroProxy listening on " + server.getListenAddress());
        if (server.getAdminAddress() != null) {
            console.println("Admin listening on " + server.getAdminAddress());
        }
        if (Simd.isVectorized()) {
            console.println("SIMD: " + Simd.ops().description());
        }
        if (parsed.clientReplay() != null) {
            clientReplay(server, parsed.clientReplay(), console);
        }
        return server;
    }

    /** Replays recorded requests through {@code server}, then stops it unless asked to keep serving. */
    private static void clientReplay(HttpProxyServer server, ClientReplayPlan plan, PrintStream console)
            throws IOException {
        List<RecordedExchange> exchanges = new ArrayList<>();
        for (Path recording : plan.recordings()) exchanges.addAll(RecordedExchange.load(recording));
        InetSocketAddress listen = server.getListenAddress();
        if (listen.getAddress() != null && listen.getAddress().isAnyLocalAddress()) {
            listen = new InetSocketAddress(InetAddress.getLoopbackAddress(), listen.getPort());
        }
        console.println("Replaying " + exchanges.size() + " recorded requests through the proxy");
        ClientReplay.Result result;
        try {
            result = ClientReplay.builder(listen).concurrency(plan.concurrency()).build().replay(exchanges);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("client replay interrupted", e);
        }
        console.println("Client replay done: " + result.sent() + " sent, " + result.failed() + " failed");
        if (!plan.keepServing()) {
            server.stop();
        }
    }

    /**
     * A parsed command line: the configured bootstrap, and resources (such as a WARC recorder) to
     * close when the server stops.
     */
    record Parsed(HttpProxyServerBootstrap bootstrap, List<AutoCloseable> resources, ClientReplayPlan clientReplay) {
        Parsed(HttpProxyServerBootstrap bootstrap, List<AutoCloseable> resources) {
            this(bootstrap, resources, null);
        }
    }

    /** Requests to replay through the proxy once it runs ({@code --client-replay}). */
    record ClientReplayPlan(List<Path> recordings, int concurrency, boolean keepServing) {}

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
        String accessLog = null;
        String accessLogFormat = null;
        boolean metrics = false;
        String statsd = null;
        boolean dogStatsd = false;
        StatsRegistry.Builder statsOptions = null;
        String accessLogJson = null;
        List<String> accessLogFilters = new ArrayList<>();
        HttpLogger.Level logHttp = null;
        boolean logHttpJson = false;
        String logHttpView = null;
        Path protoDescriptors = null;
        int maxConcurrentPerClient = 0;
        int http2MaxStreams = 0;
        boolean http2Coalesce = false;
        int http3MaxStreams = 0;
        boolean noHttp3AltSvc = false;
        boolean http3Retry = false;
        boolean http3ZeroRtt = false;
        boolean noHttp3UpstreamZeroRtt = false;
        long quicRelayIdleSeconds = 0;
        String masqueTemplate = null;
        long masqueIdleSeconds = 0;
        int masqueMaxFlows = 0;
        int masqueMaxFlowsPerConnection = 0;
        boolean masqueInterceptQuic = false;
        int[] masqueQuicPorts = null;
        Http3Options.QuicCongestionControl quicCongestion = null;
        Path qlogDir = null;
        int qlogMaxFiles = 0;
        List<String> http3UpstreamHosts = new ArrayList<>();
        Path listenerKeystore = null;
        String listenerKeystorePassword = "";
        List<AutoCloseable> resources = new ArrayList<>();
        List<String> ignoreHosts = new ArrayList<>();
        List<String> allowHosts = new ArrayList<>();
        List<String> tcpHosts = new ArrayList<>();
        List<String> quicHosts = new ArrayList<>();
        String caPassword = "microproxy";
        Path saveHar = null;
        String saveHarFilter = null;
        boolean saveHarStream = false;
        int saveHarMaxBody = -1;
        List<String> mapLocal = new ArrayList<>();
        List<String> mapRemote = new ArrayList<>();
        List<String> modifyBody = new ArrayList<>();
        List<String> modifyHeaders = new ArrayList<>();
        List<String> blockList = new ArrayList<>();
        boolean anticache = false;
        String stickyCookie = null;
        List<Path> serverReplay = new ArrayList<>();
        ServerReplay.Builder replayOptions = ServerReplay.builder();
        String replayOption = null;
        List<Path> clientReplay = new ArrayList<>();
        int clientReplayConcurrency = 1;
        boolean keepServing = false;
        String healthCheckPath = null;
        boolean healthCheckPassThrough = false;
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
                case "--transparent-tls-port" -> bootstrap.withTransparentTlsPort(intValue(queue, arg));
                case "--transparent-quic-port" -> bootstrap.withTransparentQuicPort(intValue(queue, arg));
                case "--transparent-quic-relay-idle-timeout" -> quicRelayIdleSeconds = longValue(queue, arg);
                case "--allow-requests-to-origin-server" -> bootstrap.withAllowRequestToOriginServer(true);
                case "--mode" -> {
                    String mode = value(queue, arg);
                    bootstrap.withReverseProxy(ReverseProxyMode.parseMode(mode));
                    if (mode.strip().equals("transparent")) bootstrap.withTransparent(true);
                    bootstrap.withSocksServer(mode.strip().equals("socks5"));
                }
                case "--socks" -> bootstrap.withSocksDetection(true);
                case "--reverse" -> {
                    bootstrap.withReverseProxy(ReverseProxyMode.parse(value(queue, arg)));
                    bootstrap.withSocksServer(false);
                }
                case "--keep-host-header" -> bootstrap.withKeepHostHeader(true);
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
                case "--access-log" -> accessLog = value(queue, arg);
                case "--access-log-format" -> accessLogFormat = value(queue, arg);
                case "--access-log-json" -> accessLogJson = value(queue, arg);
                case "--access-log-filter" -> accessLogFilters.add(value(queue, arg));
                case "--metrics" -> metrics = true;
                case "--statsd", "--dogstatsd" -> {
                    statsd = value(queue, arg);
                    dogStatsd = arg.equals("--dogstatsd");
                }
                case "--stats-prefix" -> statsOptions = statsOptions(statsOptions).prefix(value(queue, arg));
                case "--stats-max-clusters" -> statsOptions = statsOptions(statsOptions).maxClusters(intValue(queue, arg));
                case "--stats-cluster-lru" -> statsOptions = statsOptions(statsOptions).clusterOverflow(StatsRegistry.Overflow.LRU);
                case "--stats-per-host" -> statsOptions = statsOptions(statsOptions).perHostClusters(true);
                case "--admin-port" -> bootstrap.withAdmin(new InetSocketAddress(InetAddress.getLoopbackAddress(),
                        intValue(queue, arg)));
                case "--admin-address" -> bootstrap.withAdmin(address(value(queue, arg), arg));
                case "--admin-token" -> bootstrap.withAdminToken(value(queue, arg));
                case "--admin-token-file" -> bootstrap.withAdminToken(firstLine(Path.of(value(queue, arg)), arg));
                case "--drain-time" -> {
                    long seconds = longValue(queue, arg);
                    if (seconds < 0) throw new IllegalArgumentException(arg + " needs a non-negative number");
                    bootstrap.withDrainTime(Duration.ofSeconds(seconds));
                }
                case "--drain-strategy" -> bootstrap.withDrainStrategy(DrainStrategy.parse(value(queue, arg)));
                case "--health-check-path" -> healthCheckPath = value(queue, arg);
                case "--health-check-pass-through" -> healthCheckPassThrough = true;
                case "--log-http" -> logHttp = logHttpLevel(value(queue, arg));
                case "--log-http-json" -> logHttpJson = true;
                case "--log-http-view" -> logHttpView = value(queue, arg);
                case "--proto-descriptors" -> protoDescriptors = Path.of(value(queue, arg));
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
                case "--save-har" -> saveHar = Path.of(value(queue, arg));
                case "--save-har-filter" -> saveHarFilter = value(queue, arg);
                case "--save-har-stream" -> saveHarStream = true;
                case "--save-har-max-body" -> {
                    saveHarMaxBody = intValue(queue, arg);
                    if (saveHarMaxBody < 0) throw new IllegalArgumentException(arg + " needs a non-negative number");
                }
                case "--map-local" -> mapLocal.add(value(queue, arg));
                case "--map-remote" -> mapRemote.add(value(queue, arg));
                case "--modify-body" -> modifyBody.add(value(queue, arg));
                case "--modify-headers" -> modifyHeaders.add(value(queue, arg));
                case "--block-list" -> blockList.add(value(queue, arg));
                case "--anticache" -> anticache = true;
                case "--stickycookie" -> stickyCookie = value(queue, arg);
                case "--server-replay" -> serverReplay.add(Path.of(value(queue, arg)));
                case "--server-replay-reuse", "--server-replay-nopop" -> {
                    replayOptions.reuse(true);
                    replayOption = arg;
                }
                case "--server-replay-extra" -> {
                    replayOptions.extra(ServerReplay.Extra.parse(value(queue, arg)));
                    replayOption = arg;
                }
                case "--server-replay-kill-extra" -> {
                    replayOptions.extra(ServerReplay.Extra.kill());
                    replayOption = arg;
                }
                case "--server-replay-no-refresh" -> {
                    replayOptions.refresh(false);
                    replayOption = arg;
                }
                case "--server-replay-ignore-content" -> {
                    replayOptions.ignoreContent(true);
                    replayOption = arg;
                }
                case "--server-replay-ignore-host" -> {
                    replayOptions.ignoreHost(true);
                    replayOption = arg;
                }
                case "--server-replay-ignore-port" -> {
                    replayOptions.ignorePort(true);
                    replayOption = arg;
                }
                case "--server-replay-ignore-params" -> {
                    replayOptions.ignoreParams(list(value(queue, arg)));
                    replayOption = arg;
                }
                case "--server-replay-ignore-payload-params" -> {
                    replayOptions.ignorePayloadParams(list(value(queue, arg)));
                    replayOption = arg;
                }
                case "--server-replay-use-headers" -> {
                    replayOptions.useHeaders(list(value(queue, arg)));
                    replayOption = arg;
                }
                case "--client-replay" -> clientReplay.add(Path.of(value(queue, arg)));
                case "--client-replay-concurrency" -> {
                    clientReplayConcurrency = intValue(queue, arg);
                    if (clientReplayConcurrency <= 0) throw new IllegalArgumentException(arg + " needs a positive number");
                }
                case "--keepserving" -> keepServing = true;
                case "--mitm" -> mitm = true;
                case "--mitm-ca" -> caPath = Path.of(value(queue, arg));
                case "--mitm-ca-password" -> caPassword = value(queue, arg);
                case "--mitm-trust-all" -> mitmTrustAll = true;
                case "--ignore-hosts" -> ignoreHosts.add(value(queue, arg));
                case "--allow-hosts" -> allowHosts.add(value(queue, arg));
                case "--tcp-hosts" -> tcpHosts.add(value(queue, arg));
                case "--quic-hosts" -> quicHosts.add(value(queue, arg));
                case "--quic-framing" -> bootstrap.withQuicFraming(bootstrap.getQuicFraming().withRules(value(queue, arg)));
                case "--quic-max-message-size" ->
                        bootstrap.withQuicFraming(bootstrap.getQuicFraming().withMaxMessageSize(intValue(queue, arg)));
                case "--quic-message-error-code" ->
                        bootstrap.withQuicFraming(bootstrap.getQuicFraming().withErrorCode(Long.decode(value(queue, arg))));
                case "--http2" -> bootstrap.withHttp2(true);
                case "--http2-upstream" -> bootstrap.withHttp2Upstream(true);
                case "--http2-cleartext" -> bootstrap.withHttp2Cleartext(true);
                case "--http2-max-streams" -> http2MaxStreams = intValue(queue, arg);
                case "--http2-coalesce" -> http2Coalesce = true;
                case "--http3" -> bootstrap.withHttp3(true);
                case "--http3-upstream" -> bootstrap.withHttp3Upstream(true);
                case "--http3-upstream-hosts" -> http3UpstreamHosts.add(value(queue, arg));
                case "--http3-max-streams" -> http3MaxStreams = intValue(queue, arg);
                case "--no-http3-alt-svc" -> noHttp3AltSvc = true;
                case "--http3-retry" -> http3Retry = true;
                case "--masque" -> bootstrap.withConnectUdp(true);
                case "--masque-udp-template" -> masqueTemplate = value(queue, arg);
                case "--masque-udp-idle-timeout" -> masqueIdleSeconds = longValue(queue, arg);
                case "--masque-max-udp-flows" -> masqueMaxFlows = intValue(queue, arg);
                case "--masque-max-udp-flows-per-connection" -> masqueMaxFlowsPerConnection = intValue(queue, arg);
                case "--masque-intercept-quic" -> masqueInterceptQuic = true;
                case "--masque-quic-ports" -> masqueQuicPorts = ports(value(queue, arg), arg);
                case "--http3-0rtt" -> http3ZeroRtt = true;
                case "--no-http3-upstream-0rtt" -> noHttp3UpstreamZeroRtt = true;
                case "--quic-congestion" -> quicCongestion = Http3Options.QuicCongestionControl.parse(value(queue, arg));
                case "--qlog-dir" -> qlogDir = Path.of(value(queue, arg));
                case "--qlog-max-files" -> qlogMaxFiles = intValue(queue, arg);
                case "--listener-keystore" -> listenerKeystore = Path.of(value(queue, arg));
                case "--listener-keystore-password" -> listenerKeystorePassword = value(queue, arg);
                default -> {
                    if (extensions.stream().noneMatch(e -> e.parseOption(arg, queue))) {
                        throw new IllegalArgumentException("unknown option: " + arg + "\n\n" + usage);
                    }
                }
            }
        }
        if (healthCheckPath != null) {
            bootstrap.withHealthCheckPath(healthCheckPath, healthCheckPassThrough);
        } else if (healthCheckPassThrough) {
            throw new IllegalArgumentException("--health-check-pass-through needs --health-check-path");
        }
        if (!ignoreHosts.isEmpty()) bootstrap.withIgnoreHosts(ignoreHosts.toArray(String[]::new));
        if (!allowHosts.isEmpty()) bootstrap.withAllowHosts(allowHosts.toArray(String[]::new));
        if (!tcpHosts.isEmpty()) bootstrap.withTcpHosts(tcpHosts.toArray(String[]::new));
        if (!quicHosts.isEmpty()) bootstrap.withQuicHosts(quicHosts.toArray(String[]::new));
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
        if (http2MaxStreams > 0 || http2Coalesce) {
            Http2Options.Builder h2 = bootstrap.getHttp2Options().toBuilder();
            if (http2MaxStreams > 0) h2.maxConcurrentStreams(http2MaxStreams);
            if (http2Coalesce) h2.coalesceConnections(true);
            bootstrap.withHttp2Options(h2.build());
        }
        if (http3MaxStreams > 0 || noHttp3AltSvc || http3Retry || http3ZeroRtt || noHttp3UpstreamZeroRtt
                || quicRelayIdleSeconds > 0 || quicCongestion != null || masqueTemplate != null
                || masqueIdleSeconds > 0 || masqueMaxFlows > 0 || masqueMaxFlowsPerConnection > 0 || masqueInterceptQuic
                || masqueQuicPorts != null || qlogDir != null || qlogMaxFiles > 0) {
            Http3Options.Builder h3 = bootstrap.getHttp3Options().toBuilder();
            if (qlogDir != null) h3.qlogDirectory(qlogDir);
            if (qlogMaxFiles > 0) h3.qlogMaxFiles(qlogMaxFiles);
            if (masqueInterceptQuic) h3.connectUdpInterceptQuic(true);
            if (masqueQuicPorts != null) h3.connectUdpQuicPorts(masqueQuicPorts);
            if (http3MaxStreams > 0) h3.maxConcurrentStreams(http3MaxStreams);
            if (noHttp3AltSvc) h3.altSvc(false);
            if (http3Retry) h3.retry(true);
            if (http3ZeroRtt) h3.zeroRtt(true);
            if (noHttp3UpstreamZeroRtt) h3.upstreamZeroRtt(false);
            if (quicRelayIdleSeconds > 0) h3.transparentRelayIdleTimeout(Duration.ofSeconds(quicRelayIdleSeconds));
            if (masqueTemplate != null) h3.connectUdpTemplate(masqueTemplate);
            if (masqueIdleSeconds > 0) h3.connectUdpIdleTimeout(Duration.ofSeconds(masqueIdleSeconds));
            if (masqueMaxFlows > 0 || masqueMaxFlowsPerConnection > 0) {
                Http3Options current = bootstrap.getHttp3Options();
                h3.connectUdpMaxFlows(masqueMaxFlows > 0 ? masqueMaxFlows : current.connectUdpMaxFlows(),
                        masqueMaxFlowsPerConnection > 0 ? masqueMaxFlowsPerConnection : current.connectUdpMaxFlowsPerConnection());
            }
            if (quicCongestion != null) h3.quicCongestionControl(quicCongestion);
            bootstrap.withHttp3Options(h3.build());
        }
        if (!http3UpstreamHosts.isEmpty()) bootstrap.withHttp3UpstreamHosts(http3UpstreamHosts.toArray(String[]::new));
        if (listenerKeystore != null) {
            bootstrap.withSslContextSource(new KeyStoreSslContextSource(listenerKeystore, listenerKeystorePassword.toCharArray()));
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
        if (saveHar != null) {
            // First among the filters too: requests as clients sent them, responses as delivered.
            HarRecorder.Builder har = HarRecorder.builder(saveHar).stream(saveHarStream);
            if (saveHarFilter != null) har.filter(FlowFilter.parse(saveHarFilter));
            if (saveHarMaxBody == 0) har.content(false);
            if (saveHarMaxBody > 0) har.maxBodySize(saveHarMaxBody);
            HarRecorder recorder = har.build();
            bootstrap.withFiltersSource(HttpFiltersChain.of(recorder, bootstrap.getFiltersSource()));
            resources.add(recorder);
            console.println("Recording HAR to " + saveHar.toAbsolutePath()
                    + (saveHarStream ? " (as exchanges complete)" : " (written on exit)"));
        } else if (saveHarFilter != null || saveHarStream || saveHarMaxBody >= 0) {
            throw new IllegalArgumentException("--save-har-filter, --save-har-stream and --save-har-max-body need --save-har");
        }
        // As in mitmproxy, block_list and anticache act before scripts, the other addons after them.
        if (!blockList.isEmpty()) bootstrap.plusFiltersSource(BlockList.of(blockList.toArray(String[]::new)));
        if (anticache) bootstrap.plusFiltersSource(AntiCache.create());
        if (accessLog != null || accessLogFormat != null || accessLogJson != null || !accessLogFilters.isEmpty()) {
            if (accessLogFormat != null && accessLogJson != null) {
                throw new IllegalArgumentException("--access-log-format and --access-log-json are exclusive");
            }
            ActivityLogger.Builder logger = ActivityLogger.builder();
            if (accessLogJson != null) logger.format(AccessLogFormat.envoyJson(accessLogJson));
            if (accessLogFormat != null) logger.format(LogFormat.parse(accessLogFormat));
            for (String filter : accessLogFilters) logger.filter(AccessLogFilter.parse(filter));
            if (accessLog != null) {
                AccessLogWriter writer = AccessLogWriter.of(accessLog);
                resources.add(writer);
                logger.sink(writer);
            }
            bootstrap.plusActivityTracker(logger.build());
            console.println("Writing access logs to " + (accessLog == null ? "the System.Logger "
                    + ActivityLogger.class.getName() : "-".equals(accessLog.strip()) ? "standard output"
                    : Path.of(accessLog.strip()).toAbsolutePath()));
        }
        if (logHttp != null || logHttpJson || logHttpView != null || protoDescriptors != null) {
            HttpLogger fromConfig = findHttpLogger(bootstrap.getFiltersSource());
            boolean views = logHttpView != null || protoDescriptors != null;
            HttpLogger.Level level = logHttp != null ? logHttp
                    : fromConfig != null ? fromConfig.level()
                    : views ? HttpLogger.Level.BODY : HttpLogger.Level.HEADERS;
            HttpLogger.Format format = logHttpJson ? HttpLogger.Format.JSON
                    : fromConfig != null ? fromConfig.format() : HttpLogger.Format.TEXT;
            HttpLogger.Builder logger = HttpLogger.builder().level(level).format(format);
            ContentViews contentViews = fromConfig != null ? fromConfig.contentViews() : null;
            if (protoDescriptors != null) {
                contentViews = ContentViews.defaults().withSchema(ProtoSchema.load(protoDescriptors));
            }
            if (contentViews != null) logger.contentViews(contentViews);
            if (logHttpView != null) {
                logger.contentView(logHttpView);
            } else if (fromConfig != null && fromConfig.contentViews() != null) {
                logger.contentView(fromConfig.contentView());
            } else if (protoDescriptors != null) {
                logger.contentView(ContentViews.AUTO);
            }
            // First among the filters, replacing one from the properties file.
            bootstrap.withFiltersSource(HttpFiltersChain.of(logger.build(), withoutHttpLoggers(bootstrap.getFiltersSource())));
            console.println("Logging requests and responses (" + level.name().toLowerCase(Locale.ROOT)
                    + (format == HttpLogger.Format.JSON ? ", JSON" : "")
                    + (views || contentViews != null ? ", content views" : "") + ") to the System.Logger "
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
        if (metrics || statsd != null || statsOptions != null) {
            // Before the extensions, whose scripts may count into the registry.
            StatsRegistry registry = statsOptions != null ? statsOptions.build()
                    : bootstrap.getStats().enabled() ? bootstrap.getStats() : StatsRegistry.create();
            bootstrap.withStats(registry);
            if (statsd != null) {
                StatsdSink sink = StatsdSink.builder(registry, statsd).dogStatsd(dogStatsd).build();
                // Started once the proxy runs, and stopped (after a last flush) with it.
                resources.add(sink);
                console.println("Pushing stats to " + (dogStatsd ? "DogStatsD" : "statsd") + " at " + statsd.strip());
            }
        }
        for (LauncherExtension extension : extensions) {
            extension.configure(bootstrap, console);
        }
        if (!serverReplay.isEmpty()) {
            for (Path recording : serverReplay) replayOptions.load(recording);
            ServerReplay replay = replayOptions.build();
            bootstrap.plusFiltersSource(replay);
            console.println("Replaying " + replay.remaining() + " recorded responses");
        } else if (replayOption != null) {
            throw new IllegalArgumentException(replayOption + " needs --server-replay");
        }
        if (!mapRemote.isEmpty()) bootstrap.plusFiltersSource(MapRemote.of(mapRemote.toArray(String[]::new)));
        if (!mapLocal.isEmpty()) bootstrap.plusFiltersSource(MapLocal.of(mapLocal.toArray(String[]::new)));
        if (!modifyBody.isEmpty()) bootstrap.plusFiltersSource(ModifyBody.of(modifyBody.toArray(String[]::new)));
        if (!modifyHeaders.isEmpty()) bootstrap.plusFiltersSource(ModifyHeaders.of(modifyHeaders.toArray(String[]::new)));
        if (stickyCookie != null) bootstrap.plusFiltersSource(StickyCookie.of(stickyCookie));
        ClientReplayPlan plan = null;
        if (!clientReplay.isEmpty()) {
            plan = new ClientReplayPlan(List.copyOf(clientReplay), clientReplayConcurrency, keepServing);
        } else if (keepServing || clientReplayConcurrency != 1) {
            throw new IllegalArgumentException("--keepserving and --client-replay-concurrency need --client-replay");
        }
        // For the admin's /server_info, which redacts the secrets among them.
        bootstrap.withCommandLineOptions(List.of(args));
        return new Parsed(bootstrap, List.copyOf(resources), plan);
    }

    /** {@code host:port} as a socket address ({@code [::1]:9901} for IPv6). */
    private static InetSocketAddress address(String value, String option) {
        int colon = value.lastIndexOf(':');
        if (colon <= 0 || colon == value.length() - 1) throw new IllegalArgumentException(option + " needs host:port, got: " + value);
        String host = value.substring(0, colon);
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        try {
            return new InetSocketAddress(host, Integer.parseInt(value.substring(colon + 1)));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(option + " needs host:port, got: " + value);
        }
    }

    /** The first line of {@code file}, stripped: a secret kept off the command line. */
    private static String firstLine(Path file, String option) throws IOException {
        try (var lines = java.nio.file.Files.lines(file)) {
            String line = lines.findFirst().orElse("").strip();
            if (line.isEmpty()) throw new IllegalArgumentException(option + ": " + file + " is empty");
            return line;
        }
    }

    private static String usage(List<LauncherExtension> extensions) {
        if (extensions.isEmpty()) return USAGE;
        StringBuilder sb = new StringBuilder(USAGE).append(EXTENSION_HEADER);
        for (LauncherExtension extension : extensions) {
            sb.append(extension.usage().stripTrailing()).append('\n');
        }
        return sb.toString();
    }

    /** A comma-separated option value as an array, blanks dropped. */
    private static String[] list(String value) {
        return Arrays.stream(value.split(",")).map(String::strip).filter(v -> !v.isEmpty()).toArray(String[]::new);
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

    /** UDP ports, comma-separated, or {@code any} for every port (none). */
    private static int[] ports(String list, String option) {
        String trimmed = list.strip();
        if (trimmed.equalsIgnoreCase("any")) return new int[0];
        String[] parts = trimmed.split(",");
        int[] ports = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            try {
                ports[i] = Integer.parseInt(parts[i].strip());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(option + " needs ports (443,8443) or any, got: " + list);
            }
        }
        return ports;
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

    /** {@code options}, or a new builder of stats options if it is null. */
    private static StatsRegistry.Builder statsOptions(StatsRegistry.Builder options) {
        return options != null ? options : StatsRegistry.builder();
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
