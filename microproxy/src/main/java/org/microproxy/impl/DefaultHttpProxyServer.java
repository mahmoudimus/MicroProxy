package org.microproxy.impl;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.System.Logger.Level;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Deque;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import org.microproxy.ChainedProxyManager;
import org.microproxy.DrainStrategy;
import org.microproxy.FailureResponder;
import org.microproxy.FlowTracer;
import org.microproxy.HostResolver;
import org.microproxy.Http2Options;
import org.microproxy.Http3Options;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpFiltersSource;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.KeyMaterial;
import org.microproxy.MitmManager;
import org.microproxy.PoolMetrics;
import org.microproxy.ProxyAuthenticator;
import org.microproxy.ProxyProtocolMode;
import org.microproxy.RetryBackoff;
import org.microproxy.ReverseProxyMode;
import org.microproxy.ServerState;
import org.microproxy.SslContextSource;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.frames.FrameInterceptor;
import org.microproxy.quic.QuicFraming;
import org.microproxy.quic.QuicInterceptor;
import org.microproxy.tcp.TcpInterceptor;
import org.microproxy.udp.UdpInterceptor;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * The proxy server. A platform thread accepts connections and hands each to its own virtual
 * thread, which serves the connection with plain blocking I/O.
 */
public final class DefaultHttpProxyServer implements HttpProxyServer {

    private static final System.Logger LOG = System.getLogger(DefaultHttpProxyServer.class.getName());

    final DefaultHttpProxyServerBootstrap config;
    final String name;
    final boolean transparent;
    /** The port transparent TLS connections go to, on the host their SNI names. */
    final int transparentTlsPort;
    /** Which TLS connections are intercepted by host name; null when every one may be. */
    final HostRules hostRules;
    /** Hosts relayed as raw TCP even when they look like HTTP; null when there are none. */
    final TcpHosts tcpHosts;
    /** Hosts whose intercepted QUIC is relayed stream by stream whatever its ALPN; null when there are none. */
    final TcpHosts quicHosts;
    /** The fixed upstream in reverse proxy mode; null for a forward proxy. */
    final ReverseProxyMode reverseProxy;
    final boolean keepHostHeader;
    /** Whether the listener serves SOCKS clients only / SOCKS clients besides HTTP ones. */
    final boolean socksServer;
    final boolean socksDetection;
    final SslContextSource sslContextSource;
    final boolean authenticateSslClients;
    final ProxyAuthenticator proxyAuthenticator;
    final ChainedProxyManager chainProxyManager;
    final MitmManager mitmManager;
    final HttpFiltersSource filtersSource;
    final FailureResponder failureResponder;
    /** Socket read/write buffers, lent to connections only while bytes are moving. */
    final BufferPool ioBuffers = new BufferPool(16384, 512);
    /** Buffers for relaying bodies no filter inspects, lent per body. */
    final BufferPool relayBuffers = new BufferPool(65536, 64);
    final HostResolver serverResolver;
    final InetSocketAddress localAddress;
    final HttpCodec.Limits limits;
    final boolean allowRequestsToOriginServer;
    /** Whether clients' own {@code https://} requests are fetched over TLS, or refused. */
    final boolean tlsOrigination;
    final String proxyAlias;
    /** Whether client connections start with a PROXY header: always, maybe, or never. */
    final ProxyProtocolMode proxyProtocolMode;
    /** Whether {@link #proxyProtocolMode} is not {@link ProxyProtocolMode#OFF}. */
    final boolean acceptProxyProtocol;
    /** The peers whose PROXY headers are honored. */
    final ProxyProtocol.TrustedSources proxyProtocolTrustedSources;
    final boolean sendProxyProtocol;
    /** Whether HTTP/1.1 requests with both Transfer-Encoding and Content-Length are accepted (the latter dropped). */
    final boolean allowChunkedLength;
    final int maxWebSocketFrameBufferSize;
    final int maxWebSocketMessageSize;
    /** Shared server connection pool, or null when connections are kept per client. */
    final SharedConnectionPool pool;
    final boolean poolSharedMitmConnections;
    final boolean poolPerRequestInMitm;
    /** Numbers the MITM managers chosen per connection, for pool keys; weak, so they can be collected. */
    private final Map<MitmManager, Long> mitmManagerIds = new WeakHashMap<>();
    private final ReentrantLock mitmManagerIdsLock = new ReentrantLock();
    private long nextMitmManagerId;
    final Trackers trackers = new Trackers();
    /** Traces exchanges and flows; {@link FlowTracer#NOOP} when tracing is off. */
    final FlowTracer tracer;
    /** The proxy's own metrics, resolved once; no-ops without metrics. */
    final ProxyStats stats;
    final RateLimiter readLimiter;
    final RateLimiter writeLimiter;

    private volatile Duration idleConnectionTimeout;
    private volatile int connectTimeoutMs;
    final Duration tlsHandshakeTimeout;
    final boolean littleProxyCompatibility;
    /** Backoff between chained proxy attempts; {@link RetryBackoff#none()} when off. */
    final RetryBackoff chainedProxyBackoff;
    /** The TLS versions every TLS socket starts with, before configuration hooks; null for the contexts' defaults. */
    final String[] tlsProtocols;
    /** Retry TLS with a server without SNI after its unrecognized_name alert ({@link org.microproxy.HttpProxyServerBootstrap#withTlsRetryWithoutSni}). */
    final boolean tlsRetryWithoutSni;
    /** Headers removed from every request right before it is written upstream; empty for none. */
    final String[] strippedRequestHeaders;
    /** Whether {@link #strippedRequestHeaders} removes {@code traceparent}, so a tracer injects its own context only. */
    final boolean stripsTracingHeaders;
    /** Whether HTTP/3 alternatives are removed from Alt-Svc response headers, for clients of the explicit proxy. */
    final boolean stripAltSvcH3;
    /** Whether they are removed for clients whose traffic was redirected to the proxy. */
    final boolean stripAltSvcH3Transparent;
    /** The UDP port of the transparent QUIC listener (0 for any), or -1 for none. */
    final int transparentQuicPort;
    /** The certificate the transparent QUIC listener presents for a server name; null when it intercepts nothing. */
    private final Function<String, KeyMaterial> transparentQuicKeys;
    /** The transparent QUIC listener, once started; null without one. */
    private volatile TransparentQuicListener transparentQuicListener;
    /** Whether intercepted TLS offers HTTP/2 (ALPN {@code h2}); the codec is known to be present. */
    final boolean http2;
    /** Whether TLS connections to servers offer HTTP/2; the codec is known to be present. */
    final boolean http2Upstream;
    /** Whether the plain listener serves HTTP/2 with prior knowledge; the codec is known to be present. */
    final boolean http2Cleartext;
    /** Whether it serves nothing else: other connections are a connection error (see {@link #http2Cleartext}). */
    final boolean http2CleartextOnly;
    final Http2Options http2Options;
    /** Sees every HTTP/2 frame (see {@link FrameInterceptor}); null for none, which costs nothing. */
    final FrameInterceptor frameInterceptor;
    /** Sees the bytes of raw tunnels (see {@link TcpInterceptor}); null for none, which costs nothing. */
    final TcpInterceptor tcpInterceptor;
    /** The UDP hooks of CONNECT-UDP flows, or null. */
    final UdpInterceptor udpInterceptor;
    /** The hooks of QUIC intercepted stream by stream (see {@link QuicInterceptor}), or null. */
    final QuicInterceptor quicInterceptor;
    /** Which streams of QUIC intercepted stream by stream the interceptor sees as messages. */
    final QuicFraming quicFraming;
    /** Decides on the QUIC inside CONNECT-UDP flows; null unless {@link Http3Options#connectUdpInterceptQuic()}. */
    private volatile MasqueQuic masqueQuic;
    /**
     * The template CONNECT-UDP requests name their targets with; null unless a forward proxy serves
     * CONNECT-UDP (with HTTP/3, or {@code withConnectUdp}).
     */
    final ConnectUdpTemplate connectUdpTemplate;
    /** The CONNECT-UDP flows open now, against {@link Http3Options#connectUdpMaxFlows()}. */
    final UdpFlowBound udpFlows = new UdpFlowBound();
    /** The HTTP/2 connections to servers; null without {@link #http2Upstream}. */
    final Http2Origins http2Origins;
    /**
     * The HTTP/2 connections to chained proxies ({@link org.microproxy.ChainedProxy#http2()}); null
     * without the http2-codec module, which leaves such proxies to HTTP/1.1.
     */
    final Http2Origins http2Proxies;
    /** Whether the reverse proxy serves HTTP/3 on UDP; the modules are known to be present. */
    final boolean http3;
    final Http3Options http3Options;
    /** The certificate the HTTP/3 listener presents for a server name; null without {@link #http3}. */
    private final Function<String, KeyMaterial> http3Keys;
    /** The HTTP/3 listener, once started; null without {@link #http3}. */
    private volatile Http3Listener http3Listener;
    /** The Alt-Svc value that advertises the HTTP/3 listener on TCP responses; null for none. */
    volatile String http3AltSvc;
    /** The QUIC connections to HTTP/3 servers; null without HTTP/3 upstream. */
    final Http3Origins http3Origins;
    /**
     * The key that seals the session tickets of the proxy's QUIC listeners (a quic {@code
     * Ticketer}, typed so that the class loads without the module), made on first use.
     */
    volatile Object quicTicketer;
    /**
     * The anti-replay record of the proxy's QUIC servers (a quic {@code EarlyDataPolicy}), which
     * all of them share as they share the ticket key, so that a ticket's early data is accepted
     * once in all; made on first use.
     */
    volatile Object quicEarlyDataPolicy;
    /** The writer of the QUIC connections' qlog files (a {@link QlogWriter}), made on first use; null before, or without qlog. */
    volatile Object qlogWriter;
    /** Draws the backoff jitter; null for a {@link ThreadLocalRandom}. Replaceable by tests. */
    volatile java.util.random.RandomGenerator backoffRandom;
    /**
     * Waits out a backoff of the given nanoseconds instead of the real wait, which watches the
     * client; null for the real wait. Replaceable by tests, so they need not sleep.
     */
    volatile java.util.function.LongConsumer backoffSleeper;

    private final Set<ClientConnection> connections = ConcurrentHashMap.newKeySet();
    private ServerSocket serverSocket;
    private ExecutorService executor;
    private Thread acceptor;
    private final AtomicBoolean stopping = new AtomicBoolean();
    private InetSocketAddress boundAddress;

    /** How long stopping lets exchanges finish, and how long a drain the admin starts lasts. */
    final Duration drainTime;
    final DrainStrategy drainStrategy;
    /** The path health checks are answered on; null for none. */
    final String healthCheckPath;
    final boolean healthCheckPassThrough;
    private final AtomicReference<ServerState> state = new AtomicReference<>(ServerState.PRE_INITIALIZING);
    private volatile boolean healthCheckFailed;
    /** Set once the listeners stop accepting: a drain's end, {@link #stopListeners}, or stopping. */
    private final AtomicBoolean listenersStopped = new AtomicBoolean();
    /** Set by the first {@link #drain}; later ones wait for it. */
    private final AtomicBoolean drainBegun = new AtomicBoolean();
    private final CountDownLatch drainDone = new CountDownLatch(1);
    /** Counted down when stopping begins, which ends a drain in progress early. */
    private final CountDownLatch stopBegun = new CountDownLatch(1);
    /** Whether a drain has started; then when ({@link System#nanoTime}), for how long, and whether all at once. */
    private volatile boolean drainStarted;
    private volatile long drainStartNanos;
    private volatile long drainNanos;
    private volatile boolean drainImmediate;
    /** The admin listener, while it runs; null without one. */
    private volatile AdminServer admin;
    /** When the proxy started ({@link System#nanoTime}), for its uptime. */
    final long startNanos = System.nanoTime();

    DefaultHttpProxyServer(DefaultHttpProxyServerBootstrap b) {
        if (!Http2Support.available()) {
            if (Boolean.TRUE.equals(b.http2) || Boolean.TRUE.equals(b.http2Upstream) || b.http2Cleartext
                    || b.http2CleartextOnly) {
                // Asked for explicitly: fail at startup, not on the first client that asks for h2.
                throw new IllegalStateException(Http2Support.MISSING);
            }
            // On by default: HTTP/1.1 it is, said once.
            if (b.http2 == null || b.http2Upstream == null) Http2Support.defaultsFallBack();
        }
        if (b.chainProxyManager instanceof org.microproxy.UpstreamProxyManager upstream && upstream.usesHttp2()
                && !Http2Support.available()) {
            throw new IllegalStateException("an h2:// or h2c:// upstream proxy needs the http2-codec module"
                    + " (io.github.mahmoudimus:http2-codec) on the class path; add its jar to the class path or"
                    + " use the microproxy-starlark -all jar, which bundles it");
        }
        if ((b.http3 || b.http3Upstream || b.transparentQuicPort >= 0) && !Http3Support.available()) {
            throw new IllegalStateException(Http3Support.MISSING);
        }
        if (b.http2CleartextOnly && (b.sslContextSource != null || b.socksServer || b.socksDetection || b.transparent
                || b.reverseProxy != null && b.reverseProxy.rawTcp())) {
            throw new IllegalStateException("an h2c-only listener (withHttp2CleartextOnly, --http2-cleartext-only,"
                    + " http2_cleartext_only) serves HTTP/2 with prior knowledge alone, so not with a TLS listener, SOCKS,"
                    + " transparent mode or a tcp:// reverse proxy");
        }
        if (b.connectUdp && b.reverseProxy != null) {
            throw new IllegalStateException("CONNECT-UDP (withConnectUdp, --masque, masque) is served by a forward proxy,"
                    + " not a reverse proxy");
        }
        if (b.connectUdp && !Http3Support.available()) {
            throw new IllegalStateException("CONNECT-UDP is enabled (withConnectUdp, --masque, masque) but the quic and"
                    + " http3-codec modules (io.github.mahmoudimus:quic, io.github.mahmoudimus:http3-codec) are not both"
                    + " on the class path; add their jars to the class path or use the microproxy-starlark -all jar,"
                    + " which bundles them");
        }
        if (b.transparentQuicPort >= 0 && (!b.transparent || b.reverseProxy != null)) {
            throw new IllegalStateException("transparent QUIC (withTransparentQuicPort, --transparent-quic-port,"
                    + " transparent_quic_port) needs transparent mode (withTransparent, --transparent), and no reverse proxy");
        }
        if (b.http3 && b.reverseProxy != null && b.reverseProxy.rawTcp()) {
            throw new IllegalStateException("HTTP/3 (withHttp3, --http3, http3) is served by a reverse proxy only for an"
                    + " http:// or https:// upstream (--mode reverse:https://host), not a tcp:// one");
        }
        if (b.http3 && b.reverseProxy == null && (b.sslContextSource == null || b.transparent)) {
            // A forward proxy serves HTTP/3 next to its own TLS listener, to clients that know the
            // proxy speaks it (MASQUE clients): browsers never send HTTP/3 to a proxy otherwise.
            throw new IllegalStateException("HTTP/3 (withHttp3, --http3, http3) is served by a forward proxy only next"
                    + " to its TLS listener (withSslContextSource, --listener-keystore), and not in transparent mode,"
                    + " whose clients' QUIC goes to --transparent-quic-port");
        }
        this.config = b;
        this.name = b.name;
        // The admin listener shows the stats: it turns them on.
        if (b.adminAddress != null && !b.stats.enabled()) b.stats = org.microproxy.stats.StatsRegistry.create();
        this.stats = new ProxyStats(b.stats, b.name);
        this.transparent = b.transparent;
        this.transparentTlsPort = b.transparentTlsPort;
        this.hostRules = HostRules.of(b.ignoreHosts, b.allowHosts);
        this.tcpHosts = TcpHosts.of(b.tcpHosts);
        this.quicHosts = TcpHosts.of(b.quicHosts);
        this.reverseProxy = b.reverseProxy;
        this.keepHostHeader = b.keepHostHeader;
        if ((b.socksServer || b.socksDetection) && (b.reverseProxy != null || b.sslContextSource != null)) {
            throw new IllegalStateException("SOCKS clients are served neither by a reverse proxy nor on a TLS listener");
        }
        this.socksServer = b.socksServer;
        this.socksDetection = b.socksDetection;
        this.sslContextSource = b.sslContextSource;
        this.authenticateSslClients = b.authenticateSslClients;
        this.proxyAuthenticator = b.proxyAuthenticator;
        this.chainProxyManager = b.chainProxyManager;
        this.mitmManager = b.mitmManager;
        // The cache runs last, so other filters see requests before it answers them.
        this.filtersSource = b.httpCache == null ? b.filtersSource
                : HttpFiltersChain.of(b.filtersSource, b.httpCache);
        this.failureResponder = b.failureResponder;
        this.serverResolver = b.serverResolver;
        this.localAddress = b.localAddress;
        this.limits = new HttpCodec.Limits(b.maxInitialLineLength, b.maxHeaderSize, b.maxChunkSize);
        this.allowRequestsToOriginServer = b.allowRequestToOriginServer;
        this.tlsOrigination = b.tlsOrigination;
        this.proxyAlias = Objects.requireNonNullElseGet(b.proxyAlias, ProxyUtils::getHostName);
        this.proxyProtocolMode = b.proxyProtocolMode;
        this.acceptProxyProtocol = b.proxyProtocolMode != ProxyProtocolMode.OFF;
        this.proxyProtocolTrustedSources = b.proxyProtocolTrustedSources;
        this.sendProxyProtocol = b.sendProxyProtocol;
        this.allowChunkedLength = b.allowChunkedLength;
        this.maxWebSocketFrameBufferSize = b.maxWebSocketFrameBufferSize;
        this.maxWebSocketMessageSize = b.maxWebSocketMessageSize;
        this.pool = b.sharedServerConnectionPool
                ? new SharedConnectionPool(b.maxConnectionsPerHost, b.maxConnections, b.poolIdleTimeout)
                : null;
        this.poolSharedMitmConnections = b.poolSharedMitmConnections;
        this.poolPerRequestInMitm = b.poolSharedMitmConnections && b.poolPerRequestInMitm;
        this.idleConnectionTimeout = b.idleConnectionTimeout;
        this.connectTimeoutMs = b.connectTimeoutMs;
        this.tlsHandshakeTimeout = b.tlsHandshakeTimeout;
        this.littleProxyCompatibility = b.littleProxyCompatibility;
        this.chainedProxyBackoff = b.chainedProxyBackoff;
        this.strippedRequestHeaders = b.strippedRequestHeaders.values().toArray(String[]::new);
        this.stripsTracingHeaders = b.strippedRequestHeaders.containsKey("traceparent");
        this.tracer = b.tracer;
        this.stripAltSvcH3 = b.stripsAltSvcH3();
        this.stripAltSvcH3Transparent = b.stripsAltSvcH3ForTransparent();
        this.transparentQuicPort = b.transparentQuicPort;
        this.transparentQuicKeys = b.transparentQuicPort >= 0 ? transparentQuicKeys(b.mitmManager) : null;
        this.tlsProtocols = b.tlsProtocols.isEmpty() ? null : b.tlsProtocols.toArray(String[]::new);
        this.tlsRetryWithoutSni = b.retriesTlsWithoutSni();
        this.readLimiter = new RateLimiter(b.readThrottleBytesPerSecond);
        this.writeLimiter = new RateLimiter(b.writeThrottleBytesPerSecond);
        b.activityTrackers.forEach(trackers::add);
        this.http2 = b.offersHttp2();
        this.http2Upstream = b.offersHttp2Upstream();
        this.http2Cleartext = b.http2Cleartext || b.http2CleartextOnly;
        this.http2CleartextOnly = b.http2CleartextOnly;
        this.http2Options = b.http2Options;
        this.frameInterceptor = b.frameInterceptor;
        this.tcpInterceptor = b.tcpInterceptor;
        this.udpInterceptor = b.udpInterceptor;
        this.quicInterceptor = b.quicInterceptor;
        b.quicFraming.validate();
        this.quicFraming = b.quicFraming;
        // A forward proxy's: on its HTTP/3 listener and its TCP listener with HTTP/3, on its TCP
        // listener alone with withConnectUdp.
        this.connectUdpTemplate = (b.http3 || b.connectUdp) && b.reverseProxy == null
                ? ConnectUdpTemplate.parse(b.http3Options.connectUdpTemplate()) : null;
        // Created only when enabled: the class needs the codec.
        this.http2Origins = http2Upstream ? new Http2Origins(this) : null;
        this.http2Proxies = Http2Support.available() ? Http2Origins.forChainedProxies(this) : null;
        this.http3 = b.http3;
        this.http3Options = b.http3Options;
        this.http3Keys = b.http3 ? http3Keys(b) : null;
        // Created only when enabled: the class needs the quic module.
        this.http3Origins = b.http3Upstream ? new Http3Origins(this, b.http3UpstreamHosts) : null;
        this.drainTime = b.drainTime;
        this.drainStrategy = b.drainStrategy;
        this.healthCheckPath = b.healthCheckPath;
        this.healthCheckPassThrough = b.healthCheckPassThrough;
        if (Boolean.TRUE.equals(b.http2) && mitmManager == null && sslContextSource == null) {
            // Only when asked for: on by default, it has nothing to do on a plain forward proxy.
            LOG.log(Level.WARNING, "HTTP/2 is enabled but nothing is intercepted (no withManInTheMiddle / --mitm):"
                    + " clients are only offered HTTP/2 inside intercepted TLS sessions");
        }
    }

    /**
     * Where the HTTP/3 listener's certificate comes from: the TLS listener's source, as {@link
     * KeyMaterial}, or else the CA of a {@link CertificateAuthorityMitmManager}, which issues one for
     * the name the client asks for (the upstream's host when it asks for none).
     */
    private static Function<String, KeyMaterial> http3Keys(DefaultHttpProxyServerBootstrap b) {
        String upstreamHost = b.reverseProxy != null ? b.reverseProxy.host() : null;
        if (b.sslContextSource != null) {
            SslContextSource source = b.sslContextSource;
            if (source.getKeyMaterial(upstreamHost) == null && source.getKeyMaterial(null) == null) {
                throw new IllegalStateException("HTTP/3 needs the TLS listener's certificate and key, but its "
                        + source.getClass().getName() + " provides none (SslContextSource.getKeyMaterial); use a"
                        + " KeyStoreSslContextSource or SelfSignedSslContextSource, or implement getKeyMaterial");
            }
            return sni -> {
                KeyMaterial key = source.getKeyMaterial(sni);
                return key != null ? key : source.getKeyMaterial(null);
            };
        }
        if (b.mitmManager instanceof CertificateAuthorityMitmManager ca) {
            return sni -> sni != null && !sni.isEmpty() ? ca.keyMaterialFor(sni)
                    : upstreamHost != null ? ca.keyMaterialFor(upstreamHost) : null;
        }
        throw new IllegalStateException("HTTP/3 needs a certificate: a TLS listener (withSslContextSource, or"
                + " --listener-keystore) whose SslContextSource provides its key material, or a"
                + " CertificateAuthorityMitmManager (--mitm) to issue one");
    }

    /**
     * Where the transparent QUIC listener's certificates come from: the CA of a {@link
     * CertificateAuthorityMitmManager}, which issues one for the client's SNI; null without one, when
     * every flow is relayed.
     */
    private static Function<String, KeyMaterial> transparentQuicKeys(MitmManager manager) {
        if (manager instanceof CertificateAuthorityMitmManager ca) {
            return sni -> sni == null || sni.isEmpty() ? null : ca.keyMaterialFor(sni);
        }
        if (manager != null) {
            LOG.log(Level.WARNING, "the transparent QUIC listener intercepts only with a CertificateAuthorityMitmManager"
                    + " (--mitm), which issues the certificates QUIC needs; " + manager.getClass().getName()
                    + " does not, so every QUIC flow is relayed");
        }
        return null;
    }

    /**
     * Starts a proxy configuration with default settings.
     *
     * @return a new proxy bootstrap
     */
    public static HttpProxyServerBootstrap bootstrap() {
        return new DefaultHttpProxyServerBootstrap();
    }

    /**
     * Loads a proxy configuration from a properties file.
     *
     * @param path the properties file to read
     * @return a bootstrap initialized from the properties file
     * @throws IOException if the properties file cannot be read
     */
    public static HttpProxyServerBootstrap bootstrapFromFile(Path path) throws IOException {
        return DefaultHttpProxyServerBootstrap.fromProperties(path);
    }

    HttpProxyServer start() {
        state.set(ServerState.INITIALIZING);
        if (config.adminAddress != null) {
            // First, as Envoy does: it answers (INITIALIZING) while the proxy's listeners are bound.
            try {
                admin = AdminServer.start(this, config.adminAddress, config.adminToken);
            } catch (IOException e) {
                if (pool != null) pool.closeAll();
                throw new UncheckedIOException("unable to bind the admin listener " + config.adminAddress, e);
            }
            LOG.log(Level.INFO, "{0} admin listening on {1}", name, admin.address());
        }
        try {
            return bind();
        } catch (RuntimeException e) {
            stopAdmin();
            state.set(ServerState.STOPPED);
            throw e;
        }
    }

    private HttpProxyServer bind() {
        InetSocketAddress requested = config.address();
        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(requested, 1024);
        } catch (IOException e) {
            Tls.closeQuietly(serverSocket);
            if (pool != null) pool.closeAll();
            throw new UncheckedIOException("unable to bind " + requested, e);
        }
        boundAddress = new InetSocketAddress(serverSocket.getInetAddress(), serverSocket.getLocalPort());
        stats.bound(boundAddress);
        stats.registerServer(this, config.httpCache, filtersSource);
        executor = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name(name + "-conn-", 0).factory());
        if (http3) {
            try {
                // The same port number on UDP, where clients told by Alt-Svc look for it.
                http3Listener = Http3Listener.start(this, boundAddress, http3Keys);
            } catch (IOException | RuntimeException e) {
                Tls.closeQuietly(serverSocket);
                executor.shutdownNow();
                if (pool != null) pool.closeAll();
                throw new UncheckedIOException("unable to bind the HTTP/3 listener on UDP " + boundAddress,
                        e instanceof IOException io ? io : new IOException(e));
            }
            if (http3Options.altSvc() && reverseProxy != null) {
                // (A forward proxy's responses are its servers': their Alt-Svc is theirs to give.)
                http3AltSvc = "h3=\":" + boundAddress.getPort() + "\"; ma=" + http3Options.altSvcMaxAge().toSeconds();
            }
            LOG.log(Level.INFO, "{0} serving HTTP/3 on UDP {1}", name, http3Listener.localAddress());
        }
        if (connectUdpTemplate != null && http3Options.connectUdpInterceptQuic()) {
            // For the flows of every transport, HTTP/3's and the TCP listener's.
            masqueQuic = new MasqueQuic(this, transparentQuicKeys(mitmManager));
        }
        if (transparentQuicPort >= 0) {
            InetSocketAddress udp = new InetSocketAddress(boundAddress.getAddress(), transparentQuicPort);
            try {
                transparentQuicListener = TransparentQuicListener.start(this, udp, transparentQuicKeys);
            } catch (IOException | RuntimeException e) {
                Http3Listener h3 = http3Listener;
                if (h3 != null) h3.close();
                Tls.closeQuietly(serverSocket);
                executor.shutdownNow();
                if (pool != null) pool.closeAll();
                throw new UncheckedIOException("unable to bind the transparent QUIC listener on UDP " + udp,
                        e instanceof IOException io ? io : new IOException(e));
            }
            LOG.log(Level.INFO, "{0} transparent QUIC on UDP {1}", name, transparentQuicListener.localAddress());
        }
        // A platform, non-daemon acceptor keeps the JVM alive while the proxy runs, like Netty's
        // event loops did; all per-connection work happens on (daemon) virtual threads.
        acceptor = Thread.ofPlatform().name(name + "-acceptor").daemon(false).start(this::acceptLoop);
        state.compareAndSet(ServerState.INITIALIZING, ServerState.LIVE);
        LOG.log(Level.INFO, "{0} listening on {1}", name, boundAddress);
        if (tracer != FlowTracer.NOOP) {
            // Closed last of the resources, once the exchanges have ended and been traced.
            closeOnStop.addLast(tracer);
            tracer.proxyStarted(this);
        }
        return this;
    }

    private void acceptLoop() {
        while (!refusesNewConnections()) {
            Socket socket;
            try {
                socket = serverSocket.accept();
            } catch (SocketException e) {
                if (!refusesNewConnections()) LOG.log(Level.WARNING, "accept failed", e);
                break;
            } catch (IOException e) {
                LOG.log(Level.WARNING, "accept failed", e);
                continue;
            }
            ClientConnection connection = new ClientConnection(this, socket);
            connections.add(connection);
            try {
                executor.execute(connection);
            } catch (RuntimeException e) {
                connections.remove(connection);
                Tls.closeQuietly(socket);
            }
        }
    }

    void unregister(ClientConnection connection) {
        connections.remove(connection);
    }

    /** Serves a QUIC connection the HTTP/3 listener accepted, as a client connection of its own. */
    void acceptHttp3(io.github.mahmoudimus.quic.QuicConnection quic) {
        ClientConnection connection = new ClientConnection(this, quic.remoteAddress());
        connections.add(connection);
        try {
            executor.execute(() -> connection.serveHttp3(quic));
        } catch (RuntimeException e) {
            connections.remove(connection);
            quic.close();
        }
    }

    /**
     * Serves an intercepted QUIC connection of the transparent QUIC listener, with the client
     * connection that decided on it.
     */
    void acceptTransparentQuic(io.github.mahmoudimus.quic.QuicConnection quic, ClientConnection connection) {
        connections.add(connection);
        try {
            executor.execute(() -> connection.serveTransparentQuic(quic));
        } catch (RuntimeException e) {
            connections.remove(connection);
            quic.close();
            connection.endTransparentQuic(false);
        }
    }

    /**
     * Serves a connection intercepted stream by stream (transparent QUIC, or QUIC inside a
     * CONNECT-UDP flow), with the client connection that decided on it and its server connection.
     */
    void acceptQuicStreams(io.github.mahmoudimus.quic.QuicConnection quic, ClientConnection connection,
            QuicSession.Upstream upstream, boolean masque) {
        connections.add(connection);
        try {
            executor.execute(() -> connection.serveQuicStreams(quic, upstream, masque));
        } catch (RuntimeException e) {
            connections.remove(connection);
            quic.close();
            upstream.close();
            connection.endTransparentQuic(false);
        }
    }

    /** What decides on the QUIC inside CONNECT-UDP flows, or null when such QUIC is relayed. */
    MasqueQuic masqueQuic() {
        return masqueQuic;
    }

    /** The transparent QUIC listener, or null without one (for tests). */
    TransparentQuicListener transparentQuicListener() {
        return transparentQuicListener;
    }

    @Override
    public InetSocketAddress getTransparentQuicAddress() {
        TransparentQuicListener listener = transparentQuicListener;
        return listener == null ? null : listener.localAddress();
    }

    /** The UDP address of the HTTP/3 listener, or null without one. */
    InetSocketAddress http3Address() {
        Http3Listener listener = http3Listener;
        return listener == null ? null : listener.localAddress();
    }

    /** A number identifying {@code manager} among the MITM managers this server has used. */
    long mitmManagerId(MitmManager manager) {
        mitmManagerIdsLock.lock();
        try {
            return mitmManagerIds.computeIfAbsent(manager, m -> ++nextMitmManagerId);
        } finally {
            mitmManagerIdsLock.unlock();
        }
    }

    boolean isStopping() {
        return stopping.get();
    }

    /** Whether new connections are turned away: the listeners have stopped, or the proxy is stopping. */
    boolean refusesNewConnections() {
        return listenersStopped.get() || stopping.get();
    }

    /**
     * Whether the request starting now should drain its connection (Envoy's drain decision): always
     * while the health check fails; while draining, always with {@link DrainStrategy#IMMEDIATE}, and
     * with {@link DrainStrategy#GRADUAL} by a chance that grows from 0 to 1 over the drain time;
     * never otherwise.
     */
    boolean drainClose() {
        if (healthCheckFailed) return true;
        if (!drainStarted) return false;
        if (drainImmediate) return true;
        long elapsed = System.nanoTime() - drainStartNanos;
        return elapsed >= drainNanos || ThreadLocalRandom.current().nextLong(drainNanos) < elapsed;
    }

    /** The proxy's answer to a health check, or null to let a pass-through check go on to the server. */
    HttpResponse healthCheckResponse() {
        boolean healthy = !healthCheckFailed && state.get() == ServerState.LIVE;
        if (healthy && healthCheckPassThrough) return null;
        HttpResponse response = ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1,
                healthy ? HttpResponseStatus.OK : HttpResponseStatus.SERVICE_UNAVAILABLE, null);
        if (!healthy) response.headers().set("x-envoy-immediate-health-check-fail", "true");
        return response;
    }

    @Override
    public ServerState state() {
        return state.get();
    }

    /** Turns the state to DRAINING, unless the proxy has stopped. */
    private void toDraining() {
        state.updateAndGet(s -> s == ServerState.STOPPED ? s : ServerState.DRAINING);
    }

    /** The listeners accepting connections: the TCP one, and the HTTP/3 and transparent QUIC ones on UDP. */
    int activeListeners() {
        return refusesNewConnections() ? 0 : listeners();
    }

    private int listeners() {
        return 1 + (http3Listener != null ? 1 : 0) + (transparentQuicListener != null ? 1 : 0);
    }

    @Override
    public void stopListeners() {
        if (stopping.get()) return;
        // Closed first: once the state says DRAINING, nothing is accepted any more.
        closeListeners();
        toDraining();
    }

    /**
     * Stops accepting: closes the TCP listener; the UDP ones refuse new QUIC connections from now
     * on, but stay open for the connections they carry.
     */
    private void closeListeners() {
        if (!listenersStopped.compareAndSet(false, true)) return;
        Tls.closeQuietly(serverSocket);
        // The socket is released only once the acceptor has left accept(): until then the kernel
        // still completes connections to it.
        Thread a = acceptor;
        if (a != null && a != Thread.currentThread()) {
            try {
                a.join(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        stats.listenerStopped.add(listeners());
        LOG.log(stopping.get() ? Level.DEBUG : Level.INFO, "{0} no longer accepts connections", name);
    }

    @Override
    public void drain(Duration drainTime) {
        Objects.requireNonNull(drainTime, "drainTime");
        if (stopping.get()) return;
        if (beginDrain(drainTime)) {
            endDrain();
        } else {
            awaitQuietly(drainDone);
        }
    }

    /**
     * Begins a drain on the calling thread, unless one has begun already or the proxy is stopping.
     * When it returns true the state says DRAINING and new requests are told to go elsewhere, and
     * the caller must see that {@link #endDrain} runs. The admin's graceful
     * {@code /drain_listeners} begins the drain before it answers, so that {@code /ready} fails
     * once the client has the answer, and leaves the drain time to a thread of its own.
     *
     * @return whether this call began the drain
     */
    boolean beginDrain(Duration drainTime) {
        Objects.requireNonNull(drainTime, "drainTime");
        if (stopping.get() || !drainBegun.compareAndSet(false, true)) return false;
        try {
            long nanos = drainTime.isNegative() ? 0 : saturatedNanos(drainTime);
            drainNanos = nanos;
            drainStartNanos = System.nanoTime();
            drainImmediate = drainStrategy == DrainStrategy.IMMEDIATE || nanos == 0;
            drainStarted = true;
            toDraining();
            LOG.log(Level.INFO, "{0} draining for {1} ({2})", name, drainTime,
                    drainImmediate ? "immediate" : "gradual");
            if (drainImmediate) connections.forEach(ClientConnection::drain);
            return true;
        } catch (RuntimeException | Error e) {
            drainDone.countDown();
            throw e;
        }
    }

    /**
     * Ends the drain {@link #beginDrain} began: waits out the rest of the drain time, counted from
     * its beginning, then closes the listeners and every connection still open; at once if the
     * proxy starts stopping meanwhile.
     */
    void endDrain() {
        try {
            // The listeners keep accepting meanwhile: clients still on their way are served, and
            // told to go elsewhere.
            long left = drainNanos - (System.nanoTime() - drainStartNanos);
            if (stopBegun.await(Math.max(0, left), TimeUnit.NANOSECONDS)) return;
            closeListeners();
            for (ClientConnection c : connections) c.close();
            LOG.log(Level.INFO, "{0} drained", name);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            drainDone.countDown();
        }
    }

    private static long saturatedNanos(Duration d) {
        try {
            return d.toNanos();
        } catch (ArithmeticException e) {
            return Long.MAX_VALUE;
        }
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public Duration getDrainTime() {
        return drainTime;
    }

    @Override
    public void setHealthCheckFailed(boolean failed) {
        if (healthCheckFailed != failed) {
            LOG.log(Level.INFO, "{0} health check {1}", name, failed ? "failed" : "restored");
        }
        healthCheckFailed = failed;
    }

    @Override
    public boolean isHealthCheckFailed() {
        return healthCheckFailed;
    }

    @Override
    public Duration getIdleConnectionTimeout() {
        return idleConnectionTimeout;
    }

    @Override
    public void setIdleConnectionTimeout(Duration idleConnectionTimeout) {
        this.idleConnectionTimeout = idleConnectionTimeout == null ? Duration.ZERO : idleConnectionTimeout;
    }

    int idleTimeoutMillis() {
        Duration d = idleConnectionTimeout;
        return d == null || d.isZero() || d.isNegative() ? 0 : (int) Math.min(Integer.MAX_VALUE, d.toMillis());
    }

    @Override
    public int getConnectTimeout() {
        return connectTimeoutMs;
    }

    @Override
    public void setConnectTimeout(int connectTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
    }

    @Override
    public HttpProxyServerBootstrap clone() {
        DefaultHttpProxyServerBootstrap copy = config.copy();
        int port = boundAddress.getPort();
        copy.withAddress(new InetSocketAddress(config.address().getAddress(), config.port == 0 ? 0 : port + 1));
        copy.withIdleConnectionTimeout(idleConnectionTimeout);
        copy.withConnectTimeout(connectTimeoutMs);
        copy.withThrottling(readLimiter.rate(), writeLimiter.rate());
        // An admin listener on a fixed port is this server's alone; one on any free port is cloned.
        if (config.adminAddress != null && config.adminAddress.getPort() != 0) copy.withAdmin(null);
        return copy;
    }

    @Override
    public void stop() {
        shutdown(true);
    }

    @Override
    public void abort() {
        shutdown(false);
    }

    private final Deque<AutoCloseable> closeOnStop = new ConcurrentLinkedDeque<>();

    @Override
    public void closeOnStop(AutoCloseable resource) {
        closeOnStop.push(Objects.requireNonNull(resource));
    }

    private void shutdown(boolean graceful) {
        // Both a shutdown hook and the application may stop the server; only the first one runs.
        if (!stopping.compareAndSet(false, true)) return;
        closeListeners();
        toDraining();
        // A drain in progress ends here: this takes over.
        stopBegun.countDown();
        LOG.log(Level.INFO, "{0} stopping ({1})", name, graceful ? "graceful" : "abort");
        for (ClientConnection c : connections) {
            // Idle connections close now; busy ones finish what they are doing (HTTP/2 ones are
            // sent GOAWAY and finish their open streams), for up to the drain time.
            if (graceful) {
                c.stopGracefully();
            } else {
                c.close();
            }
        }
        executor.shutdown();
        try {
            if (graceful && !executor.awaitTermination(saturatedNanos(drainTime), TimeUnit.NANOSECONDS)) {
                LOG.log(Level.WARNING, "connections still open after {0}; closing", drainTime);
            }
            connections.forEach(ClientConnection::close);
            Http3Listener listener = http3Listener;
            if (listener != null) listener.close();
            TransparentQuicListener quicListener = transparentQuicListener;
            if (quicListener != null) quicListener.close();
            MasqueQuic masque = masqueQuic;
            if (masque != null) masque.close();
            if (http2Origins != null) http2Origins.closeAll();
            if (http2Proxies != null) http2Proxies.closeAll();
            if (http3Origins != null) http3Origins.closeAll();
            if (pool != null) pool.closeAll();
            executor.shutdownNow();
            executor.awaitTermination(5, TimeUnit.SECONDS);
            acceptor.join(5000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        AutoCloseable resource;
        while ((resource = closeOnStop.poll()) != null) {
            try {
                resource.close();
            } catch (Exception e) {
                LOG.log(Level.WARNING, "closing " + resource + " failed", e);
            }
        }
        state.set(ServerState.STOPPED);
        // Last: it reports the drain until the end.
        stopAdmin();
    }

    private void stopAdmin() {
        AdminServer a = admin;
        admin = null;
        if (a != null) a.stop();
    }

    @Override
    public InetSocketAddress getAdminAddress() {
        AdminServer a = admin;
        return a == null ? null : a.address();
    }

    /** The TCP listener's address, the HTTP/3 one's and the transparent QUIC one's (null when absent). */
    InetSocketAddress[] listenerAddresses() {
        return new InetSocketAddress[] {boundAddress, http3Address(), getTransparentQuicAddress()};
    }

    /** {@return how many client connections are open} */
    int openConnections() {
        return connections.size();
    }

    @Override
    public InetSocketAddress getListenAddress() {
        return boundAddress;
    }

    @Override
    public void setThrottle(long readThrottleBytesPerSecond, long writeThrottleBytesPerSecond) {
        readLimiter.setRate(readThrottleBytesPerSecond);
        writeLimiter.setRate(writeThrottleBytesPerSecond);
    }

    @Override
    public PoolMetrics getServerConnectionPoolMetrics() {
        return pool == null ? null : pool.metrics();
    }

    @Override
    public org.microproxy.stats.StatsRegistry getStats() {
        return stats.registry;
    }

    /** {@return number of open client connections (for tests and monitoring)} */
    public int getOpenConnectionCount() {
        return connections.size();
    }

    static InetAddress loopback() {
        return InetAddress.getLoopbackAddress();
    }
}
