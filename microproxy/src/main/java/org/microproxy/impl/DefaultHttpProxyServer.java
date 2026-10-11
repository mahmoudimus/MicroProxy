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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.DoubleSupplier;
import java.util.function.Function;
import org.microproxy.ChainedProxyManager;
import org.microproxy.FailureResponder;
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
import org.microproxy.ReverseProxyMode;
import org.microproxy.SslContextSource;
import org.microproxy.frames.FrameInterceptor;
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
    private static final Duration GRACEFUL_STOP_TIMEOUT = Duration.ofSeconds(10);

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
    final String proxyAlias;
    final boolean acceptProxyProtocol;
    final boolean sendProxyProtocol;
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
    final RateLimiter readLimiter;
    final RateLimiter writeLimiter;

    private volatile Duration idleConnectionTimeout;
    private volatile int connectTimeoutMs;
    final Duration tlsHandshakeTimeout;
    final boolean littleProxyCompatibility;
    /** Backoff between chained proxy attempts, in nanoseconds; 0 when off. */
    final long backoffInitialNanos;
    final long backoffMaxNanos;
    /** The TLS versions every TLS socket starts with, before configuration hooks; null for the contexts' defaults. */
    final String[] tlsProtocols;
    /** Headers removed from every request right before it is written upstream; empty for none. */
    final String[] strippedRequestHeaders;
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
    final Http2Options http2Options;
    /** Sees every HTTP/2 frame (see {@link FrameInterceptor}); null for none, which costs nothing. */
    final FrameInterceptor frameInterceptor;
    /** Sees the bytes of raw tunnels (see {@link TcpInterceptor}); null for none, which costs nothing. */
    final TcpInterceptor tcpInterceptor;
    /** The UDP hooks of CONNECT-UDP flows, or null. */
    final UdpInterceptor udpInterceptor;
    /** The hooks of QUIC intercepted stream by stream (see {@link QuicInterceptor}), or null. */
    final QuicInterceptor quicInterceptor;
    /** Decides on the QUIC inside CONNECT-UDP flows; null unless {@link Http3Options#connectUdpInterceptQuic()}. */
    private volatile MasqueQuic masqueQuic;
    /** The template CONNECT-UDP requests name their targets with; null unless a forward proxy serves HTTP/3. */
    final ConnectUdpTemplate connectUdpTemplate;
    /** The CONNECT-UDP flows open now, against {@link Http3Options#connectUdpMaxFlows()}. */
    final java.util.concurrent.atomic.AtomicInteger udpFlows = new java.util.concurrent.atomic.AtomicInteger();
    /** The HTTP/2 connections to servers; null without {@link #http2Upstream}. */
    final Http2Origins http2Origins;
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
    /** Draws the backoff jitter, a fraction in [0, 1); replaceable by tests. */
    volatile DoubleSupplier backoffJitter = () -> ThreadLocalRandom.current().nextDouble();

    private final Set<ClientConnection> connections = ConcurrentHashMap.newKeySet();
    private ServerSocket serverSocket;
    private ExecutorService executor;
    private Thread acceptor;
    private final AtomicBoolean stopping = new AtomicBoolean();
    private InetSocketAddress boundAddress;

    DefaultHttpProxyServer(DefaultHttpProxyServerBootstrap b) {
        if ((b.http2 || b.http2Upstream || b.http2Cleartext) && !Http2Support.available()) {
            // Fail at startup, not on the first client that asks for h2.
            throw new IllegalStateException(Http2Support.MISSING);
        }
        if ((b.http3 || b.http3Upstream || b.transparentQuicPort >= 0) && !Http3Support.available()) {
            throw new IllegalStateException(Http3Support.MISSING);
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
        this.proxyAlias = Objects.requireNonNullElseGet(b.proxyAlias, ProxyUtils::getHostName);
        this.acceptProxyProtocol = b.acceptProxyProtocol;
        this.sendProxyProtocol = b.sendProxyProtocol;
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
        this.backoffInitialNanos = b.chainedProxyBackoffInitial == null ? 0 : b.chainedProxyBackoffInitial.toNanos();
        this.strippedRequestHeaders = b.strippedRequestHeaders.values().toArray(String[]::new);
        this.stripAltSvcH3 = b.stripsAltSvcH3();
        this.stripAltSvcH3Transparent = b.stripsAltSvcH3ForTransparent();
        this.transparentQuicPort = b.transparentQuicPort;
        this.transparentQuicKeys = b.transparentQuicPort >= 0 ? transparentQuicKeys(b.mitmManager) : null;
        this.tlsProtocols = b.tlsProtocols.isEmpty() ? null : b.tlsProtocols.toArray(String[]::new);
        this.backoffMaxNanos = b.chainedProxyBackoffMax == null ? 0 : b.chainedProxyBackoffMax.toNanos();
        this.readLimiter = new RateLimiter(b.readThrottleBytesPerSecond);
        this.writeLimiter = new RateLimiter(b.writeThrottleBytesPerSecond);
        b.activityTrackers.forEach(trackers::add);
        this.http2 = b.http2;
        this.http2Upstream = b.http2Upstream;
        this.http2Cleartext = b.http2Cleartext;
        this.http2Options = b.http2Options;
        this.frameInterceptor = b.frameInterceptor;
        this.tcpInterceptor = b.tcpInterceptor;
        this.udpInterceptor = b.udpInterceptor;
        this.quicInterceptor = b.quicInterceptor;
        this.connectUdpTemplate = b.http3 && b.reverseProxy == null
                ? ConnectUdpTemplate.parse(b.http3Options.connectUdpTemplate()) : null;
        // Created only when enabled: the class needs the codec.
        this.http2Origins = http2Upstream ? new Http2Origins(this) : null;
        this.http3 = b.http3;
        this.http3Options = b.http3Options;
        this.http3Keys = b.http3 ? http3Keys(b) : null;
        // Created only when enabled: the class needs the quic module.
        this.http3Origins = b.http3Upstream ? new Http3Origins(this, b.http3UpstreamHosts) : null;
        if (http2 && mitmManager == null && sslContextSource == null) {
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
            if (connectUdpTemplate != null && http3Options.connectUdpInterceptQuic()) {
                masqueQuic = new MasqueQuic(this, transparentQuicKeys(mitmManager));
            }
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
        LOG.log(Level.INFO, "{0} listening on {1}", name, boundAddress);
        return this;
    }

    private void acceptLoop() {
        while (!stopping.get()) {
            Socket socket;
            try {
                socket = serverSocket.accept();
            } catch (SocketException e) {
                if (!stopping.get()) LOG.log(Level.WARNING, "accept failed", e);
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
        LOG.log(Level.INFO, "{0} stopping ({1})", name, graceful ? "graceful" : "abort");
        Tls.closeQuietly(serverSocket);
        for (ClientConnection c : connections) {
            // Idle connections close now; busy ones finish what they are doing (HTTP/2 ones are
            // sent GOAWAY and finish their open streams), for up to the graceful stop timeout.
            if (graceful) {
                c.stopGracefully();
            } else {
                c.close();
            }
        }
        executor.shutdown();
        try {
            if (graceful && !executor.awaitTermination(GRACEFUL_STOP_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
                LOG.log(Level.WARNING, "connections still open after {0}; closing", GRACEFUL_STOP_TIMEOUT);
            }
            connections.forEach(ClientConnection::close);
            Http3Listener listener = http3Listener;
            if (listener != null) listener.close();
            TransparentQuicListener quicListener = transparentQuicListener;
            if (quicListener != null) quicListener.close();
            MasqueQuic masque = masqueQuic;
            if (masque != null) masque.close();
            if (http2Origins != null) http2Origins.closeAll();
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

    /** {@return number of open client connections (for tests and monitoring)} */
    public int getOpenConnectionCount() {
        return connections.size();
    }

    static InetAddress loopback() {
        return InetAddress.getLoopbackAddress();
    }
}
