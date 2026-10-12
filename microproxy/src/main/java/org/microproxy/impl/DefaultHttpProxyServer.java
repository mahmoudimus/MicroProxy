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
import org.microproxy.ChainedProxyManager;
import org.microproxy.FailureResponder;
import org.microproxy.HostResolver;
import org.microproxy.Http2Options;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpFiltersSource;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MitmManager;
import org.microproxy.PoolMetrics;
import org.microproxy.ProxyAuthenticator;
import org.microproxy.ReverseProxyMode;
import org.microproxy.SslContextSource;

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
    /** The fixed upstream in reverse proxy mode; null for a forward proxy. */
    final ReverseProxyMode reverseProxy;
    final boolean keepHostHeader;
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
    /** Whether HTTP/3 alternatives are removed from Alt-Svc response headers. */
    final boolean stripAltSvcH3;
    /** Whether intercepted TLS offers HTTP/2 (ALPN {@code h2}); the codec is known to be present. */
    final boolean http2;
    /** Whether TLS connections to servers offer HTTP/2; the codec is known to be present. */
    final boolean http2Upstream;
    /** Whether the plain listener serves HTTP/2 with prior knowledge; the codec is known to be present. */
    final boolean http2Cleartext;
    final Http2Options http2Options;
    /** The HTTP/2 connections to servers; null without {@link #http2Upstream}. */
    final Http2Origins http2Origins;
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
        this.config = b;
        this.name = b.name;
        this.transparent = b.transparent;
        this.transparentTlsPort = b.transparentTlsPort;
        this.hostRules = HostRules.of(b.ignoreHosts, b.allowHosts);
        this.reverseProxy = b.reverseProxy;
        this.keepHostHeader = b.keepHostHeader;
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
        this.tlsProtocols = b.tlsProtocols.isEmpty() ? null : b.tlsProtocols.toArray(String[]::new);
        this.backoffMaxNanos = b.chainedProxyBackoffMax == null ? 0 : b.chainedProxyBackoffMax.toNanos();
        this.readLimiter = new RateLimiter(b.readThrottleBytesPerSecond);
        this.writeLimiter = new RateLimiter(b.writeThrottleBytesPerSecond);
        b.activityTrackers.forEach(trackers::add);
        this.http2 = b.http2;
        this.http2Upstream = b.http2Upstream;
        this.http2Cleartext = b.http2Cleartext;
        this.http2Options = b.http2Options;
        // Created only when enabled: the class needs the codec.
        this.http2Origins = http2Upstream ? new Http2Origins(this) : null;
        if (http2 && mitmManager == null && sslContextSource == null) {
            LOG.log(Level.WARNING, "HTTP/2 is enabled but nothing is intercepted (no withManInTheMiddle / --mitm):"
                    + " clients are only offered HTTP/2 inside intercepted TLS sessions");
        }
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
            if (http2Origins != null) http2Origins.closeAll();
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
