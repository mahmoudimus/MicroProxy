package org.microproxy.impl;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.System.Logger.Level;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import org.microproxy.AuthResult;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyAdapter;
import org.microproxy.ChainedProxyType;
import org.microproxy.ClientDetails;
import org.microproxy.FlowContext;
import org.microproxy.FullFlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersAdapter;
import org.microproxy.HttpFiltersBuilder;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpFiltersSourceAdapter;
import org.microproxy.MitmManager;
import org.microproxy.ProxyFailure;
import org.microproxy.ResponseSource;
import org.microproxy.SelectiveFilters;
import org.microproxy.cache.HttpCache;
import org.microproxy.http.DefaultFullHttpRequest;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.FullHttpRequest;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpUtil;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.LastHttpContent;
import org.microproxy.http.WebSocketFrame;

/**
 * Serves one client connection on its own virtual thread.
 *
 * <p>Requests are handled one at a time: read the request head, run filters, connect (or reuse a
 * connection) to the server, stream the request body, stream the response back. HTTP/1.1
 * pipelining works naturally because unread pipelined requests simply wait in the socket buffer.
 * CONNECT turns the connection into a byte tunnel, or, with a {@link org.microproxy.MitmManager},
 * into a TLS session whose decrypted requests are served by the same loop.
 */
final class ClientConnection implements Runnable {

    private static final System.Logger LOG = System.getLogger(ClientConnection.class.getName());
    private static final AtomicLong IDS = new AtomicLong();
    /** How long to wait for a server's 100 (Continue) before sending the body anyway. */
    private static final int CONTINUE_TIMEOUT_MS = 1000;
    private static final HttpFilters NOOP = HttpFiltersAdapter.NOOP_FILTER;

    /** Whether a filters class overrides either WebSocket frame callback. */
    private static final ClassValue<Boolean> OBSERVES_FRAMES = new ClassValue<>() {
        @Override
        protected Boolean computeValue(Class<?> type) {
            try {
                return type.getMethod("webSocketFrameReceived", WebSocketFrame.class, boolean.class)
                                .getDeclaringClass() != HttpFilters.class
                        || type.getMethod("webSocketFrameReceived", Supplier.class, boolean.class)
                                .getDeclaringClass() != HttpFilters.class;
            } catch (NoSuchMethodException e) {
                return false;
            }
        }
    };

    /** Whether a filters class rewrites WebSocket frames. */
    private static final ClassValue<Boolean> REWRITES_FRAMES = new ClassValue<>() {
        @Override
        protected Boolean computeValue(Class<?> type) {
            try {
                return type.getMethod("filterWebSocketFrame", WebSocketFrame.class, boolean.class)
                        .getDeclaringClass() != HttpFilters.class;
            } catch (NoSuchMethodException e) {
                return false;
            }
        }
    };

    /** Whether a filters class sees response body pieces. */
    private static final ClassValue<Boolean> OBSERVES_RESPONSE_CONTENT = overrides(HttpFilters.class,
            "serverToProxyResponse", "proxyToClientResponse");
    /** Whether a filters class sees request body pieces. */
    private static final ClassValue<Boolean> OBSERVES_REQUEST_CONTENT = overrides(HttpFilters.class,
            "clientToProxyRequest", "proxyToServerRequest");
    /** Whether a chained proxy filters request body pieces. */
    private static final ClassValue<Boolean> FILTERS_REQUEST_CONTENT = overrides(ChainedProxy.class, "filterRequest");

    /**
     * Whether a MITM manager may set up server connections differently per client connection, so
     * that one client's server connection must not be handed to another.
     */
    private static final ClassValue<Boolean> SERVER_TLS_PER_CLIENT = new ClassValue<>() {
        @Override
        protected Boolean computeValue(Class<?> type) {
            try {
                return type.getMethod("serverSslContext", String.class, int.class, FlowContext.class)
                                .getDeclaringClass() != MitmManager.class
                        || type.getMethod("configureServerSocket", SSLSocket.class, FlowContext.class)
                                .getDeclaringClass() != MitmManager.class;
            } catch (NoSuchMethodException e) {
                return true;
            }
        }
    };

    private static ClassValue<Boolean> overrides(Class<?> base, String... methods) {
        return new ClassValue<>() {
            @Override
            protected Boolean computeValue(Class<?> type) {
                for (String method : methods) {
                    try {
                        if (type.getMethod(method, HttpObject.class).getDeclaringClass() != base) return true;
                    } catch (NoSuchMethodException e) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    /** Whether any of {@code filters} (looking inside chains) is of a class {@code observes} flags. */
    private static boolean observes(HttpFilters filters, ClassValue<Boolean> observes) {
        if (filters instanceof HttpFiltersChain.Chained chain) {
            return chain.members().stream().anyMatch(f -> observes(f, observes));
        }
        if (filters instanceof SelectiveFilters selective) {
            // The instance knows better than its class (one class for every combination of hooks).
            return selective.sees(observes == OBSERVES_REQUEST_CONTENT
                    ? HttpFiltersBuilder.Body.REQUEST : HttpFiltersBuilder.Body.RESPONSE);
        }
        return observes.get(filters.getClass());
    }

    private static boolean observesFrames(HttpFilters filters) {
        if (filters instanceof HttpFiltersChain.Chained chain) {
            return chain.members().stream().anyMatch(ClientConnection::observesFrames);
        }
        if (filters instanceof SelectiveFilters selective) {
            return selective.sees(HttpFiltersBuilder.Body.OBSERVED_WEBSOCKET_FRAMES);
        }
        return OBSERVES_FRAMES.get(filters.getClass());
    }

    private static boolean rewritesFrames(HttpFilters filters) {
        if (filters instanceof HttpFiltersChain.Chained chain) {
            return chain.members().stream().anyMatch(ClientConnection::rewritesFrames);
        }
        if (filters instanceof SelectiveFilters selective) {
            return selective.sees(HttpFiltersBuilder.Body.WEBSOCKET_FRAMES);
        }
        return REWRITES_FRAMES.get(filters.getClass());
    }

    /**
     * Which streams the proxy parses piece by piece for {@code filters}, as {request bodies,
     * response bodies, WebSocket frames}; the others take the fast path. For tests.
     */
    static boolean[] inspectedStreams(HttpFilters filters) {
        return new boolean[] {observes(filters, OBSERVES_REQUEST_CONTENT), observes(filters, OBSERVES_RESPONSE_CONTENT),
            observesFrames(filters) || rewritesFrames(filters)};
    }

    /** How a server connection is used. */
    enum Mode {
        /** HTTP requests forwarded as-is. */
        PLAIN,
        /** Raw bytes relayed for a CONNECT tunnel. */
        TUNNEL,
        /** TLS to the origin for man-in-the-middle interception. */
        TLS
    }

    /** Server I/O failed before the response could be completed. */
    private static final class ServerFailure extends IOException {
        ServerFailure(String message, Throwable cause) {
            super(message, cause);
        }

        /** What went wrong, for filters and trackers (which cannot see this class). */
        IOException reason() {
            return getCause() instanceof IOException io ? io : new IOException(getMessage(), getCause());
        }
    }

    /** A TLS handshake with the server or a chained proxy failed; the cause is the handshake's error. */
    private static final class TlsHandshakeFailed extends IOException {
        TlsHandshakeFailed(IOException cause) {
            super("TLS handshake failed: " + cause.getMessage(), cause);
        }
    }

    /** The exception a failed connection attempt really had, without the TLS marker. */
    private static IOException unwrap(IOException e) {
        return e instanceof TlsHandshakeFailed ? (IOException) e.getCause() : e;
    }

    /** A chained proxy's own host name did not resolve. */
    private static final class UnresolvedChainedProxy extends ConnectException {
        UnresolvedChainedProxy(InetSocketAddress proxy, UnknownHostException cause) {
            super("chained proxy " + proxy.getHostString() + ":" + proxy.getPort() + " did not resolve");
            initCause(cause);
        }
    }

    /** The server did not answer within the idle timeout. */
    private static final class ServerTimeout extends IOException {
        ServerTimeout(Throwable cause) {
            super("server timed out", cause);
        }
    }

    /** Writing the request body to the server failed; the server may still have answered. */
    private static final class ServerWriteFailure extends IOException {
        ServerWriteFailure(Throwable cause) {
            super("write to server failed", cause);
        }
    }

    /** A reused keep-alive connection turned out to be closed; the request can be retried. */
    private static final class StaleConnection extends IOException {
        StaleConnection(Throwable cause) {
            super("stale server connection", cause);
        }
    }

    /**
     * The server behind a CONNECT answered the proxy's TLS handshake with something other than
     * TLS (e.g. a plain HTTP or WebSocket server), so it cannot be intercepted.
     */
    private static final class NotTlsServer extends IOException {
        NotTlsServer(String hostAndPort, SSLException cause) {
            super(hostAndPort + " does not speak TLS", cause);
        }

        /** Whether a failed client handshake means the peer is not a TLS server at all. */
        static boolean isCause(SSLException e) {
            return Tls.looksLikePlaintextPeer(e);
        }
    }

    /** Client I/O failed; the client connection is unusable. */
    private static final class ClientFailure extends IOException {
        ClientFailure(Throwable cause) {
            super("client connection failed", cause);
        }
    }

    /** State of the request/response exchange in progress. */
    private static final class Exchange {
        HttpRequest request;
        /** The request-target as the client sent it, before any rewriting. */
        final String originalUri;
        final HttpVersion clientVersion;
        /** The request body, as the client sends it. */
        final MessageBody body;
        final boolean clientKeepAlive;
        HttpFilters filters = NOOP;
        boolean responseStarted;
        /** The request body will never be read (server answered before 100-continue). */
        boolean bodyAbandoned;
        /** The server side of the connection attempt in progress, once known. */
        FullFlowContext attempt;
        /** The response was written in full ({@link HttpFilters#proxyToClientResponseSent} called). */
        boolean completed;
        /** {@link HttpFilters#exchangeEnded} has been called. */
        boolean ended;
        /** The connect timeout for this exchange, once asked; -1 before. */
        int connectTimeoutMillis = -1;

        Exchange(HttpRequest request, MessageBody body, boolean clientKeepAlive) {
            this.request = request;
            this.originalUri = request.uri();
            this.clientVersion = request.protocolVersion();
            this.body = body;
            this.clientKeepAlive = clientKeepAlive;
        }

        boolean bodyUnread() {
            return !(request instanceof FullHttpRequest) && body.hasBody() && !body.isDone();
        }

        /** The server address resolved ahead of connecting (LittleProxy compatibility). */
        private String preResolvedFor;
        private InetSocketAddress preResolved;

        void preResolve(String hostAndPort, InetSocketAddress address) {
            preResolvedFor = hostAndPort;
            preResolved = address;
        }

        /** The address resolved ahead for {@code hostAndPort}, once; null if none. */
        InetSocketAddress takePreResolved(String hostAndPort) {
            InetSocketAddress address = hostAndPort.equals(preResolvedFor) ? preResolved : null;
            preResolved = null;
            preResolvedFor = null;
            return address;
        }
    }

    private final DefaultHttpProxyServer server;
    private final Socket rawSocket;
    private final long id = IDS.incrementAndGet();
    private final ClientDetails clientDetails = new ClientDetails();
    private final ClientFlowContext flowContext;
    /** Starts every log line about this connection: {@code [conn <id>] }. */
    private final String logPrefix = "[conn " + id + "] ";
    private final Map<String, ServerConnection> serverConnections = new ConcurrentHashMap<>();

    private volatile Socket socket;
    private volatile SSLSession sslSession;
    private volatile ProxyProtocol.Header proxyHeader;
    private volatile boolean idle = true;
    private volatile boolean closed;

    private ByteReader in;
    private OutputStream out;
    private HttpCodec.HttpWriter writer;
    private boolean authenticated;
    /** Whether a request has been accepted on this connection, and as whom. */
    private boolean accepted;
    private String acceptedUser;
    /** While serving intercepted (MITM) traffic: the CONNECT target all requests go to. */
    private String mitmHostAndPort;
    /** The MITM manager chosen for this connection ({@link MitmManager#forConnection}), once asked. */
    private MitmManager connectionMitm;
    private boolean mitmChosen;

    ClientConnection(DefaultHttpProxyServer server, Socket socket) {
        this.server = server;
        this.rawSocket = socket;
        this.socket = socket;
        this.flowContext = new ClientFlowContext(id, clientDetails::getClientAddress, () -> sslSession, clientDetails);
    }

    boolean isIdle() {
        return idle;
    }

    /** Closes the client connection and every server connection it owns. */
    void close() {
        closed = true;
        Tls.closeQuietly(socket);
        Tls.closeQuietly(rawSocket);
        releaseServerConnections();
    }

    /** Gives up this client's server connections: idle pooled ones go back to the pool. */
    private void releaseServerConnections() {
        for (ServerConnection c : List.copyOf(serverConnections.values())) {
            if (c.pool != null && !c.inExchange && c.isOpen()) {
                // An intercepted session's idle server connection outlives the client.
                serverConnections.remove(c.key, c);
                c.pool.release(c);
            } else {
                c.close();
            }
        }
    }

    @Override
    public void run() {
        boolean connectedFired = false;
        try {
            rawSocket.setTcpNoDelay(true);
            rawSocket.setSoTimeout(server.idleTimeoutMillis());
            clientDetails.setClientAddress((InetSocketAddress) rawSocket.getRemoteSocketAddress());
            attachClientStreams(rawSocket);
            if (server.acceptProxyProtocol) {
                proxyHeader = ProxyProtocol.read(in);
                if (proxyHeader.source() != null) {
                    clientDetails.setClientAddress(proxyHeader.source());
                }
            }
            server.trackers.fire(t -> t.clientConnected(flowContext));
            connectedFired = true;
            if (server.sslContextSource != null) {
                handshakeWithClient(server.sslContextSource.getSslContext(), rawSocket,
                        server.authenticateSslClients, s -> server.sslContextSource.configure(s, false), null);
            }
            serveRequests();
        } catch (SocketTimeoutException e) {
            LOG.log(Level.DEBUG, logPrefix + "client connection timed out");
            server.trackers.fire(t -> t.connectionTimedOut(flowContext));
        } catch (IOException e) {
            if (!closed) {
                if (e instanceof SSLException) {
                    // A failed handshake with the client has been logged by Tls already.
                    LOG.log(Level.DEBUG, logPrefix + "client connection failed: " + e);
                } else {
                    LOG.log(Level.DEBUG, logPrefix + "client connection failed", e);
                }
                server.trackers.fire(t -> t.connectionExceptionCaught(flowContext, e));
            }
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "unexpected error on client connection", e);
            server.trackers.fire(t -> t.connectionExceptionCaught(flowContext, e));
        } finally {
            close();
            if (connectedFired) {
                SSLSession session = sslSession;
                server.trackers.fire(t -> t.clientDisconnected(flowContext, session));
            }
            server.unregister(this);
        }
    }

    /**
     * Runs the TLS handshake with the client (the TLS listener's, or an intercepted session's).
     *
     * @param host the intercepted host, or null for the TLS listener
     */
    private void handshakeWithClient(SSLContext context, Socket plain, boolean needClientAuth,
            Consumer<SSLSocket> configurer, String host) throws IOException {
        server.trackers.fire(t -> t.clientSSLHandshakeStarted(flowContext));
        flowContext.clientTlsStarted();
        SSLSocket tls;
        try {
            tls = Tls.serverHandshake(context, plain, in.drainBuffered(), needClientAuth, server.tlsProtocols, configurer,
                    server.tlsHandshakeTimeout, new TlsLog.Peer(logPrefix, "client", host));
        } catch (IOException e) {
            server.trackers.fire(t -> t.tlsHandshakeFailed(flowContext, true, e));
            throw e;
        }
        flowContext.clientTlsFinished();
        sslSession = tls.getSession();
        attachClientStreams(tls);
        SSLSession session = sslSession;
        server.trackers.fire(t -> t.clientSSLHandshakeSucceeded(flowContext, session));
    }

    private void attachClientStreams(Socket s) throws IOException {
        socket = s;
        InputStream is = s.getInputStream();
        OutputStream os = s.getOutputStream();
        if (!server.trackers.isEmpty()) {
            is = CountingStreams.counting(is, n -> server.trackers.fire(t -> t.bytesReceivedFromClient(flowContext, n)));
            os = CountingStreams.counting(os, n -> server.trackers.fire(t -> t.bytesSentToClient(flowContext, n)));
        }
        in = new ByteReader(is, server.ioBuffers).strictLineEndings();
        out = new PooledOutputStream(os, server.ioBuffers);
        writer = new HttpCodec.HttpWriter(out);
    }

    /** Reads and handles requests until the connection should close. */
    private void serveRequests() throws IOException {
        while (!closed) {
            idle = true;
            if (server.isStopping()) {
                return;
            }
            HttpRequest request;
            try {
                // Wait for the next request without holding a buffer: idle connections are cheap.
                in.awaitNext();
                if (in.buffered() > 0) {
                    flowContext.startExchange();
                }
                request = HttpCodec.readRequest(in, server.limits);
            } catch (HttpParseException e) {
                if (LOG.isLoggable(Level.DEBUG)) {
                    LOG.log(Level.DEBUG, logPrefix + "bad request from client: " + e.getMessage());
                }
                writeErrorAndClose(e.status());
                return;
            }
            if (request == null) {
                return;
            }
            idle = false;
            if (!handleRequest(request)) {
                return;
            }
        }
    }

    /** Handles one request. Returns whether the client connection stays open. */
    private boolean handleRequest(HttpRequest request) throws IOException {
        if (!server.trackers.isEmpty()) {
            // Trackers get a snapshot: the request itself is rewritten while it is proxied.
            HttpRequest snapshot = copy(request);
            server.trackers.fire(t -> t.requestReceivedFromClient(flowContext, snapshot));
        }
        Framing framing;
        try {
            framing = Framing.forRequest(request);
        } catch (HttpParseException e) {
            writeErrorAndClose(e.status());
            return false;
        }
        Exchange ex = new Exchange(
                request, new HttpCodec.BodyReader(in, framing, server.limits),
                ProxyUtils.isClientKeepAlive(request));

        if (server.proxyAuthenticator != null) {
            // Requests in an intercepted session are covered by the CONNECT that started it.
            if (mitmHostAndPort == null && (!authenticated || server.proxyAuthenticator.authenticateEveryRequest())) {
                HttpResponse refusal = authenticate(request);
                if (refusal != null) {
                    return respondDirect(ex, refusal, false, ResponseSource.PROXY);
                }
            }
            // The credentials were for this proxy, whatever their scheme: never forward them.
            request.headers().remove(HttpHeaderNames.PROXY_AUTHORIZATION);
        }

        // With no filters configured, skip the request copy the filters API hands them.
        HttpFilters filters = NOOP;
        if (server.filtersSource.getClass() != HttpFiltersSourceAdapter.class) {
            HttpRequest original = copy(request);
            filters = server.filtersSource.filterRequest(original, flowContext);
            // Built filters that a source (such as a lambda) returned as they are still get the
            // per-exchange state their logger needs; bound ones return themselves.
            if (filters instanceof HttpFiltersBuilder.Built built) filters = built.filterRequest(original, flowContext);
        }
        ex.filters = filters != null ? filters : NOOP;
        try {
            return handleFilteredRequest(ex);
        } finally {
            endExchange(ex);
        }
    }

    /** Tells the filters, once, that {@code ex} is over (see {@link HttpFilters#exchangeEnded}). */
    private void endExchange(Exchange ex) {
        if (ex.ended) return;
        ex.ended = true;
        try {
            ex.filters.exchangeEnded(ex.completed);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "exchangeEnded threw", e);
        }
    }

    /** Handles a request whose filters have been created. Returns whether the client connection stays open. */
    private boolean handleFilteredRequest(Exchange ex) throws IOException {
        HttpRequest request = ex.request;
        int maxBuffer = server.filtersSource.getMaximumRequestBufferSizeInBytes();
        if (maxBuffer <= 0 && !ProxyUtils.isCONNECT(request)) {
            maxBuffer = ex.filters.requestBufferSizeInBytes(request);
        }
        if (maxBuffer > 0 && !ProxyUtils.isCONNECT(request)) {
            FullHttpRequest full = aggregateRequest(ex, maxBuffer);
            if (full == null) {
                return false;
            }
            ex.request = full;
        }

        HttpResponse shortCircuit = ex.filters.clientToProxyRequest(ex.request);
        if (shortCircuit != null) {
            return respondDirect(ex, shortCircuit, true, ResponseSource.FILTER);
        }

        if (ProxyUtils.isCONNECT(ex.request)) {
            return handleConnect(ex);
        }

        if (mitmHostAndPort == null
                && !server.allowRequestsToOriginServer
                && !ProxyUtils.isAbsoluteUri(ex.request.uri())) {
            // An origin-form request means the client thinks we are the origin; refusing avoids
            // proxying to ourselves in a loop.
            return respondFailure(ex, new ProxyFailure.BadRequest("the proxy needs an absolute URI"), true);
        }

        String hostAndPort = mitmHostAndPort != null ? mitmHostAndPort : identifyHostAndPort(ex.request);
        if (hostAndPort == null) {
            return respondFailure(ex, new ProxyFailure.NoRoute(null), false);
        }
        return proxyRequest(ex, hostAndPort);
    }

    // ---------------------------------------------------------------------------------------
    // Plain HTTP requests
    // ---------------------------------------------------------------------------------------

    private boolean proxyRequest(Exchange ex, String hostAndPort) throws IOException {
        Mode mode = mitmHostAndPort != null ? Mode.TLS : Mode.PLAIN;
        String key = mode + "|" + hostAndPort;
        boolean webSocket = ProxyUtils.isSwitchingToWebSocketProtocol(ex.request);
        boolean pooled = !webSocket && usesPool(mode);
        // Per-request leases always come fresh from the pool; otherwise reuse this client's own.
        ServerConnection conn = pooled && leasesPerRequest(mode) ? null : serverConnections.get(key);
        if (conn != null && !conn.isOpen()) {
            serverConnections.remove(key, conn);
            conn = null;
        }
        List<ChainedProxy> route = null;
        boolean nextHopOrigin;
        if (conn != null) {
            nextHopOrigin = conn.nextHopIsOrigin();
        } else {
            route = lookupRoute(ex.request);
            if (route == null) {
                return respondFailure(ex, new ProxyFailure.NoRoute(hostAndPort), false);
            }
            nextHopOrigin = isNextHopOrigin(route.getFirst(), mode);
        }

        modifyRequestHeadersToReflectProxying(ex.request, nextHopOrigin, webSocket);
        if (webSocket && rewritesFrames(ex.filters)) {
            // Compressed (permessage-deflate) payloads could not be rewritten.
            ex.request.headers().remove(HttpHeaderNames.SEC_WEBSOCKET_EXTENSIONS);
        }

        if (server.littleProxyCompatibility && conn == null
                && route.getFirst() == ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION) {
            // LittleProxy resolves the server before proxyToServerRequest, and answers 502 without
            // calling it when the name does not resolve.
            try {
                ex.preResolve(hostAndPort, resolveServer(hostAndPort, ex.filters));
            } catch (UnknownHostException e) {
                reportServerFailure(new FullFlowContext(flowContext, hostAndPort, null, null), e);
                return respondFailure(ex, new ProxyFailure.UnresolvedHost(hostAndPort, e), false);
            }
        }

        HttpResponse shortCircuit = ex.filters.proxyToServerRequest(ex.request);
        if (shortCircuit != null) {
            return respondDirect(ex, shortCircuit, true, ResponseSource.FILTER);
        }

        boolean replayable = ex.request instanceof FullHttpRequest || !ex.body.hasBody();
        for (int attempt = 0; ; attempt++) {
            if (conn == null) {
                if (route == null) {
                    route = lookupRoute(ex.request);
                    if (route == null) {
                        return respondFailure(ex, new ProxyFailure.NoRoute(hostAndPort), false);
                    }
                }
                try {
                    conn = pooled ? lease(hostAndPort, ex, route, mode) : connect(hostAndPort, ex, route, mode);
                } catch (SharedConnectionPool.PoolExhaustedException e) {
                    LOG.log(Level.DEBUG, logPrefix + e.getMessage());
                    return respondFailure(ex, new ProxyFailure.NoConnectionAvailable(hostAndPort), false);
                } catch (ClientFailure e) {
                    LOG.log(Level.DEBUG, logPrefix + "client left before " + hostAndPort + " could be reached: "
                            + e.getCause());
                    close();
                    return false;
                } catch (IOException e) {
                    LOG.log(Level.DEBUG, logPrefix + "unable to connect to " + hostAndPort + ": " + unwrap(e));
                    return respondFailure(ex, connectFailure(hostAndPort, e), false);
                }
                conn.key = key;
                serverConnections.put(key, conn);
                if (conn.nextHopIsOrigin() != nextHopOrigin) {
                    nextHopOrigin = conn.nextHopIsOrigin();
                    adjustUriForNextHop(ex.request, hostAndPort, nextHopOrigin);
                }
            }
            try {
                // Reused connections may have been closed by the server while idle: retry those
                // (a few times, since a pool can hold several stale ones).
                return exchange(ex, conn, attempt < 3 && conn.used && replayable);
            } catch (StaleConnection e) {
                LOG.log(Level.DEBUG, logPrefix + "retrying on a new connection after stale " + conn);
                conn.close();
                conn = null;
                route = null;
            }
        }
    }

    /** Sends the request on {@code conn} and relays the response. */
    private boolean exchange(Exchange ex, ServerConnection conn, boolean retryAllowed) throws IOException {
        HttpRequest request = ex.request;
        HttpFilters filters = ex.filters;
        ChainedProxy chainedProxy = conn.chainedProxy;
        if (!conn.nextHopIsOrigin()) {
            addUpstreamProxyAuthorization(request.headers(), chainedProxy);
        }
        if (chainedProxy != null) {
            chainedProxy.filterRequest(request);
        }
        boolean streamingBody = !(request instanceof FullHttpRequest) && ex.body.hasBody();
        conn.inExchange = true;
        try {
            filters.proxyToServerRequestSending();
            stripRequestHeaders(request.headers());
            try {
                conn.writer.writeHead(request, true);
            } catch (IOException e) {
                if (retryAllowed) throw new StaleConnection(e);
                throw new ServerFailure("write to server failed", e);
            }
            conn.used = true;
            if (!streamingBody) {
                flowContext.mark(ClientFlowContext.REQUEST_SENT);
            }
            server.trackers.fire(t -> t.requestSentToServer(conn.flowContext, request));

            HttpResponse response = null;
            if (streamingBody) {
                HttpResponse early = null;
                if (HttpUtil.is100ContinueExpected(request)) {
                    // Let the server decide whether it wants the body before reading it from the
                    // client, which is waiting for a 100 (Continue). Servers that ignore Expect
                    // never answer, so after a short wait the proxy continues on their behalf.
                    early = awaitServerData(conn, CONTINUE_TIMEOUT_MS) ? readResponseHead(ex, conn, true, false) : null;
                    if (early == null || early.status().code() == 100) {
                        writeToClient(() -> writer.writeHead(
                                new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.CONTINUE), false));
                        early = null;
                    }
                }
                if (early == null) {
                    try {
                        pumpRequestBody(ex, conn);
                        flowContext.mark(ClientFlowContext.REQUEST_SENT);
                    } catch (ServerWriteFailure e) {
                        // The server may have answered early (e.g. 413) and stopped reading.
                        LOG.log(Level.DEBUG, logPrefix + "server stopped reading the request body", e);
                        early = readResponseHead(ex, conn, false, false);
                    }
                }
                if (early != null) {
                    response = early;
                    ex.bodyAbandoned = true;
                }
            }
            if (!streamingBody && !(request instanceof FullHttpRequest) && observes(filters, OBSERVES_REQUEST_CONTENT)) {
                // Filters see every streamed request end with a LastHttpContent, even without a body.
                HttpContent end = LastHttpContent.empty();
                filters.clientToProxyRequest(end);
                filters.proxyToServerRequest(end);
            }
            if (response == null) {
                filters.proxyToServerRequestSent();
                response = readResponseHead(ex, conn, false, retryAllowed);
            }
            return relayResponse(ex, conn, response);
        } catch (ServerTimeout e) {
            filters.serverToProxyResponseTimedOut();
            conn.close();
            IOException cause = (IOException) e.getCause();
            reportServerFailure(conn.flowContext, cause);
            if (ex.responseStarted) {
                close();
                return false;
            }
            return respondFailure(ex, new ProxyFailure.ServerTimeout(conn.hostAndPort, cause), false);
        } catch (ServerFailure e) {
            LOG.log(Level.DEBUG, logPrefix + "server failure on " + conn, e);
            conn.close();
            IOException reason = e.reason();
            reportServerFailure(conn.flowContext, reason);
            if (ex.responseStarted) {
                close();
                return false;
            }
            return respondFailure(ex, new ProxyFailure.BadServerResponse(conn.hostAndPort, reason), false);
        } catch (RuntimeException e) {
            // A bug, in a filter or the proxy: the server connection's state is unknown. The client
            // connection is closed (and the error logged) by run().
            conn.close();
            reportServerFailure(conn.flowContext, e);
            throw e;
        } catch (ClientFailure e) {
            LOG.log(Level.DEBUG, logPrefix + "client failure", e);
            conn.close();
            if (e.getCause() instanceof HttpParseException bad && !ex.responseStarted) {
                // A malformed request body (bad chunk framing): tell the client before closing.
                writeErrorAndClose(bad.status());
                return false;
            }
            close();
            return false;
        }
    }

    private void pumpRequestBody(Exchange ex, ServerConnection conn) throws IOException {
        if (!observes(ex.filters, OBSERVES_REQUEST_CONTENT)
                && (conn.chainedProxy == null || !FILTERS_REQUEST_CONTENT.get(conn.chainedProxy.getClass()))) {
            relayRequestBody(ex, conn);
            return;
        }
        while (true) {
            HttpContent content;
            try {
                content = ex.body.next();
            } catch (IOException e) {
                throw new ClientFailure(e);
            }
            if (content == null) {
                return;
            }
            ex.filters.clientToProxyRequest(content);
            ex.filters.proxyToServerRequest(content);
            if (conn.chainedProxy != null) {
                conn.chainedProxy.filterRequest(content);
            }
            try {
                conn.writer.writeContent(content);
            } catch (IOException e) {
                throw new ServerWriteFailure(e);
            }
        }
    }

    /** Waits up to {@code millis} for the server to send something; false on timeout. */
    private static boolean awaitServerData(ServerConnection conn, int millis) throws IOException {
        int original = conn.socket.getSoTimeout();
        conn.socket.setSoTimeout(original > 0 ? Math.min(original, millis) : millis);
        try {
            return conn.in.awaitData();
        } catch (IOException e) {
            throw new ServerFailure("read from server failed", e);
        } finally {
            conn.socket.setSoTimeout(original);
        }
    }

    /**
     * Reads the next final response head, forwarding interim (1xx) responses to the client.
     *
     * @param stopAtContinue return a 100 (Continue) instead of forwarding it
     */
    private HttpResponse readResponseHead(
            Exchange ex, ServerConnection conn, boolean stopAtContinue, boolean retryAllowed)
            throws IOException {
        while (true) {
            HttpResponse response;
            try {
                conn.in.awaitNext();
                if (conn.in.buffered() > 0) {
                    flowContext.markFirst(ClientFlowContext.FIRST_RESPONSE_BYTE);
                }
                response = HttpCodec.readResponse(conn.in, server.limits);
            } catch (SocketTimeoutException e) {
                throw new ServerTimeout(e);
            } catch (HttpParseException e) {
                throw new ServerFailure("malformed response", e);
            } catch (IOException e) {
                if (retryAllowed) throw new StaleConnection(e);
                throw new ServerFailure("read from server failed", e);
            }
            if (response == null) {
                IOException eof = new EOFException("server closed connection");
                if (retryAllowed) throw new StaleConnection(eof);
                throw new ServerFailure("server closed connection", eof);
            }
            int code = response.status().code();
            if (code == 100 && stopAtContinue) {
                return response;
            }
            if (code >= 100 && code < 200 && code != 101) {
                if (ex.clientVersion.isKeepAliveDefault()) {
                    writeToClient(() -> writer.writeHead(response, false));
                }
                continue;
            }
            return response;
        }
    }

    /** Relays a response (head and body) from the server to the client. */
    private boolean relayResponse(Exchange ex, ServerConnection conn, HttpResponse response) throws IOException {
        HttpFilters filters = ex.filters;
        HttpRequest request = ex.request;
        filters.serverToProxyResponseReceiving();
        int upstreamStatus = response.status().code();
        flowContext.upstreamStatus(upstreamStatus);
        server.trackers.fire(t -> t.responseReceivedFromServer(conn.flowContext, response));

        Framing framing;
        try {
            framing = Framing.forResponse(response, request.method());
        } catch (HttpParseException e) {
            throw new ServerFailure("malformed response framing", e);
        }
        boolean serverKeepAlive = HttpUtil.isKeepAlive(response)
                && framing.kind() != Framing.Kind.UNTIL_CLOSE && !ex.bodyAbandoned;
        boolean switching = response.status().code() == 101;
        String upgrade = response.headers().get(HttpHeaderNames.UPGRADE);

        HttpCodec.BodyReader body = switching ? null : new HttpCodec.BodyReader(conn.in, framing, server.limits);
        HttpObject head = response;
        ArrayDeque<HttpContent> prefetched = new ArrayDeque<>();
        int maxBuffer = server.filtersSource.getMaximumResponseBufferSizeInBytes();
        if (maxBuffer > 0 && !switching) {
            head = aggregateResponse(response, framing, body, maxBuffer, request.method(), null);
            body = null;
        } else if (!switching) {
            int filterBuffer = filters.responseBufferSizeInBytes(response);
            if (filterBuffer > 0) {
                // Buffer on the filter's request; if the body is larger, stream it after all.
                FullHttpResponse full = aggregateResponse(response, framing, body, filterBuffer, request.method(),
                        prefetched);
                if (full != null) {
                    head = full;
                    body = null;
                }
            }
        }

        HttpObject filtered = filters.serverToProxyResponse(head);
        if (!(filtered instanceof HttpResponse res)) {
            return abort(conn);
        }
        if (filtered instanceof FullHttpMessage && body != null) {
            // The filter replaced a streamed response with a complete one: discard the original body.
            serverKeepAlive &= drain(body);
            body = null;
        }

        boolean bodyAllowed = Framing.responseMayHaveBody(res, request.method());
        boolean closeClient = !ex.clientKeepAlive || ex.bodyAbandoned;
        boolean clientSupportsChunked = ex.clientVersion.isKeepAliveDefault();
        if (bodyAllowed && !switching && !(res instanceof FullHttpMessage)) {
            if (!ProxyUtils.isResponseSelfTerminating(res)) {
                // The server ends the body by closing. Re-chunk so the client connection survives.
                if (clientSupportsChunked) {
                    HttpUtil.setTransferEncodingChunked(res, true);
                } else {
                    closeClient = true;
                }
            } else if (!clientSupportsChunked && HttpUtil.isTransferEncodingChunked(res)) {
                // HTTP/1.0 clients cannot parse chunked bodies: de-chunk and delimit by closing.
                HttpUtil.setTransferEncodingChunked(res, false);
                closeClient = true;
            }
        }
        if (HttpUtil.isTransferEncodingChunked(res) && !res.protocolVersion().isKeepAliveDefault()) {
            res.setProtocolVersion(HttpVersion.HTTP_1_1);
        }
        if (!server.transparent) {
            modifyResponseHeadersToReflectProxying(res);
        }
        if (server.stripAltSvcH3) {
            AltSvc.stripHttp3(res.headers());
        }
        if (switching) {
            if (upgrade != null) res.headers().set(HttpHeaderNames.UPGRADE, upgrade);
            res.headers().set(HttpHeaderNames.CONNECTION, "Upgrade");
        } else {
            HttpUtil.setKeepAlive(res, !closeClient);
        }

        HttpObject toClient = filters.proxyToClientResponse(res);
        if (!(toClient instanceof HttpResponse finalResponse)) {
            return abort(conn);
        }
        if (finalResponse instanceof FullHttpMessage && body != null) {
            // Replaced by a complete response here too: the server's body must not follow it.
            serverKeepAlive &= drain(body);
            body = null;
        }
        ex.responseStarted = true;
        boolean writeBody = Framing.responseMayHaveBody(finalResponse, request.method());
        writeToClient(() -> writer.writeHead(finalResponse, writeBody));
        ResponseSource source = source(ResponseSource.SERVER, head, upstreamStatus, finalResponse);
        server.trackers.fire(t -> t.responseSentToClient(flowContext, finalResponse, source));

        if (body != null && prefetched.isEmpty() && !observes(filters, OBSERVES_RESPONSE_CONTENT)) {
            relayResponseBody(body);
        } else if (body != null) {
            boolean lastWritten = false;
            while (true) {
                HttpContent content;
                try {
                    content = prefetched.isEmpty() ? body.next() : prefetched.poll();
                } catch (IOException e) {
                    throw new ServerFailure("reading response body failed", e);
                }
                if (content == null) {
                    break;
                }
                HttpObject o = filters.serverToProxyResponse(content);
                if (o != null) {
                    o = filters.proxyToClientResponse(o);
                }
                if (o == null) {
                    return abort(conn);
                }
                if (o instanceof HttpContent piece && !lastWritten) {
                    writeToClient(() -> writer.writeContent(piece));
                    lastWritten = piece instanceof LastHttpContent;
                }
            }
            if (!lastWritten) {
                writeToClient(() -> writer.writeContent(LastHttpContent.empty()));
            }
        }
        filters.serverToProxyResponseReceived();
        completed(ex, finalResponse, source);

        if (switching) {
            boolean webSocket = upgrade != null && HttpHeaders.splitList(upgrade).stream()
                    .anyMatch(token -> token.equalsIgnoreCase("websocket"));
            // Parsing buffers each frame before forwarding it, so only do it for filters that listen.
            boolean observe = webSocket && observesFrames(filters);
            boolean rewrite = webSocket && rewritesFrames(filters);
            Tunnel.FrameHandler handler = !observe && !rewrite ? null : (frame, fromClient) -> {
                if (observe) filters.webSocketFrameReceived(frame, fromClient);
                return rewrite ? filters.filterWebSocketFrame(frame, fromClient) : frame;
            };
            Tunnel.relay(socket, in.asInputStream(), out, conn.socket, conn.in.asInputStream(), conn.out,
                    server.getIdleConnectionTimeout(), server.name + "-upgrade-" + id, logPrefix,
                    handler, server.maxWebSocketFrameBufferSize, server.ioBuffers);
            conn.close();
            return false;
        }
        if (!serverKeepAlive) {
            conn.close();
        } else {
            conn.in.release();
            conn.inExchange = false;
            if (conn.perRequestLease) {
                serverConnections.remove(conn.key, conn);
                conn.pool.release(conn);
            }
        }
        if (closeClient) {
            close();
            return false;
        }
        return true;
    }

    /** The response to the current request has been written in full. */
    private void completed(Exchange ex, HttpResponse response, ResponseSource source) {
        ex.completed = true;
        flowContext.mark(ClientFlowContext.RESPONSE_COMPLETE);
        server.trackers.fire(t -> t.responseCompleted(flowContext, response));
        ex.filters.proxyToClientResponseSent(response, source);
    }

    private boolean abort(ServerConnection conn) {
        conn.close();
        close();
        return false;
    }

    private static boolean drain(HttpCodec.BodyReader body) {
        try {
            while (body.next() != null) {
                // discard
            }
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    @FunctionalInterface
    private interface ClientWrite {
        void run() throws IOException;
    }

    /** Copies a response body straight from the server to the client: no filter needs its pieces. */
    private void relayResponseBody(HttpCodec.BodyReader body) throws IOException {
        byte[] buf = server.relayBuffers.take();
        try {
            relayResponseBody(body, buf);
        } finally {
            server.relayBuffers.give(buf);
        }
    }

    private void relayResponseBody(HttpCodec.BodyReader body, byte[] buf) throws IOException {
        while (true) {
            int n;
            try {
                n = body.read(buf, 0, buf.length);
            } catch (IOException e) {
                throw new ServerFailure("reading response body failed", e);
            }
            if (n < 0) break;
            boolean flush = !body.hasBufferedInput();
            writeToClient(() -> {
                writer.writeData(buf, 0, n);
                if (flush) writer.flush();
            });
        }
        HttpHeaders trailers = body.trailers();
        writeToClient(() -> writer.writeEnd(trailers));
    }

    /** Copies a request body straight from the client to the server. */
    private void relayRequestBody(Exchange ex, ServerConnection conn) throws IOException {
        byte[] buf = server.relayBuffers.take();
        try {
            relayRequestBody(ex, conn, buf);
        } finally {
            server.relayBuffers.give(buf);
        }
    }

    private void relayRequestBody(Exchange ex, ServerConnection conn, byte[] buf) throws IOException {
        while (true) {
            int n;
            try {
                n = ex.body.read(buf, 0, buf.length);
            } catch (IOException e) {
                throw new ClientFailure(e);
            }
            if (n < 0) break;
            try {
                conn.writer.writeData(buf, 0, n);
                if (!ex.body.hasBufferedInput()) conn.writer.flush();
            } catch (IOException e) {
                throw new ServerWriteFailure(e);
            }
        }
        try {
            conn.writer.writeEnd(ex.body.trailers());
        } catch (IOException e) {
            throw new ServerWriteFailure(e);
        }
    }

    private static void writeToClient(ClientWrite write) throws ClientFailure {
        try {
            write.run();
        } catch (IOException e) {
            throw new ClientFailure(e);
        }
    }

    // ---------------------------------------------------------------------------------------
    // CONNECT
    // ---------------------------------------------------------------------------------------

    private boolean handleConnect(Exchange ex) throws IOException {
        HttpRequest request = ex.request;
        HostAndPort target;
        try {
            target = HostAndPort.parse(request.uri(), 443);
        } catch (IllegalArgumentException e) {
            return respondFailure(ex, new ProxyFailure.BadRequest("invalid CONNECT target"), false);
        }
        String hostAndPort = target.toString();
        boolean mitm = server.mitmManager != null && mitmHostAndPort == null && ex.filters.proxyToServerAllowMitm()
                && mitmManager() != null;
        Mode mode = mitm ? Mode.TLS : Mode.TUNNEL;

        List<ChainedProxy> route = lookupRoute(request);
        if (route == null) {
            return respondFailure(ex, new ProxyFailure.NoRoute(hostAndPort), false);
        }
        modifyRequestHeadersToReflectProxying(request, false, false);
        HttpResponse shortCircuit = ex.filters.proxyToServerRequest(request);
        if (shortCircuit != null) {
            return respondDirect(ex, shortCircuit, true, ResponseSource.FILTER);
        }

        ServerConnection conn = null;
        try {
            try {
                conn = usesPool(mode) ? lease(hostAndPort, ex, route, mode) : connect(hostAndPort, ex, route, mode);
            } catch (NotTlsServer e) {
                // As LittleProxy does (issue #71, e.g. ws:// through CONNECT): the client has not been
                // answered yet, so it can still get a plain tunnel to the server instead of a 502.
                LOG.log(Level.DEBUG, logPrefix + e.getMessage() + "; tunnelling instead of intercepting");
                mitm = false;
                mode = Mode.TUNNEL;
                conn = connect(hostAndPort, ex, route, mode);
            }
        } catch (SharedConnectionPool.PoolExhaustedException e) {
            LOG.log(Level.DEBUG, logPrefix + e.getMessage());
            return respondFailure(ex, new ProxyFailure.NoConnectionAvailable(hostAndPort), false);
        } catch (ClientFailure e) {
            LOG.log(Level.DEBUG, logPrefix + "client left before " + hostAndPort + " could be reached: " + e.getCause());
            close();
            return false;
        } catch (IOException e) {
            LOG.log(Level.DEBUG, logPrefix + "CONNECT to " + hostAndPort + " failed: " + unwrap(e));
            if (!mitm || !ex.filters.proxyToServerAllowOfflineMitm()) {
                return respondFailure(ex, connectFailure(hostAndPort, e), false);
            }
            LOG.log(Level.DEBUG, logPrefix + "intercepting " + hostAndPort + " without a server connection");
        }
        if (conn != null) {
            conn.key = mode + "|" + hostAndPort;
            serverConnections.put(conn.key, conn);
        }

        HttpResponse established =
                new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, new HttpResponseStatus(200, "Connection established"));
        if (!server.transparent) {
            ProxyUtils.addVia(established, server.proxyAlias);
        }
        HttpObject o = ex.filters.serverToProxyResponse(established);
        if (o != null) {
            o = ex.filters.proxyToClientResponse(o);
        }
        if (!(o instanceof HttpResponse response)) {
            if (conn == null) {
                close();
                return false;
            }
            return abort(conn);
        }
        writeToClient(() -> writer.writeHead(response, response.status().code() / 100 != 2));
        ResponseSource source = source(ResponseSource.PROXY, established, 200, response);
        server.trackers.fire(t -> t.responseSentToClient(flowContext, response, source));
        completed(ex, response, source);
        if (response.status().code() / 100 != 2) {
            // A filter turned the CONNECT into a failure.
            if (conn != null) conn.close();
            if (!(HttpUtil.isKeepAlive(response) && ex.clientKeepAlive)) {
                close();
                return false;
            }
            return true;
        }

        if (!mitm) {
            Tunnel.relay(socket, in.asInputStream(), out, conn.socket, conn.in.asInputStream(), conn.out,
                    server.getIdleConnectionTimeout(), server.name + "-tunnel-" + id, logPrefix, server.ioBuffers);
            conn.close();
            return false;
        }

        SSLSession serverSession = conn == null ? null : ((SSLSocket) conn.socket).getSession();
        SSLContext clientContext = connectionMitm.clientSslContextFor(request, serverSession, flowContext);
        handshakeWithClient(clientContext, socket, false, null, target.host());

        mitmHostAndPort = hostAndPort;
        if (conn != null && conn.perRequestLease) {
            // Each intercepted request leases its own connection; start with this one.
            serverConnections.remove(conn.key, conn);
            conn.pool.release(conn);
        }
        // The CONNECT exchange is over; the requests inside the session are exchanges of their own.
        endExchange(ex);
        serveRequests();
        return false;
    }

    // ---------------------------------------------------------------------------------------
    // Connecting to servers
    // ---------------------------------------------------------------------------------------

    /** The MITM manager for this connection, chosen when first needed; null if it declined. */
    private MitmManager mitmManager() {
        if (!mitmChosen) {
            connectionMitm = server.mitmManager.forConnection(flowContext);
            mitmChosen = true;
        }
        return connectionMitm;
    }

    /** Whether server connections for {@code mode} come from the shared pool. */
    private boolean usesPool(Mode mode) {
        // A PROXY header names one client, so connections that carry it are never shared; nor are
        // TLS connections set up by a manager that may decide differently for each client.
        return server.pool != null && !server.sendProxyProtocol
                && (mode == Mode.PLAIN || (mode == Mode.TLS && server.poolSharedMitmConnections
                        && !SERVER_TLS_PER_CLIENT.get(connectionMitm.getClass())));
    }

    /**
     * The pool key part that keeps TLS connections made with a manager chosen for this connection
     * away from clients given another manager.
     */
    private String mitmPoolKey(Mode mode) {
        return mode == Mode.TLS && connectionMitm != server.mitmManager
                ? "|mitm" + server.mitmManagerId(connectionMitm) : "";
    }

    /** Whether pooled connections for {@code mode} are returned after every request. */
    private boolean leasesPerRequest(Mode mode) {
        return mode == Mode.PLAIN || server.poolPerRequestInMitm;
    }

    /**
     * Leases a server connection from the shared pool, creating one (counted against the pool's
     * limits) when no idle connection exists for this target and route.
     */
    private ServerConnection lease(String hostAndPort, Exchange ex, List<ChainedProxy> route, Mode mode)
            throws IOException {
        String hostKey = mode + "|" + hostAndPort;
        String managerKey = mitmPoolKey(mode);
        ServerConnection conn = server.pool.acquire(hostKey + "|" + routeKey(route.getFirst()) + managerKey, hostKey,
                Math.max(1000, server.getConnectTimeout()));
        if (conn != null) {
            if (LOG.isLoggable(Level.DEBUG)) {
                LOG.log(Level.DEBUG, logPrefix + "reusing pooled " + conn);
            }
            conn.flowContext = new FullFlowContext(flowContext, hostAndPort, conn.chainedProxy, conn.remoteAddress);
        } else {
            try {
                conn = connect(hostAndPort, ex, route, mode);
            } catch (IOException | RuntimeException e) {
                server.pool.cancel(hostKey);
                throw e;
            }
            ChainedProxy actual = conn.chainedProxy == null
                    ? ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION : conn.chainedProxy;
            server.pool.register(conn, hostKey + "|" + routeKey(actual) + managerKey, hostKey);
        }
        ServerConnection leased = conn;
        leased.onDetach = () -> serverConnections.remove(leased.key, leased);
        leased.perRequestLease = leasesPerRequest(mode);
        return leased;
    }

    /** Identifies the route (direct, or which chained proxy) part of a pool key. */
    private static String routeKey(ChainedProxy proxy) {
        if (proxy == ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION) {
            return "direct";
        }
        InetSocketAddress address = proxy.getChainedProxyAddress();
        String host = address == null ? "?" : address.getAddress() != null
                ? address.getAddress().getHostAddress() : address.getHostString();
        return proxy.getChainedProxyType() + ":" + host + ":" + (address == null ? 0 : address.getPort())
                + (proxy.requiresEncryption() ? ":tls" : "");
    }

    /**
     * The chained proxies to try in order, with {@link ChainedProxyAdapter#FALLBACK_TO_DIRECT_CONNECTION}
     * meaning a direct connection; {@code null} if the manager offered none.
     */
    private List<ChainedProxy> lookupRoute(HttpRequest request) {
        if (server.chainProxyManager == null) {
            return List.of(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        }
        Queue<ChainedProxy> queue = new ArrayDeque<>();
        server.chainProxyManager.lookupChainedProxies(request, queue, clientDetails);
        return queue.isEmpty() ? null : new ArrayList<>(queue);
    }

    private static boolean isNextHopOrigin(ChainedProxy proxy, Mode mode) {
        return proxy == ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION
                || mode != Mode.PLAIN
                || proxy.getChainedProxyType() != ChainedProxyType.HTTP;
    }

    private ServerConnection connect(String hostAndPort, Exchange ex, List<ChainedProxy> route, Mode mode)
            throws IOException {
        IOException last = null;
        boolean connecting = false;
        int failures = 0;
        long backoffBudget = server.backoffInitialNanos > 0 ? backoffBudgetNanos(ex) : 0;
        for (ChainedProxy candidate : route) {
            ChainedProxy proxy = candidate == ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION ? null : candidate;
            if (failures > 0 && backoffBudget > 0) {
                backoffBudget -= backOff(failures, backoffBudget, hostAndPort, proxy);
            }
            ex.attempt = null;
            try {
                ServerConnection conn = connectVia(hostAndPort, ex, proxy, mode);
                if (proxy != null) {
                    proxy.connectionSucceeded();
                }
                ex.filters.proxyToServerConnectionSucceeded(conn.flowContext);
                server.trackers.fire(t -> t.serverConnected(conn.flowContext, conn.remoteAddress));
                return conn;
            } catch (NotTlsServer e) {
                // The route works; the server just is not a TLS server. The caller retries as a tunnel.
                throw e;
            } catch (IOException e) {
                IOException cause = unwrap(e);
                if (LOG.isLoggable(Level.DEBUG)) {
                    // Expected failures: the cause's message is enough (TLS failures have their own line).
                    LOG.log(Level.DEBUG, logPrefix + "connection to " + hostAndPort
                            + (proxy != null ? " via " + proxy.getChainedProxyAddress() : "") + " failed: " + cause);
                }
                last = e;
                failures++;
                // A name that did not resolve never got as far as connecting.
                connecting |= !(e instanceof UnknownHostException || e instanceof UnresolvedChainedProxy);
                if (proxy != null) {
                    proxy.connectionFailed(cause);
                }
                FullFlowContext failed = ex.attempt != null ? ex.attempt
                        : new FullFlowContext(flowContext, hostAndPort, proxy, proxy == null ? null : proxy.getChainedProxyAddress());
                reportServerFailure(failed, cause);
            }
        }
        if (connecting) {
            ex.filters.proxyToServerConnectionFailed();
        }
        throw last != null ? last : new ConnectException("no route to " + hostAndPort);
    }

    /** The longest all backoff waits of one request may add up to: 30 s or the connect timeout. */
    private static final long MAX_BACKOFF_TOTAL_NANOS = TimeUnit.SECONDS.toNanos(30);

    private long backoffBudgetNanos(Exchange ex) {
        long connectTimeout = TimeUnit.MILLISECONDS.toNanos(connectTimeoutMillis(ex));
        return connectTimeout > 0 ? Math.min(connectTimeout, MAX_BACKOFF_TOTAL_NANOS) : MAX_BACKOFF_TOTAL_NANOS;
    }

    /**
     * The connect timeout for {@code ex}'s connection attempts, in milliseconds (0 = none): the
     * filters' ({@link HttpFilters#proxyToServerConnectTimeout()}), else the server's.
     */
    private int connectTimeoutMillis(Exchange ex) {
        if (ex.connectTimeoutMillis < 0) {
            java.time.Duration own = null;
            try {
                own = ex.filters.proxyToServerConnectTimeout();
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, logPrefix + "proxyToServerConnectTimeout threw; using the server's", e);
            }
            ex.connectTimeoutMillis = own != null && own.isPositive()
                    ? (int) Math.max(1, Math.min(Integer.MAX_VALUE, own.toMillis()))
                    : Math.max(0, server.getConnectTimeout());
        }
        return ex.connectTimeoutMillis;
    }

    /**
     * The backoff before the attempt that follows {@code failures} failed ones: a random time
     * up to {@code initial * 2^(failures-1)}, capped at the maximum.
     */
    static long backoffNanos(int failures, long initialNanos, long maxNanos, double jitter) {
        int doublings = Math.min(failures - 1, 62);
        long ceiling = initialNanos > (maxNanos >> doublings) ? maxNanos : Math.min(maxNanos, initialNanos << doublings);
        return (long) (ceiling * Math.min(1.0, Math.max(0.0, jitter)));
    }

    /**
     * Waits before trying the next candidate after {@code failures} failed attempts, at most
     * {@code budget} nanoseconds, while watching for the client to leave. Returns how long it
     * waited.
     *
     * @throws ClientFailure if the client disconnected meanwhile
     */
    private long backOff(int failures, long budget, String hostAndPort, ChainedProxy next) throws IOException {
        long wait = Math.min(budget,
                backoffNanos(failures, server.backoffInitialNanos, server.backoffMaxNanos, server.backoffJitter.getAsDouble()));
        if (wait <= 0) return 0;
        if (LOG.isLoggable(Level.DEBUG)) {
            LOG.log(Level.DEBUG, logPrefix + "waiting " + TimeUnit.NANOSECONDS.toMillis(wait) + " ms before trying "
                    + (next == null ? "a direct connection" : "chained proxy " + next.getChainedProxyAddress())
                    + " for " + hostAndPort + " after " + failures + " failed attempt" + (failures == 1 ? "" : "s"));
        }
        long start = System.nanoTime();
        awaitUnlessClientLeaves(start + wait);
        return System.nanoTime() - start;
    }

    /**
     * Sleeps until {@code deadline} ({@link System#nanoTime()}), returning early with a {@link
     * ClientFailure} if the client closes its connection meanwhile. Bytes the client sends (a
     * request body, a pipelined request) stay buffered for later; once some have arrived, the
     * close can no longer be seen and the rest of the wait is a plain sleep.
     */
    private void awaitUnlessClientLeaves(long deadline) throws IOException {
        Socket client = socket;
        int original = client.getSoTimeout();
        try {
            while (true) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) return;
                if (in.buffered() > 0) {
                    Thread.sleep(Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining)));
                    return;
                }
                client.setSoTimeout((int) Math.max(1, Math.min(Integer.MAX_VALUE,
                        TimeUnit.NANOSECONDS.toMillis(remaining + 999_999))));
                if (in.awaitData() && in.buffered() == 0) {
                    throw new ClientFailure(new EOFException("client disconnected while waiting to retry"));
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new java.io.InterruptedIOException("interrupted while waiting to retry");
        } catch (ClientFailure e) {
            throw e;
        } catch (IOException e) {
            throw new ClientFailure(e);
        } finally {
            if (!client.isClosed()) {
                try {
                    client.setSoTimeout(original);
                } catch (IOException ignored) {
                    // the connection is failing anyway
                }
            }
        }
    }

    /** Resolves a server for a direct connection, reporting it to {@code filters}. */
    private InetSocketAddress resolveServer(String hostAndPort, HttpFilters filters) throws UnknownHostException {
        HostAndPort target = HostAndPort.parse(hostAndPort, 80);
        InetSocketAddress remote = filters.proxyToServerResolutionStarted(hostAndPort);
        try {
            if (remote == null) {
                flowContext.markFirst(ClientFlowContext.DNS_START);
                remote = server.serverResolver.resolve(target.host(), target.port());
                flowContext.mark(ClientFlowContext.DNS_END);
            } else if (remote.isUnresolved()) {
                // A filter may name another host rather than an address: resolve it the same way.
                flowContext.markFirst(ClientFlowContext.DNS_START);
                remote = server.serverResolver.resolve(remote.getHostString(), remote.getPort());
                flowContext.mark(ClientFlowContext.DNS_END);
            }
        } catch (UnknownHostException e) {
            filters.proxyToServerResolutionFailed(hostAndPort);
            throw e;
        }
        filters.proxyToServerResolutionSucceeded(hostAndPort, remote);
        return remote;
    }

    private ServerConnection connectVia(String hostAndPort, Exchange ex, ChainedProxy proxy, Mode mode)
            throws IOException {
        HttpFilters filters = ex.filters;
        HostAndPort target = HostAndPort.parse(hostAndPort, 80);
        InetSocketAddress remote;
        if (proxy == null) {
            remote = ex.takePreResolved(hostAndPort);
            if (remote == null) {
                remote = resolveServer(hostAndPort, filters);
            }
        } else {
            remote = proxy.getChainedProxyAddress();
            if (remote == null) {
                throw new ConnectException("chained proxy has no address");
            }
            if (remote.isUnresolved()) {
                flowContext.markFirst(ClientFlowContext.DNS_START);
                try {
                    remote = new InetSocketAddress(InetAddress.getByName(remote.getHostString()), remote.getPort());
                } catch (UnknownHostException e) {
                    // The route failed, not the server's name: a ConnectFailed, not an UnresolvedHost.
                    throw new UnresolvedChainedProxy(remote, e);
                }
                flowContext.mark(ClientFlowContext.DNS_END);
            }
        }
        FullFlowContext serverContext = new FullFlowContext(flowContext, hostAndPort, proxy, remote);
        ex.attempt = serverContext;

        filters.proxyToServerConnectionStarted();
        Socket plain = new Socket(Proxy.NO_PROXY);
        try {
            InetSocketAddress local = proxy != null && proxy.getLocalAddress() != null
                    ? proxy.getLocalAddress() : server.localAddress;
            if (local != null) {
                plain.bind(local);
            }
            flowContext.markFirst(ClientFlowContext.CONNECT_START);
            plain.connect(remote, connectTimeoutMillis(ex));
            flowContext.mark(ClientFlowContext.CONNECT_END);
            plain.setTcpNoDelay(true);
            plain.setSoTimeout(server.idleTimeoutMillis());

            Socket active = plain;
            if (proxy != null && proxy.requiresEncryption()) {
                SSLContext context = proxy.getSslContext();
                if (context == null) {
                    throw new ConnectException("chained proxy requires encryption but has no SSLContext");
                }
                filters.proxyToServerConnectionSSLHandshakeStarted();
                try {
                    flowContext.markFirst(ClientFlowContext.TLS_START);
                    active = Tls.clientHandshake(context, plain, remote.getHostString(), remote.getPort(), false,
                            server.tlsProtocols,
                            s -> proxy.configure(s, true), server.tlsHandshakeTimeout,
                            new TlsLog.Peer(logPrefix, "chained proxy", remote.getHostString()));
                    flowContext.mark(ClientFlowContext.TLS_END);
                } catch (IOException e) {
                    server.trackers.fire(t -> t.tlsHandshakeFailed(serverContext, false, e));
                    throw new TlsHandshakeFailed(e);
                }
            }
            ChainedProxyType type = proxy == null ? null : proxy.getChainedProxyType();
            boolean socks = type == ChainedProxyType.SOCKS4 || type == ChainedProxyType.SOCKS5;

            ServerConnection[] holder = new ServerConnection[1];
            Supplier<FullFlowContext> currentContext =
                    () -> holder[0] != null ? holder[0].flowContext : serverContext;
            ByteReader reader = new ByteReader(serverInput(active, currentContext), server.ioBuffers);
            OutputStream output = new PooledOutputStream(serverOutput(active, currentContext), server.ioBuffers);
            InputStream rawIn = active.getInputStream();
            OutputStream rawOut = active.getOutputStream();

            // The PROXY header must reach the final server, as in LittleProxy: written first on a
            // direct connection, through the tunnel once an HTTP chained proxy has accepted the
            // CONNECT, and not at all when there is no tunnel to the final server (SOCKS, or a
            // plain request forwarded to an HTTP chained proxy).
            if (server.sendProxyProtocol && proxy == null) {
                writeProxyProtocolHeader(rawOut, remote);
            } else if (server.sendProxyProtocol && (socks || mode == Mode.PLAIN)) {
                LOG.log(Level.DEBUG, logPrefix + "not sending a PROXY header: no tunnel to {0} through {1} chained proxy {2}",
                        hostAndPort, type, remote);
            }
            if (type == ChainedProxyType.SOCKS4) {
                Socks.connect4(rawIn, rawOut, target.host(), target.port(), proxy.getUsername());
            } else if (type == ChainedProxyType.SOCKS5) {
                Socks.connect5(rawIn, rawOut, target.host(), target.port(), proxy.getUsername(), proxy.getPassword());
            }
            if (type == ChainedProxyType.HTTP && mode != Mode.PLAIN) {
                HttpRequest connectRequest = upstreamConnectRequest(ex.request, hostAndPort, proxy);
                proxy.filterRequest(connectRequest);
                stripRequestHeaders(connectRequest.headers());
                new HttpCodec.HttpWriter(output).writeHead(connectRequest, false);
                HttpResponse reply = HttpCodec.readResponse(reader, server.limits);
                if (reply == null || reply.status().code() / 100 != 2) {
                    throw new ConnectException("chained proxy refused CONNECT: "
                            + (reply == null ? "connection closed" : reply.status()));
                }
                if (server.sendProxyProtocol) {
                    writeProxyProtocolHeader(rawOut, remote);
                }
            }
            if (mode == Mode.TLS) {
                if (reader.buffered() > 0) {
                    throw new ProtocolException("unexpected data from server before TLS handshake");
                }
                filters.proxyToServerConnectionSSLHandshakeStarted();
                MitmManager manager = connectionMitm;
                SSLContext context = manager.serverSslContext(target.host(), target.port(), serverContext);
                try {
                    flowContext.markFirst(ClientFlowContext.TLS_START);
                    active = Tls.clientHandshake(context, active, target.host(), target.port(), true,
                            server.tlsProtocols,
                            s -> manager.configureServerSocket(s, serverContext), server.tlsHandshakeTimeout,
                            new TlsLog.Peer(logPrefix, "server", target.host()));
                    flowContext.mark(ClientFlowContext.TLS_END);
                } catch (IOException e) {
                    if (e instanceof SSLException ssl && NotTlsServer.isCause(ssl)) {
                        throw new NotTlsServer(hostAndPort, ssl);
                    }
                    server.trackers.fire(t -> t.tlsHandshakeFailed(serverContext, false, e));
                    throw new TlsHandshakeFailed(e);
                }
                reader = new ByteReader(serverInput(active, currentContext), server.ioBuffers);
                output = new PooledOutputStream(serverOutput(active, currentContext), server.ioBuffers);
            }
            holder[0] = new ServerConnection(mode + "|" + hostAndPort, hostAndPort, proxy, mode == Mode.TLS,
                    active, reader, output, remote, serverContext, server.trackers);
            ServerConnection created = holder[0];
            created.onDetach = () -> serverConnections.remove(created.key, created);
            return created;
        } catch (IOException e) {
            Tls.closeQuietly(plain);
            throw e;
        } catch (RuntimeException e) {
            Tls.closeQuietly(plain);
            throw new IOException("connecting to " + hostAndPort + " failed", e);
        }
    }

    private InputStream serverInput(Socket s, Supplier<FullFlowContext> serverContext)
            throws IOException {
        InputStream is = server.readLimiter.wrap(s.getInputStream());
        if (!server.trackers.isEmpty()) {
            is = CountingStreams.counting(is,
                    n -> server.trackers.fire(t -> t.bytesReceivedFromServer(serverContext.get(), n)));
        }
        return is;
    }

    private OutputStream serverOutput(Socket s, Supplier<FullFlowContext> serverContext)
            throws IOException {
        OutputStream os = server.writeLimiter.wrap(s.getOutputStream());
        if (!server.trackers.isEmpty()) {
            os = CountingStreams.counting(os,
                    n -> server.trackers.fire(t -> t.bytesSentToServer(serverContext.get(), n)));
        }
        return os;
    }

    /** @param remote the address this server connection goes to */
    private void writeProxyProtocolHeader(OutputStream os, InetSocketAddress remote) throws IOException {
        ProxyProtocol.Header received = proxyHeader;
        InetSocketAddress source = clientDetails.getClientAddress();
        InetSocketAddress destination;
        if (received != null && received.destination() != null) {
            destination = received.destination();
        } else if (server.littleProxyCompatibility) {
            // LittleProxy names the server connection's remote end, and skips mixed families.
            destination = remote;
            if (source != null && source.getAddress() != null && destination.getAddress() != null
                    && source.getAddress().getClass() != destination.getAddress().getClass()) {
                LOG.log(Level.DEBUG, logPrefix + "not sending a PROXY header: {0} and {1} are different address families",
                        source, destination);
                return;
            }
        } else {
            // As HAProxy does: the address the client connected to.
            destination = (InetSocketAddress) rawSocket.getLocalSocketAddress();
        }
        os.write(ProxyProtocol.encodeV1(source, destination));
        os.flush();
    }

    /** The CONNECT sent to an upstream HTTP proxy: the client's own CONNECT if it sent one. */
    private static HttpRequest upstreamConnectRequest(HttpRequest clientRequest, String hostAndPort, ChainedProxy proxy) {
        HttpRequest connect;
        if (ProxyUtils.isCONNECT(clientRequest)) {
            connect = copy(clientRequest);
        } else {
            connect = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.CONNECT, hostAndPort);
            connect.headers().set(HttpHeaderNames.HOST, hostAndPort);
        }
        addUpstreamProxyAuthorization(connect.headers(), proxy);
        return connect;
    }

    /** Removes the headers configured with {@code withStrippedRequestHeaders}, after every filter. */
    private void stripRequestHeaders(HttpHeaders headers) {
        for (String name : server.strippedRequestHeaders) {
            headers.remove(name);
        }
    }

    private static void addUpstreamProxyAuthorization(HttpHeaders headers, ChainedProxy proxy) {
        if (proxy != null && proxy.getChainedProxyType() == ChainedProxyType.HTTP
                && proxy.getUsername() != null && proxy.getPassword() != null) {
            String credentials = proxy.getUsername() + ":" + proxy.getPassword();
            headers.set(HttpHeaderNames.PROXY_AUTHORIZATION,
                    "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(UTF_8)));
        }
    }

    // ---------------------------------------------------------------------------------------
    // Rewriting
    // ---------------------------------------------------------------------------------------

    private void modifyRequestHeadersToReflectProxying(HttpRequest request, boolean nextHopOrigin, boolean webSocket) {
        if (!ProxyUtils.isCONNECT(request) && ProxyUtils.isAbsoluteUri(request.uri())) {
            // RFC 9112 3.2.2: the target URI's authority replaces any received Host.
            String authority = ProxyUtils.parseHostAndPort(request.uri());
            if (authority != null && !authority.isEmpty()) {
                request.headers().set(HttpHeaderNames.HOST, authority);
            }
            if (nextHopOrigin) {
                request.setUri(ProxyUtils.stripHost(request.uri()));
            }
        }
        if (!server.transparent) {
            HttpHeaders headers = request.headers();
            ProxyUtils.removeSdchEncoding(headers);
            String upgrade = webSocket ? headers.get(HttpHeaderNames.UPGRADE) : null;
            ProxyUtils.stripConnectionTokens(headers);
            ProxyUtils.stripHopByHopHeaders(headers);
            if (upgrade != null) {
                headers.set(HttpHeaderNames.CONNECTION, "Upgrade");
                headers.set(HttpHeaderNames.UPGRADE, upgrade);
            }
            ProxyUtils.addVia(request, server.proxyAlias);
        }
    }

    /** Converts between origin-form and absolute-form after falling back to another route. */
    private static void adjustUriForNextHop(HttpRequest request, String hostAndPort, boolean nextHopOrigin) {
        String uri = request.uri();
        if (nextHopOrigin) {
            request.setUri(ProxyUtils.stripHost(uri));
        } else if (!ProxyUtils.isAbsoluteUri(uri)) {
            String host = request.headers().get(HttpHeaderNames.HOST, hostAndPort);
            request.setUri("http://" + host + uri);
        }
    }

    private void modifyResponseHeadersToReflectProxying(HttpResponse response) {
        HttpHeaders headers = response.headers();
        ProxyUtils.stripConnectionTokens(headers);
        ProxyUtils.stripHopByHopHeaders(headers);
        ProxyUtils.addVia(response, server.proxyAlias);
        if (!headers.contains(HttpHeaderNames.DATE)) {
            headers.set(HttpHeaderNames.DATE, ProxyUtils.httpDate());
        }
    }

    private static String identifyHostAndPort(HttpRequest request) {
        String uri = request.uri();
        String authority = ProxyUtils.parseHostAndPort(uri);
        if (authority == null || authority.isEmpty()) {
            authority = request.headers().get(HttpHeaderNames.HOST);
        }
        if (authority == null || authority.isBlank()) {
            return null;
        }
        try {
            return HostAndPort.parse(authority.strip(), ProxyUtils.defaultPort(uri)).toString();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static HttpRequest copy(HttpRequest original) {
        if (original instanceof FullHttpRequest full) {
            DefaultFullHttpRequest copy = new DefaultFullHttpRequest(full.protocolVersion(), full.method(), full.uri(),
                    full.headers().copy(), full.content().clone());
            copy.trailingHeaders().set(full.trailingHeaders());
            return copy;
        }
        return new DefaultHttpRequest(original.protocolVersion(), original.method(), original.uri(), original.headers().copy());
    }

    // ---------------------------------------------------------------------------------------
    // Buffering
    // ---------------------------------------------------------------------------------------

    private FullHttpRequest aggregateRequest(Exchange ex, int maxBytes) throws IOException {
        HttpRequest request = ex.request;
        if (ex.body.declaredLength() > maxBytes) {
            respondFailure(ex, new ProxyFailure.RequestTooLarge(maxBytes), false);
            return null;
        }
        if (ex.body.hasBody() && HttpUtil.is100ContinueExpected(request)) {
            writer.writeHead(new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.CONTINUE), false);
        }
        request.headers().remove(HttpHeaderNames.EXPECT);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        HttpHeaders trailers = null;
        HttpContent content;
        while ((content = ex.body.next()) != null) {
            if (buffer.size() + content.contentLength() > maxBytes) {
                respondFailure(ex, new ProxyFailure.RequestTooLarge(maxBytes), false);
                return null;
            }
            buffer.write(content.content());
            if (content instanceof LastHttpContent last) {
                trailers = last.trailingHeaders();
            }
        }
        DefaultFullHttpRequest full = new DefaultFullHttpRequest(request.protocolVersion(), request.method(),
                request.uri(), request.headers(), buffer.toByteArray());
        if (trailers != null) {
            full.trailingHeaders().set(trailers);
        }
        if (ex.body.hasBody()) {
            HttpUtil.setTransferEncodingChunked(full, false);
            HttpUtil.setContentLength(full, full.content().length);
        }
        return full;
    }

    /**
     * Reads the whole response body into a {@link FullHttpResponse}. When the body exceeds {@code
     * maxBytes}: fails with 502 if {@code overflow} is null, otherwise returns null after putting
     * the pieces read so far into {@code overflow} so the response can still be streamed.
     */
    private FullHttpResponse aggregateResponse(HttpResponse response, Framing framing, HttpCodec.BodyReader body,
            int maxBytes, HttpMethod requestMethod, Deque<HttpContent> overflow) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        List<HttpContent> pieces = overflow == null ? null : new ArrayList<>();
        HttpHeaders trailers = null;
        while (true) {
            HttpContent content;
            try {
                content = body.next();
            } catch (SocketTimeoutException e) {
                throw new ServerTimeout(e);
            } catch (IOException e) {
                throw new ServerFailure("reading response body failed", e);
            }
            if (content == null) {
                break;
            }
            if (pieces != null) {
                pieces.add(content);
            }
            if (buffer.size() + content.contentLength() > maxBytes) {
                if (overflow != null) {
                    overflow.addAll(pieces);
                    return null;
                }
                throw new ServerFailure("response larger than " + maxBytes + " bytes", null);
            }
            buffer.write(content.content());
            if (content instanceof LastHttpContent last) {
                trailers = last.trailingHeaders();
            }
        }
        DefaultFullHttpResponse full = new DefaultFullHttpResponse(response.protocolVersion(), response.status(),
                response.headers(), buffer.toByteArray());
        if (trailers != null) {
            full.trailingHeaders().set(trailers);
        }
        if (framing.kind() != Framing.Kind.NONE && Framing.responseMayHaveBody(response, requestMethod)) {
            HttpUtil.setTransferEncodingChunked(full, false);
            HttpUtil.setContentLength(full, full.content().length);
        }
        return full;
    }

    // ---------------------------------------------------------------------------------------
    // Responses generated by the proxy
    // ---------------------------------------------------------------------------------------

    /**
     * Answers the client without the server's involvement: short-circuit responses from filters
     * and proxy-generated errors. The response passes through {@link HttpFilters#proxyToClientResponse}.
     *
     * @param rewriteHeaders apply the proxy's response header rewriting (Via, Date, hop-by-hop)
     * @param source who made {@code response}
     * @return whether the client connection stays open
     */
    private boolean respondDirect(Exchange ex, HttpResponse response, boolean rewriteHeaders, ResponseSource source)
            throws IOException {
        boolean keepAlive = HttpUtil.isKeepAlive(response) && ex.clientKeepAlive
                && !ex.bodyUnread() && !ex.bodyAbandoned;
        int status = response.status().code();
        HttpObject filtered = ex.filters.proxyToClientResponse(response);
        if (!(filtered instanceof HttpResponse res)) {
            close();
            return false;
        }
        if (rewriteHeaders && !server.transparent) {
            modifyResponseHeadersToReflectProxying(res);
        }
        if (rewriteHeaders && server.stripAltSvcH3) {
            AltSvc.stripHttp3(res.headers());
        }
        HttpUtil.setKeepAlive(res, keepAlive);
        boolean bodyAllowed = Framing.responseMayHaveBody(res, ex.request.method());
        boolean bare = !(res instanceof FullHttpMessage);
        if (bare && bodyAllowed && !ProxyUtils.isResponseSelfTerminating(res)) {
            HttpUtil.setContentLength(res, 0);
        }
        ex.responseStarted = true;
        writeToClient(() -> writer.writeHead(res, bodyAllowed));
        if (bare && bodyAllowed && HttpUtil.isTransferEncodingChunked(res)) {
            writeToClient(() -> writer.writeContent(LastHttpContent.empty()));
        }
        ResponseSource sent = source(source, response, status, res);
        server.trackers.fire(t -> t.responseSentToClient(flowContext, res, sent));
        completed(ex, res, sent);
        if (!keepAlive) {
            close();
        }
        return keepAlive;
    }

    /**
     * Answers the client because of {@code failure}: with the first filter's {@link
     * HttpFilters#proxyToServerFailure} response, else the failure responder's, else the proxy's
     * default. Other answers are framed here like the defaults.
     */
    private boolean respondFailure(Exchange ex, ProxyFailure failure, boolean rewriteHeaders) throws IOException {
        HttpResponse response = ex.filters.proxyToServerFailure(failure);
        ResponseSource source = response != null ? ResponseSource.FILTER : ResponseSource.PROXY;
        if (response == null && server.failureResponder != null) {
            try {
                response = server.failureResponder.respond(ex.request, failure);
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, logPrefix + "failure responder threw; sending the default response", e);
            }
        }
        if (response == null) {
            response = defaultResponse(ex, failure);
        } else if (response instanceof FullHttpMessage full) {
            response.headers().remove(HttpHeaderNames.TRANSFER_ENCODING);
            HttpUtil.setContentLength(response, full.content().length);
        }
        if (failure instanceof ProxyFailure.RequestTooLarge) {
            // The rest of the body is never read, so the connection cannot be reused.
            HttpUtil.setKeepAlive(response, false);
        }
        return respondDirect(ex, response, rewriteHeaders, source);
    }

    /**
     * Where {@code sent} came from, given that filters made it out of {@code made} (with status
     * {@code madeStatus}, from {@code source}): a cache answer, a filter's replacement or status
     * change, or {@code made} as it was.
     */
    private static ResponseSource source(ResponseSource source, HttpObject made, int madeStatus, HttpResponse sent) {
        if (sent instanceof HttpCache.Answer) {
            return ResponseSource.CACHE;
        }
        if (sent != made || sent.status().code() != madeStatus) {
            return ResponseSource.FILTER;
        }
        return source;
    }

    /** The proxy's own plain-text answer to {@code failure}. */
    private static FullHttpResponse defaultResponse(Exchange ex, ProxyFailure failure) {
        return switch (failure) {
            case ProxyFailure.BadRequest f -> errorResponse(ex, f.status(), "Bad Request: " + f.reason());
            case ProxyFailure.NoConnectionAvailable f ->
                    errorResponse(ex, f.status(), "Service Unavailable: no server connection available");
            case ProxyFailure.ServerTimeout f -> errorResponse(ex, f.status(), "Gateway Timeout");
            case ProxyFailure.RequestTooLarge f -> errorResponse(ex, f.status(), "Request Entity Too Large");
            case ProxyFailure.UnresolvedHost f -> badGateway(ex);
            case ProxyFailure.ConnectFailed f -> badGateway(ex);
            case ProxyFailure.TlsFailed f -> badGateway(ex);
            case ProxyFailure.BadServerResponse f -> badGateway(ex);
            case ProxyFailure.NoRoute f -> badGateway(ex);
        };
    }

    /** Classifies a failed connection attempt, as thrown by {@link #connect} or {@link #lease}. */
    private static ProxyFailure connectFailure(String hostAndPort, IOException e) {
        if (e instanceof TlsHandshakeFailed) {
            return new ProxyFailure.TlsFailed(hostAndPort, unwrap(e));
        }
        if (e instanceof UnknownHostException unknown) {
            return new ProxyFailure.UnresolvedHost(hostAndPort, unknown);
        }
        return new ProxyFailure.ConnectFailed(hostAndPort, e);
    }

    private void reportServerFailure(FullFlowContext serverContext, Throwable cause) {
        server.trackers.fire(t -> t.serverConnectionExceptionCaught(serverContext, cause));
    }

    private void writeErrorAndClose(HttpResponseStatus status) {
        FullHttpResponse response = ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1, status, status.reasonPhrase());
        HttpUtil.setKeepAlive(response, false);
        try {
            writer.writeHead(response, true);
        } catch (IOException ignored) {
            // closing anyway
        }
        close();
    }

    private static FullHttpResponse errorResponse(Exchange ex, HttpResponseStatus status, String body) {
        FullHttpResponse response = ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1, status, body);
        if (ProxyUtils.isHEAD(ex.request)) {
            // Keep the Content-Length a GET would have had, but send no body.
            response.setContent(new byte[0]);
        }
        return response;
    }

    private static FullHttpResponse badGateway(Exchange ex) {
        return errorResponse(ex, HttpResponseStatus.BAD_GATEWAY, "Bad Gateway");
    }

    // ---------------------------------------------------------------------------------------
    // Authentication
    // ---------------------------------------------------------------------------------------

    /** Asks the authenticator about {@code request}: null if it may proceed, else the answer. */
    private HttpResponse authenticate(HttpRequest request) {
        AuthResult result = server.proxyAuthenticator.authenticate(request, flowContext);
        if (result instanceof AuthResult.Accepted ok) {
            if (accepted && !Objects.equals(acceptedUser, ok.userName())) {
                // Another user on the same connection: its server connections were routed for the
                // previous one.
                releaseServerConnections();
            }
            accepted = true;
            acceptedUser = ok.userName();
            clientDetails.setUserName(ok.userName());
            authenticated = true;
            return null;
        }
        authenticated = false;
        clientDetails.setUserName(null);
        HttpResponse challenge = result instanceof AuthResult.Rejected rejected ? rejected.challenge() : null;
        if (challenge == null) {
            return authenticationRequired();
        }
        if (challenge instanceof FullHttpMessage full) {
            challenge.headers().remove(HttpHeaderNames.TRANSFER_ENCODING);
            HttpUtil.setContentLength(challenge, full.content().length);
        }
        return challenge;
    }

    private FullHttpResponse authenticationRequired() {
        String realm = server.proxyAuthenticator.getRealm();
        FullHttpResponse response = ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1,
                HttpResponseStatus.PROXY_AUTHENTICATION_REQUIRED,
                "Proxy Authentication Required\n");
        response.headers().set(HttpHeaderNames.PROXY_AUTHENTICATE,
                "Basic realm=\"" + (realm == null ? "Restricted Files" : realm.replace("\"", "")) + "\"");
        return response;
    }
}
