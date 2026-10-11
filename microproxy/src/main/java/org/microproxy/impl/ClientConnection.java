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
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import org.microproxy.AuthResult;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyAdapter;
import org.microproxy.ChainedProxyType;
import org.microproxy.ClientDetails;
import org.microproxy.ClientHello;
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
import org.microproxy.extras.ServerReplay;
import org.microproxy.http.DefaultFullHttpRequest;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.DefaultHttpRequest;
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
import org.microproxy.http.WebSocketMessage;
import org.microproxy.tcp.TcpInterceptor;

/**
 * Serves one client connection on its own virtual thread.
 *
 * <p>Requests are handled one at a time: read the request head, run filters, connect (or reuse a
 * connection) to the server, stream the request body, stream the response back. HTTP/1.1
 * pipelining works naturally because unread pipelined requests simply wait in the socket buffer.
 * CONNECT turns the connection into a byte tunnel, or, with a {@link org.microproxy.MitmManager},
 * into a TLS session whose decrypted requests are served by the same loop.
 *
 * <p>Two layers share this class. The connection loop ({@link #run}, {@link #serveRequests}, TLS
 * handshakes, interception) is HTTP/1's: it reads request heads through its {@link
 * Http1ClientChannel}. Everything from {@link #handleRequest} on is the exchange logic, which
 * reaches the client only through the exchange's {@link ClientChannel}, so other transports drive
 * it too: an intercepted session that negotiates {@code h2} is handed to an {@link
 * Http2Connection}, whose streams each run {@link #handleStream} on a thread of their own,
 * concurrently. See {@code README.md} in this package.
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

    /** Whether a filters class rewrites whole WebSocket messages. */
    private static final ClassValue<Boolean> REWRITES_MESSAGES = new ClassValue<>() {
        @Override
        protected Boolean computeValue(Class<?> type) {
            try {
                return type.getMethod("filterWebSocketMessage", WebSocketMessage.class, boolean.class)
                                .getDeclaringClass() != HttpFilters.class
                        || type.getMethod("filterWebSocketMessages", WebSocketMessage.class, boolean.class)
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

    private static boolean rewritesMessages(HttpFilters filters) {
        if (filters instanceof HttpFiltersChain.Chained chain) {
            return chain.members().stream().anyMatch(ClientConnection::rewritesMessages);
        }
        if (filters instanceof SelectiveFilters selective) {
            return selective.sees(HttpFiltersBuilder.Body.WEBSOCKET_MESSAGES);
        }
        return REWRITES_MESSAGES.get(filters.getClass());
    }

    /**
     * Which streams the proxy parses piece by piece for {@code filters}, as {request bodies,
     * response bodies, WebSocket frames}; the others take the fast path. For tests.
     */
    static boolean[] inspectedStreams(HttpFilters filters) {
        return new boolean[] {observes(filters, OBSERVES_REQUEST_CONTENT), observes(filters, OBSERVES_RESPONSE_CONTENT),
            observesFrames(filters) || rewritesFrames(filters) || rewritesMessages(filters)};
    }

    /** Whether the proxy joins WebSocket frames into messages for {@code filters}. For tests. */
    static boolean joinsWebSocketMessages(HttpFilters filters) {
        return rewritesMessages(filters);
    }

    /**
     * The relay for a connection upgraded to a WebSocket, or null to relay its bytes untouched
     * when no filter looks at frames or messages. Filters that rewrite read payloads through
     * permessage-deflate as each hop agreed it: {@code serverExtensions} are the server's answer,
     * {@code response} is what the client got.
     */
    private WebSocketRelay webSocketRelay(HttpFilters filters, List<String> serverExtensions, HttpResponse response,
            String log) {
        boolean observe = observesFrames(filters);
        boolean rewrite = rewritesFrames(filters);
        boolean messages = rewritesMessages(filters);
        if (!observe && !rewrite && !messages) return null;
        PerMessageDeflate.Params clientHop = null;
        PerMessageDeflate.Params serverHop = null;
        if (rewrite || messages) {
            try {
                serverHop = PerMessageDeflate.agreed(serverExtensions);
                clientHop = PerMessageDeflate.agreed(
                        response.headers().getAllElements(HttpHeaderNames.SEC_WEBSOCKET_EXTENSIONS));
            } catch (PerMessageDeflate.UnsupportedException e) {
                // The offer only had what the relay reads; a server that answers otherwise gets its
                // frames relayed as they are.
                LOG.log(Level.WARNING, log + "WebSocket extensions the proxy cannot read (" + e.getMessage()
                        + "); frames are only watched");
                rewrite = false;
                messages = false;
                if (!observe) return null;
            }
        }
        boolean watch = observe;
        boolean change = rewrite;
        WebSocketRelay.FrameHandler frames = !watch && !change ? null : (frame, fromClient) -> {
            if (watch) filters.webSocketFrameReceived(frame, fromClient);
            return change ? filters.filterWebSocketFrame(frame, fromClient) : frame;
        };
        return new WebSocketRelay(frames, messages ? filters::filterWebSocketMessages : null,
                server.maxWebSocketFrameBufferSize, server.maxWebSocketMessageSize, clientHop, serverHop);
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
    static final class ClientFailure extends IOException {
        ClientFailure(Throwable cause) {
            super("client connection failed", cause);
        }
    }

    /** State of the request/response exchange in progress. */
    private static final class Exchange {
        /** The client side: where the request body comes from and the response goes. */
        final ClientChannel channel;
        /** The record of this exchange (timings, upstream status), which flow contexts show. */
        final ClientFlowContext flow;
        /** Starts the exchange's log lines: {@code [conn <id>] }, or {@code [conn <id> stream <s>] }. */
        final String log;
        HttpRequest request;
        /** The request-target as the client sent it, before any rewriting. */
        final String originalUri;
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
        /** Whether TLS connections made for the exchange offer HTTP/2 (ALPN {@code h2}). */
        boolean offerHttp2;
        /** The client sent {@code TE: trailers} (a hop-by-hop field, removed before the request goes on). */
        boolean trailersAccepted;
        /**
         * Server TLS for this exchange's CONNECT waits for the client's ClientHello: connect now
         * (TCP, and through chained proxies), and run the handshake later ({@link #startServerTls}).
         */
        boolean deferServerTls;
        /**
         * The proxy made up this CONNECT for a connection that arrived without one (transparent TLS,
         * a {@code tcp://} reverse proxy): nothing is written to the client in HTTP.
         */
        boolean implicit;
        /**
         * The SOCKS version of the client that asked for this made-up CONNECT ({@link #implicit}),
         * which is answered in SOCKS; 0 for none.
         */
        int socks;
        /** Why the SOCKS client's CONNECT failed, for the reply code; null when it did not, or a filter refused it. */
        ProxyFailure socksFailure;
        /**
         * The HTTP/2 key whose connection this exchange claimed to make ({@link Http2Origins}) and
         * reports on only once its deferred server TLS has told what the server speaks.
         */
        String http2Claim;
        /** The CONNECT's answer, written, whose completion waits until the session is set up. */
        HttpResponse connectResponse;
        ResponseSource connectSource;
        /**
         * For a {@code CONNECT} forwarded to the intercepted server ({@link #forwardConnect}): the
         * hop through that server, which the client takes for its HTTPS proxy; null otherwise.
         */
        Hop forwarding;
        /** The intercepted proxy's 2xx to a forwarded {@code CONNECT}, once its tunnel is open. */
        HttpResponse tunnelOpened;
        /**
         * The client sent this request in absolute-form inside a session (and no filter pointed
         * it elsewhere): it goes to the session's server, which the client takes for its proxy,
         * as a proxy request, in absolute-form with the client's {@code Proxy-Authorization}, on
         * a connection no other client gets; that proxy's {@code Proxy-Authenticate} comes back.
         */
        boolean proxyForm;

        Exchange(ClientChannel channel, HttpRequest request, MessageBody body, boolean clientKeepAlive) {
            this.channel = channel;
            this.flow = channel.flowContext();
            this.log = channel.logPrefix();
            this.request = request;
            this.originalUri = request.uri();
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

    /**
     * The way to a server through the server of a session that the client takes for its proxy
     * ({@link #forwardConnect}): the client sent a {@code CONNECT} inside the session with {@link
     * #proxy} (an intercepted TLS session with an HTTPS proxy, or a plain HTTP session with an HTTP
     * proxy), which the proxy forwarded there. The session inside the tunnel it opened (when that
     * is intercepted too) reaches its server only through tunnels the same way, each opened with
     * the client's {@code CONNECT} fields ({@code Proxy-Authorization} among them).
     */
    private static final class Hop {
        private static final AtomicLong IDS = new AtomicLong();

        /** Keeps HTTP/2 connections through this hop apart from all others. */
        final long id = IDS.incrementAndGet();
        /** The session's server ({@code host:port}) that opens the tunnels. */
        final String proxy;
        /** Whether {@link #proxy} is reached over TLS (an HTTPS proxy), else over plain TCP. */
        final boolean tls;
        /** How {@link #proxy} itself is reached: through another hop, or null for the usual routes. */
        final Hop parent;
        /** The {@code CONNECT} as it was forwarded: the fields every tunnel is opened with. */
        final HttpRequest connect;
        /** The proxy, as the flow contexts of server connections through it name it. */
        final ChainedProxy chained;
        /** The client connection whose session runs through this hop: it closes the hop's HTTP/2 connections. */
        volatile ClientConnection consumer;

        Hop(String proxy, boolean tls, Hop parent, HttpRequest connect) {
            this.proxy = proxy;
            this.tls = tls;
            this.parent = parent;
            this.connect = connect;
            HostAndPort address = HostAndPort.parse(proxy, tls ? 443 : 80);
            this.chained = new InterceptedProxy(InetSocketAddress.createUnresolved(address.host(), address.port()), tls);
        }

        /** How connections to {@link #proxy} are made, and keyed. */
        Mode mode() {
            return tls ? Mode.TLS : Mode.PLAIN;
        }

        /** The {@code CONNECT} for a tunnel to {@code target}. */
        HttpRequest connectTo(String target) {
            HttpRequest request = copy(connect);
            request.setUri(target);
            request.headers().set(HttpHeaderNames.HOST, target);
            return request;
        }
    }

    /**
     * A session's server that the client takes for its proxy (HTTPS when {@code tls}), as the
     * chained proxy of the server connections made through it ({@link
     * FullFlowContext#getChainedProxy()}).
     */
    private record InterceptedProxy(InetSocketAddress address, boolean tls) implements ChainedProxy {
        @Override
        public InetSocketAddress getChainedProxyAddress() {
            return address;
        }

        @Override
        public boolean requiresEncryption() {
            return tls;
        }
    }

    private final DefaultHttpProxyServer server;
    private final Socket rawSocket;
    private final long id = IDS.incrementAndGet();
    /**
     * The client connection whose HTTP/2 connections to servers this one's requests share: itself,
     * or for the TLS session of an intercepted {@code CONNECT} stream ({@link #interceptStream}),
     * the client connection the stream belongs to (the outermost one, when such sessions nest).
     */
    private final ClientConnection owner;
    private final ClientDetails clientDetails = new ClientDetails();
    private final ClientFlowContext flowContext;
    /** Starts every log line about this connection: {@code [conn <id>] }. */
    private final String logPrefix = "[conn " + id + "] ";
    private final Map<String, ServerConnection> serverConnections = new ConcurrentHashMap<>();
    /**
     * The server connections of an HTTP/2 session's streams, which run concurrently and so never
     * share one; null until the client speaks HTTP/2.
     */
    private volatile StreamServerConnections streamConnections;
    /** The HTTP/2 connection this client switched to, once it has. */
    private volatile Http2Connection http2;
    /** Whether this client may have HTTP/2 connections to servers of its own ({@link #http2Owner}). */
    private volatile boolean ownsHttp2Connections;

    /** The client connection's transport; every client byte goes through it. */
    private final Http1ClientChannel http1;
    private volatile SSLSession sslSession;
    private volatile ProxyProtocol.Header proxyHeader;
    private volatile boolean idle = true;
    private volatile boolean closed;

    // Connection-level state the exchange logic reads. HTTP/1 exchanges run one at a time on the
    // connection's thread, so the authentication state is only ever touched by one thread. HTTP/2
    // streams run concurrently: inside an intercepted session they inherit its authentication,
    // and on a forward-proxy connection (h2c, the TLS listener) each authenticates on its own.
    // They only read mitmHostAndPort, which was written before their threads started; the MITM
    // choice is made under mitmLock, since CONNECT streams may ask for it at once.
    private boolean authenticated;
    /** Whether a request has been accepted on this connection, and as whom. */
    private boolean accepted;
    private String acceptedUser;
    /**
     * While serving intercepted (MITM) traffic: the CONNECT target that requests go to, unless
     * filters give one an absolute URI of its own ({@link #redirected}).
     */
    private String mitmHostAndPort;
    /**
     * The MITM manager chosen for this connection ({@link MitmManager#forConnection}), once asked.
     * Guarded by {@link #mitmLock}.
     */
    private MitmManager connectionMitm;
    private boolean mitmChosen;
    private final ReentrantLock mitmLock = new ReentrantLock();
    /**
     * The session after a CONNECT is plain HTTP (the client sent HTTP rather than TLS): its
     * requests go to {@link #mitmHostAndPort} without TLS.
     */
    private boolean plainSession;
    /** The next exchange is a CONNECT the proxy made up ({@link Exchange#implicit}). */
    private boolean implicitConnect;
    /** That CONNECT is a SOCKS client's request ({@link Exchange#socks}): its SOCKS version, 0 for none. */
    private int socksConnect;
    /**
     * How the intercepted server is reached when this session is inside a tunnel that the client
     * opened through an intercepted HTTPS proxy ({@link #forwardConnect}): every server connection
     * of the session is a tunnel through that proxy. Null for the usual routes. Written before the
     * session's requests start.
     */
    private volatile Hop via;

    ClientConnection(DefaultHttpProxyServer server, Socket socket) {
        this.server = server;
        this.rawSocket = socket;
        this.owner = this;
        this.flowContext = new ClientFlowContext(id, clientDetails::getClientAddress, () -> sslSession, clientDetails);
        this.http1 = new Http1ClientChannel(server, socket, flowContext, logPrefix, this::close);
    }

    /**
     * The client connection inside an intercepted {@code CONNECT} stream of {@code parent}'s HTTP/2
     * connection: {@code tunnel} is the stream as a socket, over which the client speaks TLS. It
     * has the parent's client details, PROXY header and MITM manager, and its requests share the
     * parent's HTTP/2 connections to servers.
     *
     * @param via the hop through the intercepted proxy that opened the tunnel, or null if the
     *     proxy's own connection reaches the server
     */
    private ClientConnection(ClientConnection parent, Socket tunnel, Hop via) {
        this.server = parent.server;
        this.rawSocket = tunnel;
        this.owner = parent.owner;
        this.via = via;
        if (via != null) via.consumer = this;
        clientDetails.setClientAddress(parent.clientDetails.getClientAddress());
        clientDetails.setUserName(parent.clientDetails.getUserName());
        this.proxyHeader = parent.proxyHeader;
        this.connectionMitm = parent.mitmManager();
        this.mitmChosen = true;
        this.authenticated = true;
        this.flowContext = new ClientFlowContext(id, clientDetails::getClientAddress, () -> sslSession, clientDetails);
        parent.flowContext.socksVersion().ifPresent(flowContext::socksVersion);
        this.http1 = new Http1ClientChannel(server, tunnel, flowContext, logPrefix, this::close);
    }

    /** The connection's own flow context (not one of its streams'). */
    ClientFlowContext connectionFlowContext() {
        return flowContext;
    }

    boolean isIdle() {
        Http2Connection h2 = http2;
        return h2 != null ? h2.isIdle() : idle;
    }

    /**
     * Starts a graceful stop: an idle connection is closed now; a busy HTTP/1 connection closes
     * after its exchange in progress, an HTTP/2 connection is sent GOAWAY and closes once its
     * streams have finished.
     */
    void stopGracefully() {
        Http2Connection h2 = http2;
        if (h2 != null) {
            h2.stopGracefully();
        } else if (idle) {
            close();
        }
    }

    /** Closes the client connection and every server connection it owns. */
    void close() {
        closed = true;
        Http2Connection h2 = http2;
        if (h2 != null) h2.closed();
        http1.closeSocket();
        Tls.closeQuietly(rawSocket);
        releaseServerConnections();
    }

    /** Gives up this client's server connections: idle pooled ones go back to the pool. */
    private void releaseServerConnections() {
        StreamServerConnections streams = streamConnections;
        if (streams != null) streams.releaseAll();
        // HTTP/2 connections to servers that only this client could use.
        if (ownsHttp2Connections && owner == this) server.http2Origins.closeOwnedBy(this);
        // And those through tunnels that this connection's sessions opened.
        for (Hop hop = via; hop != null && hop.consumer == this; hop = hop.parent) {
            if (server.http2Origins != null) server.http2Origins.closeOwnedBy(hop);
        }
        releaseSessionConnections();
    }

    /** Gives up the server connections of the session served now (not its streams'). */
    private void releaseSessionConnections() {
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

    // ---------------------------------------------------------------------------------------
    // The HTTP/1 connection: TLS, the PROXY header, reading request heads
    // ---------------------------------------------------------------------------------------

    @Override
    public void run() {
        boolean connectedFired = false;
        try {
            rawSocket.setTcpNoDelay(true);
            rawSocket.setSoTimeout(server.idleTimeoutMillis());
            clientDetails.setClientAddress((InetSocketAddress) rawSocket.getRemoteSocketAddress());
            http1.attach(rawSocket);
            if (server.acceptProxyProtocol) {
                proxyHeader = http1.readProxyHeader();
                if (proxyHeader.source() != null) {
                    clientDetails.setClientAddress(proxyHeader.source());
                }
            }
            server.trackers.fire(t -> t.clientConnected(flowContext));
            connectedFired = true;
            if (server.sslContextSource != null) {
                SSLSocket tls = handshakeWithClient(server.sslContextSource.getSslContext(),
                        server.authenticateSslClients, s -> {
                            server.sslContextSource.configure(s, false);
                            if (server.http2) offerHttp2(s);
                        }, null);
                if (server.http2 && "h2".equals(tls.getApplicationProtocol())) {
                    serveHttp2(tls, new byte[0], null);
                    return;
                }
            } else if ((server.socksServer || server.socksDetection) && http1.awaitRequest() && startsLikeSocks()) {
                serveSocks();
                return;
            } else if (server.socksServer) {
                if (http1.input().buffered() > 0) {
                    LOG.log(Level.DEBUG, logPrefix + "not a SOCKS client (first byte 0x"
                            + Integer.toHexString(http1.input().peek()) + "); closing");
                }
                return;
            } else if (server.http2Cleartext && http1.awaitRequest() && http1.startsWithHttp2Preface()) {
                // HTTP/2 with prior knowledge: the whole connection, preface included, is HTTP/2's.
                serveHttp2(rawSocket, http1.drainBuffered(), null);
                return;
            } else if (server.transparent && server.reverseProxy == null && http1.awaitRequest()
                    && http1.startsLikeTls()) {
                // TLS without a CONNECT (redirected to the proxy): routed by its SNI.
                serveTransparentTls();
                return;
            }
            if (server.reverseProxy != null && server.reverseProxy.rawTcp()) {
                serveImplicitConnect(server.reverseProxy.hostAndPort());
                return;
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
    private SSLSocket handshakeWithClient(SSLContext context, boolean needClientAuth,
            Consumer<SSLSocket> configurer, String host) throws IOException {
        server.trackers.fire(t -> t.clientSSLHandshakeStarted(flowContext));
        flowContext.clientTlsStarted();
        SSLSocket tls;
        try {
            tls = http1.startTls(context, needClientAuth, configurer, new TlsLog.Peer(logPrefix, "client", host));
        } catch (IOException e) {
            server.trackers.fire(t -> t.tlsHandshakeFailed(flowContext, true, e));
            throw e;
        }
        flowContext.clientTlsFinished();
        sslSession = tls.getSession();
        SSLSession session = sslSession;
        server.trackers.fire(t -> t.clientSSLHandshakeSucceeded(flowContext, session));
        return tls;
    }

    /**
     * Offers HTTP/2 to a client of the proxy's TLS listener: ALPN {@code h2}, else {@code
     * http/1.1}. A client that offers neither (or no ALPN at all) gets no protocol back and speaks
     * HTTP/1.1, as without HTTP/2; the JDK's own selection would instead fail the handshake.
     */
    private static void offerHttp2(SSLSocket socket) {
        SSLParameters params = socket.getSSLParameters();
        params.setApplicationProtocols(new String[] {"h2", "http/1.1"});
        socket.setSSLParameters(params);
        socket.setHandshakeApplicationProtocolSelector((s, offered) ->
                offered.contains("h2") ? "h2" : offered.contains("http/1.1") ? "http/1.1" : "");
    }

    /** A fatal TLS {@code unrecognized_name} alert (RFC 8446 section 6.2), for a ClientHello without SNI. */
    private static final byte[] UNRECOGNIZED_NAME_ALERT = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70};

    /**
     * Serves a TLS connection that arrived without a {@code CONNECT} on a transparent listener: its
     * ClientHello's SNI names the server ({@link DefaultHttpProxyServer#transparentTlsPort} on that
     * host), and the connection then goes on as a {@code CONNECT} to it would. Java cannot read the
     * original destination of a redirected connection (no {@code SO_ORIGINAL_DST}), so without SNI
     * there is nowhere to go.
     */
    private void serveTransparentTls() throws IOException {
        ClientStart start = peekClient(null);
        ClientHello hello = start.hello();
        if (hello == null || hello.sni() == null) {
            String reason = hello == null ? "no readable ClientHello (" + start.note() + ")" : "a ClientHello without SNI";
            LOG.log(Level.INFO, logPrefix + "transparent TLS connection with " + reason
                    + ": the server cannot be told (the destination is taken from SNI); closing");
            if (hello != null) {
                try {
                    http1.writeRaw(UNRECOGNIZED_NAME_ALERT);
                } catch (IOException ignored) {
                    // closing anyway
                }
            }
            ProtocolException e = new ProtocolException("transparent TLS connection with " + reason);
            server.trackers.fire(t -> t.connectionExceptionCaught(flowContext, e));
            return;
        }
        // Known before the made-up CONNECT, whose filters may already look at it.
        flowContext.clientHello(hello);
        serveImplicitConnect(new HostAndPort(hello.sni(), server.transparentTlsPort).toString());
    }

    /**
     * Serves the connection as if its client had sent {@code CONNECT hostAndPort} (and the proxy
     * had answered it): authentication, filters, routing, the host rules and interception apply as
     * to a real one, but nothing is written to the client in HTTP. A refused request closes the
     * connection.
     */
    private void serveImplicitConnect(String hostAndPort) throws IOException {
        serveImplicitConnect(hostAndPort, 0, null);
    }

    /**
     * {@link #serveImplicitConnect(String)} for a SOCKS client ({@code socks} its version, else 0),
     * which is answered in SOCKS: once the server is connected, or with why it could not be.
     *
     * @param authorization the {@code Proxy-Authorization} the client's SOCKS credentials make, or null
     */
    private void serveImplicitConnect(String hostAndPort, int socks, String authorization) throws IOException {
        idle = false;
        flowContext.startExchange();
        HttpRequest connect = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.CONNECT, hostAndPort);
        connect.headers().set(HttpHeaderNames.HOST, hostAndPort);
        if (authorization != null) connect.headers().set(HttpHeaderNames.PROXY_AUTHORIZATION, authorization);
        implicitConnect = true;
        socksConnect = socks;
        handleRequest(http1, connect);
    }

    // ---------------------------------------------------------------------------------------
    // SOCKS clients: the handshake, then a CONNECT the proxy makes up
    // ---------------------------------------------------------------------------------------

    /**
     * Whether the connection's first byte, received and not consumed, is a SOCKS version: 5, or 4
     * for SOCKS4 and 4a. No HTTP request, TLS record or HTTP/2 preface starts with either.
     */
    private boolean startsLikeSocks() throws IOException {
        int first = http1.input().peek();
        return first == Socks.VERSION_5 || first == Socks.VERSION_4;
    }

    /**
     * Serves a SOCKS client: the handshake ({@link SocksHandshake}), within the TLS handshake
     * timeout, then its request as a {@code CONNECT} the proxy makes up, which is authenticated,
     * filtered, routed, intercepted or tunnelled as an HTTP client's {@code CONNECT} would be. The
     * server is connected before the client is answered, so a failure is reported with its reply
     * code; the client's first bytes are read only after the answer, as after an HTTP {@code
     * CONNECT}'s {@code 200}.
     */
    private void serveSocks() throws IOException {
        ByteReader in = http1.input();
        int version = in.peek();
        flowContext.socksVersion(version);
        long deadline = server.tlsHandshakeTimeout.isZero() ? 0 : System.nanoTime() + server.tlsHandshakeTimeout.toNanos();
        SocksHandshake.Destination destination;
        try {
            destination = SocksHandshake.accept(in, n -> ensureBuffered(in, n, deadline, "SOCKS handshake"),
                    http1::writeRaw, socksAuthenticator());
        } catch (SocksHandshake.Refused e) {
            LOG.log(Level.DEBUG, logPrefix + "SOCKS client refused: " + e.getMessage());
            return;
        }
        String authorization = destination.user() == null ? null : "Basic " + Base64.getEncoder().encodeToString(
                (destination.user() + ":" + destination.password()).getBytes(UTF_8));
        LOG.log(Level.DEBUG, logPrefix + "SOCKS" + destination.version() + " CONNECT " + destination.hostAndPort());
        serveImplicitConnect(destination.hostAndPort(), destination.version(), authorization);
    }

    /**
     * The proxy's authenticator, as a SOCKS handshake asks it: SOCKS5 credentials as {@code
     * Proxy-Authorization: Basic} on a made-up {@code CONNECT} whose target is not known yet
     * ({@code 0.0.0.0:0}, SOCKS's unspecified address), and a client without credentials as that
     * request without the field. An accepted client is authenticated as an HTTP client is.
     */
    private SocksHandshake.Authenticator socksAuthenticator() {
        return new SocksHandshake.Authenticator() {
            @Override
            public boolean required() {
                return server.proxyAuthenticator != null;
            }

            @Override
            public boolean acceptsWithout() {
                return socksAuthenticate(null);
            }

            @Override
            public boolean accepts(String user, String password) {
                return socksAuthenticate("Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes(UTF_8)));
            }
        };
    }

    private boolean socksAuthenticate(String authorization) {
        HttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.CONNECT, SOCKS_UNKNOWN_TARGET);
        request.headers().set(HttpHeaderNames.HOST, SOCKS_UNKNOWN_TARGET);
        if (authorization != null) request.headers().set(HttpHeaderNames.PROXY_AUTHORIZATION, authorization);
        AuthResult result;
        try {
            result = server.proxyAuthenticator.authenticate(request, flowContext);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "proxy authenticator threw; refusing the SOCKS client", e);
            return false;
        }
        return recordAuthentication(result);
    }

    /** The target of the request a SOCKS client is authenticated with, before it has named one. */
    private static final String SOCKS_UNKNOWN_TARGET = "0.0.0.0:0";

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
                if (http1.awaitRequest()) {
                    flowContext.startExchange();
                }
                request = http1.readRequest();
            } catch (HttpParseException e) {
                if (LOG.isLoggable(Level.DEBUG)) {
                    LOG.log(Level.DEBUG, logPrefix + "bad request from client: " + e.getMessage());
                }
                http1.reject(e.status());
                return;
            }
            if (request == null) {
                return;
            }
            idle = false;
            if (!handleRequest(http1, request)) {
                return;
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Exchanges: the same for every transport, which they reach through a ClientChannel
    // ---------------------------------------------------------------------------------------

    /**
     * Handles one request that arrived on {@code channel}: everything from here on is the same for
     * any transport. Returns whether the client connection stays open.
     */
    private boolean handleRequest(ClientChannel channel, HttpRequest request) throws IOException {
        // A CONNECT or an absolute-form request inside a session goes to the session's server,
        // which the client takes for its proxy; so does everything inside the tunnel one opened.
        Hop hop = via;
        channel.flowContext().forwardedVia(mitmHostAndPort != null && isProxyRequest(request) ? mitmHostAndPort
                : hop != null ? hop.proxy : null);
        if (!server.trackers.isEmpty()) {
            // Trackers get a snapshot: the request itself is rewritten while it is proxied.
            HttpRequest snapshot = copy(request);
            server.trackers.fire(t -> t.requestReceivedFromClient(channel.flowContext(), snapshot));
        }
        MessageBody body;
        try {
            body = channel.requestBody(request);
        } catch (HttpParseException e) {
            channel.reject(e.status());
            return false;
        }
        Exchange ex = new Exchange(channel, request, body, channel.clientKeepAlive(request));
        ex.implicit = implicitConnect;
        ex.socks = socksConnect;
        implicitConnect = false;
        socksConnect = 0;
        if (server.reverseProxy != null && !ex.implicit && !ProxyUtils.isCONNECT(request)) {
            reverseProxyTarget(request);
        }

        if (server.proxyAuthenticator != null) {
            // Requests in an intercepted session (HTTP/2 streams included) are covered by the
            // CONNECT that started it. Streams of an h2c connection, which run concurrently,
            // each authenticate on their own.
            HttpResponse refusal = null;
            if (mitmHostAndPort == null && channel.multiplexed()) {
                refusal = authenticateStream(ex);
            } else if (mitmHostAndPort == null && (!authenticated || server.proxyAuthenticator.authenticateEveryRequest())) {
                refusal = authenticate(ex);
            }
            if (refusal != null) {
                return respondDirect(ex, refusal, false, ResponseSource.PROXY);
            }
            // The credentials were for this proxy, whatever their scheme: never forward them. Inside
            // an intercepted session they are the intercepted server's (a CONNECT forwarded there).
            if (mitmHostAndPort == null) request.headers().remove(HttpHeaderNames.PROXY_AUTHORIZATION);
        }

        // With no filters configured, skip the request copy the filters API hands them.
        HttpFilters filters = NOOP;
        if (server.filtersSource.getClass() != HttpFiltersSourceAdapter.class) {
            HttpRequest original = copy(request);
            filters = server.filtersSource.filterRequest(original, ex.flow);
            // Built filters that a source (such as a lambda) returned as they are still get the
            // per-exchange state their logger needs; bound ones return themselves.
            if (filters instanceof HttpFiltersBuilder.Built built) filters = built.filterRequest(original, ex.flow);
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
            LOG.log(Level.WARNING, ex.log + "exchangeEnded threw", e);
        }
    }

    /** Handles a request whose filters have been created. Returns whether the client connection stays open. */
    private boolean handleFilteredRequest(Exchange ex) throws IOException {
        HttpRequest request = ex.request;
        int maxBuffer = server.filtersSource.getMaximumRequestBufferSizeInBytes();
        if (maxBuffer <= 0 && !ProxyUtils.isCONNECT(request)) {
            maxBuffer = ex.filters.requestBufferSizeInBytes(request);
        }
        if (maxBuffer > 0 && !ProxyUtils.isCONNECT(request) && ex.channel.tunnelProtocol() == null) {
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

        if (ex.channel.tunnelProtocol() != null && !"websocket".equals(ex.channel.tunnelProtocol())) {
            return respondDirect(ex, errorResponse(ex, HttpResponseStatus.valueOf(501),
                    "Unsupported extended CONNECT protocol"), true, ResponseSource.PROXY);
        }

        if (ProxyUtils.isCONNECT(ex.request)) {
            if (server.reverseProxy != null && !ex.implicit) {
                return respondFailure(ex, new ProxyFailure.BadRequest("CONNECT is not supported by a reverse proxy"), true);
            }
            if (!ex.channel.supportsTunnels()) {
                // A future transport may carry requests without supporting tunnels.
                FullHttpResponse notImplemented = errorResponse(ex, HttpResponseStatus.valueOf(501),
                        "Not Implemented: CONNECT on this transport");
                return respondDirect(ex, notImplemented, true, ResponseSource.PROXY);
            }
            return handleConnect(ex);
        }

        if (server.reverseProxy != null && mitmHostAndPort == null && !redirected(ex)) {
            // Every request goes to the one upstream, unless a filter pointed it at an absolute URI
            // of its own (as in an intercepted session, below); its TLS is set up as an
            // intercepted server's.
            return proxyRequest(ex, server.reverseProxy.hostAndPort(), server.reverseProxy.tls());
        }

        if (mitmHostAndPort == null
                && !server.allowRequestsToOriginServer
                && !ProxyUtils.isAbsoluteUri(ex.request.uri())) {
            // An origin-form request means the client thinks we are the origin; refusing avoids
            // proxying to ourselves in a loop.
            return respondFailure(ex, new ProxyFailure.BadRequest("the proxy needs an absolute URI"), true);
        }

        // Requests in a session (intercepted TLS, or plain HTTP) go to the CONNECT target, unless a
        // filter pointed the request at an absolute URI of its own (map_remote, a script assigning
        // req.uri): then it goes where that URI says, over TLS for https. (A plain HTTP session's
        // go without TLS.) An absolute URI the client sent itself is a proxy request for the
        // session's server, which the client takes for its proxy: it goes there as it is.
        boolean redirected = mitmHostAndPort != null && redirected(ex);
        if (redirected) {
            // Not through the session's server, then (but still through a hop's, inside one).
            Hop hop = via;
            ex.flow.forwardedVia(hop != null ? hop.proxy : null);
        }
        boolean pinned = mitmHostAndPort != null && !redirected;
        ex.proxyForm = pinned && ProxyUtils.isAbsoluteUri(ex.request.uri());
        String hostAndPort = pinned ? mitmHostAndPort : identifyHostAndPort(ex.request);
        if (hostAndPort == null) {
            return respondFailure(ex, new ProxyFailure.NoRoute(null), false);
        }
        return proxyRequest(ex, hostAndPort, pinned ? !plainSession : isSecureUri(ex.request.uri()));
    }

    /**
     * Whether filters gave a request an absolute URI other than the one it arrived with, so that
     * it leaves the session's server (or a reverse proxy's upstream). An absolute URI the client
     * sent, left as it was, is not a redirect: inside a session it is a proxy request for the
     * session's server ({@link Exchange#proxyForm}); a reverse proxy has made it origin-form
     * before any filter ran ({@link #reverseProxyTarget}).
     */
    private static boolean redirected(Exchange ex) {
        String uri = ex.request.uri();
        return ProxyUtils.isAbsoluteUri(uri) && !uri.equals(ex.originalUri);
    }

    /**
     * Whether a client asks for {@code request} as of a proxy: a {@code CONNECT}, or a request in
     * absolute-form. Inside a session, such requests go to the session's server.
     */
    private static boolean isProxyRequest(HttpRequest request) {
        return ProxyUtils.isCONNECT(request) || ProxyUtils.isAbsoluteUri(request.uri());
    }

    /** Whether {@code uri} is an absolute {@code https://} (or {@code wss://}) URI. */
    private static boolean isSecureUri(String uri) {
        return uri.regionMatches(true, 0, "https://", 0, 8) || uri.regionMatches(true, 0, "wss://", 0, 6);
    }

    // ---------------------------------------------------------------------------------------
    // Plain HTTP requests
    // ---------------------------------------------------------------------------------------

    /**
     * Points a request at the reverse proxy's upstream: origin-form, with the upstream's {@code
     * Host} unless {@code keepHostHeader} (as mitmproxy's reverse mode does, before any hook).
     */
    private void reverseProxyTarget(HttpRequest request) {
        String uri = request.uri();
        if (ProxyUtils.isAbsoluteUri(uri)) {
            String authority = ProxyUtils.parseHostAndPort(uri);
            request.setUri(ProxyUtils.stripHost(uri));
            if (server.keepHostHeader && authority != null && !authority.isEmpty()) {
                request.headers().set(HttpHeaderNames.HOST, authority);
            }
        }
        if (!server.keepHostHeader) {
            request.headers().set(HttpHeaderNames.HOST, server.reverseProxy.hostHeader());
        }
    }

    /**
     * Whether the intercepted session's requests may use HTTP/2 to the server: unless its client
     * offered ALPN protocols without {@code h2}, so a client that wants HTTP/1.1 never gets HTTP/2
     * upstream.
     */
    private boolean sessionAllowsHttp2Upstream() {
        ClientHello hello = flowContext.getClientHello();
        return hello == null || hello.alpnProtocols().isEmpty() || hello.offersAlpn(ClientHello.H2);
    }

    /**
     * The ALPN protocols TLS connections to servers offer: those the client offered (mitmproxy's
     * mirroring), of those the proxy speaks ({@code h2} only with {@code offerHttp2}), so the
     * server picks what the client would have; or, for a client that sent no ALPN (and outside
     * intercepted sessions), {@code h2} and {@code http/1.1} with {@code offerHttp2}, else none.
     *
     * @return the protocols, or null to send no ALPN extension
     */
    private static List<String> upstreamAlpn(boolean offerHttp2, ClientHello hello) {
        if (hello == null || hello.alpnProtocols().isEmpty()) {
            return offerHttp2 ? List.of(ClientHello.H2, ClientHello.HTTP_1_1) : null;
        }
        List<String> mirrored = hello.httpAlpnProtocols(offerHttp2);
        return mirrored.isEmpty() ? null : mirrored;
    }

    /** The ClientHello of the intercepted TLS session whose requests are being served, if any. */
    private ClientHello sessionHello() {
        return mitmHostAndPort != null && !plainSession ? flowContext.getClientHello() : null;
    }

    /**
     * Proxies a request (not a {@code CONNECT}) to {@code hostAndPort}.
     *
     * @param tls whether the server connection uses TLS: inside an intercepted TLS session (not a
     *     plain HTTP one), to a reverse proxy's {@code https://} upstream, or for an absolute {@code
     *     https://} URI
     */
    private boolean proxyRequest(Exchange ex, String hostAndPort, boolean tls) throws IOException {
        Mode mode = tls || ex.channel.secureWebSocket() ? Mode.TLS : Mode.PLAIN;
        if (mode == Mode.TLS && mitmHostAndPort == null && server.mitmManager != null) {
            // TLS to an https:// URI (or a reverse proxy's upstream) outside an intercepted
            // session: the manager's server trust applies, as it does to intercepted requests.
            mitmManager();
        }
        String key = mode + "|" + hostAndPort;
        if (ex.proxyForm && (usesPool(mode) || mode == Mode.PLAIN && server.chainProxyManager != null && via == null)) {
            // A proxy request carries the client's credentials for the session's server: it goes on
            // connections of the client's own, never pooled, nor ones that hand an HTTP chained
            // proxy their requests (the proxy request is the session's server's).
            key += "|proxy";
        }
        boolean webSocket = ProxyUtils.isSwitchingToWebSocketProtocol(ex.request);
        boolean pooled = !webSocket && !ex.proxyForm && usesPool(mode);
        // Concurrent exchanges (HTTP/2 streams) never share an HTTP/1.1 server connection: each
        // takes an idle one of the client's for the exchange, or makes one.
        boolean multiplexed = ex.channel.multiplexed();
        // HTTP/2 to the server is negotiated on TLS; WebSockets additionally need RFC 8441.
        boolean http2 = server.http2Origins != null && mode == Mode.TLS
                && (mitmHostAndPort == null || sessionAllowsHttp2Upstream());
        ex.offerHttp2 = http2;
        // Per-request leases always come fresh from the pool; otherwise reuse this client's own.
        ServerConnection conn = pooled && leasesPerRequest(mode) ? null
                : multiplexed ? takeStreamConnection(key, ex, hostAndPort) : serverConnections.get(key);
        if (conn != null && !conn.isOpen()) {
            serverConnections.remove(key, conn);
            conn = null;
        }
        List<ChainedProxy> route = null;
        boolean nextHopOrigin;
        if (conn != null) {
            nextHopOrigin = conn.nextHopIsOrigin();
        } else {
            route = routeFor(ex, hostAndPort);
            if (route == null) {
                return respondFailure(ex, new ProxyFailure.NoRoute(hostAndPort), false);
            }
            nextHopOrigin = isNextHopOrigin(route.getFirst(), mode);
        }
        // A proxy request stays in absolute-form: the session's server is the client's proxy.
        nextHopOrigin &= !ex.proxyForm;

        // TE is hop-by-hop, but an HTTP/2 server is told the client takes trailers: the proxy relays them.
        ex.trailersAccepted = acceptsTrailers(ex.request);
        // (Proxy-Authorization is hop-by-hop too, but a proxy request's is for the server it goes to.)
        List<String> credentials = ex.proxyForm ? ex.request.headers().getAll(HttpHeaderNames.PROXY_AUTHORIZATION)
                : List.of();
        modifyRequestHeadersToReflectProxying(ex.request, nextHopOrigin, webSocket);
        for (String credential : credentials) ex.request.headers().add(HttpHeaderNames.PROXY_AUTHORIZATION, credential);
        if (ex.request.protocolVersion().majorVersion() >= 2) {
            // An HTTP/2 stream's request reaches the server as HTTP/1.1 (its Via says 2).
            ex.request.setProtocolVersion(HttpVersion.HTTP_1_1);
        }
        if (webSocket && (rewritesFrames(ex.filters) || rewritesMessages(ex.filters))) {
            // Filters read payloads through permessage-deflate, but not through other extensions.
            String offers = PerMessageDeflate.supportedOffers(
                    ex.request.headers().getAllElements(HttpHeaderNames.SEC_WEBSOCKET_EXTENSIONS));
            if (offers == null) {
                ex.request.headers().remove(HttpHeaderNames.SEC_WEBSOCKET_EXTENSIONS);
            } else {
                ex.request.headers().set(HttpHeaderNames.SEC_WEBSOCKET_EXTENSIONS, offers);
            }
        }

        if (server.littleProxyCompatibility && conn == null && via == null
                && route.getFirst() == ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION) {
            // LittleProxy resolves the server before proxyToServerRequest, and answers 502 without
            // calling it when the name does not resolve.
            try {
                ex.preResolve(hostAndPort, resolveServer(hostAndPort, ex));
            } catch (UnknownHostException e) {
                reportServerFailure(new FullFlowContext(ex.flow, hostAndPort, null, null), e);
                return respondFailure(ex, new ProxyFailure.UnresolvedHost(hostAndPort, e), false);
            }
        }

        HttpResponse shortCircuit = ex.filters.proxyToServerRequest(ex.request);
        if (shortCircuit != null) {
            return respondDirect(ex, shortCircuit, true, ResponseSource.FILTER);
        }

        boolean replayable = ex.request instanceof FullHttpRequest || !ex.body.hasBody();
        for (int attempt = 0; ; attempt++) {
            String http2Key = null;
            if (conn == null) {
                if (route == null) {
                    route = routeFor(ex, hostAndPort);
                    if (route == null) {
                        return respondFailure(ex, new ProxyFailure.NoRoute(hostAndPort), false);
                    }
                }
                // A stream on an HTTP/2 connection to the server, if there is one with room.
                http2Key = http2 ? http2Key(mode, hostAndPort, route.getFirst()) : null;
                if (http2Key != null) {
                    try {
                        conn = server.http2Origins.stream(http2Key, ex.flow, hostAndPort, ex.log,
                                ProxyUtils.isHEAD(ex.request), Math.max(1000, connectTimeoutMillis(ex)));
                    } catch (IOException e) {
                        LOG.log(Level.DEBUG, ex.log + "no HTTP/2 stream to " + hostAndPort + ": " + e.getMessage());
                        return respondFailure(ex, new ProxyFailure.NoConnectionAvailable(hostAndPort), false);
                    }
                    if (conn != null && LOG.isLoggable(Level.DEBUG)) {
                        LOG.log(Level.DEBUG, ex.log + "new stream on the HTTP/2 connection to " + hostAndPort);
                    }
                }
            }
            if (conn == null) {
                // (Making a connection for an HTTP/2 key is reported back, so others stop waiting for it.)
                boolean reported = http2Key == null;
                try {
                    try {
                        // (A plain proxy request needs a way to the session's server itself: a
                        // tunnel through an HTTP chained proxy, which would take it for its own.)
                        conn = pooled ? lease(hostAndPort, ex, route, mode)
                                : connect(hostAndPort, ex, route, ex.proxyForm && mode == Mode.PLAIN ? Mode.TUNNEL : mode);
                    } catch (SharedConnectionPool.PoolExhaustedException e) {
                        LOG.log(Level.DEBUG, ex.log + e.getMessage());
                        return respondFailure(ex, new ProxyFailure.NoConnectionAvailable(hostAndPort), false);
                    } catch (ClientFailure e) {
                        LOG.log(Level.DEBUG, ex.log + "client left before " + hostAndPort + " could be reached: "
                                + e.getCause());
                        ex.channel.close();
                        return false;
                    } catch (IOException e) {
                        LOG.log(Level.DEBUG, ex.log + "unable to connect to " + hostAndPort + ": " + unwrap(e));
                        return respondFailure(ex, connectFailure(hostAndPort, e), false);
                    }
                    if (conn.http2) {
                        // The server chose HTTP/2: the connection is shared from now on, and this
                        // exchange takes its first stream.
                        reported = true;
                        ServerConnection carrier = conn;
                        try {
                            conn = adoptHttp2(carrier, http2Key, mode, hostAndPort, ex);
                        } catch (IOException e) {
                            LOG.log(Level.DEBUG, ex.log + "HTTP/2 with " + hostAndPort + " failed: " + e.getMessage());
                            return respondFailure(ex, new ProxyFailure.BadServerResponse(hostAndPort, e), false);
                        }
                    } else {
                        if (http2Key != null) server.http2Origins.negotiatedHttp1(http2Key);
                        reported = true;
                        conn.key = key;
                        if (multiplexed) {
                            streamConnections.add(conn);
                        } else {
                            serverConnections.put(key, conn);
                        }
                    }
                } finally {
                    if (!reported) server.http2Origins.connectFailed(http2Key);
                }
                if (!ex.proxyForm && conn.nextHopIsOrigin() != nextHopOrigin) {
                    nextHopOrigin = conn.nextHopIsOrigin();
                    adjustUriForNextHop(ex.request, hostAndPort, nextHopOrigin);
                }
            }
            if (webSocket && conn.multiplexed() && !conn.supportsWebSockets()) {
                // Keep the HTTP/2 connection for ordinary requests. This WebSocket needs a
                // separate HTTP/1.1 connection when the origin does not advertise RFC 8441.
                conn.close();
                conn = null;
                http2 = false;
                ex.offerHttp2 = false;
                continue;
            }
            try {
                // Reused connections may have been closed by the server while idle: retry those
                // (a few times, since a pool can hold several stale ones).
                return exchange(ex, conn, attempt < 3 && conn.used && replayable);
            } catch (StaleConnection e) {
                LOG.log(Level.DEBUG, ex.log + "retrying on a new connection after stale " + conn);
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
        // (A CONNECT forwarded to a proxy has no body: its stream's DATA are the tunnel's, later.)
        boolean connect = ProxyUtils.isCONNECT(request);
        boolean streamingBody = !(request instanceof FullHttpRequest) && ex.body.hasBody() && !connect;
        conn.inExchange = true;
        RequestPump pump = null;
        try {
            // The transport may close it if the client cancels the exchange (an HTTP/2 reset).
            ex.channel.serverConnectionInUse(conn);
            filters.proxyToServerRequestSending();
            stripRequestHeaders(request.headers());
            try {
                conn.writeRequestHead(request, streamingBody, ex.trailersAccepted);
            } catch (IOException e) {
                if (retryAllowed && conn.retryable(e)) throw new StaleConnection(e);
                throw new ServerFailure("write to server failed", e);
            }
            conn.used = true;
            if (!streamingBody) {
                ex.flow.mark(ClientFlowContext.REQUEST_SENT);
            }
            server.trackers.fire(t -> t.requestSentToServer(conn.flowContext, request));

            HttpResponse response = null;
            if (streamingBody && fullDuplex(ex, conn)) {
                // Both ends are HTTP/2 streams: the body goes on while the response comes back
                // (bidirectional streaming, as gRPC does).
                pump = new RequestPump(ex, conn);
            } else if (streamingBody) {
                HttpResponse early = null;
                if (HttpUtil.is100ContinueExpected(request)) {
                    // Let the server decide whether it wants the body before reading it from the
                    // client, which is waiting for a 100 (Continue). Servers that ignore Expect
                    // never answer, so after a short wait the proxy continues on their behalf.
                    early = awaitServerData(conn, CONTINUE_TIMEOUT_MS) ? readResponseHead(ex, conn, true, false) : null;
                    if (early == null || early.status().code() == 100) {
                        writeToClient(ex.channel::writeContinue);
                        early = null;
                    }
                }
                if (early == null) {
                    try {
                        pumpRequestBody(ex, conn);
                        ex.flow.mark(ClientFlowContext.REQUEST_SENT);
                    } catch (ServerWriteFailure e) {
                        // The server may have answered early (e.g. 413) and stopped reading.
                        LOG.log(Level.DEBUG, ex.log + "server stopped reading the request body", e);
                        early = readResponseHead(ex, conn, false, false);
                    }
                }
                if (early != null) {
                    response = early;
                    ex.bodyAbandoned = true;
                }
            }
            if (!streamingBody && !connect && !(request instanceof FullHttpRequest)
                    && observes(filters, OBSERVES_REQUEST_CONTENT)) {
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
            if (pump != null && pump.clientFailed()) return clientLeft(ex, conn, pump);
            filters.serverToProxyResponseTimedOut();
            conn.close();
            IOException cause = (IOException) e.getCause();
            reportServerFailure(conn.flowContext, cause);
            if (ex.responseStarted) {
                ex.channel.close();
                return false;
            }
            return respondFailure(ex, new ProxyFailure.ServerTimeout(conn.hostAndPort, cause), false);
        } catch (ServerFailure e) {
            if (pump != null && pump.clientFailed()) return clientLeft(ex, conn, pump);
            LOG.log(Level.DEBUG, ex.log + "server failure on " + conn, e);
            conn.close();
            IOException reason = e.reason();
            reportServerFailure(conn.flowContext, reason);
            if (ex.responseStarted) {
                ex.channel.close();
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
            LOG.log(Level.DEBUG, ex.log + "client failure", e);
            conn.close();
            if (e.getCause() instanceof HttpParseException bad && !ex.responseStarted) {
                // A malformed request body (bad chunk framing): tell the client before closing.
                ex.channel.reject(bad.status());
                return false;
            }
            ex.channel.close();
            return false;
        } finally {
            if (pump != null) pump.stop();
        }
    }

    /**
     * Whether the request body may be relayed while the response comes back, on a thread of its
     * own: only between HTTP/2 streams (an HTTP/1 connection reads its next request after this
     * one's body), and only when no filter or chained proxy sees the body's pieces, so filters are
     * never called from two threads at once. Not with {@code Expect: 100-continue}, which decides
     * about the body first.
     */
    private static boolean fullDuplex(Exchange ex, ServerConnection conn) {
        return ex.channel.multiplexed() && conn.multiplexed() && !HttpUtil.is100ContinueExpected(ex.request)
                && !observes(ex.filters, OBSERVES_REQUEST_CONTENT)
                && (conn.chainedProxy == null || !FILTERS_REQUEST_CONTENT.get(conn.chainedProxy.getClass()));
    }

    /** The client went away while its request body was being relayed: the exchange ends. */
    private static boolean clientLeft(Exchange ex, ServerConnection conn, RequestPump pump) {
        LOG.log(Level.DEBUG, ex.log + "client failure while relaying the request body", pump.failure);
        conn.close();
        ex.channel.close();
        return false;
    }

    /**
     * Relays a request body to the server on a virtual thread of its own, while the exchange's
     * thread relays the response ({@link #fullDuplex}). A client that fails stops the server stream
     * too; a server that stops reading only ends the relay, and its response decides the rest.
     */
    private final class RequestPump {
        private final Exchange ex;
        private final ServerConnection conn;
        private final Thread thread;
        volatile IOException failure;
        private volatile boolean done;

        RequestPump(Exchange ex, ServerConnection conn) {
            this.ex = ex;
            this.conn = conn;
            this.thread = Thread.ofVirtual().name(server.name + "-request-body-" + id).start(this::run);
        }

        private void run() {
            try {
                relayRequestBody(ex, conn);
                ex.flow.mark(ClientFlowContext.REQUEST_SENT);
            } catch (ServerWriteFailure e) {
                LOG.log(Level.DEBUG, ex.log + "server stopped reading the request body: " + e.getCause());
                failure = e;
            } catch (IOException e) {
                failure = e;
                conn.close();
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, ex.log + "unexpected error relaying the request body", e);
                failure = new IOException(e);
                conn.close();
            } finally {
                done = true;
            }
        }

        boolean clientFailed() {
            return failure instanceof ClientFailure;
        }

        /**
         * The exchange is over: a body still being relayed is abandoned (the server stream and
         * the client's are reset), and the relay's thread is waited for.
         */
        void stop() {
            if (!done) {
                conn.close();
                ex.channel.close();
            }
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
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
                conn.writeContent(content);
            } catch (IOException e) {
                throw new ServerWriteFailure(e);
            }
        }
    }

    /** Waits up to {@code millis} for the server to send something; false on timeout. */
    private static boolean awaitServerData(ServerConnection conn, int millis) throws IOException {
        try {
            return conn.awaitResponse(millis);
        } catch (IOException e) {
            throw new ServerFailure("read from server failed", e);
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
                if (conn.awaitResponseHead()) {
                    ex.flow.markFirst(ClientFlowContext.FIRST_RESPONSE_BYTE);
                }
                response = conn.readResponse(server.limits);
            } catch (SocketTimeoutException e) {
                throw new ServerTimeout(e);
            } catch (HttpParseException e) {
                throw new ServerFailure("malformed response", e);
            } catch (IOException e) {
                if (retryAllowed && conn.retryable(e)) throw new StaleConnection(e);
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
                writeToClient(() -> ex.channel.writeInformational(response));
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
        // The extensions the server agreed to, before filters see (and might change) the answer.
        List<String> serverExtensions = response.status().code() == 101
                ? response.headers().getAllElements(HttpHeaderNames.SEC_WEBSOCKET_EXTENSIONS) : List.of();
        int upstreamStatus = conn.responseStatus(response);
        ex.flow.upstreamStatus(upstreamStatus);
        server.trackers.fire(t -> t.responseReceivedFromServer(conn.flowContext, response));
        if (ex.forwarding != null && response.status().code() / 100 == 2) {
            // The intercepted proxy opened the tunnel: forwardConnect takes it from here.
            ex.tunnelOpened = response;
            return false;
        }

        if ("websocket".equals(ex.channel.tunnelProtocol()) && !conn.multiplexed()
                && (response.status().code() == 101 || response.status().code() / 100 == 2)
                && !WebSocketHandshake.valid(request, response)) {
            // An RFC 8441 client cannot check the HTTP/1 nonce once the bridge strips it.
            // Nor may an ordinary HTTP response's 2xx be mistaken for CONNECT acceptance.
            throw new ServerFailure("invalid HTTP/1 WebSocket opening handshake",
                    new IOException("origin did not accept the WebSocket upgrade"));
        }

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

        MessageBody body = switching ? null : conn.responseBody(framing, server.limits);
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
            return abort(ex, conn);
        }
        if (filtered instanceof FullHttpMessage && body != null) {
            // The filter replaced a streamed response with a complete one: discard the original body.
            serverKeepAlive &= drain(body);
            body = null;
        }

        boolean bodyAllowed = Framing.responseMayHaveBody(res, request.method());
        boolean closeClient = !ex.clientKeepAlive || ex.bodyAbandoned;
        // The transport decides how the body is delimited, which may mean closing after it.
        closeClient |= ex.channel.adaptFraming(res, bodyAllowed && !switching && !(res instanceof FullHttpMessage));
        if (!server.transparent) {
            modifyResponseHeadersToReflectProxying(res, ex.forwarding != null || ex.proxyForm);
        }
        if (server.stripAltSvcH3) {
            AltSvc.stripHttp3(res.headers());
        }
        if (switching) {
            ex.channel.setUpgrade(res, upgrade);
        } else {
            ex.channel.setKeepAlive(res, !closeClient);
        }

        HttpObject toClient = filters.proxyToClientResponse(res);
        if (!(toClient instanceof HttpResponse finalResponse)) {
            return abort(ex, conn);
        }
        if (finalResponse instanceof FullHttpMessage && body != null) {
            // Replaced by a complete response here too: the server's body must not follow it.
            serverKeepAlive &= drain(body);
            body = null;
        }
        if (switching && finalResponse.status().code() != 101) {
            // A filter rejected the opening handshake: complete its response and release the
            // origin now, rather than entering a relay that can never become a WebSocket.
            ex.responseStarted = true;
            writeToClient(() -> ex.channel.writeComplete(finalResponse,
                    Framing.responseMayHaveBody(finalResponse, request.method())));
            ResponseSource rejectedSource = source(ResponseSource.SERVER, head, upstreamStatus, finalResponse);
            server.trackers.fire(t -> t.responseSentToClient(ex.flow, finalResponse, rejectedSource));
            completed(ex, finalResponse, rejectedSource);
            ex.channel.serverConnectionDone(conn);
            conn.close();
            if (!ex.channel.multiplexed()) ex.channel.close();
            return false;
        }
        ex.responseStarted = true;
        boolean writeBody = Framing.responseMayHaveBody(finalResponse, request.method());
        writeToClient(() -> ex.channel.writeHead(finalResponse, writeBody));
        ResponseSource source = source(ResponseSource.SERVER, head, upstreamStatus, finalResponse);
        server.trackers.fire(t -> t.responseSentToClient(ex.flow, finalResponse, source));

        if (body != null && prefetched.isEmpty() && !observes(filters, OBSERVES_RESPONSE_CONTENT)) {
            relayResponseBody(ex.channel, body);
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
                    return abort(ex, conn);
                }
                if (o instanceof HttpContent piece && !lastWritten) {
                    writeToClient(() -> ex.channel.writeContent(piece));
                    lastWritten = piece instanceof LastHttpContent;
                }
            }
            if (!lastWritten) {
                writeToClient(() -> ex.channel.writeContent(LastHttpContent.empty()));
            }
        }
        filters.serverToProxyResponseReceived();
        completed(ex, finalResponse, source);

        if (switching) {
            boolean webSocket = upgrade != null && HttpHeaders.splitList(upgrade).stream()
                    .anyMatch(token -> token.equalsIgnoreCase("websocket"));
            // Parsing buffers each frame before forwarding it, so only do it for filters that listen.
            WebSocketRelay relay = webSocket ? webSocketRelay(filters, serverExtensions, finalResponse, ex.channel.logPrefix())
                    : null;
            ex.channel.relay(conn, relay, null, server.name + "-upgrade-" + id);
            conn.close();
            return false;
        }
        if (conn.multiplexed()) {
            // A stream carries one exchange: it ends here (reset if the request is still being
            // sent), and its connection goes on serving others.
            ex.channel.serverConnectionDone(conn);
            conn.inExchange = false;
            conn.close();
        } else if (!serverKeepAlive || ex.forwarding != null || !ex.channel.serverConnectionDone(conn)) {
            // (Or the client cancelled the exchange, and its transport closed the connection. A
            // connection that an intercepted proxy refused a tunnel on is kept by no one.)
            conn.close();
        } else {
            conn.exchangeDone();
            conn.inExchange = false;
            if (conn.perRequestLease) {
                serverConnections.remove(conn.key, conn);
                conn.pool.release(conn);
            } else if (ex.channel.multiplexed()) {
                streamConnections.release(conn);
            }
        }
        if (closeClient) {
            ex.channel.close();
            return false;
        }
        return true;
    }

    /** The response to the current request has been written in full. */
    private void completed(Exchange ex, HttpResponse response, ResponseSource source) {
        ex.completed = true;
        ex.flow.mark(ClientFlowContext.RESPONSE_COMPLETE);
        server.trackers.fire(t -> t.responseCompleted(ex.flow, response));
        ex.filters.proxyToClientResponseSent(response, source);
    }

    /** Gives up the exchange: the server connection and the client's are in an unknown state. */
    private static boolean abort(Exchange ex, ServerConnection conn) {
        conn.close();
        ex.channel.close();
        return false;
    }

    private static boolean drain(MessageBody body) {
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

    /**
     * Copies a response body straight from the server to the client, without message objects: no
     * filter needs its pieces.
     */
    private void relayResponseBody(ClientChannel client, MessageBody body) throws IOException {
        byte[] buf = server.relayBuffers.take();
        try {
            relayResponseBody(client, body, buf);
        } finally {
            server.relayBuffers.give(buf);
        }
    }

    private static void relayResponseBody(ClientChannel client, MessageBody body, byte[] buf)
            throws IOException {
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
                client.writeData(buf, 0, n);
                if (flush) client.flush();
            });
        }
        HttpHeaders trailers = body.trailers();
        writeToClient(() -> client.writeEnd(trailers));
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
                conn.writeData(buf, 0, n);
                if (!ex.body.hasBufferedInput()) conn.flush();
            } catch (IOException e) {
                throw new ServerWriteFailure(e);
            }
        }
        try {
            conn.writeEnd(ex.body.trailers());
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
        if (mitmHostAndPort != null) {
            // The client takes the session's server for its proxy: an intercepted HTTPS proxy, or
            // an HTTP proxy whose session is plain HTTP.
            return forwardConnect(ex);
        }
        String hostAndPort = target.toString();
        // An HTTP/2 stream's CONNECT is intercepted inside the stream (interceptStream), as an
        // HTTP/1 connection's is.
        boolean mitm = server.mitmManager != null && mitmHostAndPort == null && server.reverseProxy == null
                && ex.filters.proxyToServerAllowMitm() && mitmManager() != null;
        if (mitm && server.hostRules != null && server.hostRules.ignoredByTarget(hostAndPort)) {
            // Whatever its SNI, the connection is ignored: no need to wait for its ClientHello.
            LOG.log(Level.DEBUG, ex.log + "tunnelling " + hostAndPort + ": an ignored host");
            mitm = false;
        }
        // A SOCKS client has no other way to send plain HTTP through the proxy than its tunnel: its
        // first bytes are looked at even without a MITM manager, and HTTP is served as HTTP (TLS is
        // tunnelled then, as one the MITM manager declines).
        boolean inspect = mitm || (ex.socks != 0 && server.mitmManager == null && server.reverseProxy == null
                && (server.hostRules == null || !server.hostRules.ignoredByTarget(hostAndPort)));
        Mode mode = mitm ? Mode.TLS : Mode.TUNNEL;
        // The session's requests may take streams on an HTTP/2 connection made now.
        ex.offerHttp2 = server.http2Origins != null;
        // TLS with the server waits for the client's ClientHello, whose protocols and name it mirrors.
        ex.deferServerTls = mitm;

        List<ChainedProxy> route = lookupRoute(request);
        if (route == null) {
            return respondFailure(ex, new ProxyFailure.NoRoute(hostAndPort), false);
        }
        modifyRequestHeadersToReflectProxying(request, false, false);
        HttpResponse shortCircuit = ex.filters.proxyToServerRequest(request);
        if (shortCircuit != null) {
            return respondDirect(ex, shortCircuit, true, ResponseSource.FILTER);
        }

        // An HTTP/2 connection to the server that the session's requests can share makes connecting
        // now unnecessary, as a pooled connection would.
        String http2Key = mitm && server.http2Origins != null ? http2Key(mode, hostAndPort, route.getFirst()) : null;
        SSLSession serverSession = null;
        if (http2Key != null) {
            try {
                serverSession = server.http2Origins.session(http2Key, Math.max(1000, connectTimeoutMillis(ex)));
            } catch (IOException e) {
                return respondFailure(ex, new ProxyFailure.NoConnectionAvailable(hostAndPort), false);
            }
        }
        // The server's ALPN choice on that shared connection.
        String serverAlpn = serverSession != null ? ClientHello.H2 : null;
        ServerConnection conn = null;
        // (Making a connection for an HTTP/2 key is reported back, so others stop waiting for it.)
        boolean reported = http2Key == null || serverSession != null;
        try {
            if (serverSession == null) {
                try {
                    try {
                        conn = usesPool(mode) ? lease(hostAndPort, ex, route, mode) : connect(hostAndPort, ex, route, mode);
                    } catch (NotTlsServer e) {
                        // As LittleProxy does (issue #71, e.g. ws:// through CONNECT): the client has not been
                        // answered yet, so it can still get a plain tunnel to the server instead of a 502.
                        LOG.log(Level.DEBUG, ex.log + e.getMessage() + "; tunnelling instead of intercepting");
                        mitm = false;
                        inspect = false;
                        mode = Mode.TUNNEL;
                        conn = connect(hostAndPort, ex, route, mode);
                    }
                } catch (SharedConnectionPool.PoolExhaustedException e) {
                    LOG.log(Level.DEBUG, ex.log + e.getMessage());
                    return respondFailure(ex, new ProxyFailure.NoConnectionAvailable(hostAndPort), false);
                } catch (ClientFailure e) {
                    LOG.log(Level.DEBUG, ex.log + "client left before " + hostAndPort + " could be reached: " + e.getCause());
                    ex.channel.close();
                    return false;
                } catch (IOException e) {
                    LOG.log(Level.DEBUG, ex.log + "CONNECT to " + hostAndPort + " failed: " + unwrap(e));
                    if (!mitm || !ex.filters.proxyToServerAllowOfflineMitm()) {
                        return respondFailure(ex, connectFailure(hostAndPort, e), false);
                    }
                    LOG.log(Level.DEBUG, ex.log + "intercepting " + hostAndPort + " without a server connection");
                }
                serverSession = conn != null && conn.socket instanceof SSLSocket tls ? tls.getSession() : null;
                // A reused pooled connection: what it was offered is unknown, so only h2 tells anything.
                serverAlpn = conn != null && conn.socket instanceof SSLSocket tls
                        && ClientHello.H2.equals(tls.getApplicationProtocol()) ? ClientHello.H2 : null;
            }
            if (conn != null && conn.http2) {
                // The server chose HTTP/2: the session's requests take streams on the connection.
                ServerConnection carrier = conn;
                conn = null;
                reported = true;
                adoptForSession(ex, carrier, mode, hostAndPort, http2Key);
            } else if (conn != null && conn.tlsPending && http2Key != null) {
                // What the server speaks is known only after the ClientHello: reported then. Others
                // wait for this connection only briefly until the ClientHello has come.
                ex.http2Claim = http2Key;
                server.http2Origins.awaitingClientHello(http2Key);
                reported = true;
            } else if (conn != null && http2Key != null && mode == Mode.TLS) {
                server.http2Origins.negotiatedHttp1(http2Key);
                reported = true;
            }
        } finally {
            if (!reported) server.http2Origins.connectFailed(http2Key);
        }
        if (inspect && !mitm && conn != null) {
            // Nothing is layered on the connection yet: the client's first bytes decide what it carries.
            conn.tlsPending = true;
        }
        try {
            return answerConnect(ex, conn, mitm, inspect, mode, serverSession, serverAlpn, target, hostAndPort, route,
                    http2Key);
        } finally {
            releaseHttp2Claim(ex);
        }
    }

    /** Ends {@code ex}'s claim to make an HTTP/2 connection, if it still holds one: others may make it. */
    private void releaseHttp2Claim(Exchange ex) {
        if (ex.http2Claim != null) {
            server.http2Origins.connectFailed(ex.http2Claim);
            ex.http2Claim = null;
        }
    }

    /** Completes the CONNECT exchange whose answer was written earlier (see {@link Exchange#connectResponse}). */
    private void completeConnect(Exchange ex) {
        HttpResponse response = ex.connectResponse;
        if (response != null) {
            ex.connectResponse = null;
            completed(ex, response, ex.connectSource);
        }
    }

    /**
     * Answers a CONNECT whose server connection is made (or not needed), and goes on with the connection.
     *
     * @param inspect whether the client's first bytes decide what the connection carries ({@link
     *     #interceptOrTunnel}), as they do when {@code mitm}; else it is a tunnel
     */
    private boolean answerConnect(Exchange ex, ServerConnection conn, boolean mitm, boolean inspect, Mode mode,
            SSLSession serverSession, String serverAlpn, HostAndPort target, String hostAndPort,
            List<ChainedProxy> route, String http2Key) throws IOException {
        if (conn != null) {
            conn.key = mode + "|" + hostAndPort;
            try {
                ex.channel.serverConnectionInUse(conn);
            } catch (IOException e) {
                conn.close();
                throw e;
            }
            if (ex.channel.multiplexed()) {
                // An intercepted stream's session takes the connection over (serveTunnel).
                if (!mitm) streamConnections.add(conn);
            } else {
                serverConnections.put(conn.key, conn);
            }
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
                ex.channel.close();
                return false;
            }
            return abort(ex, conn);
        }
        ResponseSource source = source(ResponseSource.PROXY, established, 200, response);
        if (ex.implicit && response.status().code() / 100 != 2) {
            // The client sent no CONNECT, so it gets no answer in HTTP; a filter's refusal closes it.
            if (conn != null) conn.close();
            if (ex.socks != 0) {
                return refuseSocks(ex, response, source);
            }
            ex.channel.close();
            return false;
        }
        if (ex.socks != 0) {
            // The SOCKS client's request succeeded: the server is connected (or will be, by the session).
            writeToClient(() -> http1.writeRaw(SocksHandshake.reply(ex.socks, Socks.REPLY_SUCCEEDED)));
            server.trackers.fire(t -> t.responseSentToClient(ex.flow, response, source));
        } else if (!ex.implicit) {
            writeToClient(() -> ex.channel.writeHead(response, response.status().code() / 100 != 2));
            server.trackers.fire(t -> t.responseSentToClient(ex.flow, response, source));
        }
        if (mitm && response.status().code() / 100 == 2) {
            // The exchange is complete once the proxy knows what to do with the connection (after
            // the server handshake, when intercepting), so its timings include that handshake.
            ex.connectResponse = response;
            ex.connectSource = source;
        } else if (!ex.implicit || ex.socks != 0) {
            completed(ex, response, source);
        }
        if (response.status().code() / 100 != 2) {
            // A filter turned the CONNECT into a failure.
            if (conn != null) conn.close();
            if (!(HttpUtil.isKeepAlive(response) && ex.clientKeepAlive)) {
                ex.channel.close();
                return false;
            }
            return true;
        }

        if (!inspect) {
            // In reverse:tcp:// mode behind a TLS listener, the bytes are the decrypted ones.
            boolean decrypted = server.reverseProxy != null && sslSession != null;
            ex.channel.relay(conn, null, tcpSession(ex.flow, target, decrypted), server.name + "-tunnel-" + id);
            conn.close();
            return false;
        }
        if (ex.channel.multiplexed()) {
            return interceptStream(ex, conn, serverSession, serverAlpn, target, hostAndPort, route, http2Key, null);
        }
        return interceptOrTunnel(ex, conn, serverSession, serverAlpn, target, hostAndPort, route, http2Key);
    }

    /**
     * Hands {@code carrier}, whose handshake negotiated HTTP/2, to {@link Http2Origins} for the
     * requests of the session being intercepted (and of others that may share it).
     */
    private void adoptForSession(Exchange ex, ServerConnection carrier, Mode mode, String hostAndPort, String http2Key) {
        serverConnections.remove(carrier.key, carrier);
        try {
            String key = http2Key(mode, hostAndPort, carrier.chainedProxy == null
                    ? ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION : carrier.chainedProxy);
            server.http2Origins.adopt(carrier, http2Key, key, http2Owner(mode, via), null, hostAndPort, ex.log, false);
        } catch (IOException e) {
            LOG.log(Level.DEBUG, ex.log + "HTTP/2 with " + hostAndPort + " failed: " + e.getMessage()
                    + "; its requests will connect again");
        }
    }

    // ---------------------------------------------------------------------------------------
    // After a CONNECT: the client's first bytes decide (mitmproxy's next layer)
    // ---------------------------------------------------------------------------------------

    /** What a client sent first after its {@code CONNECT} was accepted, or on a transparent listener. */
    private enum StartKind {
        /** A complete, readable ClientHello. */
        TLS,
        /** An HTTP/1 request line. */
        HTTP,
        /** Anything else: another protocol, an unreadable or oversized ClientHello, or the server spoke first. */
        OTHER,
        /** The client closed the connection without sending anything. */
        CLOSED
    }

    /**
     * The client's first bytes, which stay buffered for whatever serves the connection next.
     *
     * @param hello the ClientHello, for {@link StartKind#TLS}
     * @param note why the bytes are {@link StartKind#OTHER}, for log lines
     */
    private record ClientStart(StartKind kind, ClientHello hello, String note) {
        static ClientStart other(String note) {
            return new ClientStart(StartKind.OTHER, null, note);
        }
    }

    /**
     * How often the proxy looks whether a server spoke first while waiting for a client's first
     * bytes: a server-speaks-first protocol (SMTP, SSH, ...) through {@code CONNECT} must not wait
     * for a client that waits for the server.
     */
    private static final int SERVER_FIRST_CHECK_MILLIS = 100;

    /** The longest HTTP method the proxy recognizes when telling HTTP from other protocols. */
    private static final int MAX_METHOD_LENGTH = 20;

    /**
     * Reads the client's first bytes without consuming them: a TLS ClientHello (across as many
     * records as it takes, up to {@link TlsClientHello#MAX_MESSAGE_SIZE}), an HTTP request line, or
     * something else. With a connection to the server ({@code conn}), a server that sends first is
     * noticed while waiting.
     */
    private ClientStart peekClient(ServerConnection conn) throws IOException {
        ByteReader in = http1.input();
        if (!awaitClientFirst(in, conn)) {
            return in.buffered() == 0 && (conn == null || !serverSpoke(conn))
                    ? new ClientStart(StartKind.CLOSED, null, "closed") : ClientStart.other("the server spoke first");
        }
        int first = in.peek();
        if (first == 0x16) {
            // The whole ClientHello must arrive within the handshake deadline, as the rest of the
            // handshake must: a client cannot hold the connection by sending it a byte at a time.
            long deadline = server.tlsHandshakeTimeout.isZero() ? 0
                    : System.nanoTime() + server.tlsHandshakeTimeout.toNanos();
            int[] need = {5};
            while (true) {
                if (!ensureBuffered(in, need[0], deadline, "ClientHello")) {
                    return ClientStart.other("the client closed within its ClientHello");
                }
                byte[] data = in.peekBuffered();
                try {
                    byte[] message = TlsClientHello.message(data, data.length, TlsClientHello.MAX_MESSAGE_SIZE, need);
                    if (message != null) return new ClientStart(StartKind.TLS, TlsClientHello.parse(message), null);
                } catch (TlsClientHello.Malformed | TlsClientHello.TooLarge e) {
                    return ClientStart.other(e.getMessage());
                }
            }
        }
        // An HTTP/1 request starts with a method token (upper-case letters here) and a space.
        for (int i = 0; i <= MAX_METHOD_LENGTH; i++) {
            if (!in.ensureBuffered(i + 1)) return ClientStart.other("not HTTP");
            byte[] head = in.peekBuffered();
            int b = head[i];
            if (b == ' ' && i >= 3) {
                // "PRI * HTTP/2.0" is HTTP/2's preface: relayed as it is.
                boolean preface = i == 3 && head[0] == 'P' && head[1] == 'R' && head[2] == 'I';
                return preface ? ClientStart.other("HTTP/2 with prior knowledge") : new ClientStart(StartKind.HTTP, null, null);
            }
            if (b < 'A' || b > 'Z') break;
        }
        return ClientStart.other("neither TLS nor HTTP");
    }

    /**
     * {@link ByteReader#ensureBuffered} on the client's reader, failing with a {@link
     * SocketTimeoutException} once {@code deadline} ({@link System#nanoTime()}, 0 for none) passes.
     *
     * @param what what the client must send by then, for the exception's message
     */
    private boolean ensureBuffered(ByteReader in, int n, long deadline, String what) throws IOException {
        if (in.buffered() >= n || deadline == 0) return in.ensureBuffered(n);
        long remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
        if (remaining <= 0) {
            throw new SocketTimeoutException(what + " not complete within " + server.tlsHandshakeTimeout.toMillis() + " ms");
        }
        Socket client = http1.socket();
        int original = client.getSoTimeout();
        client.setSoTimeout((int) Math.max(1, original > 0 ? Math.min(original, remaining) : Math.min(Integer.MAX_VALUE, remaining)));
        try {
            return in.ensureBuffered(n);
        } finally {
            if (!client.isClosed()) client.setSoTimeout(original);
        }
    }

    /**
     * Waits for the client's first byte: true once it has come, false if the client closed first or
     * the server ({@code conn}, when not null) sent something first. Gives up, like any read, after
     * the idle timeout.
     */
    private boolean awaitClientFirst(ByteReader in, ServerConnection conn) throws IOException {
        if (in.buffered() > 0) return true;
        if (conn == null) return in.ensureBuffered(1);
        Socket client = http1.socket();
        int original = client.getSoTimeout();
        long deadline = original > 0 ? System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(original) : Long.MAX_VALUE;
        try {
            client.setSoTimeout(SERVER_FIRST_CHECK_MILLIS);
            while (true) {
                try {
                    return in.ensureBuffered(1);
                } catch (SocketTimeoutException e) {
                    if (serverSpoke(conn)) return false;
                    if (original > 0 && System.nanoTime() - deadline >= 0) throw e;
                }
            }
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

    /** How long a look at a TLS connection to a server waits for it to have spoken ({@link #serverSpoke}). */
    private static final int SERVER_TLS_LOOK_MILLIS = 1;

    /**
     * Whether the server has sent bytes on {@code conn} that nobody read yet (or closed it). On a
     * TLS connection, what the server sent is known only once decrypted, so a brief read looks.
     */
    private static boolean serverSpoke(ServerConnection conn) {
        try {
            if (conn.in.buffered() > 0) return true;
            if (conn.socket instanceof SSLSocket) {
                boolean spoke = conn.awaitResponse(SERVER_TLS_LOOK_MILLIS);
                // (Waiting held a buffer: an idle connection holds none.)
                if (!spoke) conn.in.release();
                return spoke;
            }
            return conn.socket.getInputStream().available() > 0;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * After a {@code CONNECT} that may be intercepted has been accepted (or a transparent TLS
     * connection routed): reads the client's first bytes and serves the connection accordingly.
     * TLS is intercepted unless a rule, the MITM manager or a filter decides by its ClientHello not
     * to; then the server handshake runs first, offering the client's ALPN protocols, and the
     * client's handshake mirrors the server's choice. Plain HTTP is served as HTTP; anything else
     * is tunnelled, the bytes read so far first. For a {@code CONNECT} stream of an HTTP/2
     * connection, this runs on the client connection inside the stream ({@link #serveTunnel}),
     * while {@code ex} is the stream's exchange.
     *
     * @param conn the connection to the server, its TLS pending ({@link ServerConnection#tlsPending}),
     *     already TLS (a pooled one), or null (offline, or an HTTP/2 connection the session shares)
     * @param serverAlpn the protocol the server chose on an established connection, or null
     */
    private boolean interceptOrTunnel(Exchange ex, ServerConnection conn, SSLSession serverSession, String serverAlpn,
            HostAndPort target, String hostAndPort, List<ChainedProxy> route, String http2Key) throws IOException {
        ClientStart start = peekClient(conn != null && conn.tlsPending ? conn : null);
        if (ex.http2Claim != null) server.http2Origins.clientHelloArrived(ex.http2Claim);
        switch (start.kind()) {
            case CLOSED -> {
                releaseHttp2Claim(ex);
                completeConnect(ex);
                if (conn != null) conn.close();
                ex.channel.close();
                return false;
            }
            case HTTP -> {
                if (server.tcpHosts != null && server.tcpHosts.matches(target.host(), null)) {
                    return tunnelAfterPeek(ex, conn, hostAndPort, route, "plain bytes to a TCP host");
                }
                if (!server.littleProxyCompatibility) return servePlainSession(ex, conn, hostAndPort);
                return tunnelAfterPeek(ex, conn, hostAndPort, route, "plain HTTP (LittleProxy compatibility)");
            }
            case OTHER -> {
                return tunnelAfterPeek(ex, conn, hostAndPort, route, start.note());
            }
            case TLS -> {
                // intercepted below, unless declined
            }
        }
        ClientHello hello = start.hello();
        flowContext.clientHello(hello);
        // (Inside an intercepted CONNECT stream, the stream's exchange is the CONNECT's.)
        if (ex.flow != flowContext) ex.flow.clientHello(hello);
        String declined = declineReason(ex, hello, hostAndPort, target.port(), conn != null && conn.tlsPending);
        if (declined != null) {
            return tunnelAfterPeek(ex, conn, hostAndPort, route, declined);
        }
        if (conn != null && conn.tlsPending) {
            if (serverSpoke(conn)) return tunnelAfterPeek(ex, conn, hostAndPort, route, "the server spoke first");
            try {
                List<String> offered = startServerTls(ex, conn, hello, target, hostAndPort);
                SSLSocket tls = (SSLSocket) conn.socket;
                serverSession = tls.getSession();
                // The server's choice says what it speaks only if it could have chosen h2, or if
                // it was offered other protocols than HTTP.
                serverAlpn = offered != null && (offered.contains(ClientHello.H2) || offersNoHttp(hello))
                        ? tls.getApplicationProtocol() : null;
                if (conn.http2) {
                    ServerConnection carrier = conn;
                    conn = null;
                    adoptForSession(ex, carrier, Mode.TLS, hostAndPort, http2Key);
                    ex.http2Claim = null;
                } else if (ex.http2Claim != null && offered != null && offered.contains(ClientHello.H2)) {
                    // Offered h2 and refused: the server speaks HTTP/1.1.
                    server.http2Origins.negotiatedHttp1(ex.http2Claim);
                    ex.http2Claim = null;
                }
            } catch (NotTlsServer e) {
                // The client speaks TLS, the server does not: relay what the client sends, as is.
                conn.close();
                return tunnelAfterPeek(ex, null, hostAndPort, route, e.getMessage());
            } catch (IOException e) {
                // Intercept anyway: the session's requests try the server again, and are answered
                // with the failure (a 502 for a TLS failure) through the usual filters and responder.
                LOG.log(Level.DEBUG, ex.log + "TLS with " + hostAndPort + " failed (" + unwrap(e).getMessage()
                        + "); intercepting without a server connection");
                conn.close();
                conn = null;
            }
        }
        releaseHttp2Claim(ex);
        completeConnect(ex);
        intercept(ex.request, conn, serverSession, serverAlpn, target, hostAndPort, () -> endExchange(ex));
        return false;
    }

    /**
     * Why a TLS connection with {@code hello} is not intercepted, or null if it is: the host rules,
     * a client offering only protocols the proxy does not speak (unless the TCP hooks are to see
     * them, and the server's handshake can offer the same), the MITM manager, the filters.
     *
     * @param serverTlsPending whether the server's handshake is still to come, so it can be offered
     *     the client's protocols
     */
    private String declineReason(Exchange ex, ClientHello hello, String hostAndPort, int port,
            boolean serverTlsPending) {
        if (connectionMitm == null) {
            // A SOCKS client's connection, looked at for plain HTTP.
            return "no MITM manager";
        }
        String sniName = hello.sni() == null ? null : new HostAndPort(hello.sni(), port).toString();
        if (server.hostRules != null && server.hostRules.ignored(hostAndPort, sniName)) {
            return "an ignored host" + (sniName == null ? "" : " (SNI " + hello.sni() + ")");
        }
        if (offersNoHttp(hello)) {
            String offered = "the client offers no HTTP protocol (ALPN " + hello.alpnProtocols() + ")";
            if (server.tcpInterceptor == null) return offered;
            // A certificate made by the proxy can never answer an ACME challenge (RFC 8737).
            if (hello.alpnProtocols().contains(ACME_TLS)) return offered;
            if (!serverTlsPending) return offered + " and there is no server handshake to offer them to";
        }
        try {
            if (!connectionMitm.shouldIntercept(hello, ex.flow)) return "the MITM manager declined";
            if (!ex.filters.proxyToServerAllowMitm(hello)) return "a filter declined";
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, ex.log + "deciding on interception by the ClientHello threw; tunnelling", e);
            return "the decision failed";
        }
        return null;
    }

    /** The ALPN protocol of the ACME TLS-ALPN challenge (RFC 8737), which is never intercepted. */
    private static final String ACME_TLS = "acme-tls/1";

    /** Whether the client's ALPN offers protocols, none of them HTTP ({@code imap}, {@code mqtt}, ...). */
    private static boolean offersNoHttp(ClientHello hello) {
        return !hello.alpnProtocols().isEmpty() && hello.httpAlpnProtocols(true).isEmpty();
    }

    /**
     * Runs the TLS handshake with the server that {@code conn} waited with, mirroring the client's
     * ClientHello: its ALPN protocols (those the proxy speaks, or all of them when none is HTTP:
     * the session is then relayed as raw TCP), and its SNI when the {@code CONNECT} named an IP
     * address.
     *
     * @return the ALPN protocols offered to the server, or null for none
     */
    private List<String> startServerTls(Exchange ex, ServerConnection conn, ClientHello hello, HostAndPort target,
            String hostAndPort) throws IOException {
        String sniHost = Tls.isIpLiteral(target.host()) && hello.sni() != null ? hello.sni() : target.host();
        List<String> alpn = offersNoHttp(hello) ? hello.alpnProtocols() : upstreamAlpn(ex.offerHttp2, hello);
        layerServerTls(ex, conn, target, sniHost, hostAndPort, alpn);
        return alpn;
    }

    /**
     * Runs the TLS handshake with the server over {@code conn}, a connection (or tunnel) to it with
     * nothing layered on it yet, and switches {@code conn} to the TLS session ({@link
     * ServerConnection#layerTls}).
     *
     * @param alpn the ALPN protocols to offer, or null for none
     */
    private void layerServerTls(Exchange ex, ServerConnection conn, HostAndPort target, String sniHost,
            String hostAndPort, List<String> alpn) throws IOException {
        SSLSocket tls = serverTls(ex, conn.socket, target, sniHost, hostAndPort, conn.flowContext, alpn);
        Supplier<FullFlowContext> context = () -> conn.flowContext;
        conn.layerTls(tls, new ByteReader(serverInput(tls, context), server.ioBuffers),
                new PooledOutputStream(serverOutput(tls, context), server.ioBuffers));
        conn.http2 = ClientHello.H2.equals(tls.getApplicationProtocol());
    }

    /**
     * Tunnels the client's bytes, those already read first, to the server: over {@code conn} when
     * it is still a plain connection, else over a new one.
     */
    private boolean tunnelAfterPeek(Exchange ex, ServerConnection conn, String hostAndPort, List<ChainedProxy> route,
            String why) throws IOException {
        LOG.log(Level.DEBUG, ex.log + "tunnelling " + hostAndPort + ": " + why);
        releaseHttp2Claim(ex);
        completeConnect(ex);
        if (conn != null && conn.tlsPending) {
            conn.tlsPending = false;
            if (conn.pool != null) {
                // Never to be pooled: it carries this tunnel only.
                conn.perRequestLease = false;
                conn.pool.discarded(conn);
            }
        } else {
            if (conn != null) {
                // An established TLS connection is of no use to a tunnel.
                serverConnections.remove(conn.key, conn);
                if (conn.pool != null && conn.isOpen()) {
                    conn.pool.release(conn);
                } else {
                    conn.close();
                }
            }
            try {
                ex.deferServerTls = false;
                conn = connect(hostAndPort, ex, route, Mode.TUNNEL);
            } catch (IOException e) {
                LOG.log(Level.DEBUG, ex.log + "tunnel to " + hostAndPort + " failed: " + unwrap(e));
                ex.channel.close();
                return false;
            }
            conn.key = Mode.TUNNEL + "|" + hostAndPort;
            serverConnections.put(conn.key, conn);
        }
        // The bytes read so far are this connection's (an HTTP/1 client's, or those inside an
        // intercepted CONNECT stream), not the CONNECT exchange's channel's.
        http1.relay(conn, null, tcpSession(ex.flow, HostAndPort.parse(hostAndPort, 443), false),
                server.name + "-tunnel-" + id);
        conn.close();
        return false;
    }

    /**
     * The TCP hooks for a raw tunnel to {@code target}, or null without a {@link TcpInterceptor}:
     * the tunnel then copies bytes as it always has.
     *
     * @param tlsIntercepted whether this connection terminated the client's TLS, so the tunnel's
     *     bytes are decrypted
     */
    private TcpSession tcpSession(FlowContext flow, HostAndPort target, boolean tlsIntercepted) {
        TcpInterceptor interceptor = server.tcpInterceptor;
        if (interceptor == null) return null;
        ClientHello hello = flow.getClientHello();
        String sni = hello != null ? hello.sni() : null;
        String alpn = null;
        if (tlsIntercepted && http1.socket() instanceof SSLSocket tls) {
            alpn = tls.getApplicationProtocol();
            if (sni == null) sni = requestedServerName(tls.getSession());
        }
        return new TcpSession(interceptor, flow, target, tlsIntercepted, sni, alpn, logPrefix);
    }

    /** The host name a TLS client asked for (SNI) in {@code session}, or null. */
    private static String requestedServerName(SSLSession session) {
        if (session instanceof ExtendedSSLSession extended) {
            for (SNIServerName name : extended.getRequestedServerNames()) {
                if (name instanceof SNIHostName host) return host.getAsciiName();
            }
        }
        return null;
    }

    /**
     * Serves plain HTTP sent after a {@code CONNECT} (a {@code ws://} WebSocket through the proxy,
     * say): its requests go to the {@code CONNECT} target, as an intercepted session's would, but
     * without TLS; the connection made for the {@code CONNECT} serves them when it can.
     */
    private boolean servePlainSession(Exchange ex, ServerConnection conn, String hostAndPort) throws IOException {
        LOG.log(Level.DEBUG, ex.log + "plain HTTP after CONNECT " + hostAndPort + ": serving it as HTTP");
        releaseHttp2Claim(ex);
        completeConnect(ex);
        mitmHostAndPort = hostAndPort;
        plainSession = true;
        if (conn != null) {
            serverConnections.remove(conn.key, conn);
            if (conn.tlsPending && !usesPool(Mode.PLAIN)) {
                // A connection (or tunnel) straight to the target: requests are origin-form there.
                conn.tlsPending = false;
                if (conn.pool != null) {
                    conn.perRequestLease = false;
                    conn.pool.discarded(conn);
                }
                conn.key = Mode.PLAIN + "|" + hostAndPort;
                serverConnections.put(conn.key, conn);
            } else if (conn.pool != null && !conn.tlsPending && conn.isOpen()) {
                conn.pool.release(conn);
            } else {
                conn.close();
            }
        }
        // The CONNECT exchange is over; the requests that follow are exchanges of their own.
        endExchange(ex);
        serveRequests();
        return false;
    }

    // ---------------------------------------------------------------------------------------
    // CONNECT inside an intercepted session: the intercepted server is the client's HTTPS proxy
    // ---------------------------------------------------------------------------------------

    /**
     * Forwards a {@code CONNECT} that the client sent inside a session to the session's server,
     * which the client takes for its proxy (a corporate egress proxy, say), rather than tunnelling
     * to the target itself, which would bypass the proxy the client chose: an HTTPS proxy, whose
     * TLS session is intercepted, or an HTTP proxy, whose session is plain HTTP ({@link
     * #servePlainSession}). The {@code CONNECT} goes on a stream of the session's HTTP/2
     * connection to that server when there is one, else on a connection made as the session's are
     * ({@link #proxyConnection}), with the client's fields: its {@code Proxy-Authorization} is for
     * that proxy. Filters see it as any request and may answer or rewrite it. The proxy's refusal
     * ({@code 407} and its challenge, {@code 403}, ...) reaches the client as it was sent; a 2xx
     * opens the tunnel ({@link #openForwardedTunnel}).
     */
    private boolean forwardConnect(Exchange ex) throws IOException {
        HttpRequest request = ex.request;
        // Whether the tunnel's TLS is intercepted in turn, as a CONNECT to this proxy's would be.
        boolean mitm = server.mitmManager != null && ex.filters.proxyToServerAllowMitm() && mitmManager() != null;
        List<String> credentials = request.headers().getAll(HttpHeaderNames.PROXY_AUTHORIZATION);
        modifyRequestHeadersToReflectProxying(request, false, false);
        for (String credential : credentials) request.headers().add(HttpHeaderNames.PROXY_AUTHORIZATION, credential);
        HttpResponse shortCircuit = ex.filters.proxyToServerRequest(request);
        if (shortCircuit != null) {
            return respondDirect(ex, shortCircuit, true, ResponseSource.FILTER);
        }
        // (Filters may have rewritten the target.)
        HostAndPort target;
        try {
            target = HostAndPort.parse(request.uri(), 443);
        } catch (IllegalArgumentException e) {
            return respondFailure(ex, new ProxyFailure.BadRequest("invalid CONNECT target"), false);
        }
        String hostAndPort = target.toString();
        if (mitm && server.hostRules != null && server.hostRules.ignored(hostAndPort)) {
            // The host rules apply as to a CONNECT to this proxy; the tunnel's ClientHello is not
            // read, so the target alone decides.
            LOG.log(Level.DEBUG, ex.log + "not intercepting " + hostAndPort + ": an ignored host");
            mitm = false;
        }
        // An HTTP/2 stream's CONNECT reaches an HTTP/1.1 proxy as HTTP/1.1.
        request.setProtocolVersion(HttpVersion.HTTP_1_1);
        Hop hop = new Hop(mitmHostAndPort, !plainSession, via, request);
        ex.forwarding = hop;
        LOG.log(Level.DEBUG, ex.log + "forwarding CONNECT " + hostAndPort + " to " + hop.proxy);
        for (int attempt = 0; ; attempt++) {
            ServerConnection conn;
            try {
                conn = proxyConnection(hop, ex, attempt == 0);
            } catch (ClientFailure e) {
                ex.channel.close();
                return false;
            } catch (IOException e) {
                LOG.log(Level.DEBUG, ex.log + "no connection to " + hop.proxy + ": " + unwrap(e));
                return respondFailure(ex, connectFailure(hop.proxy, e), false);
            }
            boolean open;
            try {
                // (A reused connection may have been closed by the proxy while idle: retry those.)
                open = exchange(ex, conn, attempt < 3 && conn.used);
            } catch (StaleConnection e) {
                LOG.log(Level.DEBUG, ex.log + "retrying on a new connection after stale " + conn);
                conn.close();
                continue;
            }
            HttpResponse established = ex.tunnelOpened;
            return established == null ? open : openForwardedTunnel(ex, conn, established, target, hostAndPort, mitm);
        }
    }

    /**
     * The intercepted proxy opened the tunnel of a forwarded {@code CONNECT} on {@code conn}:
     * filters see its 2xx as the response, then the tunnel's bytes are relayed as they are, or,
     * when MITM applies to the target, its TLS is intercepted as a {@code CONNECT} to this proxy's
     * would be, with the proxy's own TLS to the target inside the tunnel. The session inside then
     * reaches the target only through the intercepted proxy ({@link #via}).
     */
    private boolean openForwardedTunnel(Exchange ex, ServerConnection conn, HttpResponse established,
            HostAndPort target, String hostAndPort, boolean mitm) throws IOException {
        Hop hop = ex.forwarding;
        // A 2xx to CONNECT has no body (RFC 9110 section 9.3.6).
        established.headers().remove(HttpHeaderNames.CONTENT_LENGTH);
        established.headers().remove(HttpHeaderNames.TRANSFER_ENCODING);
        ServerConnection session = null;
        SSLSession serverSession = null;
        if (mitm) {
            ex.offerHttp2 = server.http2Origins != null;
            try {
                session = serverTlsThrough(conn, hop, hostAndPort, ex);
                serverSession = ((SSLSocket) session.socket).getSession();
            } catch (NotTlsServer e) {
                // As for a CONNECT to this proxy: the client still gets a plain tunnel, a new one.
                LOG.log(Level.DEBUG, ex.log + e.getMessage() + "; tunnelling instead of intercepting");
                mitm = false;
                ServerConnection plain;
                try {
                    plain = connectThrough(hop, hostAndPort, ex, Mode.TUNNEL);
                } catch (ClientFailure failure) {
                    ex.channel.close();
                    return false;
                } catch (IOException failure) {
                    return respondFailure(ex, connectFailure(hostAndPort, failure), false);
                }
                try {
                    ex.channel.serverConnectionInUse(plain);
                } catch (IOException failure) {
                    plain.close();
                    ex.channel.close();
                    return false;
                }
                conn = plain;
            } catch (IOException e) {
                IOException cause = unwrap(e);
                LOG.log(Level.DEBUG, ex.log + "TLS with " + hostAndPort + " through " + hop.proxy + " failed: " + cause);
                reportServerFailure(new FullFlowContext(ex.flow, hostAndPort, hop.chained, conn.remoteAddress), cause);
                return respondFailure(ex, connectFailure(hostAndPort, e), false);
            }
        }
        ServerConnection tunnel = conn;
        ServerConnection intercepted = session;
        try {
            if (!server.transparent) {
                modifyResponseHeadersToReflectProxying(established, true);
            }
            HttpObject o = ex.filters.serverToProxyResponse(established);
            if (o != null) {
                o = ex.filters.proxyToClientResponse(o);
            }
            if (!(o instanceof HttpResponse response)) {
                if (intercepted != null) intercepted.close();
                return abort(ex, tunnel);
            }
            ex.responseStarted = true;
            writeToClient(() -> ex.channel.writeHead(response, response.status().code() / 100 != 2));
            ResponseSource source = source(ResponseSource.SERVER, established, established.status().code(), response);
            server.trackers.fire(t -> t.responseSentToClient(ex.flow, response, source));
            ex.filters.serverToProxyResponseReceived();
            completed(ex, response, source);
            if (response.status().code() / 100 != 2) {
                // A filter turned the tunnel into a failure.
                if (intercepted != null) intercepted.close();
                tunnel.close();
                if (!(HttpUtil.isKeepAlive(response) && ex.clientKeepAlive)) {
                    ex.channel.close();
                    return false;
                }
                return true;
            }
        } catch (IOException | RuntimeException e) {
            if (intercepted != null) intercepted.close();
            tunnel.close();
            throw e;
        }

        if (!mitm) {
            tunnel.tunnelThroughProxy = true;
            ex.channel.relay(tunnel, null, tcpSession(ex.flow, target, false), server.name + "-tunnel-" + id);
            tunnel.close();
            return false;
        }
        // The session inside takes the tunnel over (closing its connection closes the tunnel).
        if (!ex.channel.serverConnectionDone(tunnel)) {
            // The client reset the stream meanwhile.
            intercepted.close();
            ex.channel.close();
            return false;
        }
        // The server's choice says what it speaks only if it could have chosen h2.
        String serverAlpn = ex.offerHttp2 ? ((SSLSocket) intercepted.socket).getApplicationProtocol() : null;
        intercepted = adoptIfHttp2(intercepted, hop, hostAndPort, ex);
        if (ex.channel.multiplexed()) {
            return interceptStream(ex, intercepted, serverSession, serverAlpn, target, hostAndPort, null, null, hop);
        }
        // An HTTP/1 connection turns into the tunnel: it is done with the intercepted proxy's
        // session, and its requests from now on reach the target through that proxy. The
        // ClientHello of the session inside is not read: the outer session's is not its own.
        releaseSessionConnections();
        hop.consumer = this;
        via = hop;
        // (A plain HTTP session with an HTTP proxy turns into a TLS one with the target.)
        plainSession = false;
        flowContext.clientHello(null);
        if (intercepted != null) serverConnections.put(intercepted.key, intercepted);
        return intercept(ex, intercepted, serverSession, serverAlpn, target, hostAndPort);
    }

    /**
     * Hands {@code conn}, the proxy's TLS connection to a server inside a forwarded tunnel, to
     * {@link Http2Origins} if its handshake chose {@code h2}, under the key the session's requests
     * look for (private to the hop): returns null then, else {@code conn}.
     */
    private ServerConnection adoptIfHttp2(ServerConnection conn, Hop hop, String hostAndPort, Exchange ex) {
        if (!conn.http2) return conn;
        String key = http2Key(Mode.TLS, hostAndPort, ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION, hop);
        try {
            server.http2Origins.adopt(conn, key, key, http2Owner(Mode.TLS, hop), null, hostAndPort, ex.log, false);
        } catch (IOException e) {
            LOG.log(Level.DEBUG, ex.log + "HTTP/2 with " + hostAndPort + " failed: " + e.getMessage()
                    + "; its requests will connect again");
        }
        return null;
    }

    /**
     * A connection to {@code hop}'s proxy for one tunnel: a stream on an HTTP/2 connection to it
     * (shared, under the key the intercepted session's requests use), an idle connection of the
     * session's ({@code sessionIdle}), or a new connection made as the session's are: by the usual
     * routes (or through the hop's own hop), with the same MITM manager's trust and settings for
     * an HTTPS proxy's TLS. An HTTP proxy is reached over plain TCP: directly, or through a tunnel
     * that chained proxies open, never as their own requests.
     */
    private ServerConnection proxyConnection(Hop hop, Exchange ex, boolean sessionIdle) throws IOException {
        String key = hop.mode() + "|" + hop.proxy;
        if (sessionIdle) {
            ServerConnection idle = ex.channel.multiplexed() ? takeStreamConnection(key, ex, hop.proxy)
                    : serverConnections.remove(key);
            // (Not one that hands an HTTP chained proxy its requests: the CONNECT is the proxy's.)
            if (idle != null && idle.isOpen() && !idle.inExchange && idle.nextHopIsOrigin()) {
                idle.flowContext = new FullFlowContext(ex.flow, hop.proxy, idle.chainedProxy, idle.remoteAddress);
                // It has waited, and may have been closed meanwhile: the CONNECT may be sent again.
                idle.used = true;
                return idle;
            }
            if (idle != null) idle.close();
        }
        List<ChainedProxy> route = hop.parent != null ? DIRECT : chainedRoute(connectRequest(hop.proxy));
        if (route == null) {
            throw new ConnectException("no route to " + hop.proxy);
        }
        if (!hop.tls) {
            ServerConnection conn = connect(hop.proxy, ex, route, Mode.TUNNEL, hop.parent);
            conn.key = key;
            return conn;
        }
        String http2Key = server.http2Origins == null ? null
                : http2Key(Mode.TLS, hop.proxy, route.getFirst(), hop.parent);
        if (http2Key != null) {
            ServerConnection stream = server.http2Origins.stream(http2Key, ex.flow, hop.proxy, ex.log, false,
                    Math.max(1000, connectTimeoutMillis(ex)));
            if (stream != null) return stream;
        }
        boolean offerHttp2 = ex.offerHttp2;
        // (Making a connection for an HTTP/2 key is reported back, so others stop waiting for it.)
        boolean reported = http2Key == null;
        ex.offerHttp2 = http2Key != null;
        try {
            ServerConnection conn = connect(hop.proxy, ex, route, Mode.TLS, hop.parent);
            reported = true;
            if (conn.http2) {
                ChainedProxy actual = conn.chainedProxy == null ? ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION
                        : conn.chainedProxy;
                return server.http2Origins.adopt(conn, http2Key, http2Key(Mode.TLS, hop.proxy, actual, hop.parent),
                        http2Owner(Mode.TLS, hop.parent), ex.flow, hop.proxy, ex.log, false);
            }
            if (http2Key != null) server.http2Origins.negotiatedHttp1(http2Key);
            conn.key = key;
            return conn;
        } finally {
            ex.offerHttp2 = offerHttp2;
            if (!reported) server.http2Origins.connectFailed(http2Key);
        }
    }

    /**
     * Opens a tunnel to {@code hostAndPort} through {@code hop}'s intercepted proxy, with the
     * client's {@code CONNECT} fields, for a request of the session inside a forwarded tunnel:
     * with the proxy's TLS to the server in it ({@link Mode#TLS}), or as it is.
     *
     * @throws ConnectException if the proxy refused the tunnel
     */
    private ServerConnection connectThrough(Hop hop, String hostAndPort, Exchange ex, Mode mode) throws IOException {
        ServerConnection tunnel = proxyConnection(hop, ex, false);
        HttpResponse reply;
        try {
            HttpRequest connect = hop.connectTo(hostAndPort);
            stripRequestHeaders(connect.headers());
            tunnel.writeRequestHead(connect, false, false);
            do {
                if (!tunnel.awaitResponseHead()) throw new EOFException(hop.proxy + " closed the connection");
                reply = tunnel.readResponse(server.limits);
                if (reply == null) throw new EOFException(hop.proxy + " closed the connection");
            } while (reply.status().code() / 100 == 1);
        } catch (IOException | RuntimeException e) {
            tunnel.close();
            throw e;
        }
        if (reply.status().code() / 100 != 2) {
            tunnel.close();
            throw new ConnectException(hop.proxy + " refused CONNECT " + hostAndPort + ": " + reply.status());
        }
        return mode == Mode.TLS ? serverTlsThrough(tunnel, hop, hostAndPort, ex) : tunnel;
    }

    /**
     * The proxy's TLS connection to {@code hostAndPort} inside {@code tunnel}, a tunnel through
     * {@code hop}'s intercepted proxy (an HTTP/1.1 connection to it whose {@code CONNECT} was
     * answered, or an HTTP/2 stream): set up as a direct one would be ({@link #serverTls}),
     * offering {@code h2} and {@code http/1.1} when the exchange offers HTTP/2: the session inside
     * has no ClientHello read to mirror.
     * Closing it closes the tunnel; so does failing.
     */
    private ServerConnection serverTlsThrough(ServerConnection tunnel, Hop hop, String hostAndPort, Exchange ex)
            throws IOException {
        try {
            Socket carrier;
            if (tunnel instanceof Http2UpstreamStream stream) {
                carrier = stream.tunnelSocket();
            } else if (tunnel.in.buffered() > 0) {
                throw new ProtocolException("unexpected data from server before TLS handshake");
            } else {
                carrier = tunnel.socket;
            }
            FullFlowContext serverContext =
                    new FullFlowContext(ex.flow, hostAndPort, hop.chained, tunnel.remoteAddress);
            ex.attempt = serverContext;
            HostAndPort target = HostAndPort.parse(hostAndPort, 443);
            SSLSocket tls = serverTls(ex, carrier, target, target.host(), hostAndPort, serverContext,
                    upstreamAlpn(ex.offerHttp2, null));
            ServerConnection conn = tlsConnection(hostAndPort, hop.chained, tls, tunnel.remoteAddress, serverContext);
            conn.through = tunnel;
            connected(ex, conn);
            return conn;
        } catch (IOException | RuntimeException e) {
            tunnel.close();
            throw e;
        }
    }

    /**
     * Turns the client connection into a TLS session with the {@code CONNECT}ed {@code target},
     * whose decrypted requests this loop then serves. HTTP/1-specific: the whole connection
     * changes protocol, as only an HTTP/1 connection can.
     *
     * @param conn the server connection made for the session, or null to intercept without one (or
     *     with an HTTP/2 connection, which the session's requests share with others)
     * @param serverSession the TLS session with the server, or null without one
     * @param serverAlpn the ALPN protocol the server chose when it was offered {@code h2} (so that
     *     its choice tells what it speaks), else null
     */
    private boolean intercept(Exchange ex, ServerConnection conn, SSLSession serverSession, String serverAlpn,
            HostAndPort target, String hostAndPort) throws IOException {
        assert ex.channel == http1 : "only an HTTP/1 connection turns into TLS";
        intercept(ex.request, conn, serverSession, serverAlpn, target, hostAndPort, () -> endExchange(ex));
        return false;
    }

    /**
     * Runs the TLS handshake with the client as {@code target}, choosing its ALPN protocol as
     * {@link #mirrorAlpn} does, then serves the session's decrypted requests (HTTP/1, or HTTP/2 if
     * the client negotiates {@code h2}).
     *
     * @param connect the {@code CONNECT} that started the session
     * @param serverAlpn the ALPN protocol the server chose when it was offered {@code h2}, else null
     * @param connectDone ends the {@code CONNECT} exchange, once the session is established
     */
    private void intercept(HttpRequest connect, ServerConnection conn, SSLSession serverSession, String serverAlpn,
            HostAndPort target, String hostAndPort, Runnable connectDone) throws IOException {
        SSLContext clientContext = connectionMitm.clientSslContextFor(connect, serverSession, flowContext);
        boolean http2 = server.http2;
        SSLSocket tls = handshakeWithClient(clientContext, false, s -> mirrorAlpn(s, serverAlpn, http2), target.host());

        mitmHostAndPort = hostAndPort;
        String raw = rawSessionReason(conn, tls, target);
        if (raw != null) {
            relayDecrypted(conn, target, raw, connectDone);
            return;
        }
        if (conn != null && conn.perRequestLease) {
            // Each intercepted request leases its own connection; start with this one.
            serverConnections.remove(conn.key, conn);
            conn.pool.release(conn);
        }
        // The CONNECT exchange is over; the requests inside the session are exchanges of their own.
        connectDone.run();
        if (server.http2 && "h2".equals(tls.getApplicationProtocol())) {
            serveHttp2(tls, new byte[0], target);
            return;
        }
        serveRequests();
    }

    /**
     * Why the intercepted session on {@code tls} is relayed as raw TCP rather than served as HTTP,
     * or null to serve it as HTTP, in mitmproxy's next layer's order inside TLS: an {@code h2}
     * client is HTTP; a {@linkplain org.microproxy.HttpProxyServerBootstrap#withTcpHosts TCP
     * host} is raw; then the negotiated ALPN protocol when there is one (HTTP's, or another); else
     * the client's first decrypted bytes, which must start like an HTTP request, while a server
     * that speaks first (an SMTP banner) makes the session raw at once. Only a fresh connection to
     * the server of its own can carry raw TCP; without one the session is served as HTTP, as
     * before.
     */
    private String rawSessionReason(ServerConnection conn, SSLSocket tls, HostAndPort target) throws IOException {
        String alpn = tls.getApplicationProtocol();
        // An h2 client is served as HTTP/2 whatever the server speaks: its bytes are the proxy's.
        if (ClientHello.H2.equals(alpn)) return null;
        if (conn == null || conn.multiplexed() || conn.http2 || conn.perRequestLease || conn.used) return null;
        ClientHello hello = flowContext.getClientHello();
        if (server.tcpHosts != null && server.tcpHosts.matches(target.host(), hello == null ? null : hello.sni())) {
            return "a TCP host";
        }
        if (ClientHello.HTTP_1_1.equals(alpn) || ClientHello.HTTP_1_0.equals(alpn)) return null;
        if (alpn != null && !alpn.isEmpty()) return "ALPN " + alpn;
        ClientStart start = peekClient(conn);
        return switch (start.kind()) {
            case HTTP, CLOSED -> null;
            case TLS -> "TLS inside TLS";
            case OTHER -> start.note();
        };
    }

    /**
     * Relays an intercepted session that does not carry HTTP: its decrypted bytes go both ways
     * between the client and {@code conn}, through the TCP hooks, until both are done.
     */
    private void relayDecrypted(ServerConnection conn, HostAndPort target, String why, Runnable connectDone)
            throws IOException {
        LOG.log(Level.DEBUG, logPrefix + "relaying the TLS session with " + target + " as raw TCP: " + why);
        // The CONNECT exchange is over; the session is a tunnel of its own now.
        connectDone.run();
        serverConnections.remove(conn.key, conn);
        if (conn.pool != null) {
            // Never to be pooled: it carries this session only.
            conn.pool.discarded(conn);
        }
        http1.relay(conn, null, tcpSession(flowContext, target, true), server.name + "-tls-tunnel-" + id);
        conn.close();
    }

    /**
     * Intercepts a {@code CONNECT} stream of an HTTP/2 connection: the stream, shown as a socket
     * ({@link ClientChannel#tunnelSocket}), carries the client's TLS session with {@code target},
     * which a client connection of its own serves on this stream's thread, as {@link #intercept}
     * serves an HTTP/1 connection's. The stream ends when that connection does.
     *
     * @param serverAlpn the ALPN protocol the server chose when it was offered {@code h2}, else null
     * @param route the routes to the server, for a tunnel made after the client's first bytes
     * @param http2Key the key of HTTP/2 connections the session's requests may share, or null
     * @param via the hop through the intercepted proxy that opened the stream's tunnel (a
     *     forwarded {@code CONNECT}), or null for a tunnel this proxy opened
     */
    private boolean interceptStream(Exchange ex, ServerConnection conn, SSLSession serverSession, String serverAlpn,
            HostAndPort target, String hostAndPort, List<ChainedProxy> route, String http2Key, Hop via) {
        Socket tunnel = ex.channel.tunnelSocket();
        if (tunnel == null) {
            completeConnect(ex);
            if (conn != null) conn.close();
            ex.channel.close();
            return false;
        }
        // The session's connection takes the server connection over: the stream's end must not
        // close it once that connection has given it back to the pool.
        if (conn != null && !ex.channel.serverConnectionDone(conn)) {
            // The client reset the stream meanwhile.
            completeConnect(ex);
            conn.close();
            ex.channel.close();
            return false;
        }
        ClientConnection inner = new ClientConnection(this, tunnel, via);
        LOG.log(Level.DEBUG, ex.log + "intercepting " + hostAndPort + " inside the stream: " + inner.logPrefix.strip());
        inner.serveTunnel(ex, conn, serverSession, serverAlpn, target, hostAndPort, route, http2Key);
        return false;
    }

    /**
     * Chooses the client's ALPN protocol in an intercepted handshake: the server's choice when it
     * was offered {@code h2} and the client offered that choice (and the proxy may speak it to
     * clients: {@code h2} needs {@code withHttp2}), so both sides speak the same protocol, as
     * mitmproxy keeps them. Otherwise, with HTTP/2 to clients on, {@code h2} if offered, else {@code
     * http/1.1}; without it, no protocol (HTTP/1.1), as before. The handshake never fails over ALPN.
     */
    private static void mirrorAlpn(SSLSocket socket, String serverAlpn, boolean http2) {
        SSLParameters params = socket.getSSLParameters();
        params.setApplicationProtocols(http2 ? new String[] {ClientHello.H2, ClientHello.HTTP_1_1, ClientHello.HTTP_1_0}
                : new String[] {ClientHello.HTTP_1_1, ClientHello.HTTP_1_0});
        socket.setSSLParameters(params);
        socket.setHandshakeApplicationProtocolSelector((s, offered) -> clientAlpn(offered, serverAlpn, http2));
    }

    /** The ALPN protocol for a client that offered {@code offered} (see {@link #mirrorAlpn}); "" for none. */
    static String clientAlpn(List<String> offered, String serverAlpn, boolean http2) {
        if (serverAlpn != null && !serverAlpn.isEmpty() && offered.contains(serverAlpn)
                && (http2 || !ClientHello.H2.equals(serverAlpn))) {
            return serverAlpn;
        }
        if (!http2) return "";
        if (offered.contains(ClientHello.H2)) return ClientHello.H2;
        return offered.contains(ClientHello.HTTP_1_1) ? ClientHello.HTTP_1_1 : "";
    }

    /**
     * Serves the TLS session inside an intercepted {@code CONNECT} stream (this connection was made
     * by {@link #interceptStream}) until it ends, then closes the stream. In a tunnel this proxy
     * opened, the client's first bytes decide, as after an HTTP/1 connection's {@code CONNECT}
     * ({@link #interceptOrTunnel}); in one that an intercepted proxy opened ({@link #via}), whose
     * server TLS is already made, the session is intercepted.
     *
     * @param ex the stream's {@code CONNECT} exchange
     */
    private void serveTunnel(Exchange ex, ServerConnection conn, SSLSession serverSession, String serverAlpn,
            HostAndPort target, String hostAndPort, List<ChainedProxy> route, String http2Key) {
        boolean connectedFired = false;
        try {
            rawSocket.setSoTimeout(server.idleTimeoutMillis());
            http1.attach(rawSocket);
            server.trackers.fire(t -> t.clientConnected(flowContext));
            connectedFired = true;
            if (conn != null) {
                // The server connection made for the CONNECT is this connection's now.
                conn.onDetach = () -> detach(conn);
                serverConnections.put(conn.key, conn);
            }
            if (via == null) {
                interceptOrTunnel(ex, conn, serverSession, serverAlpn, target, hostAndPort, route, http2Key);
            } else {
                intercept(ex.request, conn, serverSession, serverAlpn, target, hostAndPort, () -> endExchange(ex));
            }
        } catch (SocketTimeoutException e) {
            LOG.log(Level.DEBUG, logPrefix + "client connection timed out");
            server.trackers.fire(t -> t.connectionTimedOut(flowContext));
        } catch (IOException e) {
            if (!closed) {
                LOG.log(Level.DEBUG, logPrefix + "intercepted stream failed: " + e);
                server.trackers.fire(t -> t.connectionExceptionCaught(flowContext, e));
            }
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "unexpected error on an intercepted stream", e);
            server.trackers.fire(t -> t.connectionExceptionCaught(flowContext, e));
        } finally {
            close();
            if (connectedFired) {
                SSLSession session = sslSession;
                server.trackers.fire(t -> t.clientDisconnected(flowContext, session));
            }
        }
    }

    /**
     * Serves the connection as HTTP/2: this thread reads the frames, and each stream runs its
     * exchange ({@link #handleStream}) on a thread of its own.
     *
     * @param socket the intercepted session / listener TLS socket, or the plain one for h2c
     * @param received bytes already read from {@code socket} that belong to HTTP/2
     * @param target the intercepted {@code CONNECT} target, or null for a forward proxy
     */
    private void serveHttp2(Socket socket, byte[] received, HostAndPort target) throws IOException {
        // Choose once, before concurrent streams begin (secure extended CONNECT may need
        // origin TLS even on a forward-proxy connection).
        if (target == null && server.mitmManager != null) mitmManager();
        StreamServerConnections streams = new StreamServerConnections(server.http2Options.maxConcurrentStreams());
        streamConnections = streams;
        // The server connection made for the CONNECT serves the first stream that wants one.
        for (ServerConnection c : List.copyOf(serverConnections.values())) {
            if (serverConnections.remove(c.key, c)) {
                streams.add(c);
                streams.release(c);
            }
        }
        Http2Connection h2 = new Http2Connection(server, this, socket, received, flowContext, logPrefix, target);
        http2 = h2;
        if (closed) return;
        h2.serve();
    }

    /**
     * Handles one HTTP/2 stream's request, on the stream's own thread: the same exchange logic as
     * any request. Returns false if the exchange closed (reset) its stream.
     */
    boolean handleStream(ClientChannel channel, HttpRequest request) throws IOException {
        return handleRequest(channel, request);
    }

    /** Forgets a server connection that closed. */
    private void detach(ServerConnection c) {
        serverConnections.remove(c.key, c);
        StreamServerConnections streams = streamConnections;
        if (streams != null) streams.remove(c);
    }

    /**
     * An idle server connection for {@code key} that a stream's exchange can have to itself, or
     * null; it now records that exchange's flow.
     */
    private ServerConnection takeStreamConnection(String key, Exchange ex, String hostAndPort) {
        ServerConnection conn = streamConnections.take(key);
        if (conn != null) {
            conn.flowContext = new FullFlowContext(ex.flow, hostAndPort, conn.chainedProxy, conn.remoteAddress);
        }
        return conn;
    }

    // ---------------------------------------------------------------------------------------
    // Connecting to servers
    // ---------------------------------------------------------------------------------------

    /** The MITM manager for this connection, chosen when first needed; null if it declined. */
    private MitmManager mitmManager() {
        mitmLock.lock();
        try {
            if (!mitmChosen) {
                connectionMitm = server.mitmManager.forConnection(flowContext);
                mitmChosen = true;
            }
            return connectionMitm;
        } finally {
            mitmLock.unlock();
        }
    }

    /**
     * Whether server connections for {@code mode} come from the shared pool: never the tunnels
     * through an intercepted proxy, opened with one client's credentials.
     */
    private boolean usesPool(Mode mode) {
        return via == null && poolShares(mode);
    }

    /** Whether the shared pool may hand connections for {@code mode} made for this client to others. */
    private boolean poolShares(Mode mode) {
        // A PROXY header names one client, so connections that carry it are never shared; nor are
        // TLS connections set up by a manager that may decide differently for each client.
        return server.pool != null && !server.sendProxyProtocol
                && (mode == Mode.PLAIN || (mode == Mode.TLS && server.poolSharedMitmConnections
                        && (connectionMitm == null || !SERVER_TLS_PER_CLIENT.get(connectionMitm.getClass()))));
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
                LOG.log(Level.DEBUG, ex.log + "reusing pooled " + conn);
            }
            conn.flowContext = new FullFlowContext(ex.flow, hostAndPort, conn.chainedProxy, conn.remoteAddress);
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
        leased.onDetach = () -> detach(leased);
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
     * The key HTTP/2 connections to servers are shared under ({@link Http2Origins}): the target, the
     * route, the MITM manager, and the client connection unless it may be shared with every client.
     */
    private String http2Key(Mode mode, String hostAndPort, ChainedProxy route) {
        return http2Key(mode, hostAndPort, route, via);
    }

    /**
     * The key of HTTP/2 connections reached through {@code via} (an intercepted proxy's tunnels,
     * private to the hop whatever the route), or by the usual routes when it is null.
     */
    private String http2Key(Mode mode, String hostAndPort, ChainedProxy route, Hop via) {
        if (via != null) return mode + "|" + hostAndPort + "|via" + via.id + mitmPoolKey(mode);
        return mode + "|" + hostAndPort + "|" + routeKey(route) + mitmPoolKey(mode)
                + (http2Owner(mode, null) == null ? "" : "|conn" + owner.id);
    }

    /**
     * The client connection HTTP/2 connections to servers are private to, or null if they serve
     * every client. They are shared only as pooled connections are: with the shared pool on, and
     * nothing about them particular to one client (a PROXY protocol header, or TLS set up by a MITM
     * manager that may decide per client). Those through an intercepted proxy's tunnels belong to
     * their hop, {@code via}, and close with the session that runs through it.
     */
    private Object http2Owner(Mode mode, Hop via) {
        if (via != null) return via;
        if (server.pool != null && poolShares(mode)) return null;
        // An intercepted stream's session shares its client connection's, which closes them.
        owner.ownsHttp2Connections = true;
        return owner;
    }

    /**
     * Hands {@code carrier}, whose handshake negotiated HTTP/2, to {@link Http2Origins}, and returns
     * a stream on it for {@code ex}.
     */
    private ServerConnection adoptHttp2(ServerConnection carrier, String lookupKey, Mode mode, String hostAndPort,
            Exchange ex) throws IOException {
        ChainedProxy actual = carrier.chainedProxy == null ? ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION
                : carrier.chainedProxy;
        LOG.log(Level.DEBUG, ex.log + "HTTP/2 to " + hostAndPort + " (ALPN h2)");
        return server.http2Origins.adopt(carrier, lookupKey, http2Key(mode, hostAndPort, actual), http2Owner(mode, via),
                ex.flow, hostAndPort, ex.log, ProxyUtils.isHEAD(ex.request));
    }

    /** Whether the request's {@code TE} field accepts trailers. */
    private static boolean acceptsTrailers(HttpRequest request) {
        for (String te : request.headers().getAllElements(HttpHeaderNames.TE)) {
            int semi = te.indexOf(';');
            if ((semi < 0 ? te : te.substring(0, semi)).strip().equalsIgnoreCase("trailers")) return true;
        }
        return false;
    }

    private static final List<ChainedProxy> DIRECT = List.of(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);

    /**
     * The chained proxies to try in order, with {@link ChainedProxyAdapter#FALLBACK_TO_DIRECT_CONNECTION}
     * meaning a direct connection; {@code null} if the manager offered none. Inside a tunnel
     * through an intercepted proxy ({@link #via}) there is one way, through the proxy, which the
     * manager routes to as it routes the session's other requests to it.
     */
    private List<ChainedProxy> lookupRoute(HttpRequest request) {
        return via != null ? DIRECT : chainedRoute(request);
    }

    /**
     * The routes for {@code ex}'s request to {@code hostAndPort}: a proxy request's are those to the
     * session's server, as for a {@code CONNECT} to it ({@link #proxyConnection} asks the same).
     */
    private List<ChainedProxy> routeFor(Exchange ex, String hostAndPort) {
        return lookupRoute(ex.proxyForm ? connectRequest(hostAndPort) : ex.request);
    }

    /** The chained proxy manager's routes for {@code request}, as {@link #lookupRoute}. */
    private List<ChainedProxy> chainedRoute(HttpRequest request) {
        if (server.chainProxyManager == null) {
            return DIRECT;
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
        return connect(hostAndPort, ex, route, mode, via);
    }

    /**
     * Connects to {@code hostAndPort} by the first of {@code route} that works, or, with {@code
     * via}, through a tunnel that the hop's intercepted proxy opens ({@link #connectThrough}).
     */
    private ServerConnection connect(String hostAndPort, Exchange ex, List<ChainedProxy> route, Mode mode, Hop via)
            throws IOException {
        if (via != null) return connectThrough(via, hostAndPort, ex, mode);
        IOException last = null;
        boolean connecting = false;
        int failures = 0;
        long backoffBudget = server.backoffInitialNanos > 0 ? backoffBudgetNanos(ex) : 0;
        for (ChainedProxy candidate : route) {
            ChainedProxy proxy = candidate == ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION ? null : candidate;
            if (failures > 0 && backoffBudget > 0) {
                backoffBudget -= backOff(ex, failures, backoffBudget, hostAndPort, proxy);
            }
            ex.attempt = null;
            try {
                ServerConnection conn = connectVia(hostAndPort, ex, proxy, mode);
                if (proxy != null) {
                    proxy.connectionSucceeded();
                }
                connected(ex, conn);
                return conn;
            } catch (NotTlsServer e) {
                // The route works; the server just is not a TLS server. The caller retries as a tunnel.
                throw e;
            } catch (IOException e) {
                IOException cause = unwrap(e);
                if (LOG.isLoggable(Level.DEBUG)) {
                    // Expected failures: the cause's message is enough (TLS failures have their own line).
                    LOG.log(Level.DEBUG, ex.log + "connection to " + hostAndPort
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
                        : new FullFlowContext(ex.flow, hostAndPort, proxy, proxy == null ? null : proxy.getChainedProxyAddress());
                reportServerFailure(failed, cause);
            }
        }
        if (connecting) {
            ex.filters.proxyToServerConnectionFailed();
        }
        throw last != null ? last : new ConnectException("no route to " + hostAndPort);
    }

    /** Tells the filters and trackers that {@code conn}, a connection to a server, is made. */
    private void connected(Exchange ex, ServerConnection conn) {
        ex.filters.proxyToServerConnectionSucceeded(conn.flowContext);
        server.trackers.fire(t -> t.serverConnected(conn.flowContext, conn.remoteAddress));
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
                LOG.log(Level.WARNING, ex.log + "proxyToServerConnectTimeout threw; using the server's", e);
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
    private long backOff(Exchange ex, int failures, long budget, String hostAndPort, ChainedProxy next)
            throws IOException {
        long wait = Math.min(budget,
                backoffNanos(failures, server.backoffInitialNanos, server.backoffMaxNanos, server.backoffJitter.getAsDouble()));
        if (wait <= 0) return 0;
        if (LOG.isLoggable(Level.DEBUG)) {
            LOG.log(Level.DEBUG, ex.log + "waiting " + TimeUnit.NANOSECONDS.toMillis(wait) + " ms before trying "
                    + (next == null ? "a direct connection" : "chained proxy " + next.getChainedProxyAddress())
                    + " for " + hostAndPort + " after " + failures + " failed attempt" + (failures == 1 ? "" : "s"));
        }
        long start = System.nanoTime();
        ex.channel.awaitUnlessClientLeaves(start + wait);
        return System.nanoTime() - start;
    }

    /** Resolves a server for a direct connection, reporting it to {@code filters}. */
    private InetSocketAddress resolveServer(String hostAndPort, Exchange ex) throws UnknownHostException {
        HttpFilters filters = ex.filters;
        HostAndPort target = HostAndPort.parse(hostAndPort, 80);
        InetSocketAddress remote = filters.proxyToServerResolutionStarted(hostAndPort);
        try {
            if (remote == null) {
                ex.flow.markFirst(ClientFlowContext.DNS_START);
                remote = server.serverResolver.resolve(target.host(), target.port());
                ex.flow.mark(ClientFlowContext.DNS_END);
            } else if (remote.isUnresolved()) {
                // A filter may name another host rather than an address: resolve it the same way.
                ex.flow.markFirst(ClientFlowContext.DNS_START);
                remote = server.serverResolver.resolve(remote.getHostString(), remote.getPort());
                ex.flow.mark(ClientFlowContext.DNS_END);
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
                remote = resolveServer(hostAndPort, ex);
            }
        } else {
            remote = proxy.getChainedProxyAddress();
            if (remote == null) {
                throw new ConnectException("chained proxy has no address");
            }
            if (remote.isUnresolved()) {
                ex.flow.markFirst(ClientFlowContext.DNS_START);
                try {
                    remote = new InetSocketAddress(InetAddress.getByName(remote.getHostString()), remote.getPort());
                } catch (UnknownHostException e) {
                    // The route failed, not the server's name: a ConnectFailed, not an UnresolvedHost.
                    throw new UnresolvedChainedProxy(remote, e);
                }
                ex.flow.mark(ClientFlowContext.DNS_END);
            }
        }
        FullFlowContext serverContext = new FullFlowContext(ex.flow, hostAndPort, proxy, remote);
        ex.attempt = serverContext;

        filters.proxyToServerConnectionStarted();
        Socket plain = new Socket(Proxy.NO_PROXY);
        try {
            InetSocketAddress local = proxy != null && proxy.getLocalAddress() != null
                    ? proxy.getLocalAddress() : server.localAddress;
            if (local != null) {
                plain.bind(local);
            }
            ex.flow.markFirst(ClientFlowContext.CONNECT_START);
            plain.connect(remote, connectTimeoutMillis(ex));
            ex.flow.mark(ClientFlowContext.CONNECT_END);
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
                    ex.flow.markFirst(ClientFlowContext.TLS_START);
                    active = Tls.clientHandshake(context, plain, remote.getHostString(), remote.getPort(), false,
                            server.tlsProtocols,
                            s -> proxy.configure(s, true), server.tlsHandshakeTimeout,
                            new TlsLog.Peer(ex.log, "chained proxy", remote.getHostString()));
                    ex.flow.mark(ClientFlowContext.TLS_END);
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
                LOG.log(Level.DEBUG, ex.log + "not sending a PROXY header: no tunnel to {0} through {1} chained proxy {2}",
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
            boolean deferTls = mode == Mode.TLS && ex.deferServerTls;
            if (mode == Mode.TLS && !deferTls) {
                if (reader.buffered() > 0) {
                    throw new ProtocolException("unexpected data from server before TLS handshake");
                }
                active = serverTls(ex, active, target, target.host(), hostAndPort, serverContext,
                        upstreamAlpn(ex.offerHttp2, sessionHello()));
                reader = new ByteReader(serverInput(active, currentContext), server.ioBuffers);
                output = new PooledOutputStream(serverOutput(active, currentContext), server.ioBuffers);
            }
            holder[0] = new ServerConnection(mode + "|" + hostAndPort, hostAndPort, proxy, mode != Mode.PLAIN,
                    active, reader, output, remote, serverContext, server.trackers);
            ServerConnection created = holder[0];
            created.tlsPending = deferTls;
            created.http2 = mode == Mode.TLS && active instanceof SSLSocket tls && "h2".equals(tls.getApplicationProtocol());
            created.onDetach = () -> detach(created);
            return created;
        } catch (IOException e) {
            Tls.closeQuietly(plain);
            throw e;
        } catch (RuntimeException e) {
            Tls.closeQuietly(plain);
            throw new IOException("connecting to " + hostAndPort + " failed", e);
        }
    }

    /**
     * Runs the TLS handshake with the server over {@code active} (the connection to it, or a
     * tunnel through chained proxies), with the MITM manager's context and socket settings.
     *
     * @param sniHost the name sent as SNI and that the certificate is checked against
     * @param alpn the ALPN protocols to offer, or null for none
     * @throws NotTlsServer if the server does not speak TLS
     * @throws TlsHandshakeFailed if the handshake failed otherwise
     */
    private SSLSocket serverTls(Exchange ex, Socket active, HostAndPort target, String sniHost, String hostAndPort,
            FullFlowContext serverContext, List<String> alpn) throws IOException {
        ex.filters.proxyToServerConnectionSSLHandshakeStarted();
        MitmManager manager = connectionMitm;
        SSLContext context;
        try {
            context = manager != null ? manager.serverSslContext(target.host(), target.port(), serverContext)
                    : SSLContext.getDefault();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException("default TLS context unavailable", e);
        }
        try {
            ex.flow.markFirst(ClientFlowContext.TLS_START);
            SSLSocket tls = Tls.clientHandshake(context, active, sniHost, target.port(), true, server.tlsProtocols,
                    s -> {
                        if (alpn != null) offerAlpn(s, alpn);
                        if (manager != null) manager.configureServerSocket(s, serverContext);
                    }, server.tlsHandshakeTimeout,
                    new TlsLog.Peer(ex.log, "server", sniHost));
            ex.flow.mark(ClientFlowContext.TLS_END);
            return tls;
        } catch (IOException e) {
            if (e instanceof SSLException ssl && NotTlsServer.isCause(ssl)) {
                throw new NotTlsServer(hostAndPort, ssl);
            }
            server.trackers.fire(t -> t.tlsHandshakeFailed(serverContext, false, e));
            throw new TlsHandshakeFailed(e);
        }
    }

    /** Offers {@code protocols} through ALPN, as a TLS client. */
    private static void offerAlpn(SSLSocket socket, List<String> protocols) {
        SSLParameters params = socket.getSSLParameters();
        params.setApplicationProtocols(protocols.toArray(String[]::new));
        socket.setSSLParameters(params);
    }

    /** A server connection over {@code tls}, a handshake {@link #serverTls} made, reached via {@code proxy}. */
    private ServerConnection tlsConnection(String hostAndPort, ChainedProxy proxy, SSLSocket tls,
            InetSocketAddress remote, FullFlowContext serverContext) throws IOException {
        ServerConnection[] holder = new ServerConnection[1];
        Supplier<FullFlowContext> currentContext = () -> holder[0] != null ? holder[0].flowContext : serverContext;
        ByteReader reader = new ByteReader(serverInput(tls, currentContext), server.ioBuffers);
        OutputStream output = new PooledOutputStream(serverOutput(tls, currentContext), server.ioBuffers);
        holder[0] = new ServerConnection(Mode.TLS + "|" + hostAndPort, hostAndPort, proxy, true, tls, reader, output,
                remote, serverContext, server.trackers);
        ServerConnection created = holder[0];
        created.http2 = "h2".equals(tls.getApplicationProtocol());
        created.onDetach = () -> detach(created);
        return created;
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

    /**
     * The CONNECT sent to an upstream HTTP proxy: the client's own CONNECT if it sent one for
     * {@code hostAndPort}, else a bare one. (A CONNECT may need a connection to another server
     * than the one it names: its fields, credentials for that one, must not go to this proxy.)
     */
    private static HttpRequest upstreamConnectRequest(HttpRequest clientRequest, String hostAndPort, ChainedProxy proxy) {
        HttpRequest connect;
        if (connectsTo(clientRequest, hostAndPort)) {
            connect = copy(clientRequest);
            // A CONNECT stream of an HTTP/2 client reaches the chained proxy as HTTP/1.1.
            if (connect.protocolVersion().majorVersion() >= 2) connect.setProtocolVersion(HttpVersion.HTTP_1_1);
        } else {
            connect = connectRequest(hostAndPort);
        }
        addUpstreamProxyAuthorization(connect.headers(), proxy);
        return connect;
    }

    /** Whether {@code request} is a CONNECT to {@code hostAndPort}. */
    private static boolean connectsTo(HttpRequest request, String hostAndPort) {
        if (!ProxyUtils.isCONNECT(request)) return false;
        try {
            return HostAndPort.parse(request.uri(), 443).toString().equals(hostAndPort);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** A bare CONNECT to {@code hostAndPort}. */
    private static HttpRequest connectRequest(String hostAndPort) {
        HttpRequest connect = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.CONNECT, hostAndPort);
        connect.headers().set(HttpHeaderNames.HOST, hostAndPort);
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

    /**
     * @param forwarded the response is a session's server's answer to a forwarded {@code CONNECT} or
     *     proxy request: its {@code Proxy-Authenticate} challenges are for the client, which takes
     *     that server for its proxy
     */
    private void modifyResponseHeadersToReflectProxying(HttpResponse response, boolean forwarded) {
        HttpHeaders headers = response.headers();
        List<String> challenges = forwarded ? headers.getAll(HttpHeaderNames.PROXY_AUTHENTICATE) : List.of();
        ProxyUtils.stripConnectionTokens(headers);
        ProxyUtils.stripHopByHopHeaders(headers);
        for (String challenge : challenges) headers.add(HttpHeaderNames.PROXY_AUTHENTICATE, challenge);
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
            ex.channel.writeContinue();
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
    private FullHttpResponse aggregateResponse(HttpResponse response, Framing framing, MessageBody body,
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
        if (ex.socks != 0) {
            return refuseSocks(ex, response, source);
        }
        if (ex.implicit) {
            // The client sent no HTTP: it cannot be answered in HTTP.
            LOG.log(Level.DEBUG, ex.log + "closing the connection for " + ex.request.uri() + " instead of answering "
                    + response.status());
            ex.channel.close();
            return false;
        }
        boolean keepAlive = HttpUtil.isKeepAlive(response) && ex.clientKeepAlive
                && !ex.bodyUnread() && !ex.bodyAbandoned;
        int status = response.status().code();
        HttpObject filtered = ex.filters.proxyToClientResponse(response);
        if (!(filtered instanceof HttpResponse res)) {
            ex.channel.close();
            return false;
        }
        if (rewriteHeaders && !server.transparent) {
            modifyResponseHeadersToReflectProxying(res, false);
        }
        if (rewriteHeaders && server.stripAltSvcH3) {
            AltSvc.stripHttp3(res.headers());
        }
        ex.channel.setKeepAlive(res, keepAlive);
        boolean bodyAllowed = Framing.responseMayHaveBody(res, ex.request.method());
        ex.responseStarted = true;
        writeToClient(() -> ex.channel.writeComplete(res, bodyAllowed));
        ResponseSource sent = source(source, response, status, res);
        server.trackers.fire(t -> t.responseSentToClient(ex.flow, res, sent));
        completed(ex, res, sent);
        if (!keepAlive) {
            ex.channel.close();
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
                LOG.log(Level.WARNING, ex.log + "failure responder threw; sending the default response", e);
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
        ex.socksFailure = failure;
        return respondDirect(ex, response, rewriteHeaders, source);
    }

    /**
     * Refuses a SOCKS client's request with the reply code for its failure ({@link
     * Exchange#socksFailure}), or for {@code response}'s status when the proxy or a filter refused
     * it, and closes the connection. Trackers and filters see {@code response} as the {@code
     * CONNECT}'s answer, which the client does not get in HTTP.
     */
    private boolean refuseSocks(Exchange ex, HttpResponse response, ResponseSource source) {
        int code = ex.socksFailure != null ? SocksHandshake.replyCode(ex.socksFailure)
                : SocksHandshake.replyCode(response.status().code());
        LOG.log(Level.DEBUG, ex.log + "refusing SOCKS CONNECT " + ex.request.uri() + " with reply code " + code
                + " (" + response.status() + ")");
        try {
            http1.writeRaw(SocksHandshake.reply(ex.socks, code));
            server.trackers.fire(t -> t.responseSentToClient(ex.flow, response, source));
            completed(ex, response, source);
        } catch (IOException e) {
            LOG.log(Level.DEBUG, ex.log + "SOCKS client left before its reply: " + e);
        }
        ex.channel.close();
        return false;
    }

    /**
     * Where {@code sent} came from, given that filters made it out of {@code made} (with status
     * {@code madeStatus}, from {@code source}): a cache answer, a replayed response, a filter's
     * replacement or status change, or {@code made} as it was.
     */
    private static ResponseSource source(ResponseSource source, HttpObject made, int madeStatus, HttpResponse sent) {
        if (sent instanceof HttpCache.Answer) {
            return ResponseSource.CACHE;
        }
        if (sent instanceof ServerReplay.Replayed) {
            return ResponseSource.REPLAY;
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

    /** Asks the authenticator about {@code ex}'s request: null if it may proceed, else the answer. */
    private HttpResponse authenticate(Exchange ex) {
        AuthResult result = server.proxyAuthenticator.authenticate(ex.request, ex.flow);
        if (recordAuthentication(result)) {
            return null;
        }
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

    /** Records the authenticator's decision about the connection's client; returns whether it accepted it. */
    private boolean recordAuthentication(AuthResult result) {
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
            return true;
        }
        authenticated = false;
        clientDetails.setUserName(null);
        return false;
    }

    /**
     * Asks the authenticator about an h2c stream's request, without touching the connection's
     * authentication state, which concurrent streams would share: null if it may proceed.
     */
    private HttpResponse authenticateStream(Exchange ex) {
        AuthResult result = server.proxyAuthenticator.authenticate(ex.request, ex.flow);
        if (result instanceof AuthResult.Accepted ok) {
            if (ok.userName() != null) clientDetails.setUserName(ok.userName());
            return null;
        }
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
