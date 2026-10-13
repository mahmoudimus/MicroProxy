package org.microproxy.impl;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.function.Supplier;
import javax.net.ssl.SSLSession;
import org.microproxy.ClientDetails;
import org.microproxy.ClientHello;
import org.microproxy.FlowContext;
import org.microproxy.FlowTimings;
import org.microproxy.FlowTrace;
import org.microproxy.ProxyFailure;
import org.microproxy.ResponseFlag;
import org.microproxy.ResponseSource;

/**
 * The context of one client connection, which also records the exchange in progress (exchanges on
 * an HTTP/1 connection run one at a time), or of one HTTP/2 stream, which records that stream's
 * exchange (streams run concurrently, so each has its own). {@link org.microproxy.FullFlowContext}s
 * made from it read the same record. Recording costs a few stores into fields allocated once per
 * connection (or stream).
 */
final class ClientFlowContext extends FlowContext {

    // Marks for FlowTimings: System.nanoTime() values, 0 for "not yet".
    static final int DNS_START = 0;
    static final int DNS_END = 1;
    static final int CONNECT_START = 2;
    static final int CONNECT_END = 3;
    static final int TLS_START = 4;
    static final int TLS_END = 5;
    static final int REQUEST_SENT = 6;
    static final int FIRST_RESPONSE_BYTE = 7;
    static final int RESPONSE_COMPLETE = 8;
    private static final int EXCHANGE_MARKS = 9;

    // Written on the connection's thread; trackers on other threads may see slightly stale values.
    private final long[] marks = new long[EXCHANGE_MARKS];
    private long startNanos;
    private long startMillis;
    private long clientTlsStart;
    private long clientTlsEnd;
    /** Status of the server's final response for the current exchange; 0 for none. */
    private int upstreamStatus;
    /** The connection's context, for a stream's; null for the connection's own. */
    private final ClientFlowContext connectionFlow;
    /** The ClientHello that started the connection's session, once read. */
    private volatile ClientHello clientHello;
    /** The session's server (the client's proxy) the current exchange is forwarded through, or null. */
    private volatile String forwardedVia;
    /** The SOCKS version the client connection began with, or 0. */
    private volatile int socksVersion;
    /** Whether the client connection is a flow of the transparent QUIC listener. */
    private volatile boolean transparentQuic;
    /** Whether this HTTP/3 stream's request arrived as 0-RTT early data. */
    private volatile boolean earlyData;
    /** Whether the exchange's request had both Transfer-Encoding and Content-Length (withAllowChunkedLength). */
    private volatile boolean chunkedWithContentLength;

    // The outcome of the current exchange, for access logs; reset by startExchange. Tunnel
    // directions and a connection's reader thread write some of it, hence the atomic updates.
    private static final VarHandle FLAGS;
    private static final VarHandle BYTES_RECEIVED;
    private static final VarHandle BYTES_SENT;
    private static final VarHandle UPSTREAM_SENT;
    private static final VarHandle UPSTREAM_RECEIVED;
    private static final ResponseFlag[] FLAG_VALUES = ResponseFlag.values();

    static {
        try {
            MethodHandles.Lookup lookup = MethodHandles.lookup();
            FLAGS = lookup.findVarHandle(ClientFlowContext.class, "flags", long.class);
            BYTES_RECEIVED = lookup.findVarHandle(ClientFlowContext.class, "bytesReceived", long.class);
            BYTES_SENT = lookup.findVarHandle(ClientFlowContext.class, "bytesSent", long.class);
            UPSTREAM_SENT = lookup.findVarHandle(ClientFlowContext.class, "upstreamSent", long.class);
            UPSTREAM_RECEIVED = lookup.findVarHandle(ClientFlowContext.class, "upstreamReceived", long.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /** The response flags, one bit per {@link ResponseFlag} ordinal. */
    @SuppressWarnings("unused") // through FLAGS
    private volatile long flags;
    @SuppressWarnings("unused") // through BYTES_RECEIVED
    private volatile long bytesReceived;
    @SuppressWarnings("unused") // through BYTES_SENT
    private volatile long bytesSent;
    @SuppressWarnings("unused") // through UPSTREAM_SENT
    private volatile long upstreamSent;
    @SuppressWarnings("unused") // through UPSTREAM_RECEIVED
    private volatile long upstreamReceived;
    private volatile ProxyFailure failure;
    private volatile String details;
    private volatile ResponseSource responseSource;
    private volatile String transportFailure;
    private volatile InetSocketAddress upstreamAddress;
    private volatile InetSocketAddress upstreamLocalAddress;
    private volatile String upstreamCluster;
    private volatile String upstreamProtocol;
    private volatile SSLSession upstreamSslSession;
    /** The proxy's end of the client connection, or null. */
    private volatile InetSocketAddress localAddress;
    /** The TCP peer, when a PROXY header named another client; else null. */
    private volatile InetSocketAddress directClientAddress;
    private volatile FlowTrace trace = FlowTrace.NONE;

    ClientFlowContext(
            long connectionId,
            Supplier<InetSocketAddress> clientAddress,
            Supplier<SSLSession> clientSslSession,
            ClientDetails clientDetails) {
        super(connectionId, clientAddress, clientSslSession, clientDetails);
        this.connectionFlow = null;
    }

    /** The context of HTTP/2 stream {@code streamId} of {@code connection}'s client connection. */
    ClientFlowContext(ClientFlowContext connection, int streamId) {
        this(connection, streamId, org.microproxy.http.HttpVersion.HTTP_2_0);
    }

    /** The context of stream {@code streamId} of {@code connection}'s HTTP/2 or HTTP/3 client connection. */
    ClientFlowContext(ClientFlowContext connection, int streamId, org.microproxy.http.HttpVersion version) {
        super(connection, streamId, version);
        this.connectionFlow = connection;
        // The client handshake that the stream's connection began with.
        clientTlsStart = connection.clientTlsStart;
        clientTlsEnd = connection.clientTlsEnd;
        localAddress = connection.localAddress;
        directClientAddress = connection.directClientAddress;
    }

    /** Forgets the previous exchange: the first byte of a new request has arrived. */
    void startExchange() {
        Arrays.fill(marks, 0);
        upstreamStatus = 0;
        chunkedWithContentLength = false;
        FLAGS.setVolatile(this, 0L);
        BYTES_RECEIVED.setVolatile(this, 0L);
        BYTES_SENT.setVolatile(this, 0L);
        UPSTREAM_SENT.setVolatile(this, 0L);
        UPSTREAM_RECEIVED.setVolatile(this, 0L);
        failure = null;
        details = null;
        responseSource = null;
        transportFailure = null;
        upstreamAddress = null;
        upstreamLocalAddress = null;
        upstreamCluster = null;
        upstreamProtocol = null;
        upstreamSslSession = null;
        resetScriptStats();
        trace = FlowTrace.NONE;
        startMillis = System.currentTimeMillis();
        startNanos = now();
    }

    /** Records that phase {@code mark} happened now. */
    void mark(int mark) {
        marks[mark] = now();
    }

    /** When phase {@code mark} happened ({@link System#nanoTime()}), or 0 if it has not. */
    long markNanos(int mark) {
        return marks[mark];
    }

    /** Records that phase {@code mark} happened now, unless it already has (it began earlier). */
    void markFirst(int mark) {
        if (marks[mark] == 0) {
            marks[mark] = now();
        }
    }

    void clientTlsStarted() {
        clientTlsStart = now();
        clientTlsEnd = 0;
    }

    void clientTlsFinished() {
        clientTlsEnd = now();
    }

    /**
     * Records the ClientHello the client connection's session started with; for a stream's
     * context, the one that started the session inside the stream (an intercepted {@code CONNECT}
     * stream), which the stream's exchange sees rather than its connection's.
     */
    void clientHello(ClientHello hello) {
        clientHello = hello;
    }

    @Override
    public ClientHello getClientHello() {
        ClientHello own = clientHello;
        return own != null || connectionFlow == null ? own : connectionFlow.getClientHello();
    }

    /**
     * The ClientHello recorded for this context itself: for a stream's, the one read in the
     * stream's tunnel, never its connection's; null if none was.
     */
    ClientHello ownClientHello() {
        return clientHello;
    }

    void upstreamStatus(int status) {
        upstreamStatus = status;
    }

    /** The status of the server's final response, or 0 for none; without an {@link OptionalInt}. */
    int upstreamStatusCode() {
        return upstreamStatus;
    }

    @Override
    public OptionalInt upstreamStatus() {
        int status = upstreamStatus;
        return status == 0 ? OptionalInt.empty() : OptionalInt.of(status);
    }

    /** The client's proxy ({@code host:port}) the current exchange is forwarded through, or null. */
    void forwardedVia(String proxy) {
        forwardedVia = proxy;
    }

    @Override
    public Optional<String> forwardedVia() {
        return Optional.ofNullable(forwardedVia);
    }

    /** Records that the client connection began with a SOCKS handshake of {@code version}. */
    void socksVersion(int version) {
        socksVersion = version;
    }

    @Override
    public OptionalInt socksVersion() {
        int version = socksVersion;
        if (version == 0 && connectionFlow != null) return connectionFlow.socksVersion();
        return version == 0 ? OptionalInt.empty() : OptionalInt.of(version);
    }

    /** Records that the client connection is a QUIC flow of the transparent QUIC listener. */
    void transparentQuic() {
        transparentQuic = true;
    }

    @Override
    public boolean isTransparentQuic() {
        return transparentQuic || (connectionFlow != null && connectionFlow.isTransparentQuic());
    }

    /** Records that this stream's request arrived as 0-RTT early data. */
    void earlyData() {
        earlyData = true;
    }

    @Override
    public boolean isEarlyData() {
        return earlyData;
    }

    /** Records that the request had both framings, and its {@code Content-Length} was dropped. */
    void chunkedWithContentLength() {
        chunkedWithContentLength = true;
    }

    @Override
    public boolean isChunkedWithContentLength() {
        return chunkedWithContentLength;
    }

    /** Records that the exchange failed with {@code failure}, and the flag and details it means. */
    void failure(ProxyFailure failure) {
        this.failure = failure;
        // A client that reset its stream made the server connection fail: the reset says why.
        if (hasResponseFlag(ResponseFlag.DOWNSTREAM_REMOTE_RESET)) return;
        details = "proxy_failure:" + failureKind(failure);
        switch (failure) {
            case ProxyFailure.UnresolvedHost f -> addResponseFlag(ResponseFlag.DNS_RESOLUTION_FAILED);
            case ProxyFailure.ConnectFailed f -> addResponseFlag(ResponseFlag.UPSTREAM_CONNECTION_FAILURE);
            case ProxyFailure.TlsFailed f -> {
                addResponseFlag(ResponseFlag.UPSTREAM_CONNECTION_FAILURE);
                if (transportFailure == null && f.cause() != null) transportFailure = reason(f.cause());
            }
            case ProxyFailure.ServerTimeout f -> addResponseFlag(ResponseFlag.UPSTREAM_REQUEST_TIMEOUT);
            case ProxyFailure.BadServerResponse f -> addResponseFlag(serverClosedEarly(f.cause())
                    ? ResponseFlag.UPSTREAM_CONNECTION_TERMINATION : ResponseFlag.UPSTREAM_PROTOCOL_ERROR);
            case ProxyFailure.NoRoute f -> addResponseFlag(ResponseFlag.NO_ROUTE_FOUND);
            case ProxyFailure.NoConnectionAvailable f -> addResponseFlag(ResponseFlag.UPSTREAM_OVERFLOW);
            case ProxyFailure.BadRequest f -> addResponseFlag(ResponseFlag.DOWNSTREAM_PROTOCOL_ERROR);
            case ProxyFailure.RequestTooLarge f -> addResponseFlag(ResponseFlag.DOWNSTREAM_PROTOCOL_ERROR);
        }
    }

    /** The snake_case name of a failure's kind, as the details and scripts show it. */
    static String failureKind(ProxyFailure failure) {
        return switch (failure) {
            case ProxyFailure.UnresolvedHost f -> "unresolved_host";
            case ProxyFailure.ConnectFailed f -> "connect_failed";
            case ProxyFailure.TlsFailed f -> "tls_failed";
            case ProxyFailure.ServerTimeout f -> "server_timeout";
            case ProxyFailure.BadServerResponse f -> "bad_server_response";
            case ProxyFailure.NoRoute f -> "no_route";
            case ProxyFailure.NoConnectionAvailable f -> "no_connection_available";
            case ProxyFailure.BadRequest f -> "bad_request";
            case ProxyFailure.RequestTooLarge f -> "request_too_large";
        };
    }

    /**
     * Whether a failed response means the server closed the connection before the response head
     * was complete ({@code UC}), rather than sending something malformed ({@code UPE}).
     */
    static boolean serverClosedEarly(Throwable cause) {
        for (Throwable t = cause; t != null; t = t.getCause() == t ? null : t.getCause()) {
            if (t instanceof java.io.EOFException || t instanceof java.net.SocketException) return true;
            String message = t.getMessage();
            if (message != null && (message.contains("closed") || message.contains("ended before"))) return true;
        }
        return false;
    }

    /** A short reason for a transport failure: the innermost cause's message, or its class. */
    static String reason(Throwable cause) {
        Throwable t = cause;
        while (t.getCause() != null && t.getCause() != t) t = t.getCause();
        String message = t.getMessage();
        return message != null && !message.isBlank() ? message : t.getClass().getSimpleName();
    }

    @Override
    public Optional<ProxyFailure> failure() {
        return Optional.ofNullable(failure);
    }

    /** The failure, or null; without an {@link Optional}. */
    ProxyFailure failureOrNull() {
        return failure;
    }

    @Override
    public void addResponseFlag(ResponseFlag flag) {
        FLAGS.getAndBitwiseOr(this, 1L << flag.ordinal());
    }

    /** Whether {@code flag} has been added for the current exchange. */
    boolean hasResponseFlag(ResponseFlag flag) {
        return ((long) FLAGS.getVolatile(this) & (1L << flag.ordinal())) != 0;
    }

    /** The response flags of the current exchange, one bit per {@link ResponseFlag} ordinal; without a set. */
    long responseFlagBits() {
        return (long) FLAGS.getVolatile(this);
    }

    /** Whether any response flag has been added for the current exchange. */
    boolean hasResponseFlags() {
        return (long) FLAGS.getVolatile(this) != 0;
    }

    @Override
    public EnumSet<ResponseFlag> responseFlags() {
        long bits = (long) FLAGS.getVolatile(this);
        EnumSet<ResponseFlag> set = EnumSet.noneOf(ResponseFlag.class);
        for (int i = 0; bits != 0 && i < FLAG_VALUES.length; i++, bits >>>= 1) {
            if ((bits & 1) != 0) set.add(FLAG_VALUES[i]);
        }
        return set;
    }

    @Override
    public void setResponseCodeDetails(String details) {
        this.details = details;
    }

    /** Sets the details unless some were set already. */
    void defaultResponseCodeDetails(String details) {
        if (this.details == null) this.details = details;
    }

    /** Records where the response sent to the client came from. */
    void responseSource(ResponseSource source) {
        responseSource = source;
    }

    @Override
    public Optional<String> responseCodeDetails() {
        String own = details;
        if (own != null) return Optional.of(own);
        ResponseSource source = responseSource;
        return source == null ? Optional.empty() : Optional.of(details(source));
    }

    /** The details of a response from {@code source}, when nothing more particular is known. */
    static String details(ResponseSource source) {
        return switch (source) {
            case SERVER -> "via_upstream";
            case PROXY -> "proxy";
            case FILTER -> "filter";
            case CACHE -> "cache";
            case REPLAY -> "replay";
        };
    }

    /** Records why the TLS handshake with the server failed. */
    void transportFailure(Throwable cause) {
        transportFailure = reason(cause);
    }

    String transportFailure() {
        return transportFailure;
    }

    /** Records the server connection the exchange uses. */
    void trace(FlowTrace trace) {
        this.trace = trace;
    }

    @Override
    public FlowTrace trace() {
        return trace;
    }

    void upstream(InetSocketAddress address, InetSocketAddress local, String cluster, SSLSession session) {
        upstreamAddress = address;
        upstreamLocalAddress = local;
        upstreamCluster = cluster;
        upstreamSslSession = session;
    }

    InetSocketAddress upstreamAddress() {
        return upstreamAddress;
    }

    InetSocketAddress upstreamLocalAddress() {
        return upstreamLocalAddress;
    }

    String upstreamCluster() {
        return upstreamCluster;
    }

    /** Records the protocol spoken to the upstream ({@link org.microproxy.FlowRecord#upstreamProtocol()}). */
    void upstreamProtocol(String protocol) {
        upstreamProtocol = protocol;
    }

    String upstreamProtocol() {
        return upstreamProtocol;
    }

    SSLSession upstreamSslSession() {
        return upstreamSslSession;
    }

    /** Records the proxy's end of the client connection. */
    void localAddress(InetSocketAddress address) {
        localAddress = address;
    }

    InetSocketAddress localAddress() {
        return localAddress;
    }

    /** Records the TCP peer of a client connection whose PROXY header named another client. */
    void directClientAddress(InetSocketAddress address) {
        directClientAddress = address;
    }

    /** The TCP peer recorded by {@link #directClientAddress(InetSocketAddress)}, or null. */
    InetSocketAddress directClientAddressOrNull() {
        return directClientAddress;
    }

    @Override
    public InetSocketAddress getDirectClientAddress() {
        InetSocketAddress direct = directClientAddress;
        return direct != null ? direct : getClientAddress();
    }

    void addBytesReceived(long n) {
        BYTES_RECEIVED.getAndAdd(this, n);
    }

    void addBytesSent(long n) {
        BYTES_SENT.getAndAdd(this, n);
    }

    void addUpstreamSent(long n) {
        UPSTREAM_SENT.getAndAdd(this, n);
    }

    void addUpstreamReceived(long n) {
        UPSTREAM_RECEIVED.getAndAdd(this, n);
    }

    long bytesReceived() {
        return (long) BYTES_RECEIVED.getVolatile(this);
    }

    long bytesSent() {
        return (long) BYTES_SENT.getVolatile(this);
    }

    long upstreamSent() {
        return (long) UPSTREAM_SENT.getVolatile(this);
    }

    long upstreamReceived() {
        return (long) UPSTREAM_RECEIVED.getVolatile(this);
    }

    /** When the current exchange started ({@link System#nanoTime()}), or 0 before the first. */
    long startNanos() {
        return startNanos;
    }

    /** When the current exchange started (wall clock), or 0 before the first. */
    long startMillis() {
        return startMillis;
    }

    @Override
    public FlowTimings timings() {
        long start = startNanos;
        if (start == 0) {
            return FlowTimings.NONE;
        }
        long tls = clientTlsStart == 0 || clientTlsEnd == 0 ? -1 : clientTlsEnd - clientTlsStart;
        return new FlowTimings(startMillis, offset(DNS_START, start), offset(DNS_END, start),
                offset(CONNECT_START, start), offset(CONNECT_END, start), offset(TLS_START, start),
                offset(TLS_END, start), offset(REQUEST_SENT, start), offset(FIRST_RESPONSE_BYTE, start),
                offset(RESPONSE_COMPLETE, start), tls);
    }

    private long offset(int mark, long start) {
        long at = marks[mark];
        return at == 0 ? -1 : Math.max(0, at - start);
    }

    /** {@link System#nanoTime()}, never 0 (which means "not yet"). */
    static long now() {
        long t = System.nanoTime();
        return t == 0 ? 1 : t;
    }
}
