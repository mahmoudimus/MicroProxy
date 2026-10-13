package org.microproxy;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import javax.net.ssl.SSLSession;
import org.microproxy.http.HttpVersion;

/** Information about the client side of a proxied flow. */
public class FlowContext {

    private final long connectionId;
    private final Supplier<InetSocketAddress> clientAddress;
    private final Supplier<SSLSession> clientSslSession;
    private final ClientDetails clientDetails;
    private final Map<String, Long> timingData;
    private final Instant acceptedAt;
    /** The client connection's own context, which knows the exchange in progress. */
    private final FlowContext root;
    /** The HTTP/2 or HTTP/3 stream this flow is, or 0 for an HTTP/1 connection's exchanges. */
    private final int streamId;
    /** {@link HttpVersion#HTTP_2_0} or {@link HttpVersion#HTTP_3_0} for a stream's context; null otherwise. */
    private final HttpVersion streamVersion;
    /** The context of the client connection: this one, or the connection's for a stream's context. */
    private final FlowContext connection;
    /**
     * The totals of the calls into scripts for the exchange in progress, kept on the root context;
     * null until the first call, and again when a new exchange starts.
     */
    private volatile ScriptUsage scriptUsage;

    private static final VarHandle SCRIPT_USAGE;

    static {
        try {
            SCRIPT_USAGE = MethodHandles.lookup().findVarHandle(FlowContext.class, "scriptUsage", ScriptUsage.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /**
     * Creates a context for the supplied client address and TLS session.
     *
     * @param connectionId the client connection identifier
     * @param clientAddress the supplier of the current client socket address
     * @param clientSslSession the supplier of the client TLS session, which may return {@code null}
     * @param clientDetails the client address and authentication details
     */
    public FlowContext(
            long connectionId,
            Supplier<InetSocketAddress> clientAddress,
            Supplier<SSLSession> clientSslSession,
            ClientDetails clientDetails) {
        this(connectionId, clientAddress, clientSslSession, clientDetails, new ConcurrentHashMap<>(), Instant.now(),
                null, 0, null, null);
    }

    /**
     * Creates a context that shares identity and timing data with {@code parent}.
     *
     * @param parent the client connection context
     */
    protected FlowContext(FlowContext parent) {
        this(
                parent.connectionId,
                parent.clientAddress,
                parent.clientSslSession,
                parent.clientDetails,
                parent.timingData,
                parent.acceptedAt,
                parent.root,
                parent.streamId,
                parent.streamVersion,
                parent.connection);
    }

    /**
     * Creates the context of one HTTP/2 stream of the client connection {@code connection}: it
     * shares the connection's identity (id, addresses, TLS session, client details, acceptance
     * time) and has its own exchange record and timing data, since a connection's streams run at
     * the same time.
     *
     * @param streamId the stream's identifier, positive
     *
     * @param connection the parent client connection context
     */
    protected FlowContext(FlowContext connection, int streamId) {
        this(connection, streamId, HttpVersion.HTTP_2_0);
    }

    /**
     * Creates the context of one stream of the client connection {@code connection}, as {@link
     * #FlowContext(FlowContext, int)} does, for an HTTP/2 or an HTTP/3 connection. HTTP/3 streams
     * are QUIC streams, whose ids start at 0.
     *
     * @param connection the parent client connection context
     * @param streamId the stream's identifier: positive for HTTP/2, 0 or more for HTTP/3
     * @param version {@link HttpVersion#HTTP_2_0} or {@link HttpVersion#HTTP_3_0}
     */
    protected FlowContext(FlowContext connection, int streamId, HttpVersion version) {
        this(
                connection.connectionId,
                connection.clientAddress,
                connection.clientSslSession,
                connection.clientDetails,
                new ConcurrentHashMap<>(),
                connection.acceptedAt,
                null,
                checkStreamId(streamId, version),
                version,
                connection.connection);
    }

    private static int checkStreamId(int streamId, HttpVersion version) {
        if (!HttpVersion.HTTP_2_0.equals(version) && !HttpVersion.HTTP_3_0.equals(version)) {
            throw new IllegalArgumentException("streams are HTTP/2's or HTTP/3's, not " + version);
        }
        if (streamId < 0 || (streamId == 0 && version.majorVersion() == 2)) {
            throw new IllegalArgumentException("bad " + version + " stream id: " + streamId);
        }
        return streamId;
    }

    private FlowContext(
            long connectionId,
            Supplier<InetSocketAddress> clientAddress,
            Supplier<SSLSession> clientSslSession,
            ClientDetails clientDetails,
            Map<String, Long> timingData,
            Instant acceptedAt,
            FlowContext root,
            int streamId,
            HttpVersion streamVersion,
            FlowContext connection) {
        this.connectionId = connectionId;
        this.clientAddress = Objects.requireNonNull(clientAddress);
        this.clientSslSession = Objects.requireNonNull(clientSslSession);
        this.clientDetails = Objects.requireNonNull(clientDetails);
        this.timingData = timingData;
        this.acceptedAt = acceptedAt;
        this.root = root == null ? this : root;
        this.streamId = streamId;
        this.streamVersion = streamVersion;
        this.connection = connection == null ? this : connection;
    }

    /**
     * A process-unique id of the client connection. The proxy's log lines about the connection
     * start with {@code [conn <id>]}.
     *
     * @return a process-unique id of the client connection
     */
    public long getConnectionId() {
        return connectionId;
    }

    /**
     * The HTTP/2 or HTTP/3 stream that carries this flow's exchange, or 0 when the client
     * connection is HTTP/1 (whose exchanges run one after another). An HTTP/3 stream's id is its
     * QUIC stream id, and the first one is 0 too: {@link #getHttpVersion()} tells them apart.
     * Streams of one connection run concurrently; the proxy's log lines about a stream start with
     * {@code [conn <id> stream <streamId>]}.
     *
     * @return the stream that carries this flow's exchange, or 0 for an HTTP/1 connection
     */
    public int getStreamId() {
        return streamId;
    }

    /**
     * The HTTP version of the client connection that carries this flow: {@link
     * HttpVersion#HTTP_2_0} or {@link HttpVersion#HTTP_3_0} for a stream's flow, {@link
     * HttpVersion#HTTP_1_1} for an HTTP/1.x connection (whose request lines tell 1.0 from 1.1) and
     * for the context of a connection itself.
     *
     * @return the client connection's HTTP version
     */
    public HttpVersion getHttpVersion() {
        return streamVersion != null ? streamVersion : HttpVersion.HTTP_1_1;
    }

    /**
     * The context of the client connection this flow belongs to: this context itself (or the one
     * it was made from) for HTTP/1, the connection's own for an HTTP/2 stream's. Use it for state
     * kept per client connection; contexts of different streams are not {@linkplain #equals equal}.
     *
     * @return the context of the client connection this flow belongs to: this context itself (or the one it was made from) for HTTP/1, the connection's own for an HTTP/2 stream's
     */
    public FlowContext getConnectionContext() {
        return connection;
    }

    /**
     * The client's address. When a PROXY protocol header was accepted, this is the original client
     * address it carried rather than the address of the load balancer.
     *
     * @return the client's address
     */
    public InetSocketAddress getClientAddress() {
        return clientAddress.get();
    }

    /**
     * The peer of the client's TCP connection: the load balancer that sent a PROXY protocol header
     * when one was accepted ({@link HttpProxyServerBootstrap#withAcceptProxyProtocol(ProxyProtocolMode)}),
     * where {@link #getClientAddress()} is the client that header named; otherwise the same as
     * {@link #getClientAddress()}. Access logs render it with {@code
     * %DOWNSTREAM_DIRECT_REMOTE_ADDRESS%}.
     *
     * @return the address the client connection came from
     */
    public InetSocketAddress getDirectClientAddress() {
        return root != this ? root.getDirectClientAddress() : getClientAddress();
    }

    /**
     * The TLS session with the client, or {@code null}. This is the proxy's own TLS listener
     * session, or the intercepted session while a CONNECT is being man-in-the-middled.
     *
     * @return the TLS session with the client, or {@code null}
     */
    public SSLSession getClientSslSession() {
        return clientSslSession.get();
    }

    /**
     * When the client connection was accepted (when this context was created, for contexts made
     * outside the proxy).
     *
     * @return when the client connection was accepted (when this context was created, for contexts made outside the proxy)
     */
    public Instant acceptedAt() {
        return acceptedAt;
    }

    /**
     * The status of the final response the server sent for the exchange in progress on this
     * connection (or the last one), even when a filter or the cache changed or replaced it before
     * it reached the client; empty when no server response was received (the proxy or a filter
     * answered, or the server failed). Contexts made outside the proxy have none.
     *
     * @return the final upstream status, or empty when no upstream response was received
     */
    public OptionalInt upstreamStatus() {
        return root == this ? OptionalInt.empty() : root.upstreamStatus();
    }

    /**
     * The session's server that the exchange in progress (or the last one) is forwarded through,
     * as {@code host:port}, when the client takes that server for its proxy (an intercepted HTTPS
     * proxy, or an HTTP proxy whose session is plain HTTP): the client sent a {@code CONNECT} or an
     * absolute-form request inside the session, which the proxy forwards to that server rather than
     * to the target itself, or the request travels inside the tunnel such a {@code CONNECT} opened.
     * Empty otherwise (a filter that gives a request an absolute URI of its own sends it straight
     * there), and for contexts made outside the proxy.
     *
     * @return the proxy's {@code host:port}, or empty
     */
    public Optional<String> forwardedVia() {
        return root == this ? Optional.empty() : root.forwardedVia();
    }

    /**
     * The SOCKS version the client reached the proxy with: 5, or 4 for SOCKS4 and 4a. The
     * requests of a SOCKS client arrive as a {@code CONNECT} the proxy made up from its SOCKS
     * request (see {@link HttpProxyServerBootstrap#withSocksServer}), and as the requests inside
     * the session that follows. Empty for HTTP clients, and for contexts made outside the proxy.
     *
     * @return the client's SOCKS version, or empty
     */
    public OptionalInt socksVersion() {
        return root == this ? OptionalInt.empty() : root.socksVersion();
    }

    /**
     * Whether the client's QUIC came to the transparent QUIC listener ({@link
     * HttpProxyServerBootstrap#withTransparentQuicPort}): redirected there, routed by the SNI of
     * its ClientHello, and intercepted (its HTTP/3 requests) or relayed. False for every other
     * client, and for contexts made outside the proxy.
     *
     * @return whether the flow is a transparent QUIC client's
     */
    public boolean isTransparentQuic() {
        return root != this && root.isTransparentQuic();
    }

    /**
     * Whether the request of this HTTP/3 stream arrived, at least in part, as 0-RTT early data
     * (with {@link Http3Options.Builder#zeroRtt(boolean) 0-RTT} on). An attacker may have captured
     * and replayed such a request (RFC 8446 section 8), so the proxy sends it on with {@code
     * Early-Data: 1} (RFC 8470), answers {@code 425 Too Early} to methods that are not safe to
     * replay, and a filter may answer {@code 425} to others. False for every other request, and
     * for contexts made outside the proxy.
     *
     * @return whether the request came as early data
     */
    public boolean isEarlyData() {
        return root != this && root.isEarlyData();
    }

    /**
     * Why the proxy had to answer the exchange in progress on this connection (or the last one)
     * itself, or abandon it: the failure handed to {@link HttpFilters#proxyToServerFailure}, set
     * before the filters see it. Empty when there was none, and for contexts made outside the
     * proxy. Read it in {@link ActivityTracker#flowEnded} to see the whole exchange.
     *
     * @return the exchange's failure, or empty
     */
    public Optional<ProxyFailure> failure() {
        return root == this ? Optional.empty() : root.failure();
    }

    /**
     * Envoy-style flags saying why the exchange in progress on this connection (or the last one),
     * or the tunnel or flow it opened, ended as it did ({@code UF} for a refused connection, {@code
     * DC} for a client that left, ...). A copy, which may grow while the exchange goes on; empty
     * for contexts made outside the proxy.
     *
     * @return a copy of the exchange's response flags
     */
    public EnumSet<ResponseFlag> responseFlags() {
        return root == this ? EnumSet.noneOf(ResponseFlag.class) : root.responseFlags();
    }

    /**
     * A short snake_case reason for the response of the exchange in progress on this connection
     * (or the last one), as Envoy's {@code %RESPONSE_CODE_DETAILS%} gives: {@code via_upstream}
     * for the server's response, {@code filter}, {@code cache} or {@code replay} for one made
     * there, {@code proxy_failure:connect_failed} (and so on, one per {@link ProxyFailure}) for the
     * proxy's answer to a failure, {@code auth_rejected}, {@code too_early}, {@code
     * downstream_remote_disconnect}, ... Empty before the exchange has an outcome, and for
     * contexts made outside the proxy.
     *
     * @return the exchange's response code details, or empty
     */
    public Optional<String> responseCodeDetails() {
        return root == this ? Optional.empty() : root.responseCodeDetails();
    }

    /**
     * Adds {@code flag} to the {@linkplain #responseFlags() response flags} of the exchange in
     * progress: for a filter that answers or refuses a request for a reason the access log should
     * show (a rate limiter's {@link ResponseFlag#RATE_LIMITED}, say). Does nothing on a context
     * made outside the proxy.
     *
     * @param flag the flag to add
     */
    public void addResponseFlag(ResponseFlag flag) {
        Objects.requireNonNull(flag);
        if (root != this) root.addResponseFlag(flag);
    }

    /**
     * Sets the {@linkplain #responseCodeDetails() response code details} of the exchange in
     * progress, for a filter that answers for a reason of its own: a short snake_case string,
     * which replaces any details set before. Does nothing on a context made outside the proxy.
     *
     * @param details the details, such as {@code concurrency_limited}
     */
    public void setResponseCodeDetails(String details) {
        Objects.requireNonNull(details);
        if (root != this) root.setResponseCodeDetails(details);
    }

    /**
     * The distributed trace of the exchange in progress on this connection (or the last one), made
     * by the proxy's {@link FlowTracer}: its trace and span ids, and the span a filter may add
     * attributes and events to. {@link FlowTrace#NONE} without a tracer, and for contexts made
     * outside the proxy.
     *
     * @return the exchange's trace
     */
    public FlowTrace trace() {
        return root == this ? FlowTrace.NONE : root.trace();
    }

    /**
     * When the phases of the exchange in progress on this connection (or the last one) happened:
     * DNS lookup, connect, TLS handshakes, time to first byte, total. A snapshot; take it in
     * {@link ActivityTracker#responseCompleted} (or {@link ActivityTracker#flowEnded}) to see the
     * whole exchange. Contexts made outside
     * the proxy return {@link FlowTimings#NONE}.
     *
     * @return a snapshot of the exchange phase timings
     */
    public FlowTimings timings() {
        return root == this ? FlowTimings.NONE : root.timings();
    }

    /**
     * The TLS {@code ClientHello} the client sent to start the intercepted (or tunnelled) session
     * this flow belongs to: after a {@code CONNECT} whose client was asked for one, and on a
     * transparent TLS connection. {@code null} before then, for plain HTTP, for tunnels that were
     * never inspected, and for contexts made outside the proxy.
     *
     * @return the client's ClientHello, or {@code null}
     */
    public ClientHello getClientHello() {
        return root == this ? null : root.getClientHello();
    }

    /**
     * What the calls into scripts for the exchange in progress on this connection (or the last
     * one) added up to: how many, how long they took, the interpreter steps they ran and about how
     * many bytes of values they created. Live totals, which grow while calls go on; {@link
     * ScriptUsage#NONE} when no script was called for the exchange.
     *
     * @return the exchange's script totals
     */
    public ScriptUsage scriptStats() {
        ScriptUsage usage = root.scriptUsage;
        return usage == null ? ScriptUsage.NONE : usage;
    }

    /**
     * Adds a call into a script to the exchange's {@linkplain #scriptStats() totals}; scripting
     * modules call it at the end of every hook call they make for the exchange.
     *
     * @param nanos how long the call took
     * @param steps the interpreter steps it ran
     * @param allocBytes about how many bytes of values it created
     */
    public void recordScriptCall(long nanos, long steps, long allocBytes) {
        FlowContext r = root;
        ScriptUsage usage = r.scriptUsage;
        if (usage == null) {
            ScriptUsage made = new ScriptUsage();
            usage = (ScriptUsage) SCRIPT_USAGE.compareAndExchange(r, null, made);
            if (usage == null) usage = made;
        }
        usage.add(nanos, steps, allocBytes);
    }

    /** Forgets the script totals of the previous exchange: for the proxy, when a new one starts. */
    protected void resetScriptStats() {
        root.scriptUsage = null;
    }

    /** {@return the client address and authentication details} */
    public ClientDetails getClientDetails() {
        return clientDetails;
    }

    /**
     * Stores a named legacy timing value.
     *
     * @param key the timing measurement name
     * @param value the timing value to record
     */
    public void setTimingData(String key, Long value) {
        timingData.put(Objects.requireNonNull(key), Objects.requireNonNull(value));
    }

    /**
     * Returns a named legacy timing value.
     *
     * @param key the timing measurement name
     * @return the recorded value, or {@code null} if absent
     */
    public Long getTimingData(String key) {
        return timingData.get(key);
    }

    /**
     * Returns the legacy timing values.
     *
     * @return an immutable snapshot of the legacy timing map
     */
    public Map<String, Long> getTimings() {
        return Map.copyOf(timingData);
    }

    /**
     * Contexts are equal when they belong to the same client connection and the same HTTP/2 or
     * HTTP/3 stream (none for HTTP/1), so maps keyed by context keep one entry per exchange in
     * progress.
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof FlowContext that && that.connectionId == connectionId && that.streamId == streamId
                && Objects.equals(that.streamVersion, streamVersion);
    }

    @Override
    public int hashCode() {
        return (Long.hashCode(connectionId) * 31 + streamId) * 31 + (streamVersion == null ? 0 : streamVersion.majorVersion());
    }
}
