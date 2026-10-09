package org.microproxy;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import javax.net.ssl.SSLSession;

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
    /** The HTTP/2 stream this flow is, or 0 for an HTTP/1 connection's exchanges. */
    private final int streamId;
    /** The context of the client connection: this one, or the connection's for a stream's context. */
    private final FlowContext connection;

    public FlowContext(
            long connectionId,
            Supplier<InetSocketAddress> clientAddress,
            Supplier<SSLSession> clientSslSession,
            ClientDetails clientDetails) {
        this(connectionId, clientAddress, clientSslSession, clientDetails, new ConcurrentHashMap<>(), Instant.now(),
                null, 0, null);
    }

    /** Creates a context that shares identity and timing data with {@code parent}. */
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
                parent.connection);
    }

    /**
     * Creates the context of one HTTP/2 stream of the client connection {@code connection}: it
     * shares the connection's identity (id, addresses, TLS session, client details, acceptance
     * time) and has its own exchange record and timing data, since a connection's streams run at
     * the same time.
     *
     * @param streamId the stream's identifier, positive
     */
    protected FlowContext(FlowContext connection, int streamId) {
        this(
                connection.connectionId,
                connection.clientAddress,
                connection.clientSslSession,
                connection.clientDetails,
                new ConcurrentHashMap<>(),
                connection.acceptedAt,
                null,
                checkStreamId(streamId),
                connection.connection);
    }

    private static int checkStreamId(int streamId) {
        if (streamId <= 0) throw new IllegalArgumentException("stream id must be positive: " + streamId);
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
            FlowContext connection) {
        this.connectionId = connectionId;
        this.clientAddress = Objects.requireNonNull(clientAddress);
        this.clientSslSession = Objects.requireNonNull(clientSslSession);
        this.clientDetails = Objects.requireNonNull(clientDetails);
        this.timingData = timingData;
        this.acceptedAt = acceptedAt;
        this.root = root == null ? this : root;
        this.streamId = streamId;
        this.connection = connection == null ? this : connection;
    }

    /**
     * A process-unique id of the client connection. The proxy's log lines about the connection
     * start with {@code [conn <id>]}.
     */
    public long getConnectionId() {
        return connectionId;
    }

    /**
     * The HTTP/2 stream that carries this flow's exchange, or 0 when the client connection is
     * HTTP/1 (whose exchanges run one after another). Streams of one connection run concurrently;
     * the proxy's log lines about a stream start with {@code [conn <id> stream <streamId>]}.
     */
    public int getStreamId() {
        return streamId;
    }

    /**
     * The context of the client connection this flow belongs to: this context itself (or the one
     * it was made from) for HTTP/1, the connection's own for an HTTP/2 stream's. Use it for state
     * kept per client connection; contexts of different streams are not {@linkplain #equals equal}.
     */
    public FlowContext getConnectionContext() {
        return connection;
    }

    /**
     * The client's address. When a PROXY protocol header was accepted, this is the original client
     * address it carried rather than the address of the load balancer.
     */
    public InetSocketAddress getClientAddress() {
        return clientAddress.get();
    }

    /**
     * The TLS session with the client, or {@code null}. This is the proxy's own TLS listener
     * session, or the intercepted session while a CONNECT is being man-in-the-middled.
     */
    public SSLSession getClientSslSession() {
        return clientSslSession.get();
    }

    /**
     * When the client connection was accepted (when this context was created, for contexts made
     * outside the proxy).
     */
    public Instant acceptedAt() {
        return acceptedAt;
    }

    /**
     * The status of the final response the server sent for the exchange in progress on this
     * connection (or the last one), even when a filter or the cache changed or replaced it before
     * it reached the client; empty when no server response was received (the proxy or a filter
     * answered, or the server failed). Contexts made outside the proxy have none.
     */
    public OptionalInt upstreamStatus() {
        return root == this ? OptionalInt.empty() : root.upstreamStatus();
    }

    /**
     * When the phases of the exchange in progress on this connection (or the last one) happened:
     * DNS lookup, connect, TLS handshakes, time to first byte, total. A snapshot; take it in
     * {@link ActivityTracker#responseCompleted} to see the whole exchange. Contexts made outside
     * the proxy return {@link FlowTimings#NONE}.
     */
    public FlowTimings timings() {
        return root == this ? FlowTimings.NONE : root.timings();
    }

    public ClientDetails getClientDetails() {
        return clientDetails;
    }

    public void setTimingData(String key, Long value) {
        timingData.put(Objects.requireNonNull(key), Objects.requireNonNull(value));
    }

    public Long getTimingData(String key) {
        return timingData.get(key);
    }

    public Map<String, Long> getTimings() {
        return Map.copyOf(timingData);
    }

    /**
     * Contexts are equal when they belong to the same client connection and the same HTTP/2
     * stream (0 for HTTP/1), so maps keyed by context keep one entry per exchange in progress.
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof FlowContext that && that.connectionId == connectionId && that.streamId == streamId;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(connectionId) * 31 + streamId;
    }
}
