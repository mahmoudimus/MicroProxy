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

    public FlowContext(
            long connectionId,
            Supplier<InetSocketAddress> clientAddress,
            Supplier<SSLSession> clientSslSession,
            ClientDetails clientDetails) {
        this(connectionId, clientAddress, clientSslSession, clientDetails, new ConcurrentHashMap<>(), Instant.now(),
                null);
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
                parent.root);
    }

    private FlowContext(
            long connectionId,
            Supplier<InetSocketAddress> clientAddress,
            Supplier<SSLSession> clientSslSession,
            ClientDetails clientDetails,
            Map<String, Long> timingData,
            Instant acceptedAt,
            FlowContext root) {
        this.connectionId = connectionId;
        this.clientAddress = Objects.requireNonNull(clientAddress);
        this.clientSslSession = Objects.requireNonNull(clientSslSession);
        this.clientDetails = Objects.requireNonNull(clientDetails);
        this.timingData = timingData;
        this.acceptedAt = acceptedAt;
        this.root = root == null ? this : root;
    }

    /**
     * A process-unique id of the client connection. The proxy's log lines about the connection
     * start with {@code [conn <id>]}.
     */
    public long getConnectionId() {
        return connectionId;
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

    @Override
    public boolean equals(Object o) {
        return o instanceof FlowContext that && that.connectionId == connectionId;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(connectionId);
    }
}
