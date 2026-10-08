package org.microproxy;

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.Objects;
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

    public FlowContext(
            long connectionId,
            Supplier<InetSocketAddress> clientAddress,
            Supplier<SSLSession> clientSslSession,
            ClientDetails clientDetails) {
        this(connectionId, clientAddress, clientSslSession, clientDetails, new ConcurrentHashMap<>());
    }

    /** Creates a context that shares identity and timing data with {@code parent}. */
    protected FlowContext(FlowContext parent) {
        this(
                parent.connectionId,
                parent.clientAddress,
                parent.clientSslSession,
                parent.clientDetails,
                parent.timingData);
    }

    private FlowContext(
            long connectionId,
            Supplier<InetSocketAddress> clientAddress,
            Supplier<SSLSession> clientSslSession,
            ClientDetails clientDetails,
            Map<String, Long> timingData) {
        this.connectionId = connectionId;
        this.clientAddress = Objects.requireNonNull(clientAddress);
        this.clientSslSession = Objects.requireNonNull(clientSslSession);
        this.clientDetails = Objects.requireNonNull(clientDetails);
        this.timingData = timingData;
    }

    /** A process-unique id of the client connection. */
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
