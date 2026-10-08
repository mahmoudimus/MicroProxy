package org.microproxy;

import java.net.InetSocketAddress;
import java.time.Duration;

/** A running proxy. Obtain one from {@link MicroProxy#bootstrap()}. */
public interface HttpProxyServer extends AutoCloseable {

    Duration getIdleConnectionTimeout();

    void setIdleConnectionTimeout(Duration idleConnectionTimeout);

    /** Connect timeout for outbound connections in milliseconds (0 = system default). */
    int getConnectTimeout();

    void setConnectTimeout(int connectTimeoutMs);

    /**
     * Returns a bootstrap preconfigured like this server, listening on the next port (or an
     * ephemeral port if this one is ephemeral).
     */
    HttpProxyServerBootstrap clone();

    /** Stops accepting connections and gracefully closes existing ones. */
    void stop();

    /** Stops immediately, closing all connections without waiting. */
    void abort();

    InetSocketAddress getListenAddress();

    /** Changes global bandwidth limits for server traffic; 0 means unlimited. */
    void setThrottle(long readThrottleBytesPerSecond, long writeThrottleBytesPerSecond);

    @Override
    default void close() {
        stop();
    }
}
