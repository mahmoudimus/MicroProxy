package org.microproxy;

import java.net.InetSocketAddress;
import java.time.Duration;

/** A running proxy. Obtain one from {@link MicroProxy#bootstrap()}. */
public interface HttpProxyServer extends AutoCloseable {

    /** {@return the maximum time a connection may remain idle} */
    Duration getIdleConnectionTimeout();

    /**
     * Sets the maximum time a connection may remain idle.
     *
     * @param idleConnectionTimeout the maximum time a connection may remain idle
     */
    void setIdleConnectionTimeout(Duration idleConnectionTimeout);

    /** {@return connect timeout for outbound connections in milliseconds (0 = system default)} */
    int getConnectTimeout();

    /**
     * Sets the timeout for outbound connection attempts.
     *
     * @param connectTimeoutMs the outbound connect timeout in milliseconds; zero uses the system default
     */
    void setConnectTimeout(int connectTimeoutMs);

    /**
     * Returns a bootstrap preconfigured like this server, listening on the next port (or an
     * ephemeral port if this one is ephemeral).
     *
     * @return a bootstrap with this server's settings and the next listening port
     */
    HttpProxyServerBootstrap clone();

    /** Stops accepting connections and gracefully closes existing ones. */
    void stop();

    /** Stops immediately, closing all connections without waiting. */
    void abort();

    /**
     * Closes {@code resource} when the server stops, after its connections have finished (or been
     * closed): for things that outlive single requests, such as a WARC recorder. Resources close
     * in the reverse order they were added.
     *
     * @param resource the resource to close when the server stops
     */
    void closeOnStop(AutoCloseable resource);

    /** {@return the bound proxy listener address} */
    InetSocketAddress getListenAddress();

    /**
     * Changes global bandwidth limits for server traffic; 0 means unlimited.
     *
     * @param readThrottleBytesPerSecond the inbound bandwidth limit in bytes per second, or zero for unlimited
     * @param writeThrottleBytesPerSecond the outbound bandwidth limit in bytes per second, or zero for unlimited
     */
    void setThrottle(long readThrottleBytesPerSecond, long writeThrottleBytesPerSecond);

    /** {@return statistics of the shared server connection pool, or {@code null} if it is disabled} */
    default PoolMetrics getServerConnectionPoolMetrics() {
        return null;
    }

    @Override
    default void close() {
        stop();
    }
}
