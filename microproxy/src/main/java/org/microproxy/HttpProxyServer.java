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

    /**
     * Stops accepting connections and gracefully closes existing ones: idle connections close now,
     * HTTP/2 and HTTP/3 ones are sent GOAWAY, and exchanges in progress get up to the {@linkplain
     * #getDrainTime() drain time} to finish before every connection is closed. The state is then
     * {@link ServerState#STOPPED}.
     */
    void stop();

    /** Stops immediately, closing all connections without waiting. */
    void abort();

    /** {@return where the proxy is in its life: {@link ServerState#LIVE} once started, until it drains or stops} */
    default ServerState state() {
        return ServerState.LIVE;
    }

    /**
     * Drains the proxy, as Envoy's graceful listener drain does, and returns when the drain is
     * over. The state turns {@link ServerState#DRAINING} (so the admin {@code /ready} fails), the
     * listeners keep accepting, and new requests are told to go elsewhere as the {@linkplain
     * HttpProxyServerBootstrap#withDrainStrategy drain strategy} says: an HTTP/1 response gets
     * {@code Connection: close}, an HTTP/2 or HTTP/3 connection is sent GOAWAY. Exchanges in
     * progress get until {@code drainTime} is over; then the listeners close, and so does every
     * connection still open. The proxy stays {@code DRAINING} until {@link #stop()}.
     *
     * @param drainTime how long the drain lasts
     * @throws UnsupportedOperationException if this server cannot drain
     */
    default void drain(Duration drainTime) {
        throw new UnsupportedOperationException(getClass().getName() + " does not drain");
    }

    /**
     * Stops accepting new connections now, as Envoy's non-graceful {@code /drain_listeners} does:
     * the TCP listener closes and the UDP ones (HTTP/3, transparent QUIC) refuse new QUIC
     * connections; open connections are left alone. The state turns {@link ServerState#DRAINING}.
     *
     * @throws UnsupportedOperationException if this server cannot
     */
    default void stopListeners() {
        throw new UnsupportedOperationException(getClass().getName() + " does not stop its listeners");
    }

    /** {@return how long {@link #stop()} lets exchanges in progress finish (see {@link HttpProxyServerBootstrap#withDrainTime})} */
    default Duration getDrainTime() {
        return Duration.ofSeconds(10);
    }

    /**
     * Fails or restores the proxy's health check, as Envoy's admin {@code /healthcheck/fail} and
     * {@code /healthcheck/ok} do. While it fails, the admin {@code /ready} answers 503, the
     * {@linkplain HttpProxyServerBootstrap#withHealthCheckPath health-check path} answers 503, and
     * every new request drains its connection, as when draining with {@link DrainStrategy#IMMEDIATE}.
     *
     * @param failed whether the health check fails
     * @throws UnsupportedOperationException if this server has no health check
     */
    default void setHealthCheckFailed(boolean failed) {
        throw new UnsupportedOperationException(getClass().getName() + " has no health check");
    }

    /** {@return whether the health check has been failed with {@link #setHealthCheckFailed}} */
    default boolean isHealthCheckFailed() {
        return false;
    }

    /**
     * The admin listener's address ({@link HttpProxyServerBootstrap#withAdmin}), with the port it
     * bound.
     *
     * @return the address, or {@code null} without an admin listener
     */
    default InetSocketAddress getAdminAddress() {
        return null;
    }

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
     * The UDP address of the transparent QUIC listener ({@link
     * HttpProxyServerBootstrap#withTransparentQuicPort}), with the port it bound.
     *
     * @return the address, or {@code null} without the listener
     */
    default InetSocketAddress getTransparentQuicAddress() {
        return null;
    }

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

    /**
     * The proxy's metrics, as {@link HttpProxyServerBootstrap#withStats} or {@link
     * HttpProxyServerBootstrap#withMetrics} configured them.
     *
     * @return the registry, {@link org.microproxy.stats.StatsRegistry#NOOP} without metrics
     */
    default org.microproxy.stats.StatsRegistry getStats() {
        return org.microproxy.stats.StatsRegistry.NOOP;
    }

    @Override
    default void close() {
        stop();
    }
}
