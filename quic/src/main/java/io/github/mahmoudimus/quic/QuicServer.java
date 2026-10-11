package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.util.Objects;

/**
 * A QUIC server on one UDP socket. Handshakes run on the endpoint's virtual threads; {@link
 * #accept()} hands out each connection once its handshake completes.
 *
 * <pre>{@code
 * ServerConfig config = ServerConfig.builder(TlsConfig.builder()
 *         .certificateSelector(hello -> certificateFor(hello.serverName()))
 *         .alpnProtocols("echo")
 *         .build()).build();
 * try (QuicServer server = QuicServer.bind(new InetSocketAddress(4433), config)) {
 *     while (true) {
 *         QuicConnection connection = server.accept();
 *         Thread.ofVirtual().start(() -> serve(connection));
 *     }
 * }
 * }</pre>
 *
 * <p>The server holds at most {@link ServerConfig#maxConnections()} connections; further attempts
 * are refused with CONNECTION_REFUSED. Closing the server closes its connections and stops its
 * threads.
 */
public final class QuicServer implements AutoCloseable {

    private final EndpointDriver driver;

    private QuicServer(EndpointDriver driver) {
        this.driver = driver;
    }

    /**
     * Binds a server with the default endpoint settings.
     *
     * @param address the local address; port 0 picks one
     * @param config how to accept connections
     * @return the running server
     * @throws IOException if the socket cannot be bound
     */
    public static QuicServer bind(InetSocketAddress address, ServerConfig config) throws IOException {
        return bind(address, config, EndpointConfig.defaults());
    }

    /**
     * Binds a server.
     *
     * @param address the local address; port 0 picks one
     * @param config how to accept connections
     * @param endpointConfig the endpoint settings: connection IDs, reset key, versions
     * @return the running server
     * @throws IOException if the socket cannot be bound
     */
    public static QuicServer bind(InetSocketAddress address, ServerConfig config, EndpointConfig endpointConfig)
            throws IOException {
        Objects.requireNonNull(config, "config");
        return new QuicServer(new EndpointDriver(address, endpointConfig, config, "quic-server"));
    }

    /**
     * Waits for the next established connection.
     *
     * @return the connection
     * @throws ClosedChannelException if the server is closed
     * @throws java.io.InterruptedIOException if interrupted while waiting
     * @throws IOException if the server is closed
     */
    public QuicConnection accept() throws IOException {
        return driver.accept(-1);
    }

    /**
     * Waits for the next established connection, up to a timeout.
     *
     * @param timeout how long to wait
     * @return the connection, or null if none arrived in time
     * @throws ClosedChannelException if the server is closed
     * @throws java.io.InterruptedIOException if interrupted while waiting
     * @throws IOException if the server is closed
     */
    public QuicConnection accept(Duration timeout) throws IOException {
        return driver.accept(timeout.toNanos());
    }

    /**
     * The address the server is bound to.
     *
     * @return the address, with the actual port
     */
    public InetSocketAddress localAddress() {
        return driver.localAddress();
    }

    /**
     * The number of connections, including those still handshaking or closing.
     *
     * @return the count
     */
    public int connectionCount() {
        return driver.connectionCount();
    }

    /**
     * Closes every connection (CONNECTION_CLOSE with code 0), stops the threads and closes the
     * socket. Blocked {@link #accept()} calls fail.
     */
    @Override
    public void close() {
        driver.close();
    }
}
