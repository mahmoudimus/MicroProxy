package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
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

    /**
     * Sees the datagrams a server receives that none of its connections claims (by Destination
     * Connection ID) before its endpoint does: a client's first Initial, packets of unknown
     * versions, packets for connections the server does not know. A filter that takes a datagram
     * keeps it from the endpoint, and may hand it back later with {@link #inject}; one that does
     * not take it leaves it to the endpoint, which may start a connection with it. With a
     * filter, a server can share its socket with other uses of the same port, such as a proxy
     * relaying some clients' QUIC elsewhere.
     */
    @FunctionalInterface
    public interface DatagramFilter {

        /**
         * Called on the server's receiving thread for each datagram no connection claims: it
         * should not block. The datagram's buffer is the filter's to keep.
         *
         * @param from the sender
         * @param datagram the datagram, between its position and limit
         * @return true to take the datagram, false to leave it to the endpoint
         */
        boolean filter(InetSocketAddress from, ByteBuffer datagram);
    }

    /**
     * Where an {@linkplain #unbound unbound} server's datagrams go: the transport it runs over
     * instead of a socket.
     */
    @FunctionalInterface
    public interface DatagramSink {

        /**
         * Called for each datagram the server sends, from its connections' threads (several at
         * once) and from threads that hand it datagrams (its answers, such as Version
         * Negotiation): it should not block for long.
         *
         * @param datagram the datagram, between its position and limit; the sink may keep it
         * @param to the receiver
         */
        void send(ByteBuffer datagram, InetSocketAddress to);
    }

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
     * Binds a server whose filter sees the datagrams no connection claims first.
     *
     * @param address the local address; port 0 picks one
     * @param config how to accept connections
     * @param endpointConfig the endpoint settings: connection IDs, reset key, versions
     * @param filter what sees datagrams for no known connection before the endpoint
     * @return the running server
     * @throws IOException if the socket cannot be bound
     */
    public static QuicServer bind(InetSocketAddress address, ServerConfig config, EndpointConfig endpointConfig,
            DatagramFilter filter) throws IOException {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(filter, "filter");
        return new QuicServer(new EndpointDriver(address, endpointConfig, config, "quic-server", filter));
    }

    /**
     * A server without a socket, for QUIC over another transport: its owner hands it the
     * datagrams it receives ({@link #receive}), and it hands those it sends to {@code sink}. It has
     * no thread of its own besides its connections'. Path MTU discovery stays off.
     *
     * @param local the address the server reports as its own ({@link #localAddress()})
     * @param config how to accept connections
     * @param endpointConfig the endpoint settings: connection IDs, reset key, versions
     * @param filter what sees datagrams for no known connection before the endpoint, or null
     * @param sink where the server's datagrams go
     * @return the server
     */
    public static QuicServer unbound(InetSocketAddress local, ServerConfig config, EndpointConfig endpointConfig,
            DatagramFilter filter, DatagramSink sink) {
        Objects.requireNonNull(local, "local");
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(endpointConfig, "endpointConfig");
        Objects.requireNonNull(sink, "sink");
        return new QuicServer(new EndpointDriver(local, endpointConfig, config, "quic-server", filter, sink));
    }

    /**
     * Hands the server a datagram as if its socket had received it: to the connection it belongs
     * to, else past the {@linkplain DatagramFilter filter} to the endpoint. For an {@linkplain
     * #unbound unbound} server, this is how datagrams arrive; datagrams handed over from one thread
     * are routed in order. Does nothing once the server is closed.
     *
     * @param from the datagram's sender
     * @param datagram the datagram, between its position and limit; the server keeps it
     */
    public void receive(InetSocketAddress from, ByteBuffer datagram) {
        driver.receive(Objects.requireNonNull(from, "from"), Objects.requireNonNull(datagram, "datagram"));
    }

    /**
     * Routes a datagram the {@linkplain DatagramFilter filter} took as if it had just arrived,
     * without asking the filter again: a client's first Initial starts a connection. Datagrams
     * injected from one thread are routed in order. Does nothing once the server is closed.
     *
     * @param from the datagram's sender
     * @param datagram the datagram, between its position and limit; the server keeps it
     */
    public void inject(InetSocketAddress from, ByteBuffer datagram) {
        inject(from, datagram, null);
    }

    /**
     * Routes a datagram the {@linkplain DatagramFilter filter} took, as {@link #inject(InetSocketAddress,
     * ByteBuffer)} does, accepting a connection it starts with {@code config} instead of the
     * server's own configuration: its certificates, ALPN, transport parameters and Retry. A
     * client's datagrams after the first reach the connection by its connection IDs, whatever
     * configuration they are injected with.
     *
     * @param from the datagram's sender
     * @param datagram the datagram, between its position and limit; the server keeps it
     * @param config how to accept a connection the datagram starts, or null for the server's own
     */
    public void inject(InetSocketAddress from, ByteBuffer datagram, ServerConfig config) {
        driver.inject(Objects.requireNonNull(from, "from"), Objects.requireNonNull(datagram, "datagram"), config);
    }

    /**
     * Sends a datagram from the server's socket (an unbound server's sink), as its connections do:
     * for replies on behalf of other uses of the port.
     *
     * @param datagram the datagram, between its position and limit
     * @param to the receiver
     */
    public void send(ByteBuffer datagram, InetSocketAddress to) {
        driver.send(Objects.requireNonNull(datagram, "datagram"), Objects.requireNonNull(to, "to"));
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
     * The address the server is bound to (an unbound server's own address, as given).
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
