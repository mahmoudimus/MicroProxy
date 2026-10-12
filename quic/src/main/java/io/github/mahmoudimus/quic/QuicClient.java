package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Objects;

/**
 * A QUIC client endpoint on one UDP socket, from which any number of connections can be made.
 *
 * <pre>{@code
 * ClientConfig config = ClientConfig.builder(TlsConfig.builder()
 *         .serverName("example.com")
 *         .alpnProtocols("echo")
 *         .build()).build();
 * try (QuicClient client = QuicClient.create(config);
 *         QuicConnection connection = client.connect(new InetSocketAddress("example.com", 4433))) {
 *     QuicStream stream = connection.openBidirectionalStream();
 *     try (OutputStream out = stream.getOutputStream()) {
 *         out.write(request);
 *     }
 *     byte[] response = stream.getInputStream().readAllBytes();
 * }
 * }</pre>
 *
 * <p>Closing the client closes its connections and stops its threads.
 */
public final class QuicClient implements AutoCloseable {

    private final EndpointDriver driver;
    private final ClientConfig config;

    private QuicClient(EndpointDriver driver, ClientConfig config) {
        this.driver = driver;
        this.config = config;
    }

    /**
     * A client on an ephemeral IPv4 port, with the default endpoint settings.
     *
     * @param config how to connect
     * @return the client
     * @throws IOException if the socket cannot be bound
     */
    public static QuicClient create(ClientConfig config) throws IOException {
        return create(config, new InetSocketAddress(InetAddress.getByName("0.0.0.0"), 0), EndpointConfig.defaults());
    }

    /**
     * A client.
     *
     * @param config how to connect
     * @param bindAddress the local address; use an IPv6 address to reach IPv6 servers
     * @param endpointConfig the endpoint settings: connection IDs, reset key, versions
     * @return the client
     * @throws IOException if the socket cannot be bound
     */
    public static QuicClient create(ClientConfig config, InetSocketAddress bindAddress, EndpointConfig endpointConfig)
            throws IOException {
        Objects.requireNonNull(config, "config");
        return new QuicClient(new EndpointDriver(bindAddress, endpointConfig, null, "quic-client"), config);
    }

    /**
     * Connects with the TLS configuration's server name, waiting for the handshake.
     *
     * @param remote the server's address
     * @return the established connection
     * @throws QuicConnectionException if the handshake fails or times out (the idle timeout)
     * @throws IOException if the client is closed
     */
    public QuicConnection connect(InetSocketAddress remote) throws IOException {
        return connect(remote, null, null);
    }

    /**
     * Connects, waiting for the handshake.
     *
     * @param remote the server's address
     * @param serverName the name to send as SNI and check the certificate against, or null for the
     *     TLS configuration's
     * @param timeout the longest to wait for the handshake, or null for the idle timeout
     * @return the established connection
     * @throws QuicConnectionException if the handshake fails or times out
     * @throws IOException if the client is closed
     */
    public QuicConnection connect(InetSocketAddress remote, String serverName, Duration timeout) throws IOException {
        ConnectionDriver connection = driver.connect(config, remote, serverName);
        QuicConnection c = connection.facade();
        c.awaitConnected(timeout == null ? -1 : timeout.toNanos());
        return c;
    }

    /**
     * The address the client is bound to.
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

    /** Closes every connection (CONNECTION_CLOSE with code 0), stops the threads and the socket. */
    @Override
    public void close() {
        driver.close();
    }
}
