package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.SessionCache;
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
 * <p><b>Resumption and 0-RTT.</b> Connections keep the session tickets and NEW_TOKEN tokens
 * servers send in a {@link SessionCache}: the {@link ClientConfig.Builder#sessionCache one
 * configured}, or else one of the client's own, which {@link #sessionCache()} returns. The next
 * connection to the same server resumes the session and skips the server's Retry. With {@link
 * io.github.mahmoudimus.quic.tls.TlsConfig.Builder#earlyData(boolean) earlyData} on, {@link
 * #connectEarly} returns at once when it can send 0-RTT data:
 *
 * <pre>{@code
 * QuicConnection connection = client.connectEarly(address, null, null);
 * QuicStream stream = connection.openBidirectionalStream();   // usable at once
 * stream.getOutputStream().write(idempotentRequest);          // sent as 0-RTT data
 * connection.awaitHandshake(null);
 * boolean accepted = connection.earlyDataAccepted();          // if not, it was sent again in 1-RTT
 * }</pre>
 *
 * <p>Send only what is safe to replay as 0-RTT data: an attacker can capture and resend it.
 *
 * <p>Closing the client closes its connections and stops its threads.
 */
public final class QuicClient implements AutoCloseable {

    private final EndpointDriver driver;
    private final ClientConfig config;
    private final SessionCache sessionCache;

    private QuicClient(EndpointDriver driver, ClientConfig config) {
        this.driver = driver;
        this.config = config;
        this.sessionCache = config.sessionCache() != null ? config.sessionCache() : SessionCache.memory();
    }

    /**
     * The cache of session tickets and tokens connections use by default.
     *
     * @return the cache
     */
    public SessionCache sessionCache() {
        return sessionCache;
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
        return connect(remote, serverName, timeout, sessionCache);
    }

    /**
     * Connects with a cache of session tickets and tokens, waiting for the handshake.
     *
     * @param remote the server's address
     * @param serverName the name to send as SNI and check the certificate against, or null for the
     *     TLS configuration's
     * @param timeout the longest to wait for the handshake, or null for the idle timeout
     * @param cache the tickets and tokens to resume with and keep, or {@link SessionCache#none()}
     * @return the established connection
     * @throws QuicConnectionException if the handshake fails or times out
     * @throws IOException if the client is closed
     */
    public QuicConnection connect(InetSocketAddress remote, String serverName, Duration timeout, SessionCache cache)
            throws IOException {
        ConnectionDriver connection = driver.connect(config, remote, serverName, cache);
        QuicConnection c = connection.facade();
        c.awaitConnected(timeout == null ? -1 : timeout.toNanos());
        return c;
    }

    /**
     * Connects, returning at once if the connection can send 0-RTT data (it resumes with a ticket
     * that allows it, and the TLS configuration enables early data); otherwise waiting for the
     * handshake as {@link #connect(InetSocketAddress, String, Duration)} does. Streams of a 0-RTT
     * connection can be used at once, within the limits the server set in the earlier session;
     * {@link QuicConnection#awaitHandshake} waits for the handshake, and {@link
     * QuicConnection#earlyDataAccepted()} tells whether the server took the early data. If it did
     * not, the data is sent again in 1-RTT packets.
     *
     * @param remote the server's address
     * @param serverName the name for SNI and the certificate, or null for the TLS configuration's
     * @param timeout the longest to wait for a handshake without 0-RTT, or null for the idle timeout
     * @return the connection, possibly still handshaking
     * @throws QuicConnectionException if a handshake without 0-RTT fails or times out
     * @throws IOException if the client is closed
     */
    public QuicConnection connectEarly(InetSocketAddress remote, String serverName, Duration timeout)
            throws IOException {
        return connectEarly(remote, serverName, timeout, sessionCache);
    }

    /**
     * Connects with a cache of session tickets and tokens, returning at once if the connection can
     * send 0-RTT data.
     *
     * @param remote the server's address
     * @param serverName the name for SNI and the certificate, or null for the TLS configuration's
     * @param timeout the longest to wait for a handshake without 0-RTT, or null for the idle timeout
     * @param cache the tickets and tokens to resume with and keep
     * @return the connection, possibly still handshaking
     * @throws QuicConnectionException if a handshake without 0-RTT fails or times out
     * @throws IOException if the client is closed
     * @see #connectEarly(InetSocketAddress, String, Duration)
     */
    public QuicConnection connectEarly(InetSocketAddress remote, String serverName, Duration timeout,
            SessionCache cache) throws IOException {
        ConnectionDriver connection = driver.connect(config, remote, serverName, cache);
        QuicConnection c = connection.facade();
        if (!c.isZeroRtt()) {
            c.awaitConnected(timeout == null ? -1 : timeout.toNanos());
        }
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
