package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.Connection;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import io.github.mahmoudimus.quic.connection.Dir;
import io.github.mahmoudimus.quic.connection.StreamId;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * A QUIC connection with a blocking API made for virtual threads: open and accept streams, read and
 * write them as {@link java.io.InputStream}s and {@link java.io.OutputStream}s, send and receive
 * datagrams. Operations block while flow control, the stream limits or the peer hold them up, and
 * fail with a {@link QuicConnectionException} once the connection is gone.
 *
 * <p>Connections come from {@link QuicServer#accept()} and {@link QuicClient#connect}. Each one is
 * driven by a virtual thread of its endpoint; any number of threads may use a connection and its
 * streams at once.
 *
 * <p><b>Migration.</b> A server's connection follows a client that moves to a new address (a NAT
 * rebinding, or a client that {@linkplain #migrate migrates}), validating the new path first, unless
 * its configuration forbids migration; {@link #remoteAddress()} then changes. A client connection
 * moves with {@link #migrate} (probing the new path first) or {@link #rebind} (at once), and to a
 * server's preferred address on its own.
 *
 * <p><b>0-RTT.</b> A connection from {@link QuicClient#connectEarly} may still be handshaking: its
 * streams can be opened and written at once, and what is written goes out as 0-RTT data. A server
 * that accepted 0-RTT hands the connection out before its handshake completes; data that arrived
 * as early data ({@link QuicStream#receivedEarlyData()}) may have been replayed by an attacker.
 */
public final class QuicConnection implements AutoCloseable {

    private final ConnectionDriver driver;
    private final Connection conn;

    QuicConnection(ConnectionDriver driver) {
        this.driver = driver;
        this.conn = driver.connection();
    }

    ConnectionDriver driver() {
        return driver;
    }

    /** Waits for the handshake; called by the client right after connecting. */
    void awaitConnected(long timeoutNanos) throws IOException {
        driver.lock.lock();
        try {
            long deadline = timeoutNanos < 0 ? Long.MAX_VALUE : driver.now() + timeoutNanos;
            while (!driver.isConnected()) {
                ConnectionError lost = driver.lostReason();
                if (lost != null) {
                    throw new QuicConnectionException(lost);
                }
                if (timeoutNanos < 0) {
                    driver.changed.await();
                } else {
                    long wait = deadline - driver.now();
                    if (wait <= 0) {
                        conn.close(driver.now(), 0, "connect timed out");
                        driver.wake();
                        throw new QuicConnectionException(ConnectionError.of(ConnectionError.Kind.TIMED_OUT));
                    }
                    driver.changed.awaitNanos(wait);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("connect interrupted");
        } finally {
            driver.lock.unlock();
        }
    }

    /**
     * Waits for the handshake to complete: for a connection from {@link QuicClient#connectEarly} or
     * one a server accepted with 0-RTT data. Returns at once for other connections.
     *
     * @param timeout how long to wait, or null for no limit
     * @return true if the handshake completed, false on timeout
     * @throws QuicConnectionException if the connection ended first
     * @throws InterruptedIOException if interrupted while waiting
     */
    public boolean awaitHandshake(Duration timeout) throws IOException {
        driver.lock.lock();
        try {
            long deadline = timeout == null ? Long.MAX_VALUE : driver.now() + timeout.toNanos();
            while (!driver.isConnected()) {
                checkOpen();
                if (timeout == null) {
                    await();
                } else {
                    long wait = deadline - driver.now();
                    if (wait <= 0) {
                        return false;
                    }
                    driver.changed.awaitNanos(wait);
                }
            }
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted");
        } finally {
            driver.lock.unlock();
        }
    }

    /**
     * Whether the handshake has completed.
     *
     * @return true once complete
     */
    public boolean isHandshakeComplete() {
        return withLock(driver::isConnected);
    }

    /**
     * Whether the TLS handshake resumed an earlier session from a ticket.
     *
     * @return true if resumed (a client knows once the server answered)
     */
    public boolean isResumed() {
        return withLock(conn::isResumed);
    }

    /**
     * Whether the server accepted 0-RTT data: on a client, known once the handshake completes; on a
     * server, from the start.
     *
     * @return true if accepted
     */
    public boolean earlyDataAccepted() {
        return withLock(conn::earlyDataAccepted);
    }

    /**
     * Client: whether data written now goes out as 0-RTT data, before the handshake completes.
     *
     * @return true while sending 0-RTT data
     */
    public boolean isZeroRtt() {
        return withLock(conn::isZeroRtt);
    }

    /** Throws if the connection is gone. Called with the lock held. */
    void checkOpen() throws QuicConnectionException {
        ConnectionError lost = driver.lostReason();
        if (lost != null) {
            throw new QuicConnectionException(lost);
        }
    }

    /** Waits for the connection to change. Called with the lock held. */
    void await() throws InterruptedIOException {
        try {
            driver.changed.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted");
        }
    }

    /**
     * Opens a bidirectional stream, waiting while the peer's stream limit is reached. Nothing is sent
     * until data is written.
     *
     * @return the stream
     * @throws QuicConnectionException if the connection is gone
     * @throws InterruptedIOException if interrupted while waiting
     */
    public QuicStream openBidirectionalStream() throws IOException {
        return open(Dir.BI);
    }

    /**
     * Opens a unidirectional (send-only) stream, waiting while the peer's stream limit is reached.
     *
     * @return the stream
     * @throws QuicConnectionException if the connection is gone
     * @throws InterruptedIOException if interrupted while waiting
     */
    public QuicStream openUnidirectionalStream() throws IOException {
        return open(Dir.UNI);
    }

    private QuicStream open(Dir dir) throws IOException {
        driver.lock.lock();
        try {
            while (true) {
                checkOpen();
                StreamId id = conn.openStream(dir);
                if (id != null) {
                    return new QuicStream(this, id, true);
                }
                await();
            }
        } finally {
            driver.lock.unlock();
        }
    }

    /**
     * Waits for a stream the peer opened, bidirectional or unidirectional (receive-only).
     *
     * @return the stream
     * @throws QuicConnectionException if the connection is gone
     * @throws InterruptedIOException if interrupted while waiting
     */
    public QuicStream acceptStream() throws IOException {
        driver.lock.lock();
        try {
            while (true) {
                StreamId id = conn.acceptStream(Dir.BI);
                if (id == null) {
                    id = conn.acceptStream(Dir.UNI);
                }
                if (id != null) {
                    return new QuicStream(this, id, false);
                }
                checkOpen();
                await();
            }
        } finally {
            driver.lock.unlock();
        }
    }

    /**
     * Sends an unreliable datagram (RFC 9221). When the send buffer is full the oldest queued
     * datagrams are dropped.
     *
     * @param data the payload, at most {@link #maxDatagramSize()} bytes
     * @throws QuicConnectionException if the connection is gone
     * @throws IllegalStateException if either side does not accept datagrams
     * @throws IllegalArgumentException if the payload is too large
     * @throws IOException if the connection is gone
     */
    public void sendDatagram(byte[] data) throws IOException {
        driver.lock.lock();
        try {
            checkOpen();
            conn.sendDatagram(ByteBuffer.wrap(data));
        } finally {
            driver.lock.unlock();
        }
        driver.wake();
    }

    /**
     * Waits for a datagram from the peer.
     *
     * @return the payload
     * @throws QuicConnectionException if the connection is gone
     * @throws InterruptedIOException if interrupted while waiting
     */
    public byte[] receiveDatagram() throws IOException {
        return receiveDatagram(null);
    }

    /**
     * Waits for a datagram from the peer, up to a timeout.
     *
     * @param timeout how long to wait, or null to wait without a limit
     * @return the payload, or null if none arrived in time
     * @throws QuicConnectionException if the connection is gone
     * @throws InterruptedIOException if interrupted while waiting
     */
    public byte[] receiveDatagram(Duration timeout) throws IOException {
        driver.lock.lock();
        try {
            long deadline = timeout == null ? Long.MAX_VALUE : driver.now() + timeout.toNanos();
            while (true) {
                ByteBuffer d = conn.receiveDatagram();
                if (d != null) {
                    byte[] out = new byte[d.remaining()];
                    d.get(out);
                    return out;
                }
                checkOpen();
                if (timeout == null) {
                    await();
                } else {
                    long wait = deadline - driver.now();
                    if (wait <= 0) {
                        return null;
                    }
                    driver.changed.awaitNanos(wait);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted");
        } finally {
            driver.lock.unlock();
        }
    }

    /**
     * The largest datagram payload {@link #sendDatagram} takes now.
     *
     * @return bytes, or -1 if the peer does not accept datagrams
     */
    public int maxDatagramSize() {
        return withLock(conn::maxDatagramSize);
    }

    /**
     * Starts a key update (RFC 9001 section 6). Keys are also updated routinely.
     *
     * @return true if an update started; false while the previous one is unconfirmed
     */
    public boolean updateKeys() {
        boolean started = withLock(conn::forceKeyUpdate);
        driver.wake();
        return started;
    }

    /**
     * Closes the connection with an application error code: CONNECTION_CLOSE is sent at once and
     * streams fail. Data not yet acknowledged is abandoned; finish streams and wait for the peer's
     * reply first to deliver it.
     *
     * @param code the application error code
     * @param reason the reason phrase
     */
    public void close(long code, String reason) {
        driver.lock.lock();
        try {
            conn.close(driver.now(), code, Objects.requireNonNullElse(reason, ""));
            driver.changed.signalAll();
        } finally {
            driver.lock.unlock();
        }
        driver.wake();
    }

    /** Closes the connection with code 0 and no reason. */
    @Override
    public void close() {
        close(0, "");
    }

    /**
     * Waits until the connection has ended, for any reason.
     *
     * @param timeout how long to wait, or null for no limit
     * @return why it ended, or null on timeout
     * @throws InterruptedIOException if interrupted while waiting
     */
    public ConnectionError awaitClosed(Duration timeout) throws InterruptedIOException {
        driver.lock.lock();
        try {
            long deadline = timeout == null ? Long.MAX_VALUE : driver.now() + timeout.toNanos();
            while (true) {
                ConnectionError lost = driver.lostReason();
                if (lost != null) {
                    return lost;
                }
                if (timeout == null) {
                    await();
                } else {
                    long wait = deadline - driver.now();
                    if (wait <= 0) {
                        return null;
                    }
                    driver.changed.awaitNanos(wait);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted");
        } finally {
            driver.lock.unlock();
        }
    }

    /**
     * Whether the connection is open.
     *
     * @return false once it is closing or gone
     */
    public boolean isOpen() {
        return withLock(() -> driver.lostReason() == null);
    }

    /**
     * Why the connection ended.
     *
     * @return the reason, or null while it is open
     */
    public ConnectionError closeReason() {
        return withLock(driver::lostReason);
    }

    /**
     * The application protocol agreed with ALPN.
     *
     * @return the protocol
     */
    public String alpn() {
        return withLock(conn::alpn);
    }

    /**
     * The server name: the one a client connected to, or the client's SNI on a server.
     *
     * @return the name, or null if the client sent none
     */
    public String serverName() {
        return withLock(conn::serverName);
    }

    /**
     * The peer's certificate chain, end-entity first.
     *
     * @return the chain; empty if the peer sent none (a client without a certificate)
     */
    public List<X509Certificate> peerCertificates() {
        return withLock(conn::peerCertificates);
    }

    /**
     * The negotiated cipher suite.
     *
     * @return the suite
     */
    public CipherSuite cipherSuite() {
        return withLock(() -> conn.tlsSession().cipherSuite());
    }

    /**
     * The key exchange group the handshake used.
     *
     * @return the group
     */
    public io.github.mahmoudimus.quic.tls.NamedGroup keyExchangeGroup() {
        return withLock(() -> conn.tlsSession().negotiatedGroup());
    }

    /**
     * The peer's address.
     *
     * @return the address
     */
    public InetSocketAddress remoteAddress() {
        return conn.remoteAddress();
    }

    /**
     * The local address the connection sends from: the endpoint's socket, a socket of its own
     * after it migrated, or a server's preferred address once its client moved there.
     *
     * @return the address
     */
    public InetSocketAddress localAddress() {
        InetSocketAddress socket = driver.socketAddress();
        if (socket != null) {
            return socket;
        }
        InetSocketAddress local = withLock(conn::localAddress);
        return local != null ? local : driver.endpoint().localAddress();
    }

    /**
     * Client: moves the connection to a new local address (RFC 9000 section 9), waiting until it
     * has. A UDP socket is bound at {@code local}; the connection probes the path from there to
     * the server with PATH_CHALLENGE and a connection ID of the server's it has not used, and
     * switches to the path when the server answers. Its streams carry on meanwhile on the old
     * path; the old socket is closed once no connection uses it (a client's first socket then
     * gives way to the new one for later connections). The congestion and RTT state carry over
     * when only the port changes, and start over otherwise. A new port on the same address is
     * what a NAT rebinding looks like to the server.
     *
     * @param local the address to bind, port 0 for an ephemeral port
     * @return the new local address, with its port
     * @throws IOException if the socket cannot be bound; if the connection cannot migrate (a
     *     server's, one still handshaking, one where either side disabled active migration, one
     *     whose server gave no unused connection ID, one on an endpoint without a socket); or if
     *     the server did not answer on the new path (the connection stays where it was)
     * @throws QuicConnectionException if the connection ended meanwhile
     */
    public InetSocketAddress migrate(InetSocketAddress local) throws IOException {
        Objects.requireNonNull(local, "local");
        return migrate(driver.endpoint().bindSocket(local), true);
    }

    /**
     * Client: moves the connection to a socket of the caller's, as {@link
     * #migrate(InetSocketAddress)} does with one it binds. The connection owns the channel from
     * now on, and closes it when it no longer uses it.
     *
     * @param channel a bound socket
     * @return the new local address
     * @throws IOException if the channel is not bound, or as {@link #migrate(InetSocketAddress)}
     */
    public InetSocketAddress migrate(DatagramChannel channel) throws IOException {
        Objects.requireNonNull(channel, "channel");
        return migrate(driver.endpoint().adopt(channel), true);
    }

    /**
     * Client: moves the connection to a new local address at once, without probing the path
     * first, as quinn's endpoint does when it rebinds: packets leave from a UDP socket bound at
     * {@code local} from now on, with a connection ID of the server's not used before when it gave
     * one, and the server follows as it follows a NAT rebinding, validating the new path itself.
     * Use it with servers that answer PATH_CHALLENGE only on the path they use, which never answer
     * {@link #migrate}'s probe (aioquic is one). The old socket is closed once no connection uses
     * it.
     *
     * @param local the address to bind, port 0 for an ephemeral port
     * @return the new local address, with its port
     * @throws IOException if the socket cannot be bound, or the connection cannot migrate (as for
     *     {@link #migrate}, except that the server need not have given an unused connection ID)
     * @throws QuicConnectionException if the connection ended meanwhile
     */
    public InetSocketAddress rebind(InetSocketAddress local) throws IOException {
        Objects.requireNonNull(local, "local");
        return migrate(driver.endpoint().bindSocket(local), false);
    }

    private InetSocketAddress migrate(EndpointDriver.Socket next, boolean probe) throws IOException {
        boolean started = false;
        driver.lock.lock();
        try {
            // A connection migrates once its handshake is confirmed (RFC 9000 section 9), and
            // after any probe under way, such as that of a server's preferred address
            while (conn.isHandshaking() || conn.isEstablished() && (!conn.isHandshakeConfirmed() || conn.isProbingPath())) {
                ConnectionError lost = driver.lostReason();
                if (lost != null) {
                    throw new QuicConnectionException(lost);
                }
                driver.changed.await();
            }
            try {
                driver.startMigration(next, probe);
            } catch (IllegalStateException e) {
                throw new IOException("cannot migrate: " + e.getMessage(), e);
            }
            started = true; // the driver owns the socket from now on
            driver.wake();
            while (true) {
                Boolean migrated = driver.migrated();
                if (migrated != null) {
                    if (migrated) {
                        return next.address;
                    }
                    throw new IOException("no PATH_RESPONSE on the path from " + next.address + "; not migrated");
                }
                ConnectionError lost = driver.lostReason();
                if (lost != null) {
                    throw new QuicConnectionException(lost);
                }
                driver.changed.await();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("migration interrupted");
        } finally {
            driver.lock.unlock();
            if (!started) {
                driver.endpoint().release(next, null);
            }
        }
    }

    /**
     * The Destination Connection ID of the client's first Initial packet (after a Retry, of its
     * first Initial with the Retry's token): on a server, the ID the connection was created for.
     *
     * @return the ID
     */
    public ConnectionId initialDestinationId() {
        return conn.initialDcid();
    }

    /**
     * The QUIC version in use.
     *
     * @return the version
     */
    public QuicVersion version() {
        return conn.version();
    }

    /**
     * A snapshot of the connection's statistics.
     *
     * @return the statistics
     */
    public Stats stats() {
        return withLock(() -> new Stats(Duration.ofNanos(conn.rtt()), conn.congestionWindow(), conn.currentMtu(),
                conn.recovery().sentPackets(), conn.recovery().lostPackets(), conn.keyUpdates(),
                driver.droppedDatagrams()));
    }

    /**
     * Connection statistics.
     *
     * @param rtt the smoothed round-trip time
     * @param congestionWindow the congestion window, in bytes
     * @param mtu the current path MTU
     * @param sentPackets packets sent
     * @param lostPackets packets deemed lost
     * @param keyUpdates key updates, by either side
     * @param droppedDatagrams datagrams dropped because the connection fell behind
     */
    public record Stats(Duration rtt, long congestionWindow, int mtu, long sentPackets, long lostPackets,
            long keyUpdates, long droppedDatagrams) {}

    <T> T withLock(java.util.function.Supplier<T> s) {
        driver.lock.lock();
        try {
            return s.get();
        } finally {
            driver.lock.unlock();
        }
    }

    Connection connection() {
        return conn;
    }

    @Override
    public String toString() {
        return "QuicConnection[" + conn.side() + " " + conn.remoteAddress() + "]";
    }
}
