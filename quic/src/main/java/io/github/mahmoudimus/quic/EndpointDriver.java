package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.Connection;
import io.github.mahmoudimus.quic.connection.Endpoint;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.EndpointEvent;
import io.github.mahmoudimus.quic.connection.NanoClock;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.connection.SessionCache;
import io.github.mahmoudimus.quic.connection.Transmit;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketOption;
import java.net.StandardProtocolFamily;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The I/O side of an {@link Endpoint}: one {@link DatagramChannel}, a virtual thread that receives
 * datagrams and routes them, and one {@link ConnectionDriver} per connection. The sans-I/O endpoint
 * is guarded by a lock that is only held while routing; lock order is connection, then endpoint.
 * A server may have a {@link QuicServer.DatagramFilter}, which sees the datagrams no connection
 * claims before the endpoint does, and hands back those it wants routed ({@link #inject}).
 *
 * <p>An unbound endpoint has no socket: its owner hands it the datagrams it receives ({@link
 * #receive}), and it hands those it sends to a {@link QuicServer.DatagramSink}, so that QUIC can
 * run over another transport, such as the datagrams of a CONNECT-UDP flow.
 *
 * <p><b>More sockets.</b> A server with a preferred address (RFC 9000 section 9.6) has a socket
 * there too, and a client connection that migrates ({@link QuicConnection#migrate}) binds a socket
 * of its own for the new path; datagrams carry the local address they arrived at to the
 * connection, and each datagram a connection sends leaves from the socket its {@link
 * Transmit#source()} names. A client's socket that no connection uses any more after a migration
 * is closed; when that is the client's first socket, the new one takes its place for new
 * connections.
 */
final class EndpointDriver implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(EndpointDriver.class.getName());
    /** Socket buffer sizes asked of the OS, so bursts at high rates are not dropped. */
    private static final int SOCKET_BUFFER = 4 << 20;
    private static final long CLOSE_FLUSH_NANOS = TimeUnit.MILLISECONDS.toNanos(300);

    final NanoClock clock = NanoClock.system();

    /** One UDP socket of the endpoint and the virtual thread that receives from it. */
    final class Socket {
        final DatagramChannel channel;
        /** The bound address. */
        final InetSocketAddress address;
        /** What connections see as the local address: null for the endpoint's first socket. */
        final InetSocketAddress key;
        /** Never closed before the endpoint: the first socket of a server, its preferred addresses. */
        final boolean persistent;
        Thread receiver;
        /** Connections sending from it; guarded by the endpoint's lock. */
        int users;

        Socket(DatagramChannel channel, InetSocketAddress key, boolean persistent) throws IOException {
            this.channel = channel;
            this.address = (InetSocketAddress) channel.getLocalAddress();
            this.key = key;
            this.persistent = persistent;
        }

        void start() {
            receiver = Thread.ofVirtual().name(name + "-recv-" + address.getPort()).start(() -> receiveLoop(this));
        }

        void close() {
            try {
                channel.close();
            } catch (IOException e) {
                LOG.log(System.Logger.Level.DEBUG, "close failed", e);
            }
        }

        @Override
        public String toString() {
            return "socket " + address;
        }
    }

    /** The first socket; null for an unbound endpoint. A migrating client may replace it. */
    private volatile Socket primary;
    /** The other sockets, by bound address. */
    private final ConcurrentHashMap<InetSocketAddress, Socket> sockets = new ConcurrentHashMap<>();
    /** Where an unbound endpoint's datagrams go; null for one with a socket. */
    private final QuicServer.DatagramSink sink;
    private final Endpoint endpoint;
    private final ReentrantLock endpointLock = new ReentrantLock();
    private final ConcurrentHashMap<Connection, ConnectionDriver> drivers = new ConcurrentHashMap<>();
    private final LinkedBlockingQueue<Object> accepted;
    /** The address of an unbound endpoint. */
    private final InetSocketAddress unboundAddress;
    private final String name;
    /** Sees datagrams for no known connection first; null for none. */
    private final QuicServer.DatagramFilter filter;
    private volatile boolean closed;

    private static final Object CLOSED = new Object();

    EndpointDriver(InetSocketAddress bind, EndpointConfig config, ServerConfig serverConfig, String name)
            throws IOException {
        this(bind, config, serverConfig, name, null);
    }

    EndpointDriver(InetSocketAddress bind, EndpointConfig config, ServerConfig serverConfig, String name,
            QuicServer.DatagramFilter filter) throws IOException {
        this.name = name;
        this.filter = filter;
        this.sink = null;
        this.unboundAddress = null;
        boolean[] dontFragment = new boolean[1];
        DatagramChannel ch = openChannel(bind, dontFragment);
        List<Socket> preferred = new ArrayList<>();
        try {
            this.primary = new Socket(ch, null, true);
            if (serverConfig != null && (serverConfig.preferredIpv4() != null || serverConfig.preferredIpv6() != null)) {
                // Sockets at the preferred addresses, whose actual ports are advertised
                InetSocketAddress v4 = null;
                InetSocketAddress v6 = null;
                for (InetSocketAddress a : new InetSocketAddress[] {serverConfig.preferredIpv4(), serverConfig.preferredIpv6()}) {
                    if (a == null) {
                        continue;
                    }
                    DatagramChannel pc = openChannel(a, new boolean[1]);
                    Socket ps;
                    try {
                        InetSocketAddress bound = (InetSocketAddress) pc.getLocalAddress();
                        ps = new Socket(pc, bound, true);
                    } catch (IOException | RuntimeException e) {
                        pc.close();
                        throw e;
                    }
                    preferred.add(ps);
                    if (a.getAddress() instanceof java.net.Inet6Address) {
                        v6 = new InetSocketAddress(a.getAddress(), ps.address.getPort());
                    } else {
                        v4 = new InetSocketAddress(a.getAddress(), ps.address.getPort());
                    }
                }
                serverConfig = serverConfig.toBuilder().preferredAddress(v4, v6).build();
            }
            this.endpoint = new Endpoint(config, serverConfig, dontFragment[0]);
        } catch (IOException | RuntimeException e) {
            ch.close();
            for (Socket ps : preferred) {
                ps.close();
            }
            throw e;
        }
        this.accepted = serverConfig != null ? new LinkedBlockingQueue<>() : null;
        primary.start();
        for (Socket ps : preferred) {
            sockets.put(ps.address, ps);
            ps.start();
        }
    }

    /** Opens and binds a socket with the endpoint's options; {@code dontFragment[0]} says whether IP_DONTFRAGMENT took. */
    private static DatagramChannel openChannel(InetSocketAddress bind, boolean[] dontFragment) throws IOException {
        DatagramChannel ch = bind.getAddress() != null && bind.getAddress() instanceof java.net.Inet6Address
                ? DatagramChannel.open(StandardProtocolFamily.INET6)
                : DatagramChannel.open(StandardProtocolFamily.INET);
        try {
            trySetOption(ch, StandardSocketOptions.SO_RCVBUF, SOCKET_BUFFER);
            trySetOption(ch, StandardSocketOptions.SO_SNDBUF, SOCKET_BUFFER);
            dontFragment[0] = setDontFragment(ch);
            ch.bind(bind);
            return ch;
        } catch (IOException | RuntimeException e) {
            ch.close();
            throw e;
        }
    }

    /**
     * An unbound endpoint: no socket and no receiving thread; {@link #receive} takes the datagrams
     * it gets, and {@code sink} the datagrams it sends. Path MTU discovery stays off, since the
     * transport underneath is unknown.
     */
    EndpointDriver(InetSocketAddress local, EndpointConfig config, ServerConfig serverConfig, String name,
            QuicServer.DatagramFilter filter, QuicServer.DatagramSink sink) {
        this.name = name;
        this.filter = filter;
        this.sink = sink;
        this.primary = null;
        this.unboundAddress = local;
        this.endpoint = new Endpoint(config, serverConfig, false);
        this.accepted = serverConfig != null ? new LinkedBlockingQueue<>() : null;
    }

    /** Sets IP_DONTFRAGMENT, which path MTU discovery needs; false where the runtime lacks it. */
    private static boolean setDontFragment(DatagramChannel ch) {
        try {
            return trySetOption(ch, jdk.net.ExtendedSocketOptions.IP_DONTFRAGMENT, true);
        } catch (LinkageError e) {
            return false; // a runtime without the jdk.net module
        }
    }

    private static <T> boolean trySetOption(DatagramChannel ch, SocketOption<T> option, T value) {
        try {
            ch.setOption(option, value);
            return true;
        } catch (IOException | UnsupportedOperationException | IllegalArgumentException e) {
            return false;
        }
    }

    InetSocketAddress localAddress() {
        Socket s = primary;
        return s != null ? s.address : unboundAddress;
    }

    private void receiveLoop(Socket socket) {
        ByteBuffer buf = ByteBuffer.allocateDirect(65536);
        while (!closed && socket.channel.isOpen()) {
            InetSocketAddress from;
            buf.clear();
            try {
                from = (InetSocketAddress) socket.channel.receive(buf);
            } catch (ClosedChannelException e) {
                break;
            } catch (IOException e) {
                if (closed) {
                    break;
                }
                LOG.log(System.Logger.Level.DEBUG, "receive failed", e);
                continue;
            }
            if (from == null) {
                continue;
            }
            buf.flip();
            // Each datagram gets its own buffer: connections keep views of received data
            receive(socket.key, from, ByteBuffer.allocate(buf.remaining()).put(buf).flip());
        }
    }

    /**
     * Takes a received datagram: to the connection it belongs to, else past the filter to the
     * endpoint. The datagram's buffer becomes the endpoint's. Any thread may call it.
     */
    void receive(InetSocketAddress from, ByteBuffer datagram) {
        receive(null, from, datagram);
    }

    /** Takes a datagram received at {@code local}, null for the first socket. */
    private void receive(InetSocketAddress local, InetSocketAddress from, ByteBuffer datagram) {
        if (closed) {
            return;
        }
        if (filter != null && !knows(from, datagram) && filtered(from, datagram)) {
            return;
        }
        route(local, from, datagram, null);
    }

    /**
     * Whether a datagram belongs to one of the endpoint's connections, by its Destination
     * Connection ID. Any thread may call it.
     */
    boolean routes(InetSocketAddress from, ByteBuffer datagram) {
        return knows(from, datagram);
    }

    /** Whether the endpoint routes {@code datagram} to one of its connections. */
    private boolean knows(InetSocketAddress from, ByteBuffer datagram) {
        endpointLock.lock();
        try {
            return endpoint.knows(from, datagram.duplicate());
        } finally {
            endpointLock.unlock();
        }
    }

    /** Offers a datagram to the filter; true if the filter took it. */
    private boolean filtered(InetSocketAddress from, ByteBuffer datagram) {
        try {
            return filter.filter(from, datagram);
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.WARNING, "the datagram filter failed; routing the datagram", e);
            return false;
        }
    }

    /**
     * Routes a datagram as if it had just been received, past the filter: for datagrams the filter
     * held back. Any thread may call it.
     */
    void inject(InetSocketAddress from, ByteBuffer datagram, ServerConfig accept) {
        if (!closed) {
            route(null, from, datagram, accept);
        }
    }

    /** Routes a datagram; a connection it starts is accepted with {@code accept}, or the endpoint's configuration. */
    private void route(InetSocketAddress local, InetSocketAddress from, ByteBuffer datagram, ServerConfig accept) {
        long now = clock.nanoTime();
        Endpoint.DatagramEvent event;
        ConnectionDriver created = null;
        endpointLock.lock();
        try {
            event = endpoint.handle(now, from, 0, datagram.duplicate(), accept);
            if (event instanceof Endpoint.DatagramEvent.NewConnection n) {
                created = new ConnectionDriver(this, n.connection(), true);
                drivers.put(n.connection(), created);
                // Queued before the lock goes: once it does, another thread (the socket's, or one
                // injecting) may route the client's next datagrams to the connection, and 0-RTT
                // packets that reach it before the Initial with their keys are dropped.
                created.deliver(local, from, datagram);
            }
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.WARNING, "dropping a datagram that broke routing", e);
            return;
        } finally {
            endpointLock.unlock();
        }
        switch (event) {
            case Endpoint.DatagramEvent.Deliver d -> {
                ConnectionDriver driver = drivers.get(d.connection());
                if (driver != null) {
                    driver.deliver(local, from, datagram);
                }
            }
            case Endpoint.DatagramEvent.NewConnection n -> created.start();
            case Endpoint.DatagramEvent.Response r -> send(r.datagram(), from, local);
            case null -> {}
        }
    }

    /** Sends a datagram from the first socket. */
    void send(ByteBuffer datagram, InetSocketAddress to) {
        send(datagram, to, null);
    }

    /**
     * Sends a datagram from the socket bound to {@code source}, or the first socket for null (or
     * a socket since closed); DatagramChannel serializes concurrent senders itself.
     */
    void send(ByteBuffer datagram, InetSocketAddress to, InetSocketAddress source) {
        if (sink != null) {
            if (closed) {
                return;
            }
            try {
                sink.send(datagram, to);
            } catch (RuntimeException e) {
                LOG.log(System.Logger.Level.DEBUG, "the datagram sink failed", e);
            }
            return;
        }
        Socket socket = source != null ? sockets.getOrDefault(source, primary) : primary;
        try {
            socket.channel.send(datagram, to);
        } catch (ClosedChannelException e) {
            // shutting down, or a socket a migration left
        } catch (IOException e) {
            LOG.log(System.Logger.Level.DEBUG, "send failed", e);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Sockets of migrating client connections

    /** The socket a new connection sends from: the first one. Counts the connection as its user. */
    Socket acquirePrimary() {
        endpointLock.lock();
        try {
            Socket s = primary;
            if (s != null) {
                s.users++;
            }
            return s;
        } finally {
            endpointLock.unlock();
        }
    }

    /**
     * Binds a socket for a connection that migrates, with its first user counted.
     *
     * @param bind the address to bind, port 0 for an ephemeral one
     * @return the socket, receiving
     * @throws IOException if it cannot be bound, or the endpoint has no sockets
     */
    Socket bindSocket(InetSocketAddress bind) throws IOException {
        if (primary == null) {
            throw new IOException("an endpoint without a socket cannot migrate");
        }
        return adopt(openChannel(bind, new boolean[1]));
    }

    /**
     * Takes over a bound socket for a connection that migrates, with its first user counted.
     *
     * @param channel the socket, bound and in blocking mode
     * @return the socket, receiving
     * @throws IOException if the channel is not bound, or the endpoint has no sockets or is closed
     */
    Socket adopt(DatagramChannel channel) throws IOException {
        if (primary == null) {
            throw new IOException("an endpoint without a socket cannot migrate");
        }
        if (channel.getLocalAddress() == null) {
            throw new IOException("the channel is not bound");
        }
        Socket s;
        try {
            channel.configureBlocking(true);
            s = new Socket(channel, (InetSocketAddress) channel.getLocalAddress(), false);
        } catch (IOException | RuntimeException e) {
            channel.close();
            throw e;
        }
        endpointLock.lock();
        try {
            if (closed) {
                s.close();
                throw new ClosedChannelException();
            }
            s.users = 1;
            sockets.put(s.address, s);
        } finally {
            endpointLock.unlock();
        }
        s.start();
        return s;
    }

    /**
     * A connection stopped sending from a socket: one it moved away from, one whose probe failed,
     * or its last one as it ended. A socket nobody uses any more is closed, unless it is
     * persistent; a client's first socket is closed too after a migration ({@code replacement}
     * not null), and the replacement takes its place.
     */
    void release(Socket socket, Socket replacement) {
        if (socket == null) {
            return;
        }
        boolean close = false;
        endpointLock.lock();
        try {
            socket.users--;
            if (socket.users <= 0 && !closed) {
                if (socket != primary) {
                    close = !socket.persistent;
                } else if (replacement != null && accepted == null && sockets.remove(replacement.address, replacement)) {
                    primary = replacement; // a client's first socket, left by its only user
                    close = true;
                }
                if (close) {
                    sockets.remove(socket.address, socket);
                }
            }
        } finally {
            endpointLock.unlock();
        }
        if (close) {
            socket.close();
        }
    }

    /** Applies a connection's endpoint events; called with the connection's lock held. */
    void handleEndpointEvents(Connection conn) {
        EndpointEvent first = conn.pollEndpointEvent();
        if (first == null) {
            return;
        }
        endpointLock.lock();
        try {
            for (EndpointEvent e = first; e != null; e = conn.pollEndpointEvent()) {
                endpoint.handleEvent(conn, e);
            }
        } finally {
            endpointLock.unlock();
        }
    }

    /** Drops a failed connection's routes. */
    void forget(Connection conn) {
        endpointLock.lock();
        try {
            endpoint.handleEvent(conn, new EndpointEvent.Drained());
        } finally {
            endpointLock.unlock();
        }
    }

    void remove(ConnectionDriver driver) {
        drivers.remove(driver.connection(), driver);
    }

    void accepted(QuicConnection connection) {
        if (accepted != null && !closed) {
            accepted.add(connection);
        }
    }

    QuicConnection accept(long timeoutNanos) throws IOException {
        if (accepted == null) {
            throw new IllegalStateException("not a server");
        }
        while (true) {
            if (closed) {
                throw new ClosedChannelException();
            }
            Object o;
            try {
                o = timeoutNanos < 0 ? accepted.take() : accepted.poll(timeoutNanos, TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new java.io.InterruptedIOException("accept interrupted");
            }
            if (o == null) {
                return null;
            }
            if (o == CLOSED) {
                accepted.add(CLOSED); // wake the next acceptor too
                throw new ClosedChannelException();
            }
            QuicConnection c = (QuicConnection) o;
            if (c.isOpen()) {
                return c;
            }
        }
    }

    ConnectionDriver connect(ClientConfig config, InetSocketAddress remote, String serverName,
            SessionCache cache) throws IOException {
        if (closed) {
            throw new ClosedChannelException();
        }
        ConnectionDriver driver;
        endpointLock.lock();
        try {
            Connection conn = endpoint.connect(clock.nanoTime(), config, remote, serverName, cache);
            driver = new ConnectionDriver(this, conn, false);
            driver.useSocket(acquirePrimary());
            drivers.put(conn, driver);
        } finally {
            endpointLock.unlock();
        }
        driver.start();
        return driver;
    }

    int connectionCount() {
        return drivers.size();
    }

    boolean isClosed() {
        return closed;
    }

    String name() {
        return name;
    }

    /** Closes every connection, gives them a moment to send CONNECTION_CLOSE, then stops. */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        List<ConnectionDriver> all = new ArrayList<>(drivers.values());
        for (ConnectionDriver d : all) {
            d.closeForShutdown();
        }
        long deadline = clock.nanoTime() + CLOSE_FLUSH_NANOS;
        for (ConnectionDriver d : all) {
            d.awaitCloseSent(deadline);
        }
        for (ConnectionDriver d : all) {
            d.stop();
        }
        for (ConnectionDriver d : all) {
            d.join(deadline + CLOSE_FLUSH_NANOS);
        }
        List<Socket> open = new ArrayList<>(sockets.values());
        Socket first = primary;
        if (first != null) {
            open.add(first);
        }
        for (Socket s : open) {
            s.close();
        }
        for (Socket s : open) {
            try {
                if (s.receiver != null) {
                    s.receiver.join(TimeUnit.NANOSECONDS.toMillis(CLOSE_FLUSH_NANOS) + 1);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (accepted != null) {
            accepted.add(CLOSED);
        }
    }
}
