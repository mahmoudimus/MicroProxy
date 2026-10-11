package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.Connection;
import io.github.mahmoudimus.quic.connection.Endpoint;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.EndpointEvent;
import io.github.mahmoudimus.quic.connection.NanoClock;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.connection.SessionCache;
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
 */
final class EndpointDriver implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(EndpointDriver.class.getName());
    /** Socket buffer sizes asked of the OS, so bursts at high rates are not dropped. */
    private static final int SOCKET_BUFFER = 4 << 20;
    private static final long CLOSE_FLUSH_NANOS = TimeUnit.MILLISECONDS.toNanos(300);

    final NanoClock clock = NanoClock.system();
    /** The socket; null for an unbound endpoint. */
    private final DatagramChannel channel;
    /** Where an unbound endpoint's datagrams go; null for one with a socket. */
    private final QuicServer.DatagramSink sink;
    private final Endpoint endpoint;
    private final ReentrantLock endpointLock = new ReentrantLock();
    private final ConcurrentHashMap<Connection, ConnectionDriver> drivers = new ConcurrentHashMap<>();
    private final LinkedBlockingQueue<Object> accepted;
    private final InetSocketAddress localAddress;
    /** Receives from the socket; null for an unbound endpoint. */
    private final Thread receiver;
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
        DatagramChannel ch = bind.getAddress() != null && bind.getAddress() instanceof java.net.Inet6Address
                ? DatagramChannel.open(StandardProtocolFamily.INET6)
                : DatagramChannel.open(StandardProtocolFamily.INET);
        try {
            trySetOption(ch, StandardSocketOptions.SO_RCVBUF, SOCKET_BUFFER);
            trySetOption(ch, StandardSocketOptions.SO_SNDBUF, SOCKET_BUFFER);
            boolean dontFragment = setDontFragment(ch);
            ch.bind(bind);
            this.channel = ch;
            this.localAddress = (InetSocketAddress) ch.getLocalAddress();
            this.endpoint = new Endpoint(config, serverConfig, dontFragment);
        } catch (IOException | RuntimeException e) {
            ch.close();
            throw e;
        }
        this.accepted = serverConfig != null ? new LinkedBlockingQueue<>() : null;
        this.receiver = Thread.ofVirtual().name(name + "-recv-" + localAddress.getPort()).unstarted(this::receiveLoop);
        receiver.start();
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
        this.channel = null;
        this.receiver = null;
        this.localAddress = local;
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
        return localAddress;
    }

    private void receiveLoop() {
        ByteBuffer buf = ByteBuffer.allocateDirect(65536);
        while (!closed) {
            InetSocketAddress from;
            buf.clear();
            try {
                from = (InetSocketAddress) channel.receive(buf);
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
            receive(from, ByteBuffer.allocate(buf.remaining()).put(buf).flip());
        }
    }

    /**
     * Takes a received datagram: to the connection it belongs to, else past the filter to the
     * endpoint. The datagram's buffer becomes the endpoint's. Any thread may call it.
     */
    void receive(InetSocketAddress from, ByteBuffer datagram) {
        if (closed) {
            return;
        }
        if (filter != null && !knows(from, datagram) && filtered(from, datagram)) {
            return;
        }
        route(from, datagram, null);
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
            route(from, datagram, accept);
        }
    }

    /** Routes a datagram; a connection it starts is accepted with {@code accept}, or the endpoint's configuration. */
    private void route(InetSocketAddress from, ByteBuffer datagram, ServerConfig accept) {
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
                created.deliver(from, datagram);
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
                    driver.deliver(from, datagram);
                }
            }
            case Endpoint.DatagramEvent.NewConnection n -> created.start();
            case Endpoint.DatagramEvent.Response r -> send(r.datagram(), from);
            case null -> {}
        }
    }

    /** Sends a datagram; DatagramChannel serializes concurrent senders itself. */
    void send(ByteBuffer datagram, InetSocketAddress to) {
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
        try {
            channel.send(datagram, to);
        } catch (ClosedChannelException e) {
            // shutting down
        } catch (IOException e) {
            LOG.log(System.Logger.Level.DEBUG, "send failed", e);
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
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException e) {
                LOG.log(System.Logger.Level.DEBUG, "close failed", e);
            }
            try {
                receiver.join(TimeUnit.NANOSECONDS.toMillis(CLOSE_FLUSH_NANOS) + 1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (accepted != null) {
            accepted.add(CLOSED);
        }
    }
}
