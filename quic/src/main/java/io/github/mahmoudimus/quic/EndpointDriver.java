package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.Connection;
import io.github.mahmoudimus.quic.connection.Endpoint;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.EndpointEvent;
import io.github.mahmoudimus.quic.connection.NanoClock;
import io.github.mahmoudimus.quic.connection.ServerConfig;
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
 */
final class EndpointDriver implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(EndpointDriver.class.getName());
    /** Socket buffer sizes asked of the OS, so bursts at high rates are not dropped. */
    private static final int SOCKET_BUFFER = 4 << 20;
    private static final long CLOSE_FLUSH_NANOS = TimeUnit.MILLISECONDS.toNanos(300);

    final NanoClock clock = NanoClock.system();
    private final DatagramChannel channel;
    private final Endpoint endpoint;
    private final ReentrantLock endpointLock = new ReentrantLock();
    private final ConcurrentHashMap<Connection, ConnectionDriver> drivers = new ConcurrentHashMap<>();
    private final LinkedBlockingQueue<Object> accepted;
    private final InetSocketAddress localAddress;
    private final Thread receiver;
    private final String name;
    private volatile boolean closed;

    private static final Object CLOSED = new Object();

    EndpointDriver(InetSocketAddress bind, EndpointConfig config, ServerConfig serverConfig, String name)
            throws IOException {
        this.name = name;
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
            ByteBuffer datagram = ByteBuffer.allocate(buf.remaining()).put(buf).flip();
            route(from, datagram);
        }
    }

    private void route(InetSocketAddress from, ByteBuffer datagram) {
        long now = clock.nanoTime();
        Endpoint.DatagramEvent event;
        ConnectionDriver created = null;
        endpointLock.lock();
        try {
            event = endpoint.handle(now, from, 0, datagram.duplicate());
            if (event instanceof Endpoint.DatagramEvent.NewConnection n) {
                created = new ConnectionDriver(this, n.connection(), true);
                drivers.put(n.connection(), created);
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
            case Endpoint.DatagramEvent.NewConnection n -> {
                created.start();
                created.deliver(from, datagram);
            }
            case Endpoint.DatagramEvent.Response r -> send(r.datagram(), from);
            case null -> {}
        }
    }

    /** Sends a datagram; DatagramChannel serializes concurrent senders itself. */
    void send(ByteBuffer datagram, InetSocketAddress to) {
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

    ConnectionDriver connect(ClientConfig config, InetSocketAddress remote, String serverName) throws IOException {
        if (closed) {
            throw new ClosedChannelException();
        }
        ConnectionDriver driver;
        endpointLock.lock();
        try {
            Connection conn = endpoint.connect(clock.nanoTime(), config, remote, serverName);
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
        if (accepted != null) {
            accepted.add(CLOSED);
        }
    }
}
