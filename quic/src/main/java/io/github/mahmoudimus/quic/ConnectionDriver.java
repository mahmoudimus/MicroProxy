package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.Connection;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import io.github.mahmoudimus.quic.connection.ConnectionEvent;
import io.github.mahmoudimus.quic.connection.NanoClock;
import io.github.mahmoudimus.quic.connection.Transmit;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Drives one {@link Connection} on a virtual thread: it owns the connection under a {@link
 * ReentrantLock}, wakes on received datagrams, timeouts and application operations, and sends what
 * {@link Connection#pollTransmit} produces. Each wake-up does a bounded amount of work (a batch of
 * datagrams in each direction) and releases the lock between batches, so application threads and
 * other connections get their turn.
 *
 * <p>Application threads take the same lock to use the connection, then call {@link #wake()} so the
 * driver sends what they queued; they wait on {@link #changed}, which the driver signals whenever
 * the connection reports an event.
 */
final class ConnectionDriver implements Runnable {

    private static final System.Logger LOG = System.getLogger(ConnectionDriver.class.getName());

    /** Datagrams queued for one connection; more are dropped, as a full socket buffer would. */
    static final int INBOUND_CAPACITY = 1024;
    /** Datagrams handled per wake-up in each direction. */
    private static final int BATCH = 64;

    private record Inbound(InetSocketAddress local, InetSocketAddress from, ByteBuffer datagram) {}

    private final EndpointDriver endpoint;
    private final Connection conn;
    private final boolean server;
    final ReentrantLock lock = new ReentrantLock();
    /** Signalled when the connection reports events: streams readable or writable, closure. */
    final Condition changed = lock.newCondition();
    private final ArrayBlockingQueue<Inbound> inbound = new ArrayBlockingQueue<>(INBOUND_CAPACITY);
    private final AtomicBoolean wakeRequested = new AtomicBoolean();
    private final QuicConnection facade;
    private volatile Thread thread;
    private volatile boolean stopped;
    private volatile boolean closeSent;
    private final AtomicLong droppedDatagrams = new AtomicLong();

    // Guarded by lock
    private boolean connected;
    /** Whether a server handed the connection out before its handshake, for its 0-RTT data. */
    private boolean acceptedEarly;
    private ConnectionError lost;
    private boolean terminated;
    /** The socket a client connection sends from; null for the endpoint's first one on a server. */
    private EndpointDriver.Socket socket;
    /** The socket of the path a client probes, until it switches there or gives up. */
    private EndpointDriver.Socket probing;
    /** The outcome of the last migration: true once switched, false once failed, null while probing. */
    private Boolean migrated;

    ConnectionDriver(EndpointDriver endpoint, Connection conn, boolean server) {
        this.endpoint = endpoint;
        this.conn = conn;
        this.server = server;
        this.facade = new QuicConnection(this);
    }

    void start() {
        thread = Thread.ofVirtual().name(endpoint.name() + "-conn-" + conn.remoteAddress().getPort()).start(this);
    }

    Connection connection() {
        return conn;
    }

    QuicConnection facade() {
        return facade;
    }

    EndpointDriver endpoint() {
        return endpoint;
    }

    long now() {
        return endpoint.clock.nanoTime();
    }

    /** Sets the socket a new client connection sends from; before it starts. */
    void useSocket(EndpointDriver.Socket socket) {
        this.socket = socket;
    }

    /**
     * Queues a received datagram and wakes the driver; drops it if the queue is full.
     *
     * @param local the local address it arrived at, null for the endpoint's first socket
     */
    void deliver(InetSocketAddress local, InetSocketAddress from, ByteBuffer datagram) {
        if (!inbound.offer(new Inbound(local, from, datagram))) {
            droppedDatagrams.incrementAndGet();
        }
        wake();
    }

    /** Asks the driver to run: something was queued for sending. */
    void wake() {
        wakeRequested.set(true);
        Thread t = thread;
        if (t != null) {
            LockSupport.unpark(t);
        }
    }

    @Override
    public void run() {
        try {
            loop();
        } catch (RuntimeException | Error e) {
            LOG.log(System.Logger.Level.ERROR, "connection to " + conn.remoteAddress() + " failed", e);
            lock.lock();
            try {
                lost = ConnectionError.transport(new QuicException(QuicException.INTERNAL_ERROR, String.valueOf(e)));
            } finally {
                lock.unlock();
            }
            endpoint.forget(conn);
        } finally {
            EndpointDriver.Socket last;
            EndpointDriver.Socket probe;
            lock.lock();
            try {
                terminated = true;
                if (lost == null) {
                    ConnectionError reason = conn.closeReason();
                    lost = reason != null ? reason : ConnectionError.of(ConnectionError.Kind.LOCALLY_CLOSED);
                }
                last = socket;
                probe = probing;
                socket = null;
                probing = null;
                changed.signalAll();
            } finally {
                lock.unlock();
            }
            endpoint.remove(this);
            endpoint.release(probe, null);
            endpoint.release(last, null);
        }
    }

    private void loop() {
        while (!stopped) {
            wakeRequested.set(false);
            List<Transmit> out;
            boolean more;
            long deadline;
            boolean drained;
            EndpointDriver.Socket left;
            EndpointDriver.Socket current;
            lock.lock();
            try {
                long now = now();
                for (int i = 0; i < BATCH; i++) {
                    Inbound in = inbound.poll();
                    if (in == null) {
                        break;
                    }
                    conn.handleDatagram(now, in.local(), in.from(), 0, in.datagram());
                }
                long timeout = conn.pollTimeout();
                if (timeout != NanoClock.NONE && timeout <= now) {
                    conn.handleTimeout(now);
                }
                out = conn.pollTransmit(now, BATCH);
                if (conn.isClosed() && !closeSent) {
                    closeSent = true;
                    changed.signalAll();
                }
                if (dispatchEvents()) {
                    changed.signalAll();
                }
                endpoint.handleEndpointEvents(conn);
                drained = conn.isDrained();
                more = !inbound.isEmpty() || out.size() >= BATCH;
                deadline = conn.pollTimeout();
                left = this.left;
                current = socket;
                this.left = null;
            } finally {
                lock.unlock();
            }
            for (Transmit t : out) {
                endpoint.send(t.datagram(), t.destination(), t.source());
            }
            if (left != null) {
                // After what went out: the last datagrams from the old socket are sent
                endpoint.release(left, current);
            }
            if (drained) {
                return;
            }
            if (more) {
                Thread.yield(); // let other connections run
                continue;
            }
            if (wakeRequested.get()) {
                continue;
            }
            if (deadline == NanoClock.NONE) {
                LockSupport.park(this);
            } else {
                long wait = deadline - now();
                if (wait > 0) {
                    LockSupport.parkNanos(this, wait);
                }
            }
        }
    }

    /** Takes the connection's events; returns whether any arrived. Called with the lock held. */
    private boolean dispatchEvents() {
        boolean any = false;
        for (ConnectionEvent e; (e = conn.pollEvent()) != null; ) {
            any = true;
            switch (e) {
                case ConnectionEvent.HandshakeDataReady r -> {
                    if (server && conn.earlyDataAccepted() && !acceptedEarly) {
                        // 0-RTT data is coming: hand the connection out now
                        acceptedEarly = true;
                        endpoint.accepted(facade);
                    }
                }
                case ConnectionEvent.Connected c -> {
                    connected = true;
                    if (server && !acceptedEarly) {
                        endpoint.accepted(facade);
                    }
                }
                case ConnectionEvent.ConnectionLost l -> lost = l.reason();
                case ConnectionEvent.PathUpdated u -> {
                    if (probing != null && probing.address.equals(u.local())) {
                        // A client switched to the path it probed: the old socket goes once unused
                        left = socket;
                        socket = probing;
                        probing = null;
                        migrated = Boolean.TRUE;
                    }
                }
                case ConnectionEvent.PathProbeFailed f -> {
                    if (probing != null && probing.address.equals(f.local())) {
                        left = probing;
                        probing = null;
                        migrated = Boolean.FALSE;
                    }
                }
                default -> {}
            }
        }
        return any;
    }

    /** A socket the connection no longer sends from, released after the next send; guarded by lock. */
    private EndpointDriver.Socket left;

    /**
     * Starts a client's migration to {@code next} (bound, its user counted); called with the lock
     * held. The connection probes the path and switches if the server answers, or switches at once
     * without {@code probe}.
     *
     * @throws IllegalStateException if the connection cannot migrate now
     */
    void startMigration(EndpointDriver.Socket next, boolean probe) {
        if (probing != null) {
            throw new IllegalStateException("a migration is under way");
        }
        if (probe) {
            conn.probePath(now(), next.address);
        } else {
            conn.rebind(now(), next.address);
        }
        probing = next;
        migrated = null;
    }

    /** The outcome of the last migration, or null while it is under way; called with the lock held. */
    Boolean migrated() {
        return migrated;
    }

    /** The bound address of the socket the connection sends from, or null for an unbound endpoint. */
    InetSocketAddress socketAddress() {
        lock.lock();
        try {
            EndpointDriver.Socket s = socket;
            return s != null ? s.address : null;
        } finally {
            lock.unlock();
        }
    }

    /** Closes the connection as its endpoint shuts down. */
    void closeForShutdown() {
        lock.lock();
        try {
            conn.close(now(), 0, "endpoint closed");
        } finally {
            lock.unlock();
        }
        wake();
    }

    void awaitCloseSent(long deadline) {
        lock.lock();
        try {
            while (!closeSent && !terminated) {
                long wait = deadline - now();
                if (wait <= 0) {
                    return;
                }
                changed.awaitNanos(wait);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            lock.unlock();
        }
    }

    void stop() {
        stopped = true;
        Thread t = thread;
        if (t != null) {
            LockSupport.unpark(t);
        }
    }

    void join(long deadline) {
        Thread t = thread;
        if (t == null) {
            return;
        }
        try {
            long wait = deadline - now();
            if (wait > 0) {
                t.join(TimeUnit.NANOSECONDS.toMillis(wait) + 1);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // --- for QuicConnection, with the lock held ---

    boolean isConnected() {
        return connected;
    }

    /** Why the connection ended, or null while it is open. */
    ConnectionError lostReason() {
        if (lost != null) {
            return lost;
        }
        if (terminated || conn.isClosed()) {
            ConnectionError reason = conn.closeReason();
            return reason != null ? reason : ConnectionError.of(ConnectionError.Kind.LOCALLY_CLOSED);
        }
        return null;
    }

    boolean isTerminated() {
        return terminated;
    }

    long droppedDatagrams() {
        return droppedDatagrams.get();
    }
}
