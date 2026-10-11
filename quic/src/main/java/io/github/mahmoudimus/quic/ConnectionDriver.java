package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.Connection;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import io.github.mahmoudimus.quic.connection.ConnectionEvent;
import io.github.mahmoudimus.quic.connection.NanoClock;
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

    /** Datagrams queued for one connection; more are dropped, as a full socket buffer would. */
    static final int INBOUND_CAPACITY = 1024;
    /** Datagrams handled per wake-up in each direction. */
    private static final int BATCH = 64;

    private record Inbound(InetSocketAddress from, ByteBuffer datagram) {}

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
    private ConnectionError lost;
    private boolean terminated;

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

    /** Queues a received datagram and wakes the driver; drops it if the queue is full. */
    void deliver(InetSocketAddress from, ByteBuffer datagram) {
        if (!inbound.offer(new Inbound(from, datagram))) {
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
        } finally {
            lock.lock();
            try {
                terminated = true;
                if (lost == null) {
                    ConnectionError reason = conn.closeReason();
                    lost = reason != null ? reason : ConnectionError.of(ConnectionError.Kind.LOCALLY_CLOSED);
                }
                changed.signalAll();
            } finally {
                lock.unlock();
            }
            endpoint.remove(this);
        }
    }

    private void loop() {
        while (!stopped) {
            wakeRequested.set(false);
            List<ByteBuffer> out;
            boolean more;
            long deadline;
            boolean drained;
            lock.lock();
            try {
                long now = now();
                for (int i = 0; i < BATCH; i++) {
                    Inbound in = inbound.poll();
                    if (in == null) {
                        break;
                    }
                    conn.handleDatagram(now, in.from(), 0, in.datagram());
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
            } finally {
                lock.unlock();
            }
            InetSocketAddress remote = conn.remoteAddress();
            for (ByteBuffer d : out) {
                endpoint.send(d, remote);
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
                case ConnectionEvent.Connected c -> {
                    connected = true;
                    if (server) {
                        endpoint.accepted(facade);
                    }
                }
                case ConnectionEvent.ConnectionLost l -> lost = l.reason();
                default -> {}
            }
        }
        return any;
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
