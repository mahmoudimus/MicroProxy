package org.microproxy.impl;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.System.Logger.Level;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.PoolMetrics;

/**
 * Server connections shared by all client connections. A connection is leased exclusively (one
 * exchange, or one intercepted TLS session) and returned when its response completes with
 * keep-alive. Idle connections are kept per pool key (mode, target and route); limits apply to
 * the total and per target. When the pool is full, a lease waits for a connection to be returned
 * or closed.
 *
 * <p>All state is guarded by a {@link ReentrantLock}; connections are only closed outside it.
 */
final class SharedConnectionPool {

    private static final System.Logger LOG = System.getLogger(SharedConnectionPool.class.getName());

    /** No connection could be leased within the wait time. */
    static final class PoolExhaustedException extends IOException {
        PoolExhaustedException(String message) {
            super(message);
        }
    }

    private final int maxPerHost;
    private final int maxTotal;
    private final Duration idleTimeout;

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition changed = lock.newCondition();
    private final Map<String, ArrayDeque<ServerConnection>> idle = new HashMap<>();
    private final Map<ServerConnection, Long> idleSince = new IdentityHashMap<>();
    private final Map<String, Integer> liveByHost = new HashMap<>();
    private int live;
    private boolean closed;

    private final AtomicLong borrows = new AtomicLong();
    private final AtomicLong returns = new AtomicLong();
    private final AtomicLong evictions = new AtomicLong();
    private final AtomicLong validationFailures = new AtomicLong();
    private final Thread evictor;

    SharedConnectionPool(int maxPerHost, int maxTotal, Duration idleTimeout) {
        this.maxPerHost = maxPerHost;
        this.maxTotal = maxTotal;
        this.idleTimeout = idleTimeout == null || idleTimeout.isZero() || idleTimeout.isNegative() ? null : idleTimeout;
        this.evictor = this.idleTimeout == null ? null
                : Thread.ofVirtual().name("microproxy-pool-evictor").start(this::evictLoop);
    }

    /**
     * Leases a connection for {@code poolKey}.
     *
     * @return an idle connection to reuse, or {@code null}: the caller then holds a reservation
     *     and must either {@link #register} the connection it creates or {@link #cancel}
     */
    ServerConnection acquire(String poolKey, String hostKey, long waitMillis) throws IOException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(Math.max(0, waitMillis));
        List<ServerConnection> toClose = new ArrayList<>();
        lock.lock();
        try {
            while (true) {
                if (closed) {
                    throw new PoolExhaustedException("pool closed");
                }
                evictExpired(toClose);
                ArrayDeque<ServerConnection> candidates = idle.get(poolKey);
                while (candidates != null && !candidates.isEmpty()) {
                    ServerConnection c = candidates.pollFirst();
                    idleSince.remove(c);
                    if (c.isOpen()) {
                        borrows.incrementAndGet();
                        return c;
                    }
                    validationFailures.incrementAndGet();
                    forget(c);
                }
                if (live < maxTotal && liveByHost.getOrDefault(hostKey, 0) < maxPerHost) {
                    live++;
                    liveByHost.merge(hostKey, 1, Integer::sum);
                    borrows.incrementAndGet();
                    return null;
                }
                if (live >= maxTotal) {
                    // Make room by closing the longest-idle connection to some other target.
                    ServerConnection oldest = oldestIdle();
                    if (oldest != null) {
                        removeIdle(oldest);
                        forget(oldest);
                        evictions.incrementAndGet();
                        toClose.add(oldest);
                        continue;
                    }
                }
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    throw new PoolExhaustedException("no server connection available for " + hostKey
                            + " (" + live + "/" + maxTotal + " total, " + liveByHost.getOrDefault(hostKey, 0)
                            + "/" + maxPerHost + " for host)");
                }
                try {
                    changed.awaitNanos(remaining);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException("interrupted waiting for a pooled connection");
                }
            }
        } finally {
            lock.unlock();
            toClose.forEach(ServerConnection::close);
        }
    }

    /** Binds a newly created connection to the reservation made by {@link #acquire}. */
    void register(ServerConnection connection, String poolKey, String hostKey) {
        connection.poolKey = poolKey;
        connection.hostKey = hostKey;
        connection.pool = this;
    }

    /** Releases a reservation whose connection could not be created. */
    void cancel(String hostKey) {
        lock.lock();
        try {
            live--;
            liveByHost.computeIfPresent(hostKey, (k, v) -> v <= 1 ? null : v - 1);
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /** Returns a leased connection; closed or unusable connections are discarded instead. */
    void release(ServerConnection connection) {
        connection.onDetach = null;
        connection.perRequestLease = false;
        boolean keep;
        lock.lock();
        try {
            keep = !closed && connection.pool == this && connection.isOpen();
            if (keep) {
                idle.computeIfAbsent(connection.poolKey, k -> new ArrayDeque<>()).addFirst(connection);
                idleSince.put(connection, System.nanoTime());
                returns.incrementAndGet();
                changed.signalAll();
            }
        } finally {
            lock.unlock();
        }
        if (!keep) {
            connection.close();
        }
    }

    /** Called when a pooled connection closes, whoever closed it. */
    void discarded(ServerConnection connection) {
        lock.lock();
        try {
            if (connection.pool == this) {
                removeIdle(connection);
                forget(connection);
            }
        } finally {
            lock.unlock();
        }
    }

    PoolMetrics metrics() {
        lock.lock();
        try {
            int idleCount = idleSince.size();
            return new PoolMetrics(live, live - idleCount, idleCount, borrows.get(), returns.get(),
                    evictions.get(), validationFailures.get());
        } finally {
            lock.unlock();
        }
    }

    void closeAll() {
        List<ServerConnection> toClose;
        lock.lock();
        try {
            closed = true;
            toClose = new ArrayList<>(idleSince.keySet());
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        toClose.forEach(ServerConnection::close);
        if (evictor != null) {
            evictor.interrupt();
        }
    }

    // --- under lock -----------------------------------------------------------------------

    /** Stops counting {@code c}; it no longer refers to this pool. */
    private void forget(ServerConnection c) {
        if (c.pool != this) return;
        c.pool = null;
        live--;
        liveByHost.computeIfPresent(c.hostKey, (k, v) -> v <= 1 ? null : v - 1);
        changed.signalAll();
    }

    private void removeIdle(ServerConnection c) {
        if (idleSince.remove(c) != null) {
            ArrayDeque<ServerConnection> q = idle.get(c.poolKey);
            if (q != null) {
                q.remove(c);
                if (q.isEmpty()) idle.remove(c.poolKey);
            }
        }
    }

    private ServerConnection oldestIdle() {
        ServerConnection oldest = null;
        long oldestSince = Long.MAX_VALUE;
        for (Map.Entry<ServerConnection, Long> e : idleSince.entrySet()) {
            if (e.getValue() < oldestSince) {
                oldestSince = e.getValue();
                oldest = e.getKey();
            }
        }
        return oldest;
    }

    private void evictExpired(List<ServerConnection> toClose) {
        if (idleTimeout == null || idleSince.isEmpty()) return;
        long cutoff = System.nanoTime() - idleTimeout.toNanos();
        for (ServerConnection c : List.copyOf(idleSince.keySet())) {
            if (idleSince.get(c) < cutoff) {
                removeIdle(c);
                forget(c);
                evictions.incrementAndGet();
                toClose.add(c);
            }
        }
    }

    private void evictLoop() {
        long sleepMillis = Math.max(100, idleTimeout.toMillis() / 2);
        while (true) {
            try {
                Thread.sleep(sleepMillis);
            } catch (InterruptedException e) {
                return;
            }
            List<ServerConnection> toClose = new ArrayList<>();
            lock.lock();
            try {
                if (closed) return;
                evictExpired(toClose);
            } finally {
                lock.unlock();
            }
            if (!toClose.isEmpty()) {
                LOG.log(Level.DEBUG, "evicting {0} idle pooled connections", toClose.size());
                toClose.forEach(ServerConnection::close);
            }
        }
    }
}
