package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.PoolMetrics;

/**
 * {@link SharedConnectionPool} on its own: keys, limits, validation, eviction and closing. The
 * connections are real loopback sockets with no traffic.
 */
class SharedConnectionPoolUnitTest {

    private static final String HOST_A = "PLAIN|a.test:80";
    private static final String HOST_B = "PLAIN|b.test:80";
    private static final String DIRECT_A = HOST_A + "|direct";

    private ServerSocket listener;
    private final List<Socket> sockets = new ArrayList<>();
    private SharedConnectionPool pool;

    @BeforeEach
    void setUp() throws IOException {
        listener = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    }

    @AfterEach
    void tearDown() throws IOException {
        if (pool != null) pool.closeAll();
        for (Socket s : sockets) s.close();
        listener.close();
    }

    private ServerConnection connection() throws IOException {
        Socket client = new Socket(listener.getInetAddress(), listener.getLocalPort());
        sockets.add(client);
        sockets.add(listener.accept());
        return new ServerConnection("k", "a.test:80", null, false, client,
                new ByteReader(client.getInputStream(), 1024), client.getOutputStream(),
                (InetSocketAddress) client.getRemoteSocketAddress(), null, new Trackers());
    }

    /** Reserves a slot for {@code poolKey} and registers a new connection in it. */
    private ServerConnection leaseNew(String poolKey, String hostKey) throws IOException {
        assertNull(pool.acquire(poolKey, hostKey, 0), "expected a reservation, not a pooled connection");
        ServerConnection c = connection();
        pool.register(c, poolKey, hostKey);
        return c;
    }

    @Test
    void returnedConnectionIsReusedForTheSameKey() throws IOException {
        pool = new SharedConnectionPool(10, 200, null);
        ServerConnection c = leaseNew(DIRECT_A, HOST_A);
        assertEquals(new PoolMetrics(1, 1, 0, 1, 0, 0, 0), pool.metrics());

        pool.release(c);
        assertEquals(new PoolMetrics(1, 0, 1, 1, 1, 0, 0), pool.metrics());

        assertSame(c, pool.acquire(DIRECT_A, HOST_A, 0));
        assertEquals(new PoolMetrics(1, 1, 0, 2, 1, 0, 0), pool.metrics());
    }

    @Test
    void differentRoutesAndModesDoNotShareConnections() throws IOException {
        pool = new SharedConnectionPool(10, 200, null);
        ServerConnection direct = leaseNew(DIRECT_A, HOST_A);
        pool.release(direct);

        // Same target through a chained proxy, through another chained proxy, or over TLS: all new.
        ServerConnection viaProxy = leaseNew(HOST_A + "|HTTP:10.0.0.1:3128", HOST_A);
        ServerConnection viaOther = leaseNew(HOST_A + "|HTTP:10.0.0.2:3128", HOST_A);
        ServerConnection viaTlsProxy = leaseNew(HOST_A + "|HTTP:10.0.0.1:3128:tls", HOST_A);
        ServerConnection tls = leaseNew("TLS|a.test:80|direct", "TLS|a.test:80");
        assertEquals(5, pool.metrics().totalConnections());
        assertEquals(1, pool.metrics().idleConnections(), "the direct connection stayed in the pool");

        for (ServerConnection c : List.of(viaProxy, viaOther, viaTlsProxy, tls)) pool.release(c);
        assertSame(direct, pool.acquire(DIRECT_A, HOST_A, 0));
        assertSame(viaOther, pool.acquire(HOST_A + "|HTTP:10.0.0.2:3128", HOST_A, 0));
        assertSame(tls, pool.acquire("TLS|a.test:80|direct", "TLS|a.test:80", 0));
    }

    @Test
    void perHostLimitBlocksOnlyThatHost() throws IOException {
        pool = new SharedConnectionPool(1, 200, null);
        ServerConnection a = leaseNew(DIRECT_A, HOST_A);
        long start = System.nanoTime();
        assertThrows(SharedConnectionPool.PoolExhaustedException.class, () -> pool.acquire(DIRECT_A, HOST_A, 100));
        assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() >= 80, "waited for a connection first");
        // Routes to the same host count against the same limit.
        assertThrows(SharedConnectionPool.PoolExhaustedException.class,
                () -> pool.acquire(HOST_A + "|HTTP:10.0.0.1:3128", HOST_A, 0));
        assertNull(pool.acquire(HOST_B + "|direct", HOST_B, 0), "other hosts are not limited");
        pool.cancel(HOST_B);

        a.close();
        assertNull(pool.acquire(DIRECT_A, HOST_A, 0), "a closed connection frees its slot");
    }

    @Test
    void cancelledReservationFreesItsSlot() throws IOException {
        pool = new SharedConnectionPool(1, 1, null);
        assertNull(pool.acquire(DIRECT_A, HOST_A, 0));
        assertEquals(1, pool.metrics().totalConnections());
        pool.cancel(HOST_A);
        assertEquals(0, pool.metrics().totalConnections());
        assertNull(pool.acquire(DIRECT_A, HOST_A, 0));
    }

    @Test
    void totalLimitEvictsTheOldestIdleConnection() throws IOException {
        pool = new SharedConnectionPool(10, 1, null);
        ServerConnection a = leaseNew(DIRECT_A, HOST_A);
        pool.release(a);
        ServerConnection b = leaseNew(HOST_B + "|direct", HOST_B);
        assertFalse(a.isOpen(), "the idle connection to a.test made room");
        assertTrue(b.isOpen());
        assertEquals(new PoolMetrics(1, 1, 0, 2, 1, 1, 0), pool.metrics());
    }

    @Test
    void idleConnectionClosedByTheServerIsNotHandedOut() throws IOException {
        pool = new SharedConnectionPool(10, 200, null);
        ServerConnection c = leaseNew(DIRECT_A, HOST_A);
        pool.release(c);
        c.socket.close(); // as if the server had closed it while idle
        assertNull(pool.acquire(DIRECT_A, HOST_A, 0), "a stale connection is discarded, a new one reserved");
        PoolMetrics m = pool.metrics();
        assertEquals(1, m.validationFailureCount());
        assertEquals(1, m.totalConnections(), "only the new reservation is counted");
        assertEquals(0, m.idleConnections());
    }

    @Test
    void releasingAClosedConnectionDropsIt() throws IOException {
        pool = new SharedConnectionPool(10, 200, null);
        ServerConnection c = leaseNew(DIRECT_A, HOST_A);
        c.close();
        pool.release(c);
        assertEquals(new PoolMetrics(0, 0, 0, 1, 0, 0, 0), pool.metrics());
    }

    @Test
    void waitingLeaseGetsTheReturnedConnection() throws Exception {
        pool = new SharedConnectionPool(1, 1, null);
        ServerConnection c = leaseNew(DIRECT_A, HOST_A);
        CompletableFuture<ServerConnection> waiter = new CompletableFuture<>();
        Thread.ofVirtual().start(() -> {
            try {
                waiter.complete(pool.acquire(DIRECT_A, HOST_A, 5000));
            } catch (Throwable t) {
                waiter.completeExceptionally(t);
            }
        });
        Thread.sleep(50);
        assertFalse(waiter.isDone(), "the second lease waits while the only connection is leased");
        pool.release(c);
        assertSame(c, waiter.get(5, TimeUnit.SECONDS));
    }

    @Test
    void idleConnectionsExpire() throws Exception {
        pool = new SharedConnectionPool(10, 200, Duration.ofMillis(100));
        ServerConnection c = leaseNew(DIRECT_A, HOST_A);
        pool.release(c);
        for (int i = 0; i < 100 && pool.metrics().totalConnections() > 0; i++) {
            Thread.sleep(20);
        }
        assertEquals(0, pool.metrics().totalConnections());
        assertEquals(1, pool.metrics().evictionCount());
        assertFalse(c.isOpen());
    }

    @Test
    void closeAllClosesIdleConnectionsAndRefusesNewLeases() throws IOException {
        pool = new SharedConnectionPool(10, 200, Duration.ofMinutes(1));
        ServerConnection idle = leaseNew(DIRECT_A, HOST_A);
        pool.release(idle);
        ServerConnection leased = leaseNew(HOST_B + "|direct", HOST_B);

        pool.closeAll();
        assertFalse(idle.isOpen());
        assertTrue(leased.isOpen(), "a connection in use is left to finish its exchange");
        assertThrows(SharedConnectionPool.PoolExhaustedException.class, () -> pool.acquire(DIRECT_A, HOST_A, 1000));

        pool.release(leased);
        assertFalse(leased.isOpen(), "returned after closeAll, it is closed instead of pooled");
        assertEquals(0, pool.metrics().totalConnections());
        pool.closeAll(); // idempotent
    }
}
