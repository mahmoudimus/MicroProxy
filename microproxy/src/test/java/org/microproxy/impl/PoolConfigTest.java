package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.PoolMetrics;
import org.microproxy.ServerConnectionPoolType;

/** Configuration of the shared server connection pool: defaults, validation, properties. */
class PoolConfigTest {

    private static DefaultHttpProxyServerBootstrap fromProperties(String... keyValues) {
        Properties p = new Properties();
        for (int i = 0; i < keyValues.length; i += 2) {
            p.setProperty(keyValues[i], keyValues[i + 1]);
        }
        return DefaultHttpProxyServerBootstrap.fromProperties(p);
    }

    @Test
    void defaults() {
        DefaultHttpProxyServerBootstrap b = new DefaultHttpProxyServerBootstrap();
        assertFalse(b.sharedServerConnectionPool);
        assertEquals(ServerConnectionPoolType.CONCURRENT_MAP, b.serverConnectionPoolType);
        assertEquals(10, b.maxConnectionsPerHost);
        assertEquals(200, b.maxConnections);
        assertNull(b.poolIdleTimeout);
        assertFalse(b.poolSharedMitmConnections);
        assertFalse(b.poolPerRequestInMitm);
        assertEquals(b.sharedServerConnectionPool, fromProperties().sharedServerConnectionPool,
                "an empty properties file keeps the defaults");
        assertFalse(fromProperties().poolSharedMitmConnections);
        assertFalse(fromProperties().poolPerRequestInMitm);
    }

    @Test
    void limitsMustBePositiveAndThePoolTypeNonNull() {
        DefaultHttpProxyServerBootstrap b = new DefaultHttpProxyServerBootstrap();
        assertThrows(IllegalArgumentException.class, () -> b.withMaxConnectionsPerHost(0));
        assertThrows(IllegalArgumentException.class, () -> b.withMaxConnectionsPerHost(-1));
        assertThrows(IllegalArgumentException.class, () -> b.withMaxConnections(0));
        assertThrows(IllegalArgumentException.class, () -> b.withMaxConnections(-1));
        assertThrows(NullPointerException.class, () -> b.withServerConnectionPoolType(null));
        // Rejected values leave the previous ones in place.
        assertEquals(10, b.maxConnectionsPerHost);
        assertEquals(200, b.maxConnections);
        assertEquals(ServerConnectionPoolType.CONCURRENT_MAP, b.serverConnectionPoolType);

        b.withMaxConnectionsPerHost(5).withMaxConnections(100).withServerConnectionPoolType(ServerConnectionPoolType.CONCURRENT_MAP);
        assertEquals(5, b.maxConnectionsPerHost);
        assertEquals(100, b.maxConnections);
    }

    @Test
    void idleTimeoutIsOptional() {
        DefaultHttpProxyServerBootstrap b = new DefaultHttpProxyServerBootstrap();
        b.withPoolIdleTimeout(Duration.ofSeconds(30));
        assertEquals(Duration.ofSeconds(30), b.poolIdleTimeout);
        b.withPoolIdleTimeout(null);
        assertNull(b.poolIdleTimeout);
    }

    @Test
    void mitmPoolFlagsCanBeSetIndependentlyButPerRequestNeedsSharedMitm() {
        // The bootstrap records each flag as given...
        DefaultHttpProxyServerBootstrap b = new DefaultHttpProxyServerBootstrap();
        b.withPort(0).withSharedServerConnectionPool(true).withPoolPerRequestInMitm(true);
        assertTrue(b.poolPerRequestInMitm);
        assertFalse(b.poolSharedMitmConnections);
        // ...but per-request leasing in MITM sessions only applies with shared MITM connections.
        HttpProxyServer perRequestOnly = b.start();
        try {
            assertFalse(((DefaultHttpProxyServer) perRequestOnly).poolPerRequestInMitm);
            assertFalse(((DefaultHttpProxyServer) perRequestOnly).poolSharedMitmConnections);
        } finally {
            perRequestOnly.abort();
        }
        HttpProxyServer both = b.withPoolSharedMitmConnections(true).start();
        try {
            assertTrue(((DefaultHttpProxyServer) both).poolPerRequestInMitm);
            assertTrue(((DefaultHttpProxyServer) both).poolSharedMitmConnections);
        } finally {
            both.abort();
        }
    }

    @Test
    void poolPropertiesAreRead() {
        DefaultHttpProxyServerBootstrap b = fromProperties(
                "use_shared_server_connection_pool", "true",
                "server_connection_pool_type", "concurrent_map",
                "max_connections_per_host", "3",
                "max_total_connections", "7",
                "pool_idle_timeout", "30",
                "pool_shared_mitm_connections", "true",
                "pool_per_request_in_mitm", "true");
        assertTrue(b.sharedServerConnectionPool);
        assertEquals(ServerConnectionPoolType.CONCURRENT_MAP, b.serverConnectionPoolType);
        assertEquals(3, b.maxConnectionsPerHost);
        assertEquals(7, b.maxConnections);
        assertEquals(Duration.ofSeconds(30), b.poolIdleTimeout);
        assertTrue(b.poolSharedMitmConnections);
        assertTrue(b.poolPerRequestInMitm);
    }

    @Test
    void eachMitmPoolPropertyIsReadOnItsOwn() {
        DefaultHttpProxyServerBootstrap shared = fromProperties("pool_shared_mitm_connections", "true");
        assertTrue(shared.poolSharedMitmConnections);
        assertFalse(shared.poolPerRequestInMitm);
        DefaultHttpProxyServerBootstrap perRequest = fromProperties("pool_per_request_in_mitm", "on");
        assertTrue(perRequest.poolPerRequestInMitm);
        assertFalse(perRequest.poolSharedMitmConnections);
        assertFalse(fromProperties("pool_shared_mitm_connections", "false").poolSharedMitmConnections);
        assertFalse(fromProperties("pool_per_request_in_mitm", "nope").poolPerRequestInMitm);
    }

    @Test
    void badPoolPropertiesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> fromProperties("server_connection_pool_type", "linked_list"));
        assertThrows(IllegalArgumentException.class, () -> fromProperties("max_connections_per_host", "0"));
        assertThrows(IllegalArgumentException.class, () -> fromProperties("max_total_connections", "-5"));
        assertThrows(IllegalArgumentException.class, () -> fromProperties("pool_idle_timeout", "soon"));
    }

    @Test
    void serverHasAPoolOnlyWhenEnabled() {
        HttpProxyServer without = new DefaultHttpProxyServerBootstrap().withPort(0).start();
        HttpProxyServer with = new DefaultHttpProxyServerBootstrap().withPort(0).withSharedServerConnectionPool(true)
                .withMaxConnectionsPerHost(3).withMaxConnections(7).start();
        try {
            assertNull(((DefaultHttpProxyServer) without).pool);
            assertNull(without.getServerConnectionPoolMetrics());
            SharedConnectionPool pool = ((DefaultHttpProxyServer) with).pool;
            assertNotNull(pool);
            assertSame(pool, ((DefaultHttpProxyServer) with).pool);
            assertEquals(new PoolMetrics(0, 0, 0, 0, 0, 0, 0), with.getServerConnectionPoolMetrics());
        } finally {
            without.abort();
            with.abort();
        }
    }

    @Test
    void cloneCopiesPoolSettingsButGetsItsOwnPool() {
        HttpProxyServer original = new DefaultHttpProxyServerBootstrap().withPort(0).withSharedServerConnectionPool(true)
                .withMaxConnectionsPerHost(4).withMaxConnections(9).withPoolIdleTimeout(Duration.ofSeconds(5))
                .withPoolSharedMitmConnections(true).withPoolPerRequestInMitm(true).start();
        HttpProxyServer clone = null;
        try {
            DefaultHttpProxyServerBootstrap copy = (DefaultHttpProxyServerBootstrap) original.clone();
            assertTrue(copy.sharedServerConnectionPool);
            assertEquals(4, copy.maxConnectionsPerHost);
            assertEquals(9, copy.maxConnections);
            assertEquals(Duration.ofSeconds(5), copy.poolIdleTimeout);
            assertTrue(copy.poolSharedMitmConnections);
            assertTrue(copy.poolPerRequestInMitm);
            clone = copy.start();
            assertFalse(((DefaultHttpProxyServer) clone).pool == ((DefaultHttpProxyServer) original).pool);
        } finally {
            original.abort();
            if (clone != null) clone.abort();
        }
    }
}
