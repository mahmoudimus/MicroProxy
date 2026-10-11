package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.MetricsAssertions.awaitValue;
import static org.microproxy.MetricsAssertions.value;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.stats.StatsRegistry;

/**
 * The SOCKS stats, {@code socks.*}: clients by version, refused authentication, commands other
 * than CONNECT, and replies by code; and the tunnels SOCKS clients open, {@code tunnel.*}.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class SocksStatsTest {

    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private TestSupport.RawServer echo;
    private HttpProxyServer proxy;
    private StatsRegistry r;

    @BeforeEach
    void start() {
        echo = TestSupport.rawServer(s -> s.getInputStream().transferTo(s.getOutputStream()));
        ProxyAuthenticator alice = (user, password) -> "alice".equals(user) && "secret".equals(password);
        proxy = proxies.start(MicroProxy.bootstrap().withSocksServer(true).withMetrics(true).withProxyAuthenticator(alice));
        r = proxy.getStats();
    }

    @AfterEach
    void tearDown() throws Exception {
        proxies.close();
        echo.close();
    }

    @Test
    void anAuthenticatedClientsTunnelIsCounted() throws IOException {
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(SocksClient.USERNAME_PASSWORD, c.greet(SocksClient.USERNAME_PASSWORD));
            assertEquals(0, c.authenticate("alice", "secret"));
            assertEquals(0, c.connect("127.0.0.1", echo.port()));
            c.write("ping\n");
            assertEquals("ping\n", c.read(5));
            assertEquals(1, value(r, "tunnel.active"));
        }
        assertEquals(1, value(r, "socks.v5.connections_total"));
        assertEquals(0, value(r, "socks.v4.connections_total"));
        assertEquals(1, value(r, "socks.replies.succeeded"));
        assertEquals(0, value(r, "socks.auth_failures"));
        awaitValue(r, "tunnel.active", 0);
        assertEquals(1, value(r, "tunnel.socks.total"));
        assertEquals(5, value(r, "tunnel.rx_bytes_total"));
        assertEquals(5, value(r, "tunnel.tx_bytes_total"));
        assertEquals(1, value(r, "tunnel.duration_ms"));
        // The tunnel's bytes went to the server, and came back, over the cluster's connection
        assertEquals(5, value(r, "cluster.direct.upstream_cx_tx_bytes_total"));
        assertEquals(5, value(r, "cluster.direct.upstream_cx_rx_bytes_total"));
    }

    @Test
    void refusalsAreCountedByKindAndReply() throws IOException {
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(SocksClient.USERNAME_PASSWORD, c.greet(SocksClient.USERNAME_PASSWORD));
            assertEquals(1, c.authenticate("alice", "wrong"));
        }
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(SocksClient.NO_ACCEPTABLE, c.greet(SocksClient.NO_AUTHENTICATION));
        }
        try (SocksClient c = new SocksClient(proxy)) {
            c.greet(SocksClient.USERNAME_PASSWORD);
            c.authenticate("alice", "secret");
            assertEquals(7, c.request(SocksClient.BIND, SocksClient.IPV4, new byte[] {127, 0, 0, 1}, 80));
        }
        int closed;
        try (ServerSocket s = new ServerSocket(0)) {
            closed = s.getLocalPort();
        }
        try (SocksClient c = new SocksClient(proxy)) {
            c.greet(SocksClient.USERNAME_PASSWORD);
            c.authenticate("alice", "secret");
            assertEquals(5, c.connect("127.0.0.1", closed));
        }
        try (SocksClient c = new SocksClient(proxy)) {
            // SOCKS4 has no credentials to give the authenticator: refused, with SOCKS5's "not allowed"
            assertEquals(91, c.socks4(SocksClient.CONNECT, "127.0.0.1", echo.port(), "alice"));
        }
        awaitValue(r, "socks.replies.not_allowed", 1);
        assertEquals(4, value(r, "socks.v5.connections_total"));
        assertEquals(1, value(r, "socks.v4.connections_total"));
        assertEquals(3, value(r, "socks.auth_failures"));
        assertEquals(1, value(r, "socks.command_not_supported"));
        assertEquals(1, value(r, "socks.replies.command_not_supported"));
        assertEquals(1, value(r, "socks.replies.connection_refused"));
        assertEquals(0, value(r, "socks.replies.succeeded"));
        assertEquals(1, value(r, "cluster.direct.upstream_cx_connect_fail"));
        assertTrue(r.get("socks.replies.ttl_expired") != null, "every reply code is registered");
    }
}
