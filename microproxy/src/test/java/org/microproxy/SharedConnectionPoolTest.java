package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

class SharedConnectionPoolTest {

    private HttpServer origin;
    private HttpProxyServer proxy;
    private final AtomicInteger serverConnections = new AtomicInteger();

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(echo());
        origin.createContext("/slow", exchange -> {
            try {
                Thread.sleep(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            TestSupport.fixed(200, "slow").handle(exchange);
        });
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private HttpProxyServerBootstrap bootstrap() {
        return MicroProxy.bootstrap().withPort(0).plusActivityTracker(new ActivityTrackerAdapter() {
            @Override
            public void serverConnected(FullFlowContext ctx, InetSocketAddress address) {
                serverConnections.incrementAndGet();
            }
        });
    }

    @Test
    void separateClientsShareOneServerConnection() {
        proxy = bootstrap().withSharedServerConnectionPool(true).start();
        for (int i = 0; i < 3; i++) {
            // A new HttpClient per request means a new client connection each time.
            assertEquals(200, get(client(proxy), url(origin, "/c" + i)).statusCode());
        }
        assertEquals(1, serverConnections.get());
        PoolMetrics metrics = proxy.getServerConnectionPoolMetrics();
        assertEquals(1, metrics.totalConnections());
        assertEquals(1, metrics.idleConnections());
        assertEquals(3, metrics.borrowCount());
        assertEquals(3, metrics.returnCount());
    }

    @Test
    void withoutThePoolEachClientConnects() {
        proxy = bootstrap().start();
        for (int i = 0; i < 3; i++) {
            assertEquals(200, get(client(proxy), url(origin, "/c" + i)).statusCode());
        }
        assertEquals(3, serverConnections.get());
        assertNull(proxy.getServerConnectionPoolMetrics());
    }

    @Test
    void perHostLimitMakesRequestsWaitThenFailWith503() throws Exception {
        proxy = bootstrap().withSharedServerConnectionPool(true).withMaxConnectionsPerHost(1)
                .withConnectTimeout(100).start();
        List<CompletableFuture<HttpResponse<String>>> futures = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            futures.add(client(proxy).sendAsync(HttpRequest.newBuilder(URI.create(url(origin, "/slow"))).build(),
                    HttpResponse.BodyHandlers.ofString()));
            Thread.sleep(100);
        }
        // The second request waits about a second (minimum lease wait) for the only connection,
        // which is busy for 1.5 s, and gives up.
        assertEquals(200, futures.get(0).get().statusCode());
        assertEquals(503, futures.get(1).get().statusCode());
        assertEquals(1, serverConnections.get());
    }

    @Test
    void waitingRequestGetsTheReturnedConnection() throws Exception {
        proxy = bootstrap().withSharedServerConnectionPool(true).withMaxConnections(1)
                .withConnectTimeout(5000).start();
        List<CompletableFuture<HttpResponse<String>>> futures = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            futures.add(client(proxy).sendAsync(HttpRequest.newBuilder(URI.create(url(origin, "/slow"))).build(),
                    HttpResponse.BodyHandlers.ofString()));
        }
        for (var f : futures) {
            assertEquals(200, f.get().statusCode());
        }
        assertEquals(1, serverConnections.get());
    }

    @Test
    void idleConnectionsAreEvicted() throws Exception {
        proxy = bootstrap().withSharedServerConnectionPool(true).withPoolIdleTimeout(Duration.ofMillis(200)).start();
        assertEquals(200, get(client(proxy), url(origin, "/")).statusCode());
        Thread.sleep(800);
        PoolMetrics metrics = proxy.getServerConnectionPoolMetrics();
        assertEquals(0, metrics.totalConnections());
        assertTrue(metrics.evictionCount() >= 1);
        assertEquals(200, get(client(proxy), url(origin, "/")).statusCode());
        assertEquals(2, serverConnections.get());
    }

    @Test
    void staleIdleConnectionIsReplacedTransparently() throws Exception {
        try (TestSupport.RawServer closing = TestSupport.rawServer(socket -> {
            TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
            TestSupport.write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            // claims keep-alive, then closes
        })) {
            proxy = bootstrap().withSharedServerConnectionPool(true).start();
            for (int i = 0; i < 3; i++) {
                assertEquals("ok", get(client(proxy), "http://127.0.0.1:" + closing.port() + "/").body());
                Thread.sleep(50);
            }
        }
    }

    @Test
    void interceptedRequestsShareUpstreamTlsConnections() throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("Pool Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Pool Proxy CA");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), echo());
        try {
            proxy = bootstrap().withSharedServerConnectionPool(true)
                    .withPoolSharedMitmConnections(true).withPoolPerRequestInMitm(true)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                    .start();
            for (int i = 0; i < 3; i++) {
                try (HttpClient c = client(proxy, proxyCa.clientContext())) {
                    assertEquals(200, get(c, url(secure, "/m" + i)).statusCode());
                }
            }
            assertEquals(1, serverConnections.get(), "one upstream TLS connection for all intercepted sessions");
        } finally {
            secure.stop(0);
        }
    }

    @Test
    void sessionHeldMitmConnectionIsReturnedWhenTheClientLeaves() throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("Pool Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Pool Proxy CA");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), echo());
        try {
            proxy = bootstrap().withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                    .start();
            for (int i = 0; i < 2; i++) {
                try (HttpClient c = client(proxy, proxyCa.clientContext())) {
                    assertEquals(200, get(c, url(secure, "/s" + i)).statusCode());
                    assertEquals(200, get(c, url(secure, "/t" + i)).statusCode());
                }
                // Let the proxy notice the client closed and return the connection.
                for (int wait = 0; wait < 50 && proxy.getServerConnectionPoolMetrics().idleConnections() == 0; wait++) {
                    Thread.sleep(20);
                }
            }
            assertEquals(1, serverConnections.get());
        } finally {
            secure.stop(0);
        }
    }

    private static HttpProxyServer countingUpstream(AtomicInteger requests) {
        return MicroProxy.bootstrap().withPort(0).plusActivityTracker(new ActivityTrackerAdapter() {
            @Override
            public void requestReceivedFromClient(FlowContext ctx, org.microproxy.http.HttpRequest request) {
                requests.incrementAndGet();
            }
        }).start();
    }

    /** Routes /a and /b through two upstream proxies and everything else directly. */
    private static ChainedProxyManager routeByPath(HttpProxyServer upstreamA, HttpProxyServer upstreamB) {
        return (request, chainedProxies, clientDetails) -> {
            String path = URI.create(request.uri()).getPath();
            HttpProxyServer upstream = path.startsWith("/a") ? upstreamA : path.startsWith("/b") ? upstreamB : null;
            chainedProxies.add(upstream == null ? ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION
                    : new ChainedProxyAdapter() {
                        @Override
                        public InetSocketAddress getChainedProxyAddress() {
                            return upstream.getListenAddress();
                        }
                    });
        };
    }

    @Test
    void connectionsAreNotSharedAcrossRoutes() {
        AtomicInteger viaA = new AtomicInteger();
        AtomicInteger viaB = new AtomicInteger();
        HttpProxyServer upstreamA = countingUpstream(viaA);
        HttpProxyServer upstreamB = countingUpstream(viaB);
        try {
            proxy = bootstrap().withSharedServerConnectionPool(true)
                    .withChainProxyManager(routeByPath(upstreamA, upstreamB)).start();
            for (int round = 0; round < 2; round++) {
                for (String path : List.of("/a", "/b", "/direct")) {
                    assertEquals(200, get(client(proxy), url(origin, path + round)).statusCode());
                }
            }
            assertEquals(2, viaA.get(), "only /a goes through upstream A");
            assertEquals(2, viaB.get(), "only /b goes through upstream B");
            // One connection per route (upstream A, upstream B, direct), each reused in round two.
            assertEquals(3, serverConnections.get());
            PoolMetrics metrics = proxy.getServerConnectionPoolMetrics();
            assertEquals(3, metrics.totalConnections());
            assertEquals(3, metrics.idleConnections());
            assertEquals(6, metrics.borrowCount());
        } finally {
            upstreamA.abort();
            upstreamB.abort();
        }
    }

    @Test
    void stopClosesPooledConnections() throws Exception {
        CountDownLatch serverSawClose = new CountDownLatch(1);
        try (TestSupport.RawServer keepAlive = TestSupport.rawServer(socket -> {
            var in = socket.getInputStream();
            while (!TestSupport.readUntil(in, "\r\n\r\n").isEmpty()) {
                TestSupport.write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
            serverSawClose.countDown();
        })) {
            proxy = bootstrap().withSharedServerConnectionPool(true).start();
            assertEquals("ok", get(client(proxy), "http://127.0.0.1:" + keepAlive.port() + "/").body());
            // The connection goes back to the pool just after the response is relayed.
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (proxy.getServerConnectionPoolMetrics().idleConnections() == 0 && System.nanoTime() < deadline) {
                Thread.sleep(5);
            }
            assertEquals(1, proxy.getServerConnectionPoolMetrics().idleConnections());
            assertEquals(1, serverSawClose.getCount(), "the pooled connection stays open while the proxy runs");

            proxy.stop();
            assertTrue(serverSawClose.await(5, TimeUnit.SECONDS), "stopping closes the pooled connection");
            assertEquals(0, proxy.getServerConnectionPoolMetrics().totalConnections());
        }
    }
}
