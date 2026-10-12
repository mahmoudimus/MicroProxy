package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;

import com.sun.net.httpserver.HttpServer;
import io.github.mahmoudimus.http2.Frame;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.impl.BootstrapView;
import org.microproxy.stats.Counter;
import org.microproxy.stats.Gauge;
import org.microproxy.stats.StatsRegistry;

/**
 * The proxy's life: its states, draining (in-flight exchanges finish, new requests are told to go
 * elsewhere, the listeners close at the end), stopping listeners, the drain time {@code stop()}
 * waits, and the health check.
 */
class DrainTest {

    private HttpServer origin;
    /** Released to let the origin's slow responses go. */
    private final CountDownLatch release = new CountDownLatch(1);
    private final CountDownLatch slowArrived = new CountDownLatch(1);
    private HttpProxyServer proxy;

    @BeforeEach
    void startOrigin() {
        origin = TestSupport.origin(exchange -> {
            if (exchange.getRequestURI().getPath().equals("/slow")) {
                slowArrived.countDown();
                try {
                    release.await(20, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            TestSupport.fixed(200, "done " + exchange.getRequestURI().getPath()).handle(exchange);
        });
    }

    @AfterEach
    void tearDown() {
        release.countDown();
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private String url(String path) {
        return "http://127.0.0.1:" + origin.getAddress().getPort() + path;
    }

    @Test
    void theStateGoesFromLiveToStopped() {
        proxy = MicroProxy.bootstrap().withPort(0).start();
        assertEquals(ServerState.LIVE, proxy.state());
        assertEquals(Duration.ofSeconds(10), proxy.getDrainTime());
        proxy.stop();
        assertEquals(ServerState.STOPPED, proxy.state());
    }

    @Test
    void anImmediateDrainLetsTheExchangeInProgressFinishAndClosesNewConnectionsAfterOneRequest() throws Exception {
        StatsRegistry stats = StatsRegistry.create();
        proxy = MicroProxy.bootstrap().withPort(0).withStats(stats).withDrainStrategy(DrainStrategy.IMMEDIATE).start();
        InetSocketAddress address = proxy.getListenAddress();
        try (Client inFlight = new Client(address); Client idle = new Client(address)) {
            assertEquals(200, idle.get(url("/warm")).status);
            inFlight.send(url("/slow"));
            assertTrue(slowArrived.await(10, TimeUnit.SECONDS));

            long started = System.nanoTime();
            CompletableFuture<Void> drain = CompletableFuture.runAsync(() -> proxy.drain(Duration.ofMillis(1500)));
            eventually("draining", () -> proxy.state() == ServerState.DRAINING);
            assertEquals(1, value(stats, "server.state"));
            assertEquals(0, value(stats, "server.live"));
            // The idle keep-alive connection is closed at once.
            assertTrue(idle.closedByProxy(), "the idle connection is closed");

            // A new connection is still accepted, and told to go elsewhere.
            try (Client late = new Client(address)) {
                Response r = late.get(url("/late"));
                assertEquals(200, r.status);
                assertEquals("close", r.headers.get("connection"));
                assertTrue(late.closedByProxy());
            }

            // The exchange in progress finishes.
            release.countDown();
            Response slow = inFlight.read();
            assertEquals(200, slow.status);
            assertEquals("done /slow", slow.body);

            drain.get(10, TimeUnit.SECONDS);
            assertTrue(System.nanoTime() - started >= Duration.ofMillis(1400).toNanos(), "the drain lasts its time");
        }
        // After the drain time, the listener is closed.
        assertThrows(ConnectException.class, () -> new Socket(address.getAddress(), address.getPort()).close());
        assertEquals(ServerState.DRAINING, proxy.state());
        assertTrue(value(stats, "http.MicroProxy.downstream_cx_drain_close") >= 2, "the idle and the late connection");
        assertEquals(1, value(stats, "listener_manager.listener_stopped"));
        assertEquals(0, value(stats, "listener_manager.total_listeners_active"));
        proxy.stop();
        assertEquals(ServerState.STOPPED, proxy.state());
        assertEquals(4, value(stats, "server.state"));
    }

    @Test
    void theDrainClosesWhatIsStillOpenWhenItsTimeIsOver() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withDrainStrategy(DrainStrategy.IMMEDIATE).start();
        try (Client inFlight = new Client(proxy.getListenAddress())) {
            inFlight.send(url("/slow"));
            assertTrue(slowArrived.await(10, TimeUnit.SECONDS));
            long started = System.nanoTime();
            proxy.drain(Duration.ofMillis(300));
            assertTrue(System.nanoTime() - started < Duration.ofSeconds(5).toNanos());
            assertTrue(inFlight.closedByProxy(), "the exchange still in progress is cut off");
        }
    }

    @Test
    void aGradualDrainBarelyTouchesItsFirstRequests() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).start();
        CompletableFuture<Void> drain = CompletableFuture.runAsync(() -> proxy.drain(Duration.ofHours(1)));
        eventually("draining", () -> proxy.state() == ServerState.DRAINING);
        try (Client c = new Client(proxy.getListenAddress())) {
            for (int i = 0; i < 5; i++) {
                Response r = c.get(url("/early"));
                assertEquals(200, r.status);
                assertNull(r.headers.get("connection"), "a chance of about 1e-6 in an hour's drain");
            }
        }
        proxy.stop();
        drain.get(10, TimeUnit.SECONDS);
        assertEquals(ServerState.STOPPED, proxy.state());
    }

    @Test
    void anHttp2ConnectionIsSentGoAwayAndItsStreamIsServed() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withHttp2Cleartext(true)
                .withDrainStrategy(DrainStrategy.IMMEDIATE).start();
        String authority = "127.0.0.1:" + origin.getAddress().getPort();
        try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), authority).handshake()) {
            c.get(1, "/before");
            assertEquals(200, c.response(1).status());
            CompletableFuture<Void> drain = CompletableFuture.runAsync(() -> proxy.drain(Duration.ofSeconds(2)));
            Frame.GoAway goAway = c.awaitGoAway();
            assertEquals(1, goAway.lastStreamId());
            assertTrue(c.closedByServer());
            proxy.stop();
            drain.get(10, TimeUnit.SECONDS);
        }
        // On a new connection, the first stream is served and named the last one.
        proxy = MicroProxy.bootstrap().withPort(0).withHttp2Cleartext(true).start();
        proxy.setHealthCheckFailed(true);
        try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), authority).handshake()) {
            c.get(1, "/first");
            assertEquals(200, c.response(1).status());
            assertEquals(1, c.awaitGoAway().lastStreamId());
        }
    }

    @Test
    void stoppingTheListenersRefusesNewConnectionsAndKeepsOpenOnes() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).start();
        InetSocketAddress address = proxy.getListenAddress();
        try (Client open = new Client(address)) {
            assertEquals(200, open.get(url("/one")).status);
            proxy.stopListeners();
            assertEquals(ServerState.DRAINING, proxy.state());
            assertThrows(ConnectException.class, () -> new Socket(address.getAddress(), address.getPort()).close());
            Response again = open.get(url("/two"));
            assertEquals("done /two", again.body);
            assertNull(again.headers.get("connection"), "no drain: the connection is left alone");
        }
    }

    @Test
    void stopWaitsAtMostTheDrainTime() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withDrainTime(Duration.ofMillis(300)).start();
        assertEquals(Duration.ofMillis(300), proxy.getDrainTime());
        try (Client inFlight = new Client(proxy.getListenAddress())) {
            inFlight.send(url("/slow"));
            assertTrue(slowArrived.await(10, TimeUnit.SECONDS));
            long started = System.nanoTime();
            proxy.stop();
            long took = System.nanoTime() - started;
            assertTrue(took >= Duration.ofMillis(250).toNanos() && took < Duration.ofSeconds(8).toNanos(), "took " + took);
            assertTrue(inFlight.closedByProxy());
        }
        assertEquals(ServerState.STOPPED, proxy.state());
    }

    @Test
    void stopEndsADrainInProgress() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withDrainTime(Duration.ofMillis(200)).start();
        CompletableFuture<Void> drain = CompletableFuture.runAsync(() -> proxy.drain(Duration.ofHours(1)));
        eventually("draining", () -> proxy.state() == ServerState.DRAINING);
        proxy.stop();
        drain.get(10, TimeUnit.SECONDS);
        assertEquals(ServerState.STOPPED, proxy.state());
        // A drain after stopping does nothing.
        proxy.drain(Duration.ofHours(1));
        assertEquals(ServerState.STOPPED, proxy.state());
    }

    @Test
    void theHealthCheckPathAnswersFromTheProxy() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withHealthCheckPath("/healthz", false).start();
        try (Client c = new Client(proxy.getListenAddress())) {
            assertEquals(200, c.get("/healthz?probe=1").status);
            assertFalse(proxy.isHealthCheckFailed());
            proxy.setHealthCheckFailed(true);
            Response failed = c.get("/healthz");
            assertEquals(503, failed.status);
            assertEquals("true", failed.headers.get("x-envoy-immediate-health-check-fail"));
            assertEquals("close", failed.headers.get("connection"), "a failed health check drains connections");
        }
        try (Client c = new Client(proxy.getListenAddress())) {
            proxy.setHealthCheckFailed(false);
            assertEquals(200, c.get("/healthz").status);
            // Not the health-check path, nor a request through the proxy for one.
            assertEquals("done /healthz", c.get(url("/healthz")).body);
            assertEquals("done /healthz/more", c.get(url("/healthz/more")).body);
            // Not ready once draining.
            proxy.stopListeners();
            assertEquals(503, c.get("/healthz").status);
        }
    }

    @Test
    void aPassThroughHealthCheckGoesToTheServerUnlessItFails() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0)
                .withReverseProxy("http://127.0.0.1:" + origin.getAddress().getPort())
                .withHealthCheckPath("/healthz", true).start();
        try (Client c = new Client(proxy.getListenAddress())) {
            assertEquals("done /healthz", c.get("/healthz").body);
            proxy.setHealthCheckFailed(true);
            assertEquals(503, c.get("/healthz").status);
        }
        assertThrows(IllegalArgumentException.class, () -> MicroProxy.bootstrap().withHealthCheckPath("healthz", false));
    }

    @Test
    void thePropertiesConfigureTheDrainAndTheHealthCheck(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("proxy.properties");
        Files.writeString(file, "drain_time = 3\ndrain_strategy = IMMEDIATE\nhealth_check_path = /ready\n"
                + "health_check_pass_through = true\n");
        HttpProxyServerBootstrap b = MicroProxy.bootstrapFromFile(file);
        assertArrayEquals(new Object[] {Duration.ofSeconds(3), DrainStrategy.IMMEDIATE}, BootstrapView.drain(b));
        assertArrayEquals(new Object[] {"/ready", true}, BootstrapView.healthCheck(b));
        assertArrayEquals(new Object[] {Duration.ofSeconds(10), DrainStrategy.GRADUAL},
                BootstrapView.drain(MicroProxy.bootstrap()));
        assertThrows(IllegalArgumentException.class, () -> MicroProxy.bootstrap().withDrainTime(Duration.ofSeconds(-1)));
        assertThrows(IllegalArgumentException.class, () -> DrainStrategy.parse("slow"));
        assertEquals(DrainStrategy.GRADUAL, DrainStrategy.parse(" Gradual "));
    }

    private static long value(StatsRegistry stats, String name) {
        return switch (stats.get(name)) {
            case Counter c -> c.value();
            case Gauge g -> g.value();
            case null, default -> throw new AssertionError("no counter or gauge " + name);
        };
    }

    // ---------------------------------------------------------------------------------------

    record Response(int status, Map<String, String> headers, String body) {}

    /** A blocking HTTP/1.1 client on one connection, which reads responses framed by Content-Length. */
    static final class Client implements AutoCloseable {
        private final Socket socket;
        private final InputStream in;

        Client(InetSocketAddress address) throws IOException {
            socket = new Socket(address.getAddress(), address.getPort());
            socket.setSoTimeout(15_000);
            in = socket.getInputStream();
        }

        void send(String target) throws IOException {
            String host = target.startsWith("http://") ? target.substring(7, target.indexOf('/', 7)) : "proxy";
            TestSupport.write(socket.getOutputStream(), "GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n");
        }

        Response get(String target) throws IOException {
            send(target);
            return read();
        }

        Response read() throws IOException {
            String head = TestSupport.readUntil(in, "\r\n\r\n");
            if (head.isEmpty()) throw new IOException("connection closed");
            String[] lines = head.split("\r\n");
            int status = Integer.parseInt(lines[0].split(" ")[1]);
            Map<String, String> headers = new LinkedHashMap<>();
            for (int i = 1; i < lines.length; i++) {
                int colon = lines[i].indexOf(':');
                if (colon > 0) headers.put(lines[i].substring(0, colon).toLowerCase(Locale.ROOT), lines[i].substring(colon + 1).strip());
            }
            int length = Integer.parseInt(headers.getOrDefault("content-length", "0"));
            return new Response(status, headers, new String(in.readNBytes(length), StandardCharsets.UTF_8));
        }

        /** Whether the proxy closes the connection (within the read timeout). */
        boolean closedByProxy() {
            try {
                return in.read() < 0;
            } catch (IOException e) {
                return true;
            }
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }
}
