package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.impl.BootstrapView;

/** The launcher's admin, drain and health-check flags, and what its shutdown hook (SIGTERM) does. */
class LauncherAdminTest {

    private final ByteArrayOutputStream console = new ByteArrayOutputStream();
    private final List<HttpProxyServer> servers = new ArrayList<>();
    private HttpServer origin;

    @AfterEach
    void tearDown() {
        servers.forEach(HttpProxyServer::abort);
        if (origin != null) origin.stop(0);
    }

    private PrintStream out() {
        return new PrintStream(console, true, StandardCharsets.UTF_8);
    }

    private HttpProxyServerBootstrap parse(String... args) throws IOException {
        return Launcher.parse(args, out()).bootstrap();
    }

    private HttpProxyServer launch(String... args) throws IOException {
        HttpProxyServer server = Launcher.start(args, out());
        servers.add(server);
        return server;
    }

    @Test
    void adminFlags(@TempDir Path dir) throws IOException {
        assertArrayEquals(new Object[] {null, null}, BootstrapView.admin(parse()));
        assertArrayEquals(new Object[] {new InetSocketAddress(TestSupport.LOOPBACK, 9901), "t0k"},
                BootstrapView.admin(parse("--admin-port", "9901", "--admin-token", "t0k")));
        Object[] all = BootstrapView.admin(parse("--admin-address", "0.0.0.0:9902"));
        assertEquals(new InetSocketAddress("0.0.0.0", 9902), all[0]);
        assertEquals(new InetSocketAddress("::1", 9903), BootstrapView.admin(parse("--admin-address", "[::1]:9903"))[0]);
        Path tokenFile = dir.resolve("token");
        Files.writeString(tokenFile, "from-file\nignored\n");
        assertEquals("from-file", BootstrapView.admin(parse("--admin-token-file", tokenFile.toString()))[1]);
        assertThrows(IllegalArgumentException.class, () -> parse("--admin-address", "9901"));
        assertThrows(IllegalArgumentException.class, () -> parse("--admin-address", "host:port"));
        Files.writeString(tokenFile, "\n");
        assertThrows(IllegalArgumentException.class, () -> parse("--admin-token-file", tokenFile.toString()));
        // The command line goes to /server_info.
        assertEquals(List.of("--port", "0", "--metrics"), BootstrapView.commandLineOptions(parse("--port", "0", "--metrics")));
    }

    @Test
    void drainAndHealthCheckFlags() throws IOException {
        assertArrayEquals(new Object[] {Duration.ofSeconds(10), DrainStrategy.GRADUAL}, BootstrapView.drain(parse()));
        assertArrayEquals(new Object[] {Duration.ofSeconds(30), DrainStrategy.IMMEDIATE},
                BootstrapView.drain(parse("--drain-time", "30", "--drain-strategy", "immediate")));
        assertArrayEquals(new Object[] {Duration.ZERO, DrainStrategy.GRADUAL}, BootstrapView.drain(parse("--drain-time", "0")));
        assertThrows(IllegalArgumentException.class, () -> parse("--drain-time", "-1"));
        assertThrows(IllegalArgumentException.class, () -> parse("--drain-strategy", "eventually"));
        assertArrayEquals(new Object[] {"/healthz", false}, BootstrapView.healthCheck(parse("--health-check-path", "/healthz")));
        assertArrayEquals(new Object[] {"/healthz", true},
                BootstrapView.healthCheck(parse("--health-check-path", "/healthz", "--health-check-pass-through")));
        assertThrows(IllegalArgumentException.class, () -> parse("--health-check-pass-through"));
        assertThrows(IllegalArgumentException.class, () -> parse("--health-check-path", "healthz"));
    }

    @Test
    void theLaunchedAdminListenerAnswersWithItsToken() throws Exception {
        HttpProxyServer server = launch("--port", "0", "--admin-port", "0", "--admin-token", "s3cret");
        InetSocketAddress admin = server.getAdminAddress();
        assertEquals(TestSupport.LOOPBACK, admin.getAddress());
        assertTrue(console.toString(StandardCharsets.UTF_8).contains("Admin listening on " + admin));
        HttpClient http = HttpClient.newHttpClient();
        URI info = URI.create("http://127.0.0.1:" + admin.getPort() + "/server_info");
        assertEquals(401, http.send(HttpRequest.newBuilder(info).build(), HttpResponse.BodyHandlers.ofString()).statusCode());
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(info).header("Authorization", "Bearer s3cret").build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode());
        assertTrue(r.body().contains("\"--admin-token\": \"[redacted]\""), r.body());
        assertTrue(!r.body().contains("s3cret"), r.body());
    }

    @Test
    void theShutdownHookDrainsTheExchangeInProgressThenStops() throws Exception {
        CountDownLatch arrived = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        origin = TestSupport.origin(exchange -> {
            arrived.countDown();
            try {
                release.await(20, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            TestSupport.fixed(200, "finished").handle(exchange);
        });
        HttpProxyServer server = launch("--port", "0", "--drain-time", "5");
        InetSocketAddress address = server.getListenAddress();
        try (DrainTest.Client inFlight = new DrainTest.Client(address)) {
            inFlight.send(TestSupport.url(origin, "/slow"));
            assertTrue(arrived.await(10, TimeUnit.SECONDS));

            Thread hook = Launcher.shutdownHook(server, out());
            assertEquals("microproxy-shutdown", hook.getName());
            long started = System.nanoTime();
            hook.start();
            eventually("draining", () -> server.state() == ServerState.DRAINING);
            assertThrows(ConnectException.class, () -> new Socket(address.getAddress(), address.getPort()).close(),
                    "no new connections once draining to stop");
            assertTrue(hook.isAlive(), "it waits for the exchange in progress");
            release.countDown();
            DrainTest.Response r = inFlight.read();
            assertEquals("finished", r.body());
            hook.join(10_000);
            assertTrue(!hook.isAlive());
            assertTrue(System.nanoTime() - started < Duration.ofSeconds(5).toNanos(), "it ends once the exchange has");
        }
        assertEquals(ServerState.STOPPED, server.state());
        assertTrue(console.toString(StandardCharsets.UTF_8).contains("MicroProxy stopping: draining for up to 5.0 s"));
        // Another signal, or System.exit after a stop, does nothing more.
        console.reset();
        Launcher.shutdown(server, out());
        assertEquals("", console.toString(StandardCharsets.UTF_8));
    }

    @Test
    void theShutdownHookCutsOffWhatOutlastsTheDrainTime() throws Exception {
        CountDownLatch arrived = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        origin = TestSupport.origin(exchange -> {
            arrived.countDown();
            try {
                release.await(20, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            TestSupport.fixed(200, "late").handle(exchange);
        });
        HttpProxyServer server = launch("--port", "0", "--drain-time", "1");
        try (DrainTest.Client inFlight = new DrainTest.Client(server.getListenAddress())) {
            inFlight.send(TestSupport.url(origin, "/slow"));
            assertTrue(arrived.await(10, TimeUnit.SECONDS));
            long started = System.nanoTime();
            Launcher.shutdown(server, out());
            long took = System.nanoTime() - started;
            assertTrue(took >= Duration.ofMillis(900).toNanos() && took < Duration.ofSeconds(8).toNanos(), "took " + took);
            assertTrue(inFlight.closedByProxy());
        } finally {
            release.countDown();
        }
        assertEquals(ServerState.STOPPED, server.state());
        assertNull(server.getAdminAddress());
    }
}
