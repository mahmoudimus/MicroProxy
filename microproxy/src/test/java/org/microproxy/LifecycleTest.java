package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.impl.BootstrapView;

class LifecycleTest {

    @Test
    void stopReleasesThePort() {
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).start();
        int port = proxy.getListenAddress().getPort();
        proxy.stop();
        assertThrows(ConnectException.class, () -> new Socket(TestSupport.LOOPBACK, port).close());
    }

    @Test
    void gracefulStopLetsInFlightRequestsFinish() throws Exception {
        HttpServer origin = TestSupport.origin(exchange -> {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            TestSupport.fixed(200, "late").handle(exchange);
        });
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).start();
        try {
            var future = client(proxy).sendAsync(
                    java.net.http.HttpRequest.newBuilder(java.net.URI.create(TestSupport.url(origin, "/"))).build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString());
            Thread.sleep(150);
            proxy.stop();
            assertEquals("late", future.get().body());
        } finally {
            origin.stop(0);
        }
    }

    @Test
    void closeIsStop() {
        int port;
        try (HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).start()) {
            port = proxy.getListenAddress().getPort();
        }
        assertThrows(ConnectException.class, () -> new Socket(TestSupport.LOOPBACK, port).close());
    }

    @Test
    void cloneCopiesConfiguration() {
        HttpProxyServer first = MicroProxy.bootstrap().withPort(0).withIdleConnectionTimeout(42).start();
        HttpProxyServer second = first.clone().start();
        try {
            assertNotEquals(first.getListenAddress().getPort(), second.getListenAddress().getPort());
            assertEquals(Duration.ofSeconds(42), second.getIdleConnectionTimeout());
        } finally {
            first.abort();
            second.abort();
        }
    }

    @Test
    void propertiesFileConfiguresTheServer(@TempDir Path dir) throws IOException {
        HttpServer origin = TestSupport.origin(TestSupport.echo());
        Path props = dir.resolve("microproxy.properties");
        Files.writeString(props, """
                port=0
                proxy_alias=from-file
                idle_connection_timeout=12
                connect_timeout=1234
                """);
        HttpProxyServer proxy = MicroProxy.bootstrapFromFile(props).start();
        try {
            assertEquals(Duration.ofSeconds(12), proxy.getIdleConnectionTimeout());
            assertEquals(1234, proxy.getConnectTimeout());
            assertEquals("1.1 from-file",
                    get(client(proxy), TestSupport.url(origin, "/")).headers().firstValue("via").orElseThrow());
        } finally {
            proxy.abort();
            origin.stop(0);
        }
    }

    @Test
    void propertiesEnableThePoolLoggerAndDnssec(@TempDir Path dir) throws IOException {
        HttpServer origin = TestSupport.origin(TestSupport.echo());
        Path props = dir.resolve("microproxy.properties");
        Files.writeString(props, """
                port=0
                use_shared_server_connection_pool=true
                max_connections_per_host=3
                max_total_connections=7
                pool_idle_timeout=30
                activity_log_format=json
                dnssec=true
                dnssec_resolver=https://cloudflare-dns.com/dns-query
                """);
        HttpProxyServer proxy = MicroProxy.bootstrapFromFile(props).start();
        try {
            // An IP literal needs no lookup, so this works offline even with DNSSEC enabled.
            assertEquals(200, get(client(proxy), TestSupport.url(origin, "/")).statusCode());
            assertEquals(1, proxy.getServerConnectionPoolMetrics().totalConnections());
        } finally {
            proxy.abort();
            origin.stop(0);
        }
    }

    @Test
    void launcherStartsAProxyWithMitm(@TempDir Path dir) throws IOException {
        ByteArrayOutputStream console = new ByteArrayOutputStream();
        Path ca = dir.resolve("ca.p12");
        HttpProxyServer proxy = Launcher.start(new String[] {"--port", "0", "--mitm", "--mitm-ca", ca.toString(), "--dnssec", "--shared-pool", "--activity-log-format", "clf"},
                new PrintStream(console, true));
        try {
            assertTrue(Files.isRegularFile(ca));
            assertTrue(Files.readString(dir.resolve("ca.pem")).startsWith("-----BEGIN CERTIFICATE-----"));
            assertTrue(console.toString().contains("listening on"));
        } finally {
            proxy.abort();
        }
        assertNull(Launcher.start(new String[] {"--help"}, new PrintStream(new ByteArrayOutputStream())));
        assertThrows(IllegalArgumentException.class, () -> Launcher.start(new String[] {"--bogus"}, System.out));
    }

    @Test
    void launcherCachesOnDiskAndGoesOffline(@TempDir Path dir) throws Exception {
        java.util.concurrent.atomic.AtomicInteger hits = new java.util.concurrent.atomic.AtomicInteger();
        HttpServer origin = origin(exchange -> {
            byte[] body = ("page #" + hits.incrementAndGet()).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Cache-Control", "max-age=0");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        Path cacheDir = dir.resolve("cache");
        String target = url(origin, "/page");
        ByteArrayOutputStream console = new ByteArrayOutputStream();
        HttpProxyServer online = Launcher.start(new String[] {"--port", "0", "--cache-dir", cacheDir.toString()},
                new PrintStream(console, true));
        try {
            assertEquals("page #1", get(client(online), target).body());
            assertTrue(console.toString().contains("Caching in"));
        } finally {
            online.abort();
        }
        // A new process with the same directory, offline: the page is still there.
        HttpProxyServer offline = Launcher.start(new String[] {"--port", "0", "--cache-dir", cacheDir.toString(), "--offline"},
                new PrintStream(new ByteArrayOutputStream(), true));
        try {
            assertEquals("page #1", get(client(offline), target).body());
            assertEquals(504, get(client(offline), url(origin, "/elsewhere")).statusCode());
            assertEquals(1, hits.get());
        } finally {
            offline.abort();
            origin.stop(0);
        }
        assertThrows(IllegalArgumentException.class, () -> Launcher.start(new String[] {"--offline"}, System.out));
    }

    // --- clones (LittleProxy's ClonedProxyTest) ------------------------------------------------

    @Test
    void cloneServesRequestsOnItsOwnPort() {
        HttpServer origin = origin(TestSupport.fixed(200, "success"));
        HttpProxyServer original = MicroProxy.bootstrap().withPort(0).withName("original").start();
        HttpProxyServer clone = original.clone().withName("clone").start();
        try {
            assertNotEquals(original.getListenAddress(), clone.getListenAddress());
            assertEquals("success", get(client(clone), url(origin, "/")).body());
            assertEquals("success", get(client(original), url(origin, "/")).body());
        } finally {
            original.abort();
            clone.abort();
            origin.stop(0);
        }
    }

    @Test
    void stoppingTheCloneLeavesTheOriginalRunning() {
        HttpServer origin = origin(TestSupport.fixed(200, "success"));
        HttpProxyServer original = MicroProxy.bootstrap().withPort(0).start();
        HttpProxyServer clone = original.clone().start();
        try {
            clone.abort();
            assertEquals(200, get(client(original), url(origin, "/")).statusCode());
        } finally {
            original.abort();
            origin.stop(0);
        }
    }

    @Test
    void stoppingTheOriginalLeavesTheCloneRunning() {
        HttpServer origin = origin(TestSupport.fixed(200, "success"));
        HttpProxyServer original = MicroProxy.bootstrap().withPort(0).start();
        HttpProxyServer clone = original.clone().start();
        try {
            original.stop();
            assertEquals(200, get(client(clone), url(origin, "/")).statusCode());
        } finally {
            clone.abort();
            origin.stop(0);
        }
    }

    @Test
    void cloneTakesTheRuntimeSettingsAndTheNextPort() throws IOException {
        int port;
        try (ServerSocket free = new ServerSocket(0, 1, TestSupport.LOOPBACK)) {
            port = free.getLocalPort();
        }
        HttpProxyServer original = MicroProxy.bootstrap().withAddress(new InetSocketAddress(TestSupport.LOOPBACK, port))
                .withThrottling(1, 2).start();
        try {
            original.setIdleConnectionTimeout(Duration.ofSeconds(5));
            original.setConnectTimeout(777);
            original.setThrottle(10, 20);
            BootstrapView copy = BootstrapView.of(original.clone());
            assertEquals(port + 1, copy.address().getPort(), "a fixed port is cloned to the next one");
            assertEquals(Duration.ofSeconds(5), copy.idleConnectionTimeout());
            assertEquals(777, copy.connectTimeoutMs());
            assertEquals(10, copy.readThrottle());
            assertEquals(20, copy.writeThrottle());
        } finally {
            original.abort();
        }
    }

    // --- stopping (LittleProxy's StopProxyTest / EndToEndStoppingTest) -------------------------

    @Test
    void abortCutsInFlightRequests() throws Exception {
        CountDownLatch arrived = new CountDownLatch(1);
        HttpServer origin = origin(exchange -> {
            arrived.countDown();
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            TestSupport.fixed(200, "too late").handle(exchange);
        });
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).start();
        try {
            CompletableFuture<HttpResponse<String>> future = client(proxy).sendAsync(
                    HttpRequest.newBuilder(URI.create(url(origin, "/"))).build(), HttpResponse.BodyHandlers.ofString());
            assertTrue(arrived.await(5, TimeUnit.SECONDS));
            long start = System.nanoTime();
            proxy.abort();
            ExecutionException e = assertThrows(ExecutionException.class, () -> future.get(5, TimeUnit.SECONDS));
            assertTrue(e.getCause() instanceof IOException, e.getCause().toString());
            assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() < 2000, "abort does not wait");
        } finally {
            origin.stop(0);
        }
    }

    @Test
    void gracefulStopClosesIdleKeepAliveConnectionsWithoutWaiting() throws Exception {
        HttpServer origin = origin(TestSupport.fixed(200, "ok"));
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).start();
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            s.setSoTimeout(5000);
            TestSupport.write(s.getOutputStream(), "GET " + url(origin, "/") + " HTTP/1.1\r\nHost: x\r\n\r\n");
            InputStream in = s.getInputStream();
            assertTrue(TestSupport.readUntil(in, "\r\n\r\n").startsWith("HTTP/1.1 200"));
            assertEquals("ok", new String(in.readNBytes(2), StandardCharsets.US_ASCII));

            long start = System.nanoTime();
            proxy.stop();
            assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() < 3000,
                    "an idle keep-alive connection does not hold up a graceful stop");
            assertEquals(-1, in.read(), "the idle connection was closed");
        } finally {
            origin.stop(0);
        }
    }

    @Test
    void stopAndAbortEndTheAcceptorThread() {
        for (boolean graceful : new boolean[] {true, false}) {
            String name = "stop-threads-" + graceful;
            HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).withName(name).start();
            assertEquals(1, liveThreads(name + "-acceptor"), "the acceptor runs while the proxy does");
            if (graceful) {
                proxy.stop();
            } else {
                proxy.abort();
            }
            assertEquals(0, liveThreads(name + "-acceptor"), "no non-daemon thread keeps the JVM alive");
        }
    }

    private static long liveThreads(String name) {
        return Thread.getAllStackTraces().keySet().stream().filter(t -> t.getName().equals(name) && t.isAlive()).count();
    }

    @Test
    void stopAndAbortAreIdempotent() {
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).start();
        proxy.stop();
        proxy.stop();
        proxy.abort();
        HttpProxyServer aborted = MicroProxy.bootstrap().withPort(0).start();
        aborted.abort();
        aborted.abort();
        aborted.stop();
    }

    @Test
    void startingOnABusyPortFails() {
        HttpProxyServer first = MicroProxy.bootstrap().withPort(0).start();
        try {
            UncheckedIOException e = assertThrows(UncheckedIOException.class,
                    () -> MicroProxy.bootstrap().withPort(first.getListenAddress().getPort()).start());
            assertTrue(e.getMessage().startsWith("unable to bind"), e.getMessage());
        } finally {
            first.abort();
        }
    }

    @Test
    void closeOnStopResourcesCloseInReverseOrder() {
        List<String> closed = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).start();
        proxy.closeOnStop(() -> closed.add("first"));
        proxy.closeOnStop(() -> {
            closed.add("second");
            throw new IOException("a failing resource does not stop the others");
        });
        proxy.stop();
        assertEquals(List.of("second", "first"), closed);
    }
}
