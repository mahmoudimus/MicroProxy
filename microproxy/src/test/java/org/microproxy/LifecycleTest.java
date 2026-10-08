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
import java.io.PrintStream;
import java.net.ConnectException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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
}
