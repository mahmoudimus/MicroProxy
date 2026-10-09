package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;

import com.sun.net.httpserver.HttpServer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Global bandwidth limits on server traffic: "read" limits what the proxy reads from servers
 * (downloads), "write" what it writes to them (uploads). Timings only assert loose lower bounds,
 * at 60% of the time the rate implies: the limiter allows a short burst, and machines vary.
 */
class ThrottlingTest {

    private static final double TOLERANCE = 0.6;

    private final byte[] payload = new byte[200_000];
    private HttpServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() {
        new Random(42).nextBytes(payload);
        origin = TestSupport.origin(exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(200, payload.length);
            exchange.getResponseBody().write(payload);
            exchange.close();
        });
        // Answers with the number of request body bytes received.
        origin.createContext("/upload", exchange -> {
            byte[] count = String.valueOf(exchange.getRequestBody().readAllBytes().length).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, count.length);
            exchange.getResponseBody().write(count);
            exchange.close();
        });
        // Sends the request body back.
        origin.createContext("/echo", exchange -> {
            byte[] body = exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private static long minimumMillis(long bytes, long bytesPerSecond) {
        return (long) (bytes * 1000.0 / bytesPerSecond * TOLERANCE);
    }

    private static long millisSince(long startNanos) {
        return Duration.ofNanos(System.nanoTime() - startNanos).toMillis();
    }

    private HttpRequest download() {
        return HttpRequest.newBuilder(URI.create(TestSupport.url(origin, "/"))).build();
    }

    private HttpRequest upload(int bytes) {
        return HttpRequest.newBuilder(URI.create(TestSupport.url(origin, "/upload")))
                .POST(HttpRequest.BodyPublishers.ofByteArray(new byte[bytes])).build();
    }

    @Test
    void readThrottleLimitsDownloads() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withThrottling(200_000, 0).start();
        HttpClient client = client(proxy);
        long start = System.nanoTime();
        HttpResponse<byte[]> response = client.send(download(), HttpResponse.BodyHandlers.ofByteArray());
        long took = millisSince(start);
        assertArrayEquals(payload, response.body());
        assertTrue(took >= minimumMillis(payload.length, 200_000), "200 KB at 200 KB/s took only " + took + " ms");

        proxy.setThrottle(0, 0);
        start = System.nanoTime();
        client.send(download(), HttpResponse.BodyHandlers.ofByteArray());
        took = millisSince(start);
        assertTrue(took < 1500, "unthrottled took " + took + " ms");
    }

    @Test
    void writeThrottleLimitsUploads() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withThrottling(0, 200_000).start();
        long start = System.nanoTime();
        HttpResponse<String> response = client(proxy).send(upload(200_000), HttpResponse.BodyHandlers.ofString());
        long took = millisSince(start);
        assertEquals("200000", response.body(), "the whole body arrived");
        assertTrue(took >= minimumMillis(200_000, 200_000), "200 KB at 200 KB/s took only " + took + " ms");
    }

    @Test
    void throttleChangesApplyToOpenConnections() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).start();
        HttpClient client = client(proxy); // one client, so the same connections throughout
        assertEquals("100000", client.send(upload(100_000), HttpResponse.BodyHandlers.ofString()).body());

        proxy.setThrottle(0, 100_000);
        long start = System.nanoTime();
        assertEquals("100000", client.send(upload(100_000), HttpResponse.BodyHandlers.ofString()).body());
        long took = millisSince(start);
        assertTrue(took >= minimumMillis(100_000, 100_000), "100 KB at 100 KB/s took only " + took + " ms");

        proxy.setThrottle(0, 0);
        start = System.nanoTime();
        assertEquals("100000", client.send(upload(100_000), HttpResponse.BodyHandlers.ofString()).body());
        took = millisSince(start);
        assertTrue(took < 1500, "after lifting the limit the upload took " + took + " ms");
    }

    @Test
    void readAndWriteThrottlesCombine() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withThrottling(200_000, 200_000).start();
        byte[] body = new byte[150_000];
        new Random(7).nextBytes(body);
        long start = System.nanoTime();
        HttpResponse<byte[]> response = client(proxy).send(
                HttpRequest.newBuilder(URI.create(TestSupport.url(origin, "/echo")))
                        .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        long took = millisSince(start);
        assertArrayEquals(body, response.body());
        // 150 KB up, then 150 KB down, each at 200 KB/s.
        assertTrue(took >= minimumMillis(2 * body.length, 200_000), "the round trip took only " + took + " ms");
    }

    @Test
    void theLimitIsSharedByAllConnections() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withThrottling(400_000, 0).start();
        long start = System.nanoTime();
        // Two clients, so two client and two server connections, downloading at once.
        CompletableFuture<HttpResponse<byte[]>> first =
                client(proxy).sendAsync(download(), HttpResponse.BodyHandlers.ofByteArray());
        CompletableFuture<HttpResponse<byte[]>> second =
                client(proxy).sendAsync(download(), HttpResponse.BodyHandlers.ofByteArray());
        assertArrayEquals(payload, first.get().body());
        assertArrayEquals(payload, second.get().body());
        long took = millisSince(start);
        assertTrue(took >= minimumMillis(2L * payload.length, 400_000),
                "2 x 200 KB through a 400 KB/s limit took only " + took + " ms");
    }
}
