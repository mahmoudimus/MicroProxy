package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SimpleProxyTest {

    private HttpServer origin;
    private HttpProxyServer proxy;
    private final AtomicInteger serverConnections = new AtomicInteger();
    private final AtomicInteger clientConnections = new AtomicInteger();

    @BeforeEach
    void setUp() {
        origin = origin(echo());
        origin.createContext("/big", exchange -> {
            byte[] data = bigPayload();
            exchange.sendResponseHeaders(200, 0); // chunked
            for (int i = 0; i < data.length; i += 10_000) {
                exchange.getResponseBody().write(data, i, Math.min(10_000, data.length - i));
            }
            exchange.close();
        });
        origin.createContext("/nocontent", TestSupport.fixed(204, ""));
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withProxyAlias("test-proxy")
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void serverConnected(FullFlowContext ctx, InetSocketAddress address) {
                        serverConnections.incrementAndGet();
                    }

                    @Override
                    public void clientConnected(FlowContext ctx) {
                        clientConnections.incrementAndGet();
                    }
                })
                .start();
    }

    @AfterEach
    void tearDown() throws IOException {
        proxy.abort();
        origin.stop(0);
        for (Socket r : refusing) r.close();
    }

    /** Reserved until the test ends, so a server started meanwhile cannot be given the same port. */
    private final List<Socket> refusing = new ArrayList<>();

    /** A loopback port that refuses connections, reserved until the test ends. */
    private int closedPort() {
        Socket s = TestSupport.refusingPort();
        refusing.add(s);
        return s.getLocalPort();
    }

    static byte[] bigPayload() {
        byte[] data = new byte[1_000_000];
        new Random(42).nextBytes(data);
        return data;
    }

    @Test
    void getIsProxiedWithViaHeadersBothWays() {
        HttpResponse<String> response = get(client(proxy), url(origin, "/hello?x=1"));
        assertEquals(200, response.statusCode());
        assertEquals("/hello?x=1", echoedUri(response.body()), "absolute-form must become origin-form");
        assertEquals(java.util.List.of("1.1 test-proxy"), echoedHeader(response.body(), "via"));
        assertEquals("1.1 test-proxy", response.headers().firstValue("via").orElseThrow());
        assertTrue(response.headers().firstValue("date").isPresent());
    }

    @Test
    void postBodyIsForwarded() {
        HttpClient client = client(proxy);
        HttpResponse<String> response = send(client, HttpRequest.newBuilder(URI.create(url(origin, "/post")))
                .POST(HttpRequest.BodyPublishers.ofString("hello body")).build());
        assertEquals(200, response.statusCode());
        assertTrue(response.body().startsWith("method: POST"));
        assertEquals("hello body", echoedBody(response.body()));
    }

    @Test
    void streamedChunkedUploadIsForwarded() {
        byte[] payload = new byte[300_000];
        Arrays.fill(payload, (byte) 'a');
        HttpResponse<String> response = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/up")))
                .POST(HttpRequest.BodyPublishers.ofInputStream(() -> new java.io.ByteArrayInputStream(payload)))
                .build());
        assertEquals(200, response.statusCode());
        assertEquals(echoedHeader(response.body(), "transfer-encoding"), java.util.List.of("chunked"));
        assertEquals(new String(payload, StandardCharsets.ISO_8859_1), echoedBody(response.body()));
    }

    @Test
    void largeChunkedResponseStreamsIntact() throws Exception {
        HttpResponse<byte[]> response = client(proxy).send(
                HttpRequest.newBuilder(URI.create(url(origin, "/big"))).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, response.statusCode());
        assertTrue(Arrays.equals(bigPayload(), response.body()));
    }

    @Test
    void keepAliveReusesClientAndServerConnections() {
        HttpClient client = client(proxy);
        for (int i = 0; i < 5; i++) {
            assertEquals(200, get(client, url(origin, "/k" + i)).statusCode());
        }
        assertEquals(1, clientConnections.get());
        assertEquals(1, serverConnections.get());
    }

    @Test
    void headAndNoContentResponsesHaveNoBody() {
        HttpClient client = client(proxy);
        HttpResponse<String> head = send(client, HttpRequest.newBuilder(URI.create(url(origin, "/h")))
                .method("HEAD", HttpRequest.BodyPublishers.noBody()).build());
        assertEquals(200, head.statusCode());
        assertEquals("", head.body());
        HttpResponse<String> noContent = get(client, url(origin, "/nocontent"));
        assertEquals(204, noContent.statusCode());
        // The connection must still be usable afterwards.
        assertEquals(200, get(client, url(origin, "/after")).statusCode());
    }

    @Test
    void unknownHostGivesBadGateway() {
        HttpResponse<String> response = get(client(proxy), "http://no-such-host.invalid/");
        assertEquals(502, response.statusCode());
        assertTrue(response.body().contains("Bad Gateway"));
    }

    @Test
    void refusedConnectionGivesBadGateway() throws Exception {
        int port = closedPort();
        assertEquals(502, get(client(proxy), "http://127.0.0.1:" + port + "/").statusCode());
    }

    @Test
    void manyConcurrentClientsAreServedByVirtualThreads() throws Exception {
        origin.createContext("/slow", exchange -> {
            try {
                Thread.sleep(300);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            TestSupport.fixed(200, "ok").handle(exchange);
        });
        int clients = 300;
        HttpClient client = client(proxy);
        long start = System.nanoTime();
        var futures = new java.util.ArrayList<java.util.concurrent.CompletableFuture<HttpResponse<String>>>();
        for (int i = 0; i < clients; i++) {
            futures.add(client.sendAsync(HttpRequest.newBuilder(URI.create(url(origin, "/slow"))).build(),
                    HttpResponse.BodyHandlers.ofString()));
        }
        for (var f : futures) {
            assertEquals(200, f.get().statusCode());
        }
        Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
        // Serially this would take 90 s; with a thread per connection it takes a fraction of that.
        assertTrue(elapsed.toSeconds() < 20, "took " + elapsed);
        assertFalse(clientConnections.get() < 2, "expected parallel client connections");
    }
}
