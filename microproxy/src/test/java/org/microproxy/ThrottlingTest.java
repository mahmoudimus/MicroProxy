package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;

import com.sun.net.httpserver.HttpServer;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class ThrottlingTest {

    @Test
    void readThrottleLimitsDownloadRate() throws Exception {
        byte[] payload = new byte[300_000];
        HttpServer origin = TestSupport.origin(exchange -> {
            exchange.sendResponseHeaders(200, payload.length);
            exchange.getResponseBody().write(payload);
            exchange.close();
        });
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).withThrottling(100_000, 0).start();
        try {
            var client = client(proxy);
            HttpRequest request = HttpRequest.newBuilder(URI.create(TestSupport.url(origin, "/"))).build();
            long start = System.nanoTime();
            HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
            Duration throttled = Duration.ofNanos(System.nanoTime() - start);
            assertEquals(payload.length, response.body().length);
            assertTrue(throttled.toMillis() >= 2000, "300 KB at 100 KB/s took only " + throttled);

            proxy.setThrottle(0, 0);
            start = System.nanoTime();
            client.send(request, HttpResponse.BodyHandlers.ofByteArray());
            Duration unthrottled = Duration.ofNanos(System.nanoTime() - start);
            assertTrue(unthrottled.toMillis() < 1500, "unthrottled took " + unthrottled);
        } finally {
            proxy.abort();
            origin.stop(0);
        }
    }
}
