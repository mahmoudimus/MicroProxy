package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;

import java.io.InputStream;
import java.net.Socket;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpRequest;

class TimeoutTest {

    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    @Test
    void silentServerGivesGatewayTimeout() throws Exception {
        AtomicBoolean timedOut = new AtomicBoolean();
        proxy = MicroProxy.bootstrap().withPort(0).withIdleConnectionTimeout(Duration.ofMillis(500))
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(HttpRequest req, FlowContext ctx) {
                        return new HttpFilters() {
                            @Override
                            public void serverToProxyResponseTimedOut() {
                                timedOut.set(true);
                            }
                        };
                    }
                }).start();
        try (TestSupport.RawServer silent = TestSupport.rawServer(s -> {
            TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            Thread.sleep(5000);
        })) {
            long start = System.nanoTime();
            var response = get(client(proxy), "http://127.0.0.1:" + silent.port() + "/");
            assertEquals(504, response.statusCode());
            assertTrue(timedOut.get());
            assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() < 4000);
        }
    }

    @Test
    void idleClientConnectionsAreClosed() throws Exception {
        AtomicInteger timeouts = new AtomicInteger();
        proxy = MicroProxy.bootstrap().withPort(0).withIdleConnectionTimeout(Duration.ofMillis(300))
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void connectionTimedOut(FlowContext ctx) {
                        timeouts.incrementAndGet();
                    }
                }).start();
        try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(5000);
            InputStream in = s.getInputStream();
            assertEquals(-1, in.read(), "proxy should close the idle connection");
        }
        assertEquals(1, timeouts.get());
    }

    @Test
    void connectTimeoutIsApplied() {
        // 10.255.255.1 is non-routable: connecting hangs until the timeout.
        proxy = MicroProxy.bootstrap().withPort(0).withConnectTimeout(300).start();
        long start = System.nanoTime();
        var response = get(client(proxy), "http://10.255.255.1:81/");
        assertEquals(502, response.statusCode());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() < 5000);
    }
}
