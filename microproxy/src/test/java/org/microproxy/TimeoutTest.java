package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpRequest;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

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
    void connectTimeoutGivesBadGateway() throws Exception {
        // A listening socket whose accept queue is full leaves new connection attempts hanging
        // (on Linux the SYN is dropped), which makes the connect timeout observable.
        try (ServerSocket full = new ServerSocket(0, 1, TestSupport.LOOPBACK)) {
            List<Socket> fillers = new ArrayList<>();
            boolean saturated = false;
            try {
                for (int i = 0; i < 16 && !saturated; i++) {
                    Socket s = new Socket();
                    try {
                        s.connect(full.getLocalSocketAddress(), 200);
                        fillers.add(s);
                    } catch (SocketTimeoutException e) {
                        s.close();
                        saturated = true;
                    }
                }
                assumeTrue(saturated, "connections to a full backlog do not hang on this OS");

                proxy = MicroProxy.bootstrap().withPort(0).withConnectTimeout(300).start();
                long start = System.nanoTime();
                var response = get(client(proxy), "http://127.0.0.1:" + full.getLocalPort() + "/");
                long took = Duration.ofNanos(System.nanoTime() - start).toMillis();
                assertEquals(502, response.statusCode());
                assertTrue(took >= 250, "gave up after only " + took + " ms");
                assertTrue(took < 3000, "took " + took + " ms");
            } finally {
                for (Socket s : fillers) s.close();
            }
        }
    }

    @Test
    void idleClientIsClosedAfterACompletedExchange() throws Exception {
        // LittleProxy's ClientToProxyTimeoutBugTest: a client whose server connection is still open
        // (kept alive after the response) must still be timed out when it goes quiet.
        CountDownLatch serverSawClose = new CountDownLatch(1);
        AtomicInteger timeouts = new AtomicInteger();
        try (TestSupport.RawServer keepAlive = TestSupport.rawServer(socket -> {
            InputStream in = socket.getInputStream();
            while (!TestSupport.readUntil(in, "\r\n\r\n").isEmpty()) {
                TestSupport.write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
            serverSawClose.countDown();
        })) {
            proxy = MicroProxy.bootstrap().withPort(0).withIdleConnectionTimeout(Duration.ofMillis(300))
                    .plusActivityTracker(new ActivityTrackerAdapter() {
                        @Override
                        public void connectionTimedOut(FlowContext ctx) {
                            timeouts.incrementAndGet();
                        }
                    }).start();
            try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
                s.setSoTimeout(5000);
                TestSupport.write(s.getOutputStream(),
                        "GET http://127.0.0.1:" + keepAlive.port() + "/ HTTP/1.1\r\nHost: x\r\n\r\n");
                InputStream in = s.getInputStream();
                assertTrue(TestSupport.readUntil(in, "\r\n\r\n").startsWith("HTTP/1.1 200"));
                assertEquals("ok", new String(in.readNBytes(2), StandardCharsets.US_ASCII));
                long start = System.nanoTime();
                assertEquals(-1, in.read(), "the idle client connection is closed");
                long took = Duration.ofNanos(System.nanoTime() - start).toMillis();
                assertTrue(took >= 150 && took < 3000, "closed after " + took + " ms");
            }
            assertTrue(serverSawClose.await(3, TimeUnit.SECONDS), "its server connection is closed too");
            for (int i = 0; i < 100 && timeouts.get() == 0; i++) Thread.sleep(10);
            assertEquals(1, timeouts.get());
        }
    }

    @Test
    void incompleteRequestIsDroppedAfterTheIdleTimeout() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withIdleConnectionTimeout(Duration.ofMillis(300)).start();
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            s.setSoTimeout(3000);
            // No line end: the request never completes.
            TestSupport.write(s.getOutputStream(), "GET http://127.0.0.1:1/ HTTP/1.1");
            long start = System.nanoTime();
            String reply = new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
            assertFalse(reply.startsWith("HTTP/1.1 200"), reply);
            assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() < 3000);
        }
    }

    @Test
    void stalledResponseBodyIsCutOff() throws Exception {
        try (TestSupport.RawServer stalling = TestSupport.rawServer(s -> {
            TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            TestSupport.write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc");
            Thread.sleep(5000);
        })) {
            proxy = MicroProxy.bootstrap().withPort(0).withIdleConnectionTimeout(Duration.ofMillis(300)).start();
            long start = System.nanoTime();
            assertThrows(UncheckedIOException.class, () -> get(client(proxy), "http://127.0.0.1:" + stalling.port() + "/"),
                    "a truncated body is not passed off as complete");
            assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() < 3000);
        }
    }

    @Test
    void silentServerBehindMitmGivesGatewayTimeout() throws Exception {
        // LittleProxy's IdlingProxyTest, for an intercepted HTTPS request.
        CertificateAuthority originCa = CertificateAuthority.generate("Silent Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Silent Proxy CA");
        HttpsServer silent = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), exchange -> {
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exchange.close();
        });
        try {
            proxy = MicroProxy.bootstrap().withPort(0).withIdleConnectionTimeout(Duration.ofMillis(500))
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext())).start();
            long start = System.nanoTime();
            var response = get(client(proxy, proxyCa.clientContext()), TestSupport.url(silent, "/hang"));
            assertEquals(504, response.statusCode());
            assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() < 4000);
        } finally {
            silent.stop(0);
        }
    }

    @Test
    void idleTimeoutCanBeChangedAtRuntime() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).start();
        assertEquals(Duration.ofSeconds(70), proxy.getIdleConnectionTimeout());
        proxy.setIdleConnectionTimeout(Duration.ofMillis(300));
        assertEquals(Duration.ofMillis(300), proxy.getIdleConnectionTimeout());
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            s.setSoTimeout(3000);
            assertEquals(-1, s.getInputStream().read(), "new connections use the new timeout");
        }

        proxy.setIdleConnectionTimeout(null);
        assertEquals(Duration.ZERO, proxy.getIdleConnectionTimeout(), "null means no timeout");
        HttpServer origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            s.setSoTimeout(3000);
            Thread.sleep(500);
            TestSupport.write(s.getOutputStream(), "GET " + TestSupport.url(origin, "/") + " HTTP/1.1\r\nHost: x\r\n\r\n");
            assertTrue(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"),
                    "without a timeout a quiet connection stays usable");
        } finally {
            origin.stop(0);
        }
    }
}
