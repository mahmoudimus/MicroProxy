package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpResponse;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/** Per-exchange timings: which phases are recorded, and in which order. */
class FlowTimingsTest {

    private HttpServer origin;
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private final Completed completed = new Completed();

    /** Captures the timings of each completed exchange, with its request line. */
    static final class Completed extends ActivityTrackerAdapter {
        final List<String> requests = new CopyOnWriteArrayList<>();
        final List<FlowTimings> timings = new CopyOnWriteArrayList<>();
        private final List<String> pending = new CopyOnWriteArrayList<>();

        @Override
        public void requestReceivedFromClient(FlowContext ctx, org.microproxy.http.HttpRequest request) {
            pending.add(request.method() + " " + request.uri());
        }

        @Override
        public void responseCompleted(FlowContext ctx, HttpResponse response) {
            timings.add(ctx.timings());
            requests.add(pending.removeFirst());
        }

        FlowTimings await(int n) throws InterruptedException {
            for (int i = 0; i < 200 && timings.size() < n; i++) Thread.sleep(10);
            return timings.get(n - 1);
        }
    }

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(echo());
        origin.createContext("/slow", exchange -> {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            TestSupport.fixed(200, "slow").handle(exchange);
        });
    }

    @AfterEach
    void tearDown() {
        proxies.close();
        origin.stop(0);
    }

    private static void assertOrdered(long... offsets) {
        for (int i = 1; i < offsets.length; i++) {
            assertTrue(offsets[i - 1] >= 0 && offsets[i] >= offsets[i - 1],
                    "offset " + i + " out of order: " + java.util.Arrays.toString(offsets));
        }
    }

    @Test
    void directRequestRecordsEveryServerPhaseInOrder() throws Exception {
        Instant before = Instant.now().minusMillis(1);
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().plusActivityTracker(completed));
        assertEquals(200, get(client(proxy), url(origin, "/slow")).statusCode());

        FlowTimings t = completed.await(1);
        assertOrdered(0, t.dnsStartNanos(), t.dnsEndNanos(), t.connectStartNanos(), t.connectEndNanos(),
                t.requestSentNanos(), t.firstResponseByteNanos(), t.responseCompleteNanos());
        assertTrue(t.dnsLookup().isPresent());
        assertTrue(t.connect().isPresent());
        assertFalse(t.tlsHandshake().isPresent());
        assertFalse(t.clientTlsHandshake().isPresent());
        // The server took at least 100 ms to answer.
        assertTrue(t.timeToFirstByte().orElseThrow().compareTo(Duration.ofMillis(90)) >= 0, t.toString());
        assertTrue(t.total().orElseThrow().compareTo(t.timeToFirstByte().orElseThrow()) >= 0);
        Instant start = t.start().orElseThrow();
        assertFalse(start.isBefore(before));
        assertFalse(start.isAfter(Instant.now()));
    }

    @Test
    void keepAliveReuseHasNoLookupOrConnect() throws Exception {
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().plusActivityTracker(completed));
        HttpClient client = client(proxy);
        assertEquals(200, get(client, url(origin, "/one")).statusCode());
        assertEquals(200, get(client, url(origin, "/two")).statusCode());

        assertTrue(completed.await(1).connect().isPresent());
        FlowTimings second = completed.await(2);
        assertEquals(-1, second.dnsStartNanos());
        assertEquals(-1, second.connectStartNanos());
        assertFalse(second.dnsLookup().isPresent());
        assertFalse(second.connect().isPresent());
        assertOrdered(0, second.requestSentNanos(), second.firstResponseByteNanos(), second.responseCompleteNanos());
        assertTrue(second.timeToFirstByte().isPresent());
    }

    @Test
    void interceptedHttpsRecordsBothHandshakes() throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("Timing Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Timing Proxy CA");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), echo());
        try {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().plusActivityTracker(completed)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext())));
            assertEquals(200, get(client(proxy, proxyCa.clientContext()), url(secure, "/inside")).statusCode());

            // The CONNECT exchange connected to the server and shook hands with it...
            FlowTimings connect = completed.await(1);
            assertTrue(completed.requests.getFirst().startsWith("CONNECT "), completed.requests.toString());
            assertOrdered(0, connect.connectStartNanos(), connect.connectEndNanos(), connect.tlsStartNanos(),
                    connect.tlsEndNanos(), connect.responseCompleteNanos());
            assertTrue(connect.tlsHandshake().isPresent());

            // ...and the request inside the session reused that connection, over the client handshake.
            FlowTimings inside = completed.await(2);
            assertEquals("GET /inside", completed.requests.get(1));
            assertTrue(inside.clientTlsHandshake().isPresent());
            assertFalse(inside.tlsHandshake().isPresent());
            assertOrdered(0, inside.requestSentNanos(), inside.firstResponseByteNanos(), inside.responseCompleteNanos());
        } finally {
            secure.stop(0);
        }
    }

    @Test
    void proxyAnswersHaveOnlyATotal() throws Exception {
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().plusActivityTracker(completed)
                .withFiltersSource((request, ctx) -> HttpFilters.builder()
                        .onRequest(r -> new org.microproxy.http.DefaultFullHttpResponse(
                                org.microproxy.http.HttpVersion.HTTP_1_1,
                                org.microproxy.http.HttpResponseStatus.NO_CONTENT))
                        .build()));
        assertEquals(204, get(client(proxy), url(origin, "/")).statusCode());
        FlowTimings t = completed.await(1);
        assertTrue(t.total().isPresent());
        assertFalse(t.timeToFirstByte().isPresent());
        assertEquals(-1, t.requestSentNanos());
    }

    @Test
    void contextsMadeOutsideTheProxyHaveNoTimings() {
        FlowContext ctx = new FlowContext(1, () -> null, () -> null, new ClientDetails());
        assertEquals(FlowTimings.NONE, ctx.timings());
        assertEquals(FlowTimings.NONE, new FullFlowContext(ctx, "h:1", null, null).timings());
        assertFalse(FlowTimings.NONE.start().isPresent());
        assertFalse(FlowTimings.NONE.total().isPresent());
    }
}
