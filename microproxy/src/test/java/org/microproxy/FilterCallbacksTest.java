package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Which {@link HttpFilters} callbacks run, and in which order, when connecting to the server
 * succeeds or fails (ported from LittleProxy's {@code HttpFilterTest} and {@code
 * HttpStreamingFilterTest}).
 *
 * <p>One deliberate difference from LittleProxy: MicroProxy calls {@link
 * HttpFilters#proxyToServerRequest} with the request head before it resolves and connects to the
 * server (so a filter can still short-circuit without a connection), where LittleProxy resolves
 * first. The tests below assert MicroProxy's order.
 */
class FilterCallbacksTest {

    private static final List<String> SERVER_EXCHANGE = List.of("proxyToServerRequestSending",
            "proxyToServerRequestSent", "serverToProxyResponseReceiving", "serverToProxyResponse:head",
            "serverToProxyResponseReceived", "serverToProxyResponseTimedOut");

    private HttpServer origin;
    private HttpProxyServer proxy;
    private HttpProxyServer upstream;

    @BeforeEach
    void setUp() {
        origin = origin(echo());
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (upstream != null) upstream.abort();
        origin.stop(0);
    }

    private static int closedPort() throws Exception {
        try (ServerSocket s = new ServerSocket(0, 1, TestSupport.LOOPBACK)) {
            return s.getLocalPort();
        }
    }

    private static void assertNone(List<String> events, List<String> unexpected) {
        for (String e : unexpected) {
            assertFalse(events.contains(e), e + " should not have been called: " + events);
        }
    }

    private static void assertInOrder(List<String> events, String... expected) {
        int last = -1;
        for (String e : expected) {
            int i = events.indexOf(e);
            assertTrue(i > last, e + " missing or out of order in " + events);
            last = i;
        }
    }

    @Test
    void successfulRequestRunsTheConnectionHooksInOrder() {
        RecordingFilters filters = new RecordingFilters();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(RecordingFilters.sourceOf(filters)).start();
        assertEquals(200, get(client(proxy), url(origin, "/ok")).statusCode());
        assertInOrder(filters.events, "clientToProxyRequest:head", "proxyToServerRequest:head",
                "proxyToServerResolutionStarted", "proxyToServerResolutionSucceeded",
                "proxyToServerConnectionStarted", "proxyToServerConnectionSucceeded",
                "proxyToServerRequestSending", "proxyToServerRequestSent", "serverToProxyResponseReceiving",
                "serverToProxyResponse:head", "proxyToClientResponse:head");
        assertNone(filters.events, List.of("proxyToServerResolutionFailed", "proxyToServerConnectionFailed",
                "proxyToServerConnectionSSLHandshakeStarted", "serverToProxyResponseTimedOut",
                "proxyToServerAllowMitm"));
    }

    @Test
    void resolutionFailureCallsResolutionFailedAndNoConnectionHooks() {
        RecordingFilters filters = new RecordingFilters();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(RecordingFilters.sourceOf(filters))
                .withServerResolver((host, port) -> {
                    throw new UnknownHostException(host);
                })
                .start();
        HttpResponse<String> response = get(client(proxy), "http://www.does-not-exist/some-resource");
        assertEquals(502, response.statusCode());
        assertInOrder(filters.events, "clientToProxyRequest:head", "proxyToServerResolutionStarted",
                "proxyToServerResolutionFailed", "proxyToClientResponse:full");
        assertNone(filters.events, List.of("proxyToServerResolutionSucceeded", "proxyToServerConnectionStarted",
                "proxyToServerConnectionFailed", "proxyToServerConnectionSucceeded",
                "proxyToServerConnectionSSLHandshakeStarted", "proxyToServerAllowMitm"));
        assertNone(filters.events, SERVER_EXCHANGE);
    }

    @Test
    void refusedConnectionCallsConnectionFailed() throws Exception {
        RecordingFilters filters = new RecordingFilters();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(RecordingFilters.sourceOf(filters)).start();
        HttpResponse<String> response = get(client(proxy), "http://127.0.0.1:" + closedPort() + "/some-resource");
        assertEquals(502, response.statusCode());
        assertInOrder(filters.events, "clientToProxyRequest:head", "proxyToServerRequest:head",
                "proxyToServerResolutionStarted", "proxyToServerResolutionSucceeded",
                "proxyToServerConnectionStarted", "proxyToServerConnectionFailed", "proxyToClientResponse:full");
        assertNone(filters.events, List.of("proxyToServerResolutionFailed", "proxyToServerConnectionSucceeded",
                "proxyToServerConnectionSSLHandshakeStarted", "proxyToServerAllowMitm"));
        assertNone(filters.events, SERVER_EXCHANGE);
    }

    /** A chained proxy that records its connection callbacks into {@code events}. */
    private static ChainedProxy recordingChainedProxy(List<String> events, InetSocketAddress address,
            SSLContext tls) {
        return new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return address;
            }

            @Override
            public boolean requiresEncryption() {
                return tls != null;
            }

            @Override
            public SSLContext getSslContext() {
                return tls;
            }

            @Override
            public void connectionSucceeded() {
                events.add("chained.connectionSucceeded");
            }

            @Override
            public void connectionFailed(Throwable cause) {
                events.add("chained.connectionFailed");
            }
        };
    }

    @Test
    void unreachableChainedProxyCallsConnectionFailed() throws Exception {
        RecordingFilters filters = new RecordingFilters();
        InetSocketAddress unreachable = new InetSocketAddress(TestSupport.LOOPBACK, closedPort());
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(RecordingFilters.sourceOf(filters))
                .withChainProxyManager((request, queue, details) ->
                        queue.add(recordingChainedProxy(filters.events, unreachable, null)))
                .start();
        // The server need not exist: the connection to the chained proxy fails first.
        HttpResponse<String> response = get(client(proxy), "http://localhost:1234/some-resource");
        assertEquals(502, response.statusCode());
        assertInOrder(filters.events, "clientToProxyRequest:head", "proxyToServerRequest:head",
                "proxyToServerConnectionStarted", "chained.connectionFailed", "proxyToServerConnectionFailed",
                "proxyToClientResponse:full");
        // The chained proxy's address is not the server's: no server name resolution happens.
        assertNone(filters.events, List.of("proxyToServerResolutionStarted", "proxyToServerResolutionSucceeded",
                "proxyToServerResolutionFailed", "proxyToServerConnectionSucceeded",
                "proxyToServerConnectionSSLHandshakeStarted", "chained.connectionSucceeded",
                "proxyToServerAllowMitm"));
        assertNone(filters.events, SERVER_EXCHANGE);
    }

    @Test
    void failedTlsHandshakeWithChainedProxyCallsSslHandshakeStartedThenConnectionFailed() {
        // The upstream proxy presents a certificate from one CA; the chained proxy trusts another.
        CertificateAuthority upstreamCa = CertificateAuthority.generate("Upstream CA");
        CertificateAuthority otherCa = CertificateAuthority.generate("Other CA");
        SSLContext upstreamTls = upstreamCa.serverContext("127.0.0.1", "localhost");
        upstream = MicroProxy.bootstrap().withPort(0).withSslContextSource(() -> upstreamTls).start();

        RecordingFilters filters = new RecordingFilters();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(RecordingFilters.sourceOf(filters))
                .withChainProxyManager((request, queue, details) -> queue.add(recordingChainedProxy(
                        filters.events, upstream.getListenAddress(), otherCa.clientContext())))
                .start();
        HttpResponse<String> response = get(client(proxy), "http://localhost:1234/some-resource");
        assertEquals(502, response.statusCode());
        assertInOrder(filters.events, "clientToProxyRequest:head", "proxyToServerRequest:head",
                "proxyToServerConnectionStarted", "proxyToServerConnectionSSLHandshakeStarted",
                "chained.connectionFailed", "proxyToServerConnectionFailed", "proxyToClientResponse:full");
        assertNone(filters.events, List.of("proxyToServerResolutionStarted", "proxyToServerConnectionSucceeded",
                "chained.connectionSucceeded", "proxyToServerAllowMitm"));
        assertNone(filters.events, SERVER_EXCHANGE);
    }

    @Test
    void mitmConnectRunsTheTlsHandshakeHooksInOrder() {
        CertificateAuthority originCa = CertificateAuthority.generate("Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Proxy CA");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), echo());
        Map<String, RecordingFilters> byMethod = new ConcurrentHashMap<>();
        try {
            proxy = MicroProxy.bootstrap().withPort(0)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                    .withFiltersSource(new HttpFiltersSourceAdapter() {
                        @Override
                        public HttpFilters filterRequest(org.microproxy.http.HttpRequest req, FlowContext ctx) {
                            return byMethod.computeIfAbsent(req.method().name(), m -> new RecordingFilters());
                        }
                    })
                    .start();
            assertEquals(200, get(client(proxy, proxyCa.clientContext()), url(secure, "/mitm")).statusCode());
            List<String> connect = byMethod.get("CONNECT").events;
            assertInOrder(connect, "clientToProxyRequest:head", "proxyToServerAllowMitm", "proxyToServerRequest:head",
                    "proxyToServerResolutionStarted", "proxyToServerResolutionSucceeded",
                    "proxyToServerConnectionStarted", "proxyToServerConnectionSSLHandshakeStarted",
                    "proxyToServerConnectionSucceeded", "serverToProxyResponse:full", "proxyToClientResponse:full");
            assertNone(connect, List.of("proxyToServerConnectionFailed", "proxyToServerResolutionFailed"));
            // The decrypted GET goes out on the connection the CONNECT opened.
            List<String> getEvents = byMethod.get("GET").events;
            assertInOrder(getEvents, "clientToProxyRequest:head", "proxyToServerRequest:head",
                    "proxyToServerRequestSending", "proxyToServerRequestSent", "serverToProxyResponse:head",
                    "proxyToClientResponse:head");
            assertNone(getEvents, List.of("proxyToServerConnectionStarted", "proxyToServerAllowMitm"));
        } finally {
            secure.stop(0);
        }
    }

    @Test
    void serverTimeoutCallsTimedOutButNoResponseHooks() throws Exception {
        RecordingFilters filters = new RecordingFilters();
        proxy = MicroProxy.bootstrap().withPort(0).withIdleConnectionTimeout(Duration.ofMillis(500))
                .withFiltersSource(RecordingFilters.sourceOf(filters)).start();
        try (TestSupport.RawServer silent = TestSupport.rawServer(s -> {
            TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            Thread.sleep(5000);
        })) {
            assertEquals(504, get(client(proxy), "http://127.0.0.1:" + silent.port() + "/").statusCode());
        }
        assertInOrder(filters.events, "clientToProxyRequest:head", "proxyToServerRequest:head",
                "proxyToServerResolutionStarted", "proxyToServerResolutionSucceeded",
                "proxyToServerConnectionStarted", "proxyToServerConnectionSucceeded",
                "proxyToServerRequestSending", "proxyToServerRequestSent", "serverToProxyResponseTimedOut",
                "proxyToClientResponse:full");
        assertNone(filters.events, List.of("serverToProxyResponseReceiving", "serverToProxyResponse:head",
                "serverToProxyResponseReceived", "proxyToServerConnectionFailed", "proxyToServerResolutionFailed"));
    }

    // -------------------------------------------------------------------------------------------
    // proxyToServerResolutionStarted returning an address
    // -------------------------------------------------------------------------------------------

    @Test
    void unresolvedAddressFromResolutionStartedIsResolved() {
        AtomicReference<InetSocketAddress> resolved = new AtomicReference<>();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(RecordingFilters.sourceOf(new HttpFilters() {
            @Override
            public InetSocketAddress proxyToServerResolutionStarted(String hostAndPort) {
                return InetSocketAddress.createUnresolved("localhost", origin.getAddress().getPort());
            }

            @Override
            public void proxyToServerResolutionSucceeded(String hostAndPort, InetSocketAddress address) {
                resolved.set(address);
            }
        })).start();
        HttpResponse<String> response = get(client(proxy), "http://rewritten.invalid/x");
        assertEquals(200, response.statusCode());
        assertFalse(resolved.get().isUnresolved(), "expected a resolved address, got " + resolved.get());
        assertEquals(origin.getAddress().getPort(), resolved.get().getPort());
    }

    @Test
    void unresolvedAddressFromResolutionStartedUsesTheServerResolver() {
        List<String> lookups = new CopyOnWriteArrayList<>();
        RecordingFilters filters = new RecordingFilters() {
            @Override
            public InetSocketAddress proxyToServerResolutionStarted(String hostAndPort) {
                super.proxyToServerResolutionStarted(hostAndPort);
                String host = hostAndPort.startsWith("good.") ? "origin.test" : "nowhere.test";
                return InetSocketAddress.createUnresolved(host, origin.getAddress().getPort());
            }
        };
        // The configured resolver (e.g. a DNSSEC one) must be the one that resolves the name.
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(RecordingFilters.sourceOf(filters))
                .withServerResolver((host, port) -> {
                    lookups.add(host + ":" + port);
                    if (!host.equals("origin.test")) throw new UnknownHostException(host);
                    return new InetSocketAddress(TestSupport.LOOPBACK, port);
                })
                .start();
        int port = origin.getAddress().getPort();
        assertEquals(200, get(client(proxy), "http://good.invalid/x").statusCode());
        assertEquals(List.of("origin.test:" + port), lookups);
        assertTrue(filters.saw("proxyToServerResolutionSucceeded"));

        filters.events.clear();
        assertEquals(502, get(client(proxy), "http://bad.invalid/x").statusCode());
        assertEquals(List.of("origin.test:" + port, "nowhere.test:" + port), lookups);
        assertTrue(filters.saw("proxyToServerResolutionFailed"), filters.events.toString());
        assertNone(filters.events, List.of("proxyToServerResolutionSucceeded", "proxyToServerConnectionStarted",
                "proxyToServerConnectionFailed"));
    }

    // -------------------------------------------------------------------------------------------
    // Request bodies
    // -------------------------------------------------------------------------------------------

    @Test
    void streamedRequestBodyReachesFiltersAsHeadThenChunksThenLast() {
        RecordingFilters filters = new RecordingFilters();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(RecordingFilters.sourceOf(filters)).start();
        byte[] body = new byte[20_000];
        Arrays.fill(body, (byte) 'x');
        HttpResponse<String> response = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/up")))
                .POST(HttpRequest.BodyPublishers.ofInputStream(() -> new java.io.ByteArrayInputStream(body)))
                .build());
        assertEquals(200, response.statusCode());
        assertEquals(20_000, echoedBody(response.body()).length());

        List<String> c2p = filters.events.stream().filter(e -> e.startsWith("clientToProxyRequest:")).toList();
        assertEquals("clientToProxyRequest:head", c2p.get(0));
        assertEquals("clientToProxyRequest:last", c2p.get(c2p.size() - 1));
        assertEquals(1, c2p.stream().filter(e -> e.endsWith(":head")).count());
        assertEquals(1, c2p.stream().filter(e -> e.endsWith(":last")).count());
        assertTrue(c2p.contains("clientToProxyRequest:content"), "expected body chunks: " + c2p);
        assertEquals(c2p.size(), filters.events.stream().filter(e -> e.startsWith("proxyToServerRequest:")).count(),
                "both request hooks see every piece");
        // The request counts as sent only once its last piece is written.
        assertInOrder(filters.events, "proxyToServerRequestSending", "proxyToServerRequest:last",
                "proxyToServerRequestSent", "serverToProxyResponseReceiving");
    }

    @Test
    void bodilessRequestStillEndsWithLastContent() {
        RecordingFilters filters = new RecordingFilters();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(RecordingFilters.sourceOf(filters)).start();
        assertEquals(200, get(client(proxy), url(origin, "/get")).statusCode());
        assertInOrder(filters.events, "clientToProxyRequest:head", "proxyToServerRequest:head",
                "proxyToServerRequestSending", "clientToProxyRequest:last", "proxyToServerRequest:last",
                "proxyToServerRequestSent");
        assertEquals(1, filters.events.stream().filter(e -> e.equals("proxyToServerRequest:last")).count());
        assertFalse(filters.saw("proxyToServerRequest:content"));
    }
}
