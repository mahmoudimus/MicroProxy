package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.send;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.impl.BootstrapView;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/** Removing tracing (and other) headers from requests sent upstream. */
class StrippedRequestHeadersTest {

    /** Every tracing header, in mixed case, with the values a client might send. */
    private static final List<String> TRACING = List.of(
            "TraceParent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "tracestate", "vendor=opaque",
            "Baggage", "user.id=alice",
            "b3", "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1",
            "X-B3-TraceId", "80f198ee56343ba864fe8b2a57d3eff7",
            "X-B3-SpanId", "e457b5a2e4d86bd1",
            "X-B3-ParentSpanId", "05e3ac9a4f6e3b90",
            "X-B3-Sampled", "1",
            "X-B3-Flags", "1",
            "Uber-Trace-Id", "1:2:0:1",
            "X-Amzn-Trace-Id", "Root=1-5759e988-bd862e3fe1be46a994272793",
            "X-Cloud-Trace-Context", "105445aa7843bc8bf206b12000100000/1;o=1",
            "grpc-trace-bin", "AAAA",
            "sentry-trace", "771a43a4192642f0b136d5159a501700-ab12",
            "X-Request-Id", "req-1",
            "X-Keep", "yes");

    private static HttpServer origin;
    private HttpProxyServer proxy;
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();

    @BeforeAll
    static void startOrigin() {
        origin = TestSupport.origin(echo());
    }

    @AfterAll
    static void stopOrigin() {
        origin.stop(0);
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        proxies.close();
    }

    private static String fetch(HttpClient client, String url) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(20));
        for (int i = 0; i < TRACING.size(); i += 2) b.header(TRACING.get(i), TRACING.get(i + 1));
        var response = send(client, b.build());
        assertEquals(200, response.statusCode(), response.body());
        return response.body();
    }

    private static void assertNoTracingHeaders(String echoed) {
        for (String name : HttpHeaderNames.TRACING_HEADERS) {
            assertEquals(List.of(), echoedHeader(echoed, name), name + " reached the server");
        }
        assertEquals(List.of("yes"), echoedHeader(echoed, "X-Keep"));
    }

    @Test
    void tracingHeadersPassUnlessAsked() {
        proxy = MicroProxy.bootstrap().withPort(0).start();
        String echoed = fetch(client(proxy), TestSupport.url(origin, "/"));
        assertEquals(List.of("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
                echoedHeader(echoed, "traceparent"));
        assertEquals(List.of("req-1"), echoedHeader(echoed, "X-Request-Id"));
    }

    @Test
    void tracingHeadersAreRemovedButRequestIdsKept() {
        proxy = MicroProxy.bootstrap().withPort(0).withoutTracingHeadersUpstream().start();
        String echoed = fetch(client(proxy), TestSupport.url(origin, "/"));
        assertNoTracingHeaders(echoed);
        assertEquals(List.of("req-1"), echoedHeader(echoed, "X-Request-Id"), "X-Request-Id is not a tracing header");
    }

    @Test
    void headersFiltersAddAreRemovedTooAndMoreNamesCanBeAdded() {
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(HttpFilters.builder()
                        .beforeSending(request -> {
                            request.headers().set("traceparent", "00-added-by-a-filter-01");
                            request.headers().set("X-Internal", "secret");
                            return null;
                        })
                        .build())
                .withoutTracingHeadersUpstream()
                .plusStrippedRequestHeaders("x-request-id", "X-Internal")
                .start();
        String echoed = fetch(client(proxy), TestSupport.url(origin, "/"));
        assertNoTracingHeaders(echoed);
        assertEquals(List.of(), echoedHeader(echoed, "X-Request-Id"));
        assertEquals(List.of(), echoedHeader(echoed, "X-Internal"));
    }

    @Test
    void interceptedRequestsAreStripped() {
        CertificateAuthority originCa = CertificateAuthority.generate("Strip Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Strip Proxy CA");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), echo());
        try {
            proxy = MicroProxy.bootstrap().withPort(0).withoutTracingHeadersUpstream()
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext())).start();
            assertNoTracingHeaders(fetch(client(proxy, proxyCa.clientContext()), TestSupport.url(secure, "/")));
        } finally {
            secure.stop(0);
        }
    }

    @Test
    void connectRequestsToAChainedProxyAreStripped() throws Exception {
        List<String> connectHeaders = new CopyOnWriteArrayList<>();
        HttpProxyServer upstream = proxies.start(MicroProxy.bootstrap().plusActivityTracker(new ActivityTrackerAdapter() {
            @Override
            public void requestReceivedFromClient(FlowContext flowContext, org.microproxy.http.HttpRequest request) {
                request.headers().forEach(e -> connectHeaders.add(e.getKey().toLowerCase(Locale.ROOT)));
            }
        }));
        proxy = MicroProxy.bootstrap().withPort(0).withoutTracingHeadersUpstream()
                .withChainProxyManager(ChainTestSupport.always(ChainTestSupport.http(upstream.getListenAddress())))
                .start();
        String target = "127.0.0.1:" + origin.getAddress().getPort();
        try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
            StringBuilder head = new StringBuilder("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n");
            for (int i = 0; i < TRACING.size(); i += 2) head.append(TRACING.get(i)).append(": ").append(TRACING.get(i + 1)).append("\r\n");
            TestSupport.write(s.getOutputStream(), head.append("\r\n").toString());
            assertEquals(200, ChainTestSupport.status(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n")));
        }
        assertTrue(connectHeaders.contains("x-keep"), connectHeaders.toString());
        for (String name : HttpHeaderNames.TRACING_HEADERS) {
            assertFalse(connectHeaders.contains(name.toLowerCase(Locale.ROOT)), name + " reached the chained proxy");
        }
    }

    @Test
    void configurationFromPropertiesAndTheCommandLine() throws Exception {
        HttpProxyServerBootstrap b = MicroProxy.bootstrap().withStrippedRequestHeaders("A", "b", "a", " ");
        assertEquals(List.of("A", "b"), BootstrapView.strippedRequestHeaders(b), "no duplicates, case-insensitively");
        b.withStrippedRequestHeaders();
        assertEquals(List.of(), BootstrapView.strippedRequestHeaders(b));
        assertThrows(IllegalArgumentException.class, () -> MicroProxy.bootstrap().withStrippedRequestHeaders("bad name"));

        java.nio.file.Path props = java.nio.file.Files.createTempFile("strip", ".properties");
        try {
            java.nio.file.Files.writeString(props, "strip_tracing_headers=true\nstrip_request_headers=X-Request-Id, X-Other\n");
            List<String> fromFile = BootstrapView.strippedRequestHeaders(MicroProxy.bootstrapFromFile(props));
            assertTrue(fromFile.containsAll(HttpHeaderNames.TRACING_HEADERS));
            assertTrue(fromFile.containsAll(List.of("X-Request-Id", "X-Other")));
        } finally {
            java.nio.file.Files.delete(props);
        }
        Launcher.Parsed parsed = Launcher.parse(new String[] {"--strip-tracing-headers", "--strip-request-headers", "X-A,X-B"},
                new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
        List<String> fromFlags = BootstrapView.strippedRequestHeaders(parsed.bootstrap());
        assertEquals(HttpHeaderNames.TRACING_HEADERS.size() + 2, fromFlags.size());
        assertTrue(fromFlags.containsAll(List.of("X-A", "X-B", "traceparent")));
    }
}
