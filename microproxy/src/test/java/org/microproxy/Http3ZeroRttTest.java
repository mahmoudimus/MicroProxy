package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.quic.connection.SessionCache;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * Session resumption and 0-RTT through the proxy. Upstream, the proxy resumes its QUIC sessions
 * with an HTTP/3 server and sends requests that are safe to replay as 0-RTT data, others after the
 * handshake, and sends again after the handshake a request the server answers {@code 425 Too
 * Early}. As a reverse proxy serving HTTP/3 with 0-RTT on, it resumes its clients' sessions, sends a
 * request that arrived as early data on with {@code Early-Data: 1}, answers {@code 425} to an
 * unsafe one, and lets a filter answer {@code 425} to others. A relay delays every answer so that
 * the 0-RTT data surely goes before the handshake completes.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class Http3ZeroRttTest {

    private static final long DELAY_MILLIS = 150;

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private HttpProxyServer proxy;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("H3 0-RTT Origin CA");
        proxyCa = CertificateAuthority.generate("H3 0-RTT Proxy CA");
    }

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    private UdpDelayRelay relay(InetSocketAddress target) throws Exception {
        UdpDelayRelay relay = new UdpDelayRelay(0, target, DELAY_MILLIS);
        closeables.add(relay);
        return relay;
    }

    // ---------------------------------------------------------------------------------------
    // Upstream

    @Test
    void upstreamResumesAndSendsSafeRequestsAsZeroRtt() throws Exception {
        H3TestOrigin origin = new H3TestOrigin(originCa, 0, true);
        closeables.add(origin);
        InetSocketAddress originAddress = new InetSocketAddress(TestSupport.LOOPBACK, origin.port());
        // Each relay is another port of origin.test, so another QUIC connection to the same server,
        // which resumes the session of the first with the ticket the proxy keeps for origin.test.
        // A TCP server on each port takes the client's CONNECT; the requests go over HTTP/3.
        List<UdpDelayRelay> ports = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            HttpsServer tcp = TestSupport.httpsOrigin(originCa.serverContext("origin.test"), TestSupport.fixed(200, "over tcp"));
            closeables.add(() -> tcp.stop(0));
            UdpDelayRelay relay = new UdpDelayRelay(tcp.getAddress().getPort(), originAddress, DELAY_MILLIS);
            closeables.add(relay);
            ports.add(relay);
        }
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withServerResolver((host, port) -> {
                    if (host.equals("origin.test")) return new InetSocketAddress(TestSupport.LOOPBACK, port);
                    throw new UnknownHostException(host);
                })
                .withHttp3Upstream(true)
                .withHttp3UpstreamHosts("^origin\\.test:")
                .start();
        HttpClient client = TestSupport.client(proxy, proxyCa.clientContext());

        HttpResponse<String> first = get(client, ports.get(0), "/hello");
        assertEquals(200, first.statusCode());
        assertEquals("h3", first.headers().firstValue("x-origin-protocol").orElse(null));
        assertEquals(0, origin.resumed.get());

        HttpResponse<String> early = get(client, ports.get(1), "/echo");
        assertEquals(200, early.statusCode());
        assertEquals(2, origin.connections.get());
        assertEquals(1, origin.resumed.get(), "the second connection resumed the first one's session");
        assertEquals(List.of("GET /echo"), origin.earlyRequestLines(), "the GET went as 0-RTT data");
        assertEquals(List.of(), TestSupport.echoedHeader(early.body(), "early-data"),
                "the proxy chose 0-RTT itself: no Early-Data field, which marks a client's early data");

        HttpResponse<String> post = TestSupport.send(client, HttpRequest.newBuilder(url(ports.get(2), "/echo"))
                .POST(HttpRequest.BodyPublishers.ofString("not safe to replay")).build());
        assertEquals(200, post.statusCode());
        assertEquals("not safe to replay", TestSupport.echoedBody(post.body()));
        assertEquals(2, origin.resumed.get());
        assertEquals(List.of("GET /echo"), origin.earlyRequestLines(), "the POST waited for the handshake");

        HttpResponse<String> tooEarly = get(client, ports.get(3), "/too-early");
        assertEquals(200, tooEarly.statusCode(), "the 425 was the proxy's to handle");
        assertEquals("after the handshake", tooEarly.body());
        assertEquals(List.of("GET /echo", "GET /too-early"), origin.earlyRequestLines());
        assertEquals(2, origin.requestLines().stream().filter(l -> l.equals("GET /too-early")).count(),
                "sent again after the handshake");
        assertTrue(origin.errors().isEmpty(), origin.errors().toString());
    }

    private static URI url(UdpDelayRelay port, String path) {
        return URI.create("https://origin.test:" + port.port() + path);
    }

    private static HttpResponse<String> get(HttpClient client, UdpDelayRelay port, String path) throws Exception {
        return TestSupport.send(client, HttpRequest.newBuilder(url(port, path)).build());
    }

    // ---------------------------------------------------------------------------------------
    // Serving HTTP/3

    @Test
    void reverseProxyTakesEarlyDataAndMarksIt() throws Exception {
        HttpServer backend = TestSupport.origin(TestSupport.echo());
        closeables.add(() -> backend.stop(0));
        SelfSignedSslContextSource tls = new SelfSignedSslContextSource();
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withReverseProxy("http://127.0.0.1:" + backend.getAddress().getPort())
                .withSslContextSource(tls)
                .withHttp3(true)
                .withHttp3Options(Http3Options.builder().zeroRtt(true).build())
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(org.microproxy.http.HttpRequest request, FlowContext flow) {
                        return new HttpFiltersAdapter(request, flow) {
                            @Override
                            public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject object) {
                                if (flow.isEarlyData() && request.uri().startsWith("/veto")) {
                                    return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(425));
                                }
                                return null;
                            }
                        };
                    }
                })
                .start();
        UdpDelayRelay relay = relay(new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort()));
        SessionCache sessions = SessionCache.memory();

        try (H3TestClient first = H3TestClient.connect(relay.address(), "localhost", tls.getCertificate(),
                options(sessions, false))) {
            H3TestClient.Response r = first.get("/first");
            assertEquals(200, r.status());
            assertEquals(List.of(), TestSupport.echoedHeader(r.text(), "early-data"));
            assertFalse(first.quic.isResumed());
        }

        try (H3TestClient early = H3TestClient.connect(relay.address(), "localhost", tls.getCertificate(),
                options(sessions, true))) {
            assertTrue(early.quic.isZeroRtt(), "connected without waiting for the handshake");
            H3TestClient.Response r = early.get("/early");
            assertEquals(200, r.status());
            assertEquals(List.of("1"), TestSupport.echoedHeader(r.text(), "early-data"), "RFC 8470: Early-Data: 1");
            assertTrue(early.quic.awaitHandshake(java.time.Duration.ofSeconds(10)));
            assertTrue(early.quic.isResumed());
            assertTrue(early.quic.earlyDataAccepted());
            H3TestClient.Response later = early.get("/later");
            assertEquals(List.of(), TestSupport.echoedHeader(later.text(), "early-data"), "after the handshake");
        }

        try (H3TestClient unsafe = H3TestClient.connect(relay.address(), "localhost", tls.getCertificate(),
                options(sessions, true))) {
            H3TestClient.Response r = unsafe.post("/echo", "not safe to replay".getBytes(StandardCharsets.UTF_8));
            assertEquals(425, r.status(), "a POST in 0-RTT data is too early");
            assertTrue(unsafe.quic.earlyDataAccepted());
            assertTrue(unsafe.quic.awaitHandshake(java.time.Duration.ofSeconds(10)));
            H3TestClient.Response again = unsafe.post("/echo", "not safe to replay".getBytes(StandardCharsets.UTF_8));
            assertEquals(200, again.status(), "sent again after the handshake");
            assertEquals("not safe to replay", TestSupport.echoedBody(again.text()));
        }

        try (H3TestClient vetoed = H3TestClient.connect(relay.address(), "localhost", tls.getCertificate(),
                options(sessions, true))) {
            H3TestClient.Response r = vetoed.get("/veto");
            assertEquals(425, r.status(), "a filter found it unsafe to replay");
        }
    }

    @Test
    void earlyDataFromAClientReachesAnHttp3OriginMarked() throws Exception {
        H3TestOrigin origin = new H3TestOrigin(originCa, 0, true);
        closeables.add(origin);
        SelfSignedSslContextSource tls = new SelfSignedSslContextSource();
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withReverseProxy("https://origin.test:" + origin.port())
                .withSslContextSource(tls)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withServerResolver((host, port) -> {
                    if (host.equals("origin.test")) return new InetSocketAddress(TestSupport.LOOPBACK, port);
                    throw new UnknownHostException(host);
                })
                .withHttp3(true)
                .withHttp3Options(Http3Options.builder().zeroRtt(true).build())
                .withHttp3Upstream(true)
                .withHttp3UpstreamHosts("^origin\\.test:")
                .start();
        UdpDelayRelay relay = relay(new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort()));
        SessionCache sessions = SessionCache.memory();
        try (H3TestClient first = H3TestClient.connect(relay.address(), "localhost", tls.getCertificate(),
                options(sessions, false))) {
            assertEquals("h3", first.get("/hello").header("x-origin-protocol"));
        }
        try (H3TestClient early = H3TestClient.connect(relay.address(), "localhost", tls.getCertificate(),
                options(sessions, true))) {
            H3TestClient.Response r = early.get("/echo");
            assertEquals(200, r.status());
            assertEquals("h3", r.header("x-origin-protocol"));
            assertEquals(List.of("1"), TestSupport.echoedHeader(r.text(), "early-data"),
                    "the client's early data reached the HTTP/3 origin marked");
            assertTrue(early.quic.earlyDataAccepted());
        }
        assertTrue(origin.errors().isEmpty(), origin.errors().toString());
    }

    private static H3TestClient.Options options(SessionCache sessions, boolean earlyData) {
        H3TestClient.Options options = new H3TestClient.Options();
        options.sessions = sessions;
        options.earlyData = earlyData;
        return options;
    }
}
