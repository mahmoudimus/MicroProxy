package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpsServer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

class HttpsTest {

    /** Signs the origin's certificate. */
    static CertificateAuthority originCa;
    /** The proxy's interception CA. */
    static CertificateAuthority proxyCa;

    private HttpsServer origin;
    private HttpProxyServer proxy;

    @BeforeAll
    static void createAuthorities() {
        originCa = CertificateAuthority.generate("Test Origin CA");
        proxyCa = CertificateAuthority.generate("Test Proxy CA");
    }

    @BeforeEach
    void setUp() {
        origin = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), echo());
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    @Test
    void connectTunnelsTlsEndToEnd() {
        List<String> methods = new CopyOnWriteArrayList<>();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(org.microproxy.http.HttpRequest req, FlowContext ctx) {
                methods.add(req.method() + " " + req.uri());
                return null;
            }
        }).start();
        HttpClient client = client(proxy, originCa.clientContext());
        HttpResponse<String> response = get(client, url(origin, "/secure"));
        assertEquals(200, response.statusCode());
        assertEquals("/secure", echoedUri(response.body()));
        // Only the CONNECT is visible to the proxy; the tunnelled request is not.
        assertEquals(List.of("CONNECT 127.0.0.1:" + origin.getAddress().getPort()), methods);
        // The tunnel stays open for further requests.
        assertEquals(200, get(client, url(origin, "/again")).statusCode());
        assertEquals(1, methods.size());
    }

    @Test
    void mitmDecryptsRequestsAndResponses() throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        AtomicInteger handshakes = new AtomicInteger();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void clientSSLHandshakeSucceeded(FlowContext ctx, SSLSession session) {
                        handshakes.incrementAndGet();
                    }
                })
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(org.microproxy.http.HttpRequest req, FlowContext ctx) {
                        seen.add(req.method() + " " + req.uri());
                        return new HttpFilters() {
                            @Override
                            public org.microproxy.http.HttpResponse proxyToServerRequest(HttpObject o) {
                                if (o instanceof org.microproxy.http.HttpRequest r) r.headers().set("X-Mitm", "1");
                                return null;
                            }

                            @Override
                            public HttpObject serverToProxyResponse(HttpObject o) {
                                if (o instanceof org.microproxy.http.HttpResponse r) r.headers().set("X-Intercepted", "true");
                                return o;
                            }
                        };
                    }
                })
                .start();
        // The client trusts only the proxy's CA: it can only succeed through interception.
        HttpClient client = client(proxy, proxyCa.clientContext());
        HttpResponse<String> response = send(client, HttpRequest.newBuilder(URI.create(url(origin, "/private?q=1")))
                .POST(HttpRequest.BodyPublishers.ofString("secret")).build());
        assertEquals(200, response.statusCode());
        assertEquals("true", response.headers().firstValue("x-intercepted").orElseThrow());
        assertEquals(List.of("1"), echoedHeader(response.body(), "x-mitm"));
        assertEquals("secret", echoedBody(response.body()));
        assertEquals(List.of("CONNECT 127.0.0.1:" + origin.getAddress().getPort(), "POST /private?q=1"), seen);
        assertEquals(1, handshakes.get());

        X509Certificate presented = (X509Certificate) response.sslSession().orElseThrow().getPeerCertificates()[0];
        assertEquals(proxyCa.getCertificate().getSubjectX500Principal(), presented.getIssuerX500Principal());

        // Keep-alive inside the intercepted session.
        assertEquals(200, get(client, url(origin, "/second")).statusCode());
        assertTrue(seen.contains("GET /second"));
    }

    @Test
    void mitmCanShortCircuitInsideTls() {
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(org.microproxy.http.HttpRequest req, FlowContext ctx) {
                        return new HttpFilters() {
                            @Override
                            public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject o) {
                                if (o instanceof org.microproxy.http.HttpRequest r && r.uri().equals("/mock")) {
                                    FullHttpResponse res = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                                            HttpResponseStatus.OK, "mocked".getBytes(StandardCharsets.UTF_8));
                                    return res;
                                }
                                return null;
                            }
                        };
                    }
                })
                .start();
        HttpResponse<String> response = get(client(proxy, proxyCa.clientContext()), url(origin, "/mock"));
        assertEquals("mocked", response.body());
    }

    @Test
    void mitmCanBeSkippedPerRequest() {
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(org.microproxy.http.HttpRequest req, FlowContext ctx) {
                        return new HttpFilters() {
                            @Override
                            public boolean proxyToServerAllowMitm() {
                                return false;
                            }
                        };
                    }
                })
                .start();
        // Not intercepted, so the client sees (and must trust) the origin's real certificate.
        assertEquals(200, get(client(proxy, originCa.clientContext()), url(origin, "/")).statusCode());
        assertThrows(java.io.UncheckedIOException.class,
                () -> get(client(proxy, proxyCa.clientContext()), url(origin, "/")));
    }

    @Test
    void mitmRefusesUntrustedUpstreamCertificates() {
        // The proxy validates the origin against the JDK trust store, which does not know originCa.
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa))
                .start();
        // The server handshake waits for the client's ClientHello, so the CONNECT succeeds and the
        // request inside the session is refused, as mitmproxy does.
        var response = get(client(proxy, proxyCa.clientContext()), url(origin, "/"));
        assertEquals(502, response.statusCode());
    }
}
