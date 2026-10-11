package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.impl.BootstrapView;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/** Removing HTTP/3 alternatives from {@code Alt-Svc}, so clients do not bypass the proxy over QUIC. */
class AltSvcStrippingTest {

    private static final List<String> ADVERTISED = List.of("h3=\":443\"; ma=86400, h2=\":443\"; ma=86400", "h3-29=\":443\"");
    private static final List<String> STRIPPED = List.of("h2=\":443\"; ma=86400");

    /** Answers with two Alt-Svc fields advertising HTTP/3 next to HTTP/2. */
    private static final HttpHandler ADVERTISING = exchange -> {
        exchange.getRequestBody().readAllBytes();
        ADVERTISED.forEach(v -> exchange.getResponseHeaders().add("Alt-Svc", v));
        byte[] out = "ok".getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, out.length);
        exchange.getResponseBody().write(out);
        exchange.close();
    };

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;
    private static HttpServer origin;
    private static HttpsServer secureOrigin;
    private HttpProxyServer proxy;

    @BeforeAll
    static void startOrigins() {
        origin = TestSupport.origin(ADVERTISING);
        originCa = CertificateAuthority.generate("Alt-Svc Origin CA");
        proxyCa = CertificateAuthority.generate("Alt-Svc Proxy CA");
        secureOrigin = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), ADVERTISING);
    }

    @AfterAll
    static void stopOrigins() {
        origin.stop(0);
        secureOrigin.stop(0);
    }

    @AfterEach
    void stopProxy() {
        if (proxy != null) proxy.abort();
    }

    private static HttpProxyServerBootstrap intercepting() {
        return MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()));
    }

    private static List<String> altSvc(java.net.http.HttpResponse<String> response) {
        assertEquals(200, response.statusCode(), response.body());
        return response.headers().allValues("alt-svc");
    }

    @Test
    void aPlainForwardProxyPassesAltSvcOn() {
        proxy = MicroProxy.bootstrap().withPort(0).start();
        assertEquals(ADVERTISED, altSvc(get(client(proxy), url(origin, "/"))));
    }

    @Test
    void interceptedResponsesLoseTheirHttp3AlternativesByDefault() {
        proxy = intercepting().start();
        assertEquals(STRIPPED, altSvc(get(client(proxy, proxyCa.clientContext()), url(secureOrigin, "/"))));
        // Plain requests through an intercepting proxy too: the proxy is meant to see that client.
        assertEquals(STRIPPED, altSvc(get(client(proxy), url(origin, "/"))));
    }

    @Test
    void transparentProxiesStripByDefault() {
        proxy = MicroProxy.bootstrap().withPort(0).withTransparent(true).start();
        assertEquals(STRIPPED, altSvc(get(client(proxy), url(origin, "/"))));
    }

    /** The h3 alternatives of a response as a raw HTTP/1.1 exchange shows them. */
    private static List<String> altSvc(String rawResponse) {
        assertTrue(rawResponse.startsWith("HTTP/1.1 200"), rawResponse);
        return rawResponse.lines().filter(l -> l.regionMatches(true, 0, "alt-svc:", 0, 8))
                .map(l -> l.substring(8).strip()).toList();
    }

    /**
     * With a transparent QUIC listener, clients whose traffic was redirected to the proxy keep
     * their h3 alternatives: their QUIC reaches the proxy too. Clients of the explicit proxy, whose
     * UDP may go anywhere, still lose them, and an explicit setting applies to every client.
     */
    @Test
    void withTransparentQuicRedirectedClientsKeepHttp3() throws Exception {
        HttpsServer localhostOrigin = TestSupport.httpsOrigin(originCa.serverContext("localhost"), ADVERTISING);
        try {
            HttpProxyServerBootstrap b = intercepting().withTransparent(true).withTransparentQuicPort(0)
                    .withTransparentTlsPort(localhostOrigin.getAddress().getPort())
                    .withAllowRequestToOriginServer(true);
            proxy = b.start();
            // Plain HTTP routed by Host, as a firewall redirects it.
            String routedByHost = TestSupport.rawExchange(proxy.getListenAddress(), "GET / HTTP/1.1\r\nHost: 127.0.0.1:"
                    + origin.getAddress().getPort() + "\r\nConnection: close\r\n\r\n");
            assertEquals(ADVERTISED, altSvc(routedByHost));
            // TLS routed by its SNI.
            try (java.net.Socket raw = new java.net.Socket(proxy.getListenAddress().getAddress(),
                    proxy.getListenAddress().getPort());
                    javax.net.ssl.SSLSocket tls = TlsHellos.startTls(raw, "localhost", proxyCa.clientContext(), "http/1.1")) {
                assertEquals(ADVERTISED, altSvc(TlsHellos.get(tls, "localhost", "/")));
            }
            // A client of the explicit proxy: CONNECT, and an absolute-form request.
            assertEquals(STRIPPED, altSvc(get(client(proxy, proxyCa.clientContext()), url(secureOrigin, "/"))));
            assertEquals(STRIPPED, altSvc(get(client(proxy), url(origin, "/"))));
            proxy.abort();

            proxy = b.withAltSvcH3Stripping(true).start();
            assertEquals(STRIPPED, altSvc(TestSupport.rawExchange(proxy.getListenAddress(), "GET / HTTP/1.1\r\nHost: 127.0.0.1:"
                    + origin.getAddress().getPort() + "\r\nConnection: close\r\n\r\n")));
        } finally {
            localhostOrigin.stop(0);
        }
    }

    @Test
    void strippingCanBeTurnedOffOrOn() {
        proxy = intercepting().withAltSvcH3Stripping(false).start();
        assertEquals(ADVERTISED, altSvc(get(client(proxy, proxyCa.clientContext()), url(secureOrigin, "/"))));
        proxy.abort();
        proxy = MicroProxy.bootstrap().withPort(0).withoutHttp3Advertisement().start();
        assertEquals(STRIPPED, altSvc(get(client(proxy), url(origin, "/"))));
    }

    @Test
    void filtersSeeServerResponsesStrippedAndShortCircuitsAreStrippedToo() {
        List<String> seenBeforeStripping = new CopyOnWriteArrayList<>();
        List<String> seenByProxyToClient = new CopyOnWriteArrayList<>();
        proxy = MicroProxy.bootstrap().withPort(0).withoutHttp3Advertisement()
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
                        return new HttpFiltersAdapter(originalRequest) {
                            @Override
                            public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                                if (!originalRequest.uri().endsWith("/short")) return null;
                                HttpResponse answer = new DefaultFullHttpResponse(
                                        HttpVersion.HTTP_1_1, HttpResponseStatus.OK, "short");
                                answer.headers().add("Alt-Svc", "h3=\":443\", h2=\":443\"");
                                return answer;
                            }

                            @Override
                            public HttpObject serverToProxyResponse(HttpObject httpObject) {
                                if (httpObject instanceof HttpResponse r) seenBeforeStripping.addAll(r.headers().getAll("Alt-Svc"));
                                return httpObject;
                            }

                            @Override
                            public HttpObject proxyToClientResponse(HttpObject httpObject) {
                                if (httpObject instanceof HttpResponse r) seenByProxyToClient.addAll(r.headers().getAll("Alt-Svc"));
                                return httpObject;
                            }
                        };
                    }
                })
                .start();
        assertEquals(STRIPPED, altSvc(get(client(proxy), url(origin, "/"))));
        assertEquals(ADVERTISED, seenBeforeStripping);
        assertEquals(STRIPPED, seenByProxyToClient);
        assertEquals(List.of("h2=\":443\""), altSvc(get(client(proxy), url(origin, "/short"))));
    }

    @Test
    void configurationFromPropertiesAndTheCommandLine() throws Exception {
        PrintStream quiet = new PrintStream(OutputStream.nullOutputStream());
        assertTrue(BootstrapView.stripsAltSvcH3(Launcher.parse(new String[] {"--no-alt-svc-h3"}, quiet).bootstrap()));
        assertFalse(BootstrapView.stripsAltSvcH3(Launcher.parse(new String[] {}, quiet).bootstrap()));
        assertTrue(BootstrapView.stripsAltSvcH3(Launcher.parse(new String[] {"--transparent"}, quiet).bootstrap()));
        assertFalse(BootstrapView.stripsAltSvcH3(
                Launcher.parse(new String[] {"--transparent", "--keep-alt-svc-h3"}, quiet).bootstrap()));
        assertTrue(BootstrapView.stripsAltSvcH3(intercepting()), "on with interception");
        // With a transparent QUIC listener, off for redirected clients only, unless set.
        HttpProxyServerBootstrap quic = Launcher.parse(new String[] {"--transparent", "--transparent-quic-port", "4433"}, quiet)
                .bootstrap();
        assertTrue(BootstrapView.stripsAltSvcH3(quic));
        assertFalse(BootstrapView.stripsAltSvcH3ForTransparent(quic));
        assertTrue(BootstrapView.stripsAltSvcH3ForTransparent(Launcher.parse(new String[] {"--transparent"}, quiet).bootstrap()));
        assertTrue(BootstrapView.stripsAltSvcH3ForTransparent(Launcher.parse(
                new String[] {"--transparent", "--transparent-quic-port", "4433", "--no-alt-svc-h3"}, quiet).bootstrap()));

        Path props = Files.createTempFile("altsvc", ".properties");
        try {
            Files.writeString(props, "strip_alt_svc_h3=true\n");
            assertTrue(BootstrapView.stripsAltSvcH3(MicroProxy.bootstrapFromFile(props)));
            Files.writeString(props, "transparent=true\nstrip_alt_svc_h3=false\n");
            assertFalse(BootstrapView.stripsAltSvcH3(MicroProxy.bootstrapFromFile(props)));
        } finally {
            Files.delete(props);
        }
    }
}
