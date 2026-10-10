package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TlsHellos.issuer;
import static org.microproxy.TlsHellos.startTls;

import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Transparent HTTPS: TLS that arrives on a {@code withTransparent} listener without a {@code
 * CONNECT}, as from a firewall redirect, is routed by its SNI and intercepted or tunnelled like a
 * {@code CONNECT} to that host.
 */
class TransparentTlsTest {

    private static CertificateAuthority proxyCa;
    private static CertificateAuthority originCa;
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private final List<String> received = new CopyOnWriteArrayList<>();
    private HttpsServer origin;

    @BeforeAll
    static void authorities() {
        proxyCa = CertificateAuthority.generate("Transparent Proxy CA");
        originCa = CertificateAuthority.generate("Transparent Origin CA");
    }

    @BeforeEach
    void startOrigin() {
        origin = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), exchange -> {
            received.add(exchange.getRequestMethod() + " " + exchange.getRequestURI() + " "
                    + exchange.getRequestHeaders().getFirst("Host"));
            TestSupport.echo().handle(exchange);
        });
    }

    @AfterEach
    void tearDown() {
        proxies.close();
        origin.stop(0);
    }

    /** A transparent proxy that sends SNI-routed TLS to the origin's port. */
    private HttpProxyServerBootstrap transparent() {
        return MicroProxy.bootstrap().withTransparent(true).withTransparentTlsPort(origin.getAddress().getPort());
    }

    private static Socket direct(HttpProxyServer proxy) throws IOException {
        Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort());
        s.setSoTimeout(20_000);
        return s;
    }

    @Test
    void tlsWithoutConnectIsRoutedBySniAndIntercepted() throws Exception {
        List<String> connects = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(transparent()
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource((request, ctx) -> {
                    connects.add(request.method() + " " + request.uri() + " sni=" + (ctx.getClientHello() == null
                            ? "-" : ctx.getClientHello().sni()));
                    return null;
                }));
        try (SSLSocket tls = startTls(direct(proxy), "localhost", proxyCa.clientContext(), "http/1.1")) {
            assertEquals(proxyCa.getCertificate().getSubjectX500Principal().getName(), issuer(tls));
            String response = TlsHellos.get(tls, "localhost", "/through");
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            assertTrue(response.contains("uri: /through"), response);
        }
        assertEquals(List.of("GET /through localhost"), received, "the request reached the origin");
        int port = origin.getAddress().getPort();
        // Filters saw a CONNECT made up from the SNI, then the request inside the session.
        assertEquals(List.of("CONNECT localhost:" + port + " sni=localhost", "GET /through sni=localhost"), connects);
    }

    @Test
    void withoutMitmTheConnectionIsTunnelledToTheSniHost() throws Exception {
        HttpProxyServer proxy = proxies.start(transparent());
        try (SSLSocket tls = startTls(direct(proxy), "localhost", originCa.clientContext())) {
            assertEquals(originCa.getCertificate().getSubjectX500Principal().getName(), issuer(tls));
            String response = TlsHellos.get(tls, "localhost", "/raw");
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            assertFalse(response.contains("h:via:"), response);
        }
        assertEquals(List.of("GET /raw localhost"), received);
    }

    @Test
    void ignoredHostsAreTunnelled() throws Exception {
        HttpProxyServer proxy = proxies.start(transparent()
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withIgnoreHosts("^localhost:"));
        try (SSLSocket tls = startTls(direct(proxy), "localhost", originCa.clientContext())) {
            assertEquals(originCa.getCertificate().getSubjectX500Principal().getName(), issuer(tls));
        }
    }

    @Test
    void aClientHelloWithoutSniIsRefused() throws Exception {
        List<Throwable> failures = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(transparent()
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void connectionExceptionCaught(FlowContext flowContext, Throwable cause) {
                        failures.add(cause);
                    }
                }));
        SSLException e = assertThrows(SSLException.class, () -> startTls(direct(proxy), null, proxyCa.clientContext()));
        assertTrue(String.valueOf(e.getMessage()).contains("unrecognized_name"), String.valueOf(e.getMessage()));
        TestSupport.eventually("the failure to be reported", () -> !failures.isEmpty());
        assertTrue(failures.getFirst().getMessage().contains("without SNI"), failures.getFirst().getMessage());
        assertEquals(List.of(), received);
    }

    @Test
    void plainHttpIsRoutedByHostWhenOriginFormIsAllowed() throws Exception {
        java.util.List<String> plain = new CopyOnWriteArrayList<>();
        com.sun.net.httpserver.HttpServer http = TestSupport.origin(exchange -> {
            plain.add(exchange.getRequestURI() + " " + exchange.getRequestHeaders().getFirst("Host"));
            TestSupport.echo().handle(exchange);
        });
        try {
            String host = "127.0.0.1:" + http.getAddress().getPort();
            HttpProxyServer refusing = proxies.start(transparent());
            String refused = TestSupport.rawExchange(refusing.getListenAddress(),
                    "GET /plain HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n");
            assertTrue(refused.startsWith("HTTP/1.1 400"), "origin-form needs allow_requests_to_origin_server: " + refused);

            HttpProxyServer proxy = proxies.start(transparent().withAllowRequestToOriginServer(true));
            String response = TestSupport.rawExchange(proxy.getListenAddress(),
                    "GET /plain HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n");
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            assertFalse(response.contains("h:via:"), "transparent: no Via " + response);
            assertEquals(List.of("/plain " + host), plain);
        } finally {
            http.stop(0);
        }
    }
}
