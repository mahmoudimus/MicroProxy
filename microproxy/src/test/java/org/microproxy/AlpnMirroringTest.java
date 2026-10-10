package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * ALPN mirroring on intercepted TLS: the server is offered only the protocols the client offered
 * (of those the proxy speaks and has enabled), and the client gets the protocol the server chose,
 * so a client that wants HTTP/1.1 never gets HTTP/2 upstream, and one that wants HTTP/2 gets it
 * end to end where the server has it.
 */
class AlpnMirroringTest {

    private static CertificateAuthority proxyCa;
    private static CertificateAuthority originCa;
    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();

    @BeforeAll
    static void authorities() {
        proxyCa = CertificateAuthority.generate("ALPN Proxy CA");
        originCa = CertificateAuthority.generate("ALPN Origin CA");
    }

    @AfterEach
    void tearDown() throws Exception {
        proxies.close();
        for (AutoCloseable c : closeables) c.close();
    }

    private HttpProxyServerBootstrap mitm() {
        return MicroProxy.bootstrap().withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()));
    }

    /** Answers an HTTP/1.1 request on {@code s} with its negotiated ALPN protocol as the body. */
    private static void http1Answer(Socket s) throws IOException {
        TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
        String body = "http1 alpn=" + ((SSLSocket) s).getApplicationProtocol();
        TestSupport.write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: " + body.length()
                + "\r\nConnection: close\r\n\r\n" + body);
    }

    /** An origin with HTTP/2 and HTTP/1.1, which picks h2 when offered. */
    private H2TestOrigin h2AndHttp1Origin() throws IOException {
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        options.http1Handler = AlpnMirroringTest::http1Answer;
        H2TestOrigin origin = new H2TestOrigin(originCa.serverContext("localhost", "127.0.0.1"), options, s -> {
            s.readBody();
            byte[] body = "h2".getBytes(StandardCharsets.UTF_8);
            s.respond(200, false, "content-length", Integer.toString(body.length));
            s.data(body, true);
        });
        closeables.add(origin);
        return origin;
    }

    /** An HTTP/1.1-only TLS origin that negotiates ALPN {@code http/1.1} and records what it was offered. */
    private TestSupport.RawServer http1AlpnOrigin(List<List<String>> offered) {
        SSLContext context = originCa.serverContext("localhost", "127.0.0.1");
        TestSupport.RawServer server = TestSupport.rawServer(plain -> {
            SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(plain, null, true);
            tls.setUseClientMode(false);
            SSLParameters params = tls.getSSLParameters();
            params.setApplicationProtocols(new String[] {"http/1.1"});
            tls.setSSLParameters(params);
            tls.setHandshakeApplicationProtocolSelector((socket, protocols) -> {
                offered.add(List.copyOf(protocols));
                return protocols.contains("http/1.1") ? "http/1.1" : null;
            });
            tls.startHandshake();
            http1Answer(tls);
            tls.close();
        });
        closeables.add(server);
        return server;
    }

    private static HttpResponse<String> h2Get(HttpProxyServer proxy, String url) throws Exception {
        HttpClient client = Http2ProxyTest.h2Client(proxy, proxyCa.clientContext());
        return client.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(20)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void aClientOfferingOnlyHttp11NeverGetsHttp2Upstream() throws Exception {
        H2TestOrigin origin = h2AndHttp1Origin();
        HttpProxyServer proxy = proxies.start(mitm().withHttp2(true).withHttp2Upstream(true));
        try (SSLSocket tls = TlsHellos.throughConnect(proxy, "localhost:" + origin.port(), "localhost",
                proxyCa.clientContext(), "http/1.1")) {
            assertEquals("http/1.1", tls.getApplicationProtocol(), "the server's choice, mirrored");
            String response = TlsHellos.get(tls, "localhost:" + origin.port(), "/");
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            assertTrue(response.endsWith("http1 alpn=http/1.1"), response);
        }
        assertEquals(List.of(List.of("http/1.1")), origin.offeredAlpn, "offered only what the client offered");
        assertEquals(List.of(), origin.connections, "no HTTP/2 connection to the server");
    }

    @Test
    void aClientOfferingHttp2GetsItEndToEnd() throws Exception {
        H2TestOrigin origin = h2AndHttp1Origin();
        HttpProxyServer proxy = proxies.start(mitm().withHttp2(true).withHttp2Upstream(true));
        HttpResponse<String> response = h2Get(proxy, origin.url("/"));
        assertEquals(200, response.statusCode());
        assertEquals(HttpClient.Version.HTTP_2, response.version());
        assertEquals("h2", response.body());
        assertEquals(List.of(List.of("h2", "http/1.1")), origin.offeredAlpn);
        assertEquals(1, origin.connections.size());
    }

    @Test
    void aServerThatDeclinesHttp2HasTheClientSpeakHttp11Too() throws Exception {
        List<List<String>> offered = new CopyOnWriteArrayList<>();
        TestSupport.RawServer origin = http1AlpnOrigin(offered);
        HttpProxyServer proxy = proxies.start(mitm().withHttp2(true).withHttp2Upstream(true));
        HttpResponse<String> response = h2Get(proxy, "https://localhost:" + origin.port() + "/");
        assertEquals(200, response.statusCode());
        assertEquals(HttpClient.Version.HTTP_1_1, response.version(), "mirrors the server's http/1.1");
        assertEquals("http1 alpn=http/1.1", response.body());
        assertEquals(List.of(List.of("h2", "http/1.1")), offered);
    }

    @Test
    void withoutHttp2UpstreamTheServerIsNotOfferedH2AndClientsStillGetIt() throws Exception {
        List<List<String>> offered = new CopyOnWriteArrayList<>();
        TestSupport.RawServer origin = http1AlpnOrigin(offered);
        HttpProxyServer proxy = proxies.start(mitm().withHttp2(true));
        HttpResponse<String> response = h2Get(proxy, "https://localhost:" + origin.port() + "/");
        assertEquals(200, response.statusCode());
        // The server could not have chosen h2, so its choice says nothing: the client keeps HTTP/2.
        assertEquals(HttpClient.Version.HTTP_2, response.version());
        assertEquals(List.of(List.of("http/1.1")), offered, "h2 is offered only with HTTP/2 upstream");
    }

    @Test
    void withHttp2OffAClientOfferingH2GetsHttp11BothWays() throws Exception {
        H2TestOrigin origin = h2AndHttp1Origin();
        HttpProxyServer proxy = proxies.start(mitm());
        try (SSLSocket tls = TlsHellos.throughConnect(proxy, "localhost:" + origin.port(), "localhost",
                proxyCa.clientContext(), "h2", "http/1.1")) {
            assertEquals("", tls.getApplicationProtocol(), "no protocol: HTTP/1.1, as before");
            String response = TlsHellos.get(tls, "localhost:" + origin.port(), "/");
            assertTrue(response.endsWith("http1 alpn=http/1.1"), response);
        }
        assertEquals(List.of(List.of("http/1.1")), origin.offeredAlpn);
    }
}
