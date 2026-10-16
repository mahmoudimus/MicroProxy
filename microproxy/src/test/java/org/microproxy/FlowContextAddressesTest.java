package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.http3.HeaderField;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.http.HttpRequest;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * {@link FlowContext#getLocalAddress()} and {@link FlowContext#getProxyProtocolDestinationAddress()}
 * on every kind of listener: the proxy's own address the client connected to (a UDP address for
 * HTTP/3), and the destination of the PROXY header the connection started with, as against the
 * client addresses.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class FlowContextAddressesTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("Addresses Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("Addresses Proxy CA");
    static final SslContextSource LISTENER_TLS = () -> proxyCa.serverContext("localhost", "127.0.0.1");

    private HttpProxyServer proxy;
    private HttpServer origin;
    private HttpsServer httpsOrigin;
    /** What each request's filters saw, by its method and URI. */
    private final Map<String, Seen> seen = new ConcurrentHashMap<>();

    /** The addresses one request's contexts had. */
    record Seen(InetSocketAddress local, InetSocketAddress destination, InetSocketAddress client,
            InetSocketAddress direct, InetSocketAddress serverSideLocal) {}

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.stop(0);
        if (httpsOrigin != null) httpsOrigin.stop(0);
    }

    /** Records each request's addresses, those of its server-side context too. */
    private HttpFiltersSource recording() {
        return (request, ctx) -> new HttpFilters() {
            InetSocketAddress serverSide;

            @Override
            public void proxyToServerConnectionSucceeded(FullFlowContext serverContext) {
                serverSide = serverContext.getLocalAddress();
            }

            @Override
            public void exchangeEnded(boolean completed) {
                seen.put(key(request), new Seen(ctx.getLocalAddress(), ctx.getProxyProtocolDestinationAddress(),
                        ctx.getClientAddress(), ctx.getDirectClientAddress(), serverSide));
            }
        };
    }

    private static String key(HttpRequest request) {
        return request.method() + " " + request.uri();
    }

    private Seen await(String key) {
        TestSupport.eventually("the exchange " + key, () -> seen.containsKey(key));
        return seen.get(key);
    }

    private String originAuthority() {
        return "127.0.0.1:" + origin.getAddress().getPort();
    }

    private void startOrigin() {
        origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
    }

    private InetSocketAddress listen() {
        return new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
    }

    /** Sends one HTTP/1.1 request on {@code s} and reads the whole answer (the request closes). */
    private static String exchange(Socket s, String requestLine, String host) throws IOException {
        s.setSoTimeout(20_000);
        write(s.getOutputStream(), requestLine + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n");
        return new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
    }

    @Test
    void anHttp1ConnectionHasTheProxysSocketAddress() throws Exception {
        startOrigin();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(recording()).start();
        String uri = "http://" + originAuthority() + "/plain";
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            assertTrue(exchange(s, "GET " + uri, originAuthority()).startsWith("HTTP/1.1 200"));
            Seen addresses = await("GET " + uri);
            assertEquals(s.getRemoteSocketAddress(), addresses.local());
            assertEquals(s.getLocalSocketAddress(), addresses.client());
            assertEquals(s.getLocalSocketAddress(), addresses.direct());
            assertNull(addresses.destination(), "no PROXY header");
            assertEquals(addresses.local(), addresses.serverSideLocal(), "a FullFlowContext has the client side's");
        }
    }

    @Test
    void aProxyHeadersDestinationIsNotTheLocalAddress() throws Exception {
        startOrigin();
        proxy = MicroProxy.bootstrap().withPort(0).withAcceptProxyProtocol(true).withFiltersSource(recording()).start();
        String uri = "http://" + originAuthority() + "/behind-lb";
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            write(s.getOutputStream(), "PROXY TCP4 203.0.113.7 198.51.100.9 40000 443\r\n");
            assertTrue(exchange(s, "GET " + uri, originAuthority()).startsWith("HTTP/1.1 200"));
            Seen addresses = await("GET " + uri);
            assertEquals(s.getRemoteSocketAddress(), addresses.local());
            assertEquals(new InetSocketAddress("198.51.100.9", 443), addresses.destination());
            assertEquals(new InetSocketAddress("203.0.113.7", 40000), addresses.client());
            assertEquals(s.getLocalSocketAddress(), addresses.direct());
        }
    }

    @Test
    void anH2cConnectionsStreamsHaveIt() throws Exception {
        startOrigin();
        proxy = MicroProxy.bootstrap().withPort(0).withHttp2Cleartext(true).withFiltersSource(recording()).start();
        try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), originAuthority()).handshake()) {
            c.get(1, "/h2c");
            assertEquals(200, c.response(1).status());
        }
        Seen addresses = await("GET http://" + originAuthority() + "/h2c");
        assertNotNull(addresses.local());
        assertEquals(proxy.getListenAddress().getPort(), addresses.local().getPort());
        assertTrue(addresses.local().getAddress().isLoopbackAddress());
    }

    @Test
    void theTlsListenerAndTheSessionsInsideItsConnectStreamsHaveIt() throws Exception {
        httpsOrigin = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), TestSupport.echo());
        proxy = MicroProxy.bootstrap().withPort(0).withSslContextSource(LISTENER_TLS).withHttp2(true)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(recording()).start();
        String target = "localhost:" + httpsOrigin.getAddress().getPort();
        try (H2StreamClient c = H2StreamClient.tls(proxy.getListenAddress(), proxyCa.clientContext(), "unused:1")) {
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target), false);
            assertEquals(200, tunnel.status());
            SSLContext trust = proxyCa.clientContext();
            try (SSLSocket tls = (SSLSocket) trust.getSocketFactory()
                    .createSocket(tunnel.asSocket(), "localhost", httpsOrigin.getAddress().getPort(), true)) {
                tls.setUseClientMode(true);
                tls.startHandshake();
                assertTrue(exchange(tls, "GET /inside", target).startsWith("HTTP/1.1 200"));
            }
        }
        Seen connect = await("CONNECT " + target);
        Seen inside = await("GET /inside");
        assertEquals(proxy.getListenAddress().getPort(), connect.local().getPort());
        assertEquals(connect.local(), inside.local(), "the session inside the stream has its connection's");
    }

    @Test
    void transparentTlsHasTheListenersAddress() throws Exception {
        httpsOrigin = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), TestSupport.echo());
        proxy = MicroProxy.bootstrap().withPort(0).withTransparent(true)
                .withTransparentTlsPort(httpsOrigin.getAddress().getPort())
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(recording()).start();
        Socket raw = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        try (SSLSocket tls = TlsHellos.startTls(raw, "localhost", proxyCa.clientContext(), "http/1.1")) {
            assertTrue(exchange(tls, "GET /redirected", "localhost").startsWith("HTTP/1.1 200"));
            assertEquals(raw.getRemoteSocketAddress(), await("GET /redirected").local());
        }
    }

    @Test
    void aSocksClientHasIt() throws Exception {
        startOrigin();
        proxy = MicroProxy.bootstrap().withPort(0).withSocksServer(true).withFiltersSource(recording()).start();
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.open("127.0.0.1", origin.getAddress().getPort()));
            assertTrue(exchange(c.socket, "GET /socks", originAuthority()).startsWith("HTTP/1.1 200"));
            Seen addresses = await("GET /socks");
            assertEquals(c.socket.getRemoteSocketAddress(), addresses.local());
            assertEquals(addresses.local(), await("CONNECT 127.0.0.1:" + origin.getAddress().getPort()).local());
        }
    }

    @Test
    void aReverseProxyHasIt() throws Exception {
        startOrigin();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withReverseProxy(ReverseProxyMode.parse("http://" + originAuthority()))
                .withFiltersSource(recording()).start();
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            assertTrue(exchange(s, "GET /reverse", "public.example").startsWith("HTTP/1.1 200"));
            // (However the reverse proxy rewrote its target.)
            TestSupport.eventually("the exchange", () -> seen.keySet().stream().anyMatch(k -> k.endsWith("/reverse")));
            String key = seen.keySet().stream().filter(k -> k.endsWith("/reverse")).findFirst().orElseThrow();
            assertEquals(s.getRemoteSocketAddress(), seen.get(key).local());
        }
    }

    @Test
    void anHttp3ConnectionHasTheUdpAddress() throws Exception {
        startOrigin();
        org.microproxy.tls.SelfSignedSslContextSource tls = new org.microproxy.tls.SelfSignedSslContextSource();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withSslContextSource(tls).withHttp3(true).withFiltersSource(recording()).start();
        H3TestClient.Options options = new H3TestClient.Options();
        options.authority = originAuthority();
        try (H3TestClient client = H3TestClient.connect(listen(), "localhost", tls.getCertificate(), options)) {
            List<HeaderField> head = List.of(new HeaderField(":method", "GET"), new HeaderField(":scheme", "http"),
                    new HeaderField(":authority", originAuthority()), new HeaderField(":path", "/h3"));
            assertEquals(200, client.readResponse(client.send(head, true)).status());
        }
        Seen addresses = await("GET http://" + originAuthority() + "/h3");
        assertNotNull(addresses.local());
        assertEquals(proxy.getListenAddress().getPort(), addresses.local().getPort(), "the UDP port");
    }

    @Test
    void contextsMadeOutsideTheProxyHaveNeither() {
        FlowContext outside = new FlowContext(1, () -> null, () -> null, new ClientDetails());
        assertNull(outside.getLocalAddress());
        assertNull(outside.getProxyProtocolDestinationAddress());
        FullFlowContext full = new FullFlowContext(outside, "example.com:443", null, null);
        assertNull(full.getLocalAddress());
        assertNull(full.getProxyProtocolDestinationAddress());
    }
}
