package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.eventually;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3ErrorCode;
import io.github.mahmoudimus.quic.QuicStreamException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tcp.TcpContext;
import org.microproxy.tcp.TcpInterceptor;
import org.microproxy.tcp.TcpMessage;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * {@code CONNECT} over HTTP/3 (RFC 9114 section 4.4) on a forward proxy's HTTP/3 listener: tunnels
 * to raw TCP servers in the stream's DATA, half-closes and resets both ways, interception with TLS
 * layered over the stream and filters seeing the requests inside, plain HTTP inside, the TCP
 * hooks, proxy authentication and filters refusing the tunnel.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class Http3ConnectTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("H3 CONNECT Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("H3 CONNECT Proxy CA");
    /** The proxy's own TLS listener's identity, which its HTTP/3 listener presents too. */
    static final org.microproxy.tls.SelfSignedSslContextSource LISTENER_TLS = new org.microproxy.tls.SelfSignedSslContextSource();

    private HttpProxyServer proxy;
    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    private <T extends AutoCloseable> T closing(T c) {
        closeables.add(c);
        return c;
    }

    private static HttpProxyServerBootstrap forwardProxy() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("hx").withSslContextSource(LISTENER_TLS).withHttp3(true);
    }

    private static CertificateAuthorityMitmManager mitmManager() {
        return new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext());
    }

    private H3TestClient client() throws IOException {
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        return closing(H3TestClient.connect(address, "localhost", LISTENER_TLS.getCertificate()));
    }

    /** A raw TCP server that echoes what it reads until the client half-closes, then closes. */
    private TestSupport.RawServer echoServer(AtomicInteger ended) {
        return closing(TestSupport.rawServer(s -> {
            try {
                s.getInputStream().transferTo(s.getOutputStream());
            } finally {
                if (ended != null) ended.incrementAndGet();
            }
        }));
    }

    private static String target(TestSupport.RawServer server) {
        return "127.0.0.1:" + server.port();
    }

    @Test
    void aConnectStreamTunnelsToARawServerAndHalfCloses() throws Exception {
        AtomicInteger ended = new AtomicInteger();
        TestSupport.RawServer echo = echoServer(ended);
        proxy = forwardProxy().start();
        H3TestClient client = client();
        H3TestClient.Tunnel tunnel = client.open(H3TestClient.connect(target(echo)));
        assertEquals(200, tunnel.status);
        assertNull(tunnel.header("content-length"));
        assertEquals("1.1 hx", tunnel.header("via"));
        tunnel.out().write("hello through h3".getBytes(StandardCharsets.UTF_8));
        // Half-close: the FIN reaches the server as one; its close comes back as the stream's FIN.
        tunnel.end();
        assertEquals("hello through h3", tunnel.text());
        eventually("the server connection to end", () -> ended.get() == 1);
    }

    @Test
    void megabytesFlowBothWaysUnderFlowControl() throws Exception {
        TestSupport.RawServer echo = echoServer(null);
        proxy = forwardProxy().start();
        byte[] payload = H2TestOrigin.bytes(3_000_000, 7);
        H3TestClient.Tunnel tunnel = client().open(H3TestClient.connect(target(echo)));
        assertEquals(200, tunnel.status);
        CompletableFuture<byte[]> back = CompletableFuture.supplyAsync(() -> {
            try {
                return tunnel.readAll();
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        });
        for (int off = 0; off < payload.length; off += 50_000) {
            tunnel.out().write(payload, off, Math.min(50_000, payload.length - off));
        }
        tunnel.end();
        assertArrayEquals(payload, back.get(30, TimeUnit.SECONDS));
    }

    @Test
    void theServerHalfClosesFirstAndTheClientGoesOnSending() throws Exception {
        List<String> received = new CopyOnWriteArrayList<>();
        TestSupport.RawServer server = closing(TestSupport.rawServer(s -> {
            s.getOutputStream().write("banner\n".getBytes(StandardCharsets.US_ASCII));
            s.shutdownOutput();
            received.add(new String(s.getInputStream().readAllBytes(), StandardCharsets.US_ASCII));
        }));
        proxy = forwardProxy().start();
        H3TestClient.Tunnel tunnel = client().open(H3TestClient.connect(target(server)));
        assertEquals(200, tunnel.status);
        assertEquals("banner\n", tunnel.text(), "the server's FIN ends the stream's response side");
        tunnel.out().write("still sending".getBytes(StandardCharsets.US_ASCII));
        tunnel.end();
        eventually("the server to read the client's bytes", () -> received.equals(List.of("still sending")));
    }

    @Test
    void aServerResetResetsTheStreamWithConnectError() throws Exception {
        TestSupport.RawServer server = closing(TestSupport.rawServer(s -> {
            s.getInputStream().read();
            s.setSoLinger(true, 0); // a TCP RST
            s.close();
        }));
        proxy = forwardProxy().start();
        H3TestClient.Tunnel tunnel = client().open(H3TestClient.connect(target(server)));
        assertEquals(200, tunnel.status);
        tunnel.out().write('x');
        QuicStreamException reset = assertThrows(QuicStreamException.class, tunnel::readAll);
        assertEquals(Http3ErrorCode.H3_CONNECT_ERROR.code(), reset.errorCode());
    }

    @Test
    void aClientResetClosesTheServerConnection() throws Exception {
        AtomicInteger ended = new AtomicInteger();
        TestSupport.RawServer echo = echoServer(ended);
        proxy = forwardProxy().start();
        H3TestClient client = client();
        H3TestClient.Tunnel tunnel = client.open(H3TestClient.connect(target(echo)));
        tunnel.out().write("ping".getBytes(StandardCharsets.US_ASCII));
        assertEquals("ping", new String(tunnel.in().readNBytes(4), StandardCharsets.US_ASCII));
        tunnel.reset(Http3ErrorCode.H3_CONNECT_ERROR.code());
        eventually("the server connection to end", () -> ended.get() == 1);
        // A reset that ends a tunnel is no rapid reset: the connection serves on.
        assertEquals(200, client.open(H3TestClient.connect(target(echo))).status);
    }

    @Test
    void aTargetThatRefusesGets502() throws Exception {
        try (Socket refusing = TestSupport.refusingPort()) {
            proxy = forwardProxy().start();
            H3TestClient.Tunnel tunnel = client().open(H3TestClient.connect("127.0.0.1:" + refusing.getLocalPort()));
            assertEquals(502, tunnel.status);
        }
    }

    @Test
    void proxyAuthenticationAndFiltersDecideOnTheConnect() throws Exception {
        TestSupport.RawServer echo = echoServer(null);
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = forwardProxy()
                .withProxyAuthenticator((user, password) -> "user".equals(user) && "secret".equals(password))
                .withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject o) {
                        HttpRequest r = (HttpRequest) o;
                        seen.add(r.method() + " " + r.uri() + " " + r.protocolVersion());
                        if (r.uri().startsWith("blocked.test")) {
                            return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN);
                        }
                        return null;
                    }
                })
                .start();
        H3TestClient client = client();
        assertEquals(407, client.open(H3TestClient.connect(target(echo))).status);
        HeaderField credentials = new HeaderField("proxy-authorization",
                "Basic " + Base64.getEncoder().encodeToString("user:secret".getBytes(StandardCharsets.UTF_8)));
        assertEquals(403, client.open(H3TestClient.connect("blocked.test:443", credentials)).status);
        H3TestClient.Tunnel tunnel = client.open(H3TestClient.connect(target(echo), credentials));
        assertEquals(200, tunnel.status);
        tunnel.out().write("ok".getBytes(StandardCharsets.US_ASCII));
        tunnel.end();
        assertEquals("ok", tunnel.text());
        assertEquals(List.of("CONNECT blocked.test:443 HTTP/3.0", "CONNECT " + target(echo) + " HTTP/3.0"), seen);
    }

    @Test
    void theTcpHooksSeeTheTunnelsBytes() throws Exception {
        TestSupport.RawServer echo = echoServer(null);
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = forwardProxy().withTcpInterceptor(new TcpInterceptor() {
            @Override
            public byte[] tcpMessage(TcpMessage message, TcpContext context) {
                seen.add((message.fromClient() ? "> " : "< ") + message.text() + " " + context.port());
                return message.fromClient() ? message.text().toUpperCase().getBytes(StandardCharsets.UTF_8) : message.data();
            }
        }).start();
        H3TestClient.Tunnel tunnel = client().open(H3TestClient.connect(target(echo)));
        tunnel.out().write("shout".getBytes(StandardCharsets.UTF_8));
        tunnel.end();
        assertEquals("SHOUT", tunnel.text());
        assertEquals(List.of("> shout " + echo.port(), "< SHOUT " + echo.port()), seen);
    }

    // -------------------------------------------------------------------------------------------
    // Interception: TLS over the stream
    // -------------------------------------------------------------------------------------------

    private HttpsServer httpsOrigin() {
        HttpsServer origin = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), TestSupport.echo());
        closeables.add(() -> origin.stop(0));
        return origin;
    }

    /** Runs a TLS handshake over a CONNECT stream, as a client trusting the proxy's CA. */
    private static SSLSocket tlsOver(H3TestClient.Tunnel tunnel, int port, String... alpn) throws IOException {
        SSLContext trust = proxyCa.clientContext();
        SSLSocket tls = (SSLSocket) trust.getSocketFactory().createSocket(tunnel.asSocket(), "localhost", port, true);
        tls.setUseClientMode(true);
        if (alpn.length > 0) {
            javax.net.ssl.SSLParameters params = tls.getSSLParameters();
            params.setApplicationProtocols(alpn);
            tls.setSSLParameters(params);
        }
        tls.setSoTimeout(10_000);
        tls.startHandshake();
        return tls;
    }

    @Test
    void anInterceptedConnectStreamServesTheRequestsInsideToFilters() throws Exception {
        HttpsServer origin = httpsOrigin();
        List<String> requests = new CopyOnWriteArrayList<>();
        proxy = forwardProxy().withManInTheMiddle(mitmManager())
                .withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject o) {
                        if (o instanceof HttpRequest r) requests.add(r.method() + " " + r.uri() + " " + r.protocolVersion());
                        return null;
                    }

                    @Override
                    public HttpObject proxyToClientResponse(HttpObject o) {
                        if (o instanceof HttpResponse r) r.headers().set("x-intercepted", "yes");
                        return o;
                    }
                })
                .start();
        String target = "localhost:" + origin.getAddress().getPort();
        H3TestClient.Tunnel tunnel = client().open(H3TestClient.connect(target));
        assertEquals(200, tunnel.status);
        // The client trusts only the proxy's CA: this works only if the stream is intercepted.
        SSLSocket tls = tlsOver(tunnel, origin.getAddress().getPort(), "http/1.1");
        write(tls.getOutputStream(), "GET /inside?a=1 HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
        String first = TestSupport.readUntil(tls.getInputStream(), "\r\n\r\n");
        assertTrue(first.startsWith("HTTP/1.1 200"), first);
        assertTrue(first.contains("x-intercepted: yes"), first);
        int length = Integer.parseInt(WebSocketTestSupport.header(first, "Content-Length"));
        assertEquals("/inside?a=1", echoedUri(new String(tls.getInputStream().readNBytes(length), StandardCharsets.UTF_8)));
        write(tls.getOutputStream(), "GET /second HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n");
        String second = new String(tls.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
        assertTrue(second.startsWith("HTTP/1.1 200"), second);
        tls.close();
        assertEquals(List.of("CONNECT " + target + " HTTP/3.0", "GET /inside?a=1 HTTP/1.1", "GET /second HTTP/1.1"),
                requests);
    }

    @Test
    void anInterceptedConnectStreamServesHttp2InsideTls() throws Exception {
        HttpsServer origin = httpsOrigin();
        proxy = forwardProxy().withManInTheMiddle(mitmManager()).withHttp2(true).start();
        String target = "localhost:" + origin.getAddress().getPort();
        H3TestClient.Tunnel tunnel = client().open(H3TestClient.connect(target));
        assertEquals(200, tunnel.status);
        SSLSocket tls = tlsOver(tunnel, origin.getAddress().getPort(), "h2");
        assertEquals("h2", tls.getApplicationProtocol());
        try (H2TestClient inner = H2TestClient.over(tls, target).handshake()) {
            inner.get(1, "/nested");
            H2TestClient.Response r = inner.response(1);
            assertEquals(200, r.status());
            assertEquals("/nested", echoedUri(r.text()));
        }
    }

    @Test
    void plainHttpInsideAConnectStreamIsServedAsHttp() throws Exception {
        List<String> requests = new CopyOnWriteArrayList<>();
        com.sun.net.httpserver.HttpServer origin = TestSupport.origin(TestSupport.echo());
        closeables.add(() -> origin.stop(0));
        proxy = forwardProxy().withManInTheMiddle(mitmManager())
                .withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject o) {
                        if (o instanceof HttpRequest r) requests.add(r.method() + " " + r.uri());
                        return null;
                    }
                })
                .start();
        String target = "127.0.0.1:" + origin.getAddress().getPort();
        H3TestClient.Tunnel tunnel = client().open(H3TestClient.connect(target));
        assertEquals(200, tunnel.status);
        tunnel.out().write(("GET /plain HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        String response = tunnel.text();
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        assertTrue(response.contains("uri: /plain"), response);
        assertEquals(List.of("CONNECT " + target, "GET /plain"), requests);
    }
}
