package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.eventually;
import static org.microproxy.TestSupport.readUntil;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.http2.ErrorCode;
import io.github.mahmoudimus.http2.HeaderField;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLParameters;
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
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * MicroProxy in front of an HTTPS proxy: the client tunnels to a corporate proxy through
 * MicroProxy, which intercepts that session, and then asks the corporate proxy for tunnels of its
 * own, with {@code CONNECT} streams (HTTP/2) or {@code CONNECT} requests (HTTP/1.1) inside the
 * session. MicroProxy forwards them to the corporate proxy (a second MicroProxy with a TLS
 * listener), never straight to the target: over HTTP/2 when its connection to the corporate proxy
 * speaks it, else over HTTP/1.1.
 */
@Timeout(60)
class HttpsProxyForwardingTest {

    /** Signs the corporate proxy's and the origins' certificates, which MicroProxy trusts. */
    static final CertificateAuthority serverCa = CertificateAuthority.generate("Forwarding Server CA");
    /** MicroProxy's interception CA, which the clients trust. */
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("Forwarding Proxy CA");

    static final String CORP_CREDENTIALS =
            "Basic " + Base64.getEncoder().encodeToString("corp-user:corp-secret".getBytes(StandardCharsets.UTF_8));
    static final String PROXY_CREDENTIALS =
            "Basic " + Base64.getEncoder().encodeToString("mp-user:mp-secret".getBytes(StandardCharsets.UTF_8));

    private HttpProxyServer proxy;
    private HttpProxyServer corp;
    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();
    /** The requests the corporate proxy received: {@code method uri version proxy-authorization}. */
    private final List<String> corpSaw = new CopyOnWriteArrayList<>();
    private final AtomicInteger corpConnections = new AtomicInteger();

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        if (corp != null) corp.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    private <T extends AutoCloseable> T closing(T c) {
        closeables.add(c);
        return c;
    }

    // -------------------------------------------------------------------------------------------
    // The servers
    // -------------------------------------------------------------------------------------------

    /** Starts the corporate proxy: a TLS listener, offering HTTP/2 if {@code h2}. */
    private void startCorp(boolean h2, ProxyAuthenticator authenticator) {
        HttpProxyServerBootstrap b = MicroProxy.bootstrap().withPort(0).withProxyAlias("corp")
                .withSslContextSource(() -> serverCa.serverContext("localhost", "127.0.0.1"))
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void clientConnected(FlowContext ctx) {
                        corpConnections.incrementAndGet();
                    }

                    @Override
                    public void requestReceivedFromClient(FlowContext ctx, HttpRequest r) {
                        corpSaw.add(r.method() + " " + r.uri() + " " + r.protocolVersion() + " "
                                + r.headers().get("Proxy-Authorization"));
                    }
                });
        if (h2) b.withHttp2(true);
        if (authenticator != null) b.withProxyAuthenticator(authenticator);
        corp = b.start();
    }

    /** MicroProxy: intercepts, offers HTTP/2 to clients and to servers. */
    private static HttpProxyServerBootstrap microProxy() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("mp")
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, serverCa.clientContext()))
                .withHttp2(true)
                .withHttp2Upstream(true);
    }

    /** Filters that intercept the corporate proxy's session, but not the tunnels through it. */
    private static HttpFiltersSource interceptOnlyTheCorporateProxy() {
        return (original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public boolean proxyToServerAllowMitm() {
                return ctx.forwardedVia().isEmpty();
            }
        };
    }

    private String corpTarget() {
        return "localhost:" + corp.getListenAddress().getPort();
    }

    /** A raw TCP server that echoes what it reads until the client half-closes, then closes. */
    private TestSupport.RawServer echoServer() {
        return closing(TestSupport.rawServer(s -> s.getInputStream().transferTo(s.getOutputStream())));
    }

    private static String target(TestSupport.RawServer server) {
        return "127.0.0.1:" + server.port();
    }

    private HttpsServer httpsOrigin(com.sun.net.httpserver.HttpHandler handler) {
        HttpsServer origin = TestSupport.httpsOrigin(serverCa.serverContext("localhost", "127.0.0.1"), handler);
        closeables.add(() -> origin.stop(0));
        return origin;
    }

    private static ProxyAuthenticator basic(String user, String password, String realm) {
        return new ProxyAuthenticator() {
            @Override
            public boolean authenticate(String userName, String pw) {
                return user.equals(userName) && password.equals(pw);
            }

            @Override
            public String getRealm() {
                return realm;
            }
        };
    }

    // -------------------------------------------------------------------------------------------
    // The clients
    // -------------------------------------------------------------------------------------------

    /** An HTTP/2 client's session with the corporate proxy, intercepted by MicroProxy. */
    private H2StreamClient h2Session() throws IOException {
        return closing(H2StreamClient.intercepted(proxy.getListenAddress(), corpTarget(), proxyCa.clientContext()));
    }

    /** An HTTP/1.1 client's session with the corporate proxy, intercepted by MicroProxy. */
    private SSLSocket h1Session(String... connectHeaders) throws IOException {
        Socket s = closing(new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort()));
        s.setSoTimeout(20_000);
        StringBuilder connect = new StringBuilder("CONNECT " + corpTarget() + " HTTP/1.1\r\nHost: " + corpTarget() + "\r\n");
        for (String h : connectHeaders) connect.append(h).append("\r\n");
        write(s.getOutputStream(), connect.append("\r\n").toString());
        String head = readUntil(s.getInputStream(), "\r\n\r\n");
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        return tls(s, "localhost", corp.getListenAddress().getPort(), "http/1.1");
    }

    /** A TLS handshake over {@code s} as a client trusting MicroProxy's CA. */
    private SSLSocket tls(Socket s, String host, int port, String alpn) throws IOException {
        SSLSocket tls = closing((SSLSocket) proxyCa.clientContext().getSocketFactory().createSocket(s, host, port, true));
        tls.setUseClientMode(true);
        SSLParameters params = tls.getSSLParameters();
        params.setApplicationProtocols(new String[] {alpn});
        tls.setSSLParameters(params);
        tls.setSoTimeout(20_000);
        tls.startHandshake();
        return tls;
    }

    /** Sends an HTTP/1.1 {@code CONNECT} inside {@code session} and returns the response head. */
    private static String connectInside(Socket session, String target, String... headers) throws IOException {
        StringBuilder connect = new StringBuilder("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n");
        for (String h : headers) connect.append(h).append("\r\n");
        write(session.getOutputStream(), connect.append("\r\n").toString());
        return readUntil(session.getInputStream(), "\r\n\r\n");
    }

    /** Reads the body {@code head} declares with its Content-Length. */
    private static String body(Socket session, String head) throws IOException {
        int length = Integer.parseInt(WebSocketTestSupport.header(head, "Content-Length"));
        return new String(session.getInputStream().readNBytes(length), StandardCharsets.UTF_8);
    }

    /** Sends {@code text}, ends the stream, and returns everything the tunnel sends back. */
    private static String roundTrip(H2StreamClient.Stream tunnel, String text) throws IOException {
        tunnel.out().write(text.getBytes(StandardCharsets.UTF_8));
        tunnel.end();
        return tunnel.text();
    }

    private static String echoBack(Socket tunnel, String text) throws IOException {
        write(tunnel.getOutputStream(), text);
        return new String(tunnel.getInputStream().readNBytes(text.length()), StandardCharsets.ISO_8859_1);
    }

    // -------------------------------------------------------------------------------------------
    // Raw tunnels through the corporate proxy
    // -------------------------------------------------------------------------------------------

    @Test
    void aConnectStreamGoesThroughTheCorporateProxyOverHttp2() throws Exception {
        TestSupport.RawServer echo = echoServer();
        startCorp(true, null);
        proxy = microProxy().withFiltersSource(interceptOnlyTheCorporateProxy()).start();
        try (H2StreamClient c = h2Session()) {
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(echo)), false);
            assertEquals(200, tunnel.status());
            assertNull(tunnel.header("content-length"));
            assertTrue(tunnel.header("via").contains("corp"), tunnel.header("via"));
            // Half-closes go through both proxies, each way.
            assertEquals("through the corporate proxy", roundTrip(tunnel, "through the corporate proxy"));
            assertNull(tunnel.awaitEnd());
            H2StreamClient.Stream second = c.open(H2StreamClient.connect(target(echo)), false);
            assertEquals(200, second.status());
            assertEquals("again", roundTrip(second, "again"));
        }
        // On a stream of the session's own HTTP/2 connection to the corporate proxy.
        assertEquals(List.of("CONNECT " + target(echo) + " HTTP/2.0 null", "CONNECT " + target(echo) + " HTTP/2.0 null"),
                corpSaw);
        assertEquals(1, corpConnections.get());
    }

    @Test
    void aConnectStreamGoesThroughAnHttp11CorporateProxy() throws Exception {
        TestSupport.RawServer echo = echoServer();
        startCorp(false, null);
        proxy = microProxy().withFiltersSource(interceptOnlyTheCorporateProxy()).start();
        try (H2StreamClient c = h2Session()) {
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(echo)), false);
            assertEquals(200, tunnel.status());
            assertEquals("over http/1.1", roundTrip(tunnel, "over http/1.1"));
            assertNull(tunnel.awaitEnd());
        }
        assertEquals(List.of("CONNECT " + target(echo) + " HTTP/1.1 null"), corpSaw);
    }

    @Test
    void anHttp11ClientsConnectInsideTheSessionGoesThroughTheCorporateProxy() throws Exception {
        TestSupport.RawServer echo = echoServer();
        startCorp(true, null);
        proxy = microProxy().withFiltersSource(interceptOnlyTheCorporateProxy()).start();
        SSLSocket session = h1Session();
        String head = connectInside(session, target(echo));
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        assertEquals("over h2 upstream", echoBack(session, "over h2 upstream"));
        assertEquals(List.of("CONNECT " + target(echo) + " HTTP/2.0 null"), corpSaw);
    }

    @Test
    void anHttp11ClientThroughAnHttp11CorporateProxy() throws Exception {
        TestSupport.RawServer echo = echoServer();
        startCorp(false, null);
        proxy = microProxy().withFiltersSource(interceptOnlyTheCorporateProxy()).start();
        SSLSocket session = h1Session();
        String head = connectInside(session, target(echo));
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        assertEquals("all http/1.1", echoBack(session, "all http/1.1"));
        assertEquals(List.of("CONNECT " + target(echo) + " HTTP/1.1 null"), corpSaw);
        // The connection made for the session carried the tunnel.
        assertEquals(1, corpConnections.get());
    }

    // -------------------------------------------------------------------------------------------
    // Authentication with the corporate proxy
    // -------------------------------------------------------------------------------------------

    @Test
    void theCorporateProxysChallengeAndTheClientsCredentialsPassThrough() throws Exception {
        TestSupport.RawServer echo = echoServer();
        startCorp(true, basic("corp-user", "corp-secret", "corp"));
        proxy = microProxy().withFiltersSource(interceptOnlyTheCorporateProxy()).start();
        try (H2StreamClient c = h2Session()) {
            H2StreamClient.Stream refused = c.open(H2StreamClient.connect(target(echo)), false);
            assertEquals(407, refused.status());
            assertEquals("Basic realm=\"corp\"", refused.header("proxy-authenticate"));
            assertEquals("Proxy Authentication Required\n", refused.text());
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(echo), "proxy-authorization",
                    CORP_CREDENTIALS), false);
            assertEquals(200, tunnel.status());
            assertEquals("authenticated", roundTrip(tunnel, "authenticated"));
        }
        assertEquals(List.of("CONNECT " + target(echo) + " HTTP/2.0 null",
                "CONNECT " + target(echo) + " HTTP/2.0 " + CORP_CREDENTIALS), corpSaw);
    }

    @Test
    void anHttp11ClientRetriesWithCredentialsOnTheSameSession() throws Exception {
        TestSupport.RawServer echo = echoServer();
        startCorp(false, basic("corp-user", "corp-secret", "corp"));
        // MicroProxy authenticates its own clients: the CONNECT to it carries its own credentials.
        proxy = microProxy().withFiltersSource(interceptOnlyTheCorporateProxy())
                .withProxyAuthenticator(basic("mp-user", "mp-secret", "mp")).start();
        SSLSocket session = h1Session("Proxy-Authorization: " + PROXY_CREDENTIALS);
        String refused = connectInside(session, target(echo));
        assertTrue(refused.startsWith("HTTP/1.1 407"), refused);
        assertEquals("Basic realm=\"corp\"", WebSocketTestSupport.header(refused, "Proxy-Authenticate"));
        assertEquals("Proxy Authentication Required\n", body(session, refused));
        String head = connectInside(session, target(echo), "Proxy-Authorization: " + CORP_CREDENTIALS);
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        assertEquals("second try", echoBack(session, "second try"));
        // The corporate proxy got its own credentials, never MicroProxy's.
        assertEquals(List.of("CONNECT " + target(echo) + " HTTP/1.1 null",
                "CONNECT " + target(echo) + " HTTP/1.1 " + CORP_CREDENTIALS), corpSaw);
    }

    // -------------------------------------------------------------------------------------------
    // Filters
    // -------------------------------------------------------------------------------------------

    @Test
    void filtersSeeRejectAndRewriteTheForwardedConnect() throws Exception {
        TestSupport.RawServer echo = echoServer();
        startCorp(true, null);
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = microProxy().withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public boolean proxyToServerAllowMitm() {
                return ctx.forwardedVia().isEmpty();
            }

            @Override
            public HttpResponse clientToProxyRequest(HttpObject o) {
                if (o instanceof HttpRequest r) {
                    seen.add(r.method() + " " + r.uri() + " via=" + ctx.forwardedVia().orElse("-"));
                    if (r.uri().startsWith("blocked.test")) {
                        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN,
                                "not through here".getBytes(StandardCharsets.UTF_8));
                    }
                }
                return null;
            }

            @Override
            public HttpResponse proxyToServerRequest(HttpObject o) {
                if (o instanceof HttpRequest r && r.uri().startsWith("rewritten.test")) r.setUri(target(echo));
                return null;
            }
        }).start();
        try (H2StreamClient c = h2Session()) {
            H2StreamClient.Stream blocked = c.open(H2StreamClient.connect("blocked.test:443"), false);
            assertEquals(403, blocked.status());
            assertEquals("not through here", blocked.text());
            H2StreamClient.Stream rewritten = c.open(H2StreamClient.connect("rewritten.test:443"), false);
            assertEquals(200, rewritten.status());
            assertEquals("rewritten", roundTrip(rewritten, "rewritten"));
        }
        assertEquals(List.of("CONNECT " + corpTarget() + " via=-", "CONNECT blocked.test:443 via=" + corpTarget(),
                "CONNECT rewritten.test:443 via=" + corpTarget()), seen);
        assertEquals(List.of("CONNECT " + target(echo) + " HTTP/2.0 null"), corpSaw);
    }

    // -------------------------------------------------------------------------------------------
    // Interception inside the tunnel
    // -------------------------------------------------------------------------------------------

    /** Records what MicroProxy's filters see: requests, and the server connections made. */
    private static HttpFiltersSource recording(List<String> seen) {
        return (original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public HttpResponse clientToProxyRequest(HttpObject o) {
                if (o instanceof HttpRequest r) seen.add(r.method() + " " + r.uri() + " via=" + ctx.forwardedVia().orElse("-"));
                return null;
            }

            @Override
            public void proxyToServerConnectionSucceeded(FullFlowContext serverCtx) {
                ChainedProxy chained = serverCtx.getChainedProxy();
                seen.add("connected " + serverCtx.getServerHostAndPort() + " through "
                        + (chained == null ? "-" : chained.getChainedProxyAddress().getHostString() + ":"
                                + chained.getChainedProxyAddress().getPort()));
            }
        };
    }

    @Test
    void theTunnelsTlsIsInterceptedWithTheCorporateProxyAsTheChainedHop() throws Exception {
        HttpsServer origin = httpsOrigin(TestSupport.echo());
        String target = "localhost:" + origin.getAddress().getPort();
        startCorp(true, null);
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = microProxy().withFiltersSource(recording(seen)).start();
        try (H2StreamClient c = h2Session()) {
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target), false);
            assertEquals(200, tunnel.status());
            // The client trusts only MicroProxy's CA: this works only if the tunnel is intercepted.
            SSLSocket tls = tls(tunnel.asSocket(), "localhost", origin.getAddress().getPort(), "http/1.1");
            write(tls.getOutputStream(), "GET /inner?q=1 HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
            String head = readUntil(tls.getInputStream(), "\r\n\r\n");
            assertTrue(head.startsWith("HTTP/1.1 200"), head);
            String body = body(tls, head);
            assertEquals("/inner?q=1", echoedUri(body));
            assertEquals(List.of("1.1 mp"), echoedHeader(body, "via"));
            tls.close();
            assertNull(tunnel.awaitEnd());
        }
        assertEquals(List.of("CONNECT " + target + " HTTP/2.0 null"), corpSaw);
        String corpAddress = "localhost:" + corp.getListenAddress().getPort();
        assertEquals(List.of("CONNECT " + corpTarget() + " via=-", "connected " + corpTarget() + " through -",
                "CONNECT " + target + " via=" + corpTarget(), "connected " + target + " through " + corpAddress,
                "GET /inner?q=1 via=" + corpTarget()), seen);
    }

    @Test
    void anHttp11ClientsInterceptedTunnelOpensMoreTunnelsAsItNeedsThem() throws Exception {
        // Every response closes its connection: each request needs a new tunnel.
        HttpsServer origin = httpsOrigin(exchange -> {
            exchange.getResponseHeaders().set("Connection", "close");
            TestSupport.echo().handle(exchange);
        });
        String target = "localhost:" + origin.getAddress().getPort();
        startCorp(false, null);
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = microProxy().withFiltersSource(recording(seen)).start();
        SSLSocket session = h1Session();
        String head = connectInside(session, target, "Proxy-Authorization: " + CORP_CREDENTIALS);
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        // HTTP/2 inside the tunnel, to an HTTP/1.1 origin.
        SSLSocket inner = tls(session, "localhost", origin.getAddress().getPort(), "h2");
        assertEquals("h2", inner.getApplicationProtocol());
        try (H2TestClient h2 = H2TestClient.over(inner, target).handshake()) {
            for (int stream = 1; stream <= 5; stream += 2) {
                h2.get(stream, "/n" + stream);
                H2TestClient.Response response = h2.response(stream);
                assertEquals(200, response.status());
                assertEquals("/n" + stream, echoedUri(response.text()));
            }
        }
        // Each tunnel was opened with the client's credentials for the corporate proxy.
        eventually("three tunnels", () -> corpSaw.size() >= 3);
        for (String request : corpSaw) assertEquals("CONNECT " + target + " HTTP/1.1 " + CORP_CREDENTIALS, request);
        assertTrue(seen.containsAll(List.of("GET /n1 via=" + corpTarget(), "GET /n3 via=" + corpTarget(),
                "GET /n5 via=" + corpTarget())), seen.toString());
    }

    @Test
    void aTunnelToAServerThatDoesNotSpeakTlsIsRelayedAsItIs() throws Exception {
        // Answers a TLS ClientHello in plain text; echoes anything else.
        TestSupport.RawServer echo = closing(TestSupport.rawServer(s -> {
            int first = s.getInputStream().read();
            if (first == 0x16) {
                write(s.getOutputStream(), "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
                // Ends its side, then reads the rest of the ClientHello (and anything after it)
                // until the client is done: a socket closed with bytes unread is reset, and the
                // reset can overtake the answer, through the corporate proxy's tunnel too.
                s.shutdownOutput();
                s.getInputStream().transferTo(OutputStream.nullOutputStream());
            } else if (first >= 0) {
                s.getOutputStream().write(first);
                s.getInputStream().transferTo(s.getOutputStream());
            }
        }));
        startCorp(true, null);
        proxy = microProxy().start();
        try (H2StreamClient c = h2Session()) {
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(echo)), false);
            assertEquals(200, tunnel.status());
            assertEquals("plain bytes", roundTrip(tunnel, "plain bytes"));
        }
        // The first tunnel ended with the failed handshake; the client got a second, plain one.
        assertEquals(List.of("CONNECT " + target(echo) + " HTTP/2.0 null", "CONNECT " + target(echo) + " HTTP/2.0 null"),
                corpSaw);
    }

    // -------------------------------------------------------------------------------------------
    // Resets
    // -------------------------------------------------------------------------------------------

    @Test
    void endingForwardedTunnelsWithResetsIsNotARapidReset() throws Exception {
        AtomicInteger ended = new AtomicInteger();
        TestSupport.RawServer echo = closing(TestSupport.rawServer(s -> {
            try {
                s.getInputStream().transferTo(s.getOutputStream());
            } finally {
                ended.incrementAndGet();
            }
        }));
        startCorp(true, null);
        proxy = microProxy().withFiltersSource(interceptOnlyTheCorporateProxy())
                .withHttp2Options(Http2Options.builder().maxRapidResets(3).build()).start();
        try (H2StreamClient c = h2Session()) {
            for (int i = 0; i < 10; i++) {
                H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(echo)), false);
                assertEquals(200, tunnel.status());
                assertEquals("x", echoBack(tunnel, "x"));
                tunnel.reset(ErrorCode.CANCEL);
            }
            // Each reset went on to the corporate proxy, which closed its tunnel.
            eventually("the reset tunnels to end", () -> ended.get() == 10);
            H2StreamClient.Stream last = c.open(H2StreamClient.connect(target(echo)), false);
            assertEquals(200, last.status());
            assertEquals("still open", roundTrip(last, "still open"));
            assertNull(c.goAway());
        }
        assertEquals(11, corpSaw.size());
    }

    private static String echoBack(H2StreamClient.Stream tunnel, String text) throws IOException {
        tunnel.out().write(text.getBytes(StandardCharsets.UTF_8));
        return new String(tunnel.in().readNBytes(text.length()), StandardCharsets.UTF_8);
    }

    @Test
    void aServerResetResetsTheClientsStream() throws Exception {
        TestSupport.RawServer server = closing(TestSupport.rawServer(s -> {
            s.getInputStream().read();
            s.setSoLinger(true, 0);
        }));
        startCorp(true, null);
        proxy = microProxy().withFiltersSource(interceptOnlyTheCorporateProxy()).start();
        try (H2StreamClient c = h2Session()) {
            H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target(server)), false);
            assertEquals(200, tunnel.status());
            tunnel.out().write('x');
            assertEquals(ErrorCode.CANCEL, tunnel.awaitReset());
            // The session goes on.
            assertEquals(200, c.open(H2StreamClient.connect(target(server)), false).status());
        }
    }

    // -------------------------------------------------------------------------------------------
    // What still gets 421
    // -------------------------------------------------------------------------------------------

    @Test
    void requestsForAnotherAuthorityStillGetMisdirectedRequest() throws Exception {
        startCorp(true, null);
        proxy = microProxy().start();
        try (H2StreamClient c = h2Session()) {
            List<HeaderField> get = new ArrayList<>(c.request("GET", "/x"));
            get.set(2, new HeaderField(":authority", "other.example:443"));
            assertEquals(421, c.open(get, true).status());
            // A WebSocket (extended CONNECT) for another authority too.
            List<HeaderField> ws = new ArrayList<>(c.webSocket("/chat"));
            ws.set(3, new HeaderField(":authority", "other.example:443"));
            assertEquals(421, c.open(ws, false).status());
        }
        assertEquals(List.of(), corpSaw);
    }
}
