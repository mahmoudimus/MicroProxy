package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.readUntil;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.WebSocketMessage;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * MicroProxy in front of a plain-HTTP proxy: the client tunnels to a corporate proxy (a second
 * MicroProxy, a plain forward proxy) through MicroProxy, which sees plain HTTP in the tunnel and
 * serves it as HTTP. The client then uses the corporate proxy as it would without MicroProxy:
 * absolute-form requests, and {@code CONNECT}s for tunnels. MicroProxy forwards both there, never
 * straight to the target, unless a filter points a request at an absolute URI of its own.
 */
@Timeout(60)
class HttpProxyForwardingTest {

    /** Signs the origins' certificates, which MicroProxy trusts. */
    static final CertificateAuthority serverCa = CertificateAuthority.generate("Plain Forwarding Server CA");
    /** MicroProxy's interception CA, which the clients trust. */
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("Plain Forwarding Proxy CA");

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

    /** Starts the corporate proxy: a plain forward proxy, asking for credentials if {@code authenticator}. */
    private void startCorp(ProxyAuthenticator authenticator) {
        HttpProxyServerBootstrap b = MicroProxy.bootstrap().withPort(0).withProxyAlias("corp")
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
        if (authenticator != null) b.withProxyAuthenticator(authenticator);
        corp = b.start();
    }

    /** MicroProxy: intercepts, which is what serves plain HTTP inside a tunnel as HTTP. */
    private static HttpProxyServerBootstrap microProxy() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("mp")
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, serverCa.clientContext()));
    }

    /** Filters that intercept nothing inside the tunnels through the corporate proxy. */
    private static HttpFiltersSource interceptOnlyTheCorporateProxy() {
        return (original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public boolean proxyToServerAllowMitm() {
                return ctx.forwardedVia().isEmpty();
            }
        };
    }

    private String corpTarget() {
        return "127.0.0.1:" + corp.getListenAddress().getPort();
    }

    private HttpServer origin(String name) {
        HttpServer origin = TestSupport.origin(exchange -> {
            exchange.getResponseHeaders().set("X-Origin", name);
            TestSupport.echo().handle(exchange);
        });
        closeables.add(() -> origin.stop(0));
        return origin;
    }

    private HttpsServer httpsOrigin() {
        HttpsServer origin = TestSupport.httpsOrigin(serverCa.serverContext("localhost", "127.0.0.1"), TestSupport.echo());
        closeables.add(() -> origin.stop(0));
        return origin;
    }

    private static String authority(HttpServer server) {
        return "127.0.0.1:" + server.getAddress().getPort();
    }

    /** A raw TCP server that echoes what it reads. */
    private TestSupport.RawServer echoServer() {
        return closing(TestSupport.rawServer(s -> s.getInputStream().transferTo(s.getOutputStream())));
    }

    static ProxyAuthenticator basic(String user, String password, String realm) {
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

    /** A client's plain HTTP session with the corporate proxy, through MicroProxy. */
    private Socket plainSession(String... connectHeaders) throws IOException {
        Socket s = closing(new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort()));
        s.setSoTimeout(20_000);
        String head = request(s, "CONNECT " + corpTarget() + " HTTP/1.1", corpTarget(), connectHeaders);
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        return s;
    }

    /** Sends a request head ({@code requestLine}, {@code Host}, {@code headers}) and returns the response head. */
    private static String request(Socket s, String requestLine, String host, String... headers) throws IOException {
        StringBuilder request = new StringBuilder(requestLine + "\r\nHost: " + host + "\r\n");
        for (String h : headers) request.append(h).append("\r\n");
        write(s.getOutputStream(), request.append("\r\n").toString());
        return readUntil(s.getInputStream(), "\r\n\r\n");
    }

    /** Sends an absolute-form GET for {@code http://authority/path} and returns the response head. */
    private static String get(Socket s, String authority, String path, String... headers) throws IOException {
        return request(s, "GET http://" + authority + path + " HTTP/1.1", authority, headers);
    }

    /** Reads the body {@code head} declares with its Content-Length. */
    private static String body(Socket s, String head) throws IOException {
        int length = Integer.parseInt(WebSocketTestSupport.header(head, "Content-Length"));
        return new String(s.getInputStream().readNBytes(length), StandardCharsets.UTF_8);
    }

    private static String echoBack(Socket tunnel, String text) throws IOException {
        write(tunnel.getOutputStream(), text);
        return new String(tunnel.getInputStream().readNBytes(text.length()), StandardCharsets.ISO_8859_1);
    }

    /** A TLS handshake over {@code s} as a client trusting MicroProxy's CA, offering {@code alpn}. */
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

    /** Records what MicroProxy's filters see: requests, where they go, and the server connections made. */
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

    // -------------------------------------------------------------------------------------------
    // Absolute-form requests
    // -------------------------------------------------------------------------------------------

    @Test
    void absoluteFormRequestsGoThroughTheHttpProxy() throws Exception {
        HttpServer origin = origin("first");
        HttpServer other = origin("other");
        startCorp(null);
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = microProxy().withFiltersSource(recording(seen)).start();
        Socket session = plainSession();
        String head = get(session, authority(origin), "/a?q=1");
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        assertEquals("first", WebSocketTestSupport.header(head, "X-Origin"));
        String body = body(session, head);
        // The corporate proxy made it origin-form for the origin; both proxies are on the way.
        assertEquals("/a?q=1", echoedUri(body));
        assertEquals(List.of("1.1 mp", "1.1 corp"), echoedHeader(body, "via"));
        assertTrue(WebSocketTestSupport.header(head, "Via").contains("corp"), head);
        // Another origin, on the same session and the same connection to the corporate proxy.
        String second = get(session, authority(other), "/b");
        assertEquals("other", WebSocketTestSupport.header(second, "X-Origin"));
        assertEquals("/b", echoedUri(body(session, second)));
        assertEquals(List.of("GET http://" + authority(origin) + "/a?q=1 HTTP/1.1 null",
                "GET http://" + authority(other) + "/b HTTP/1.1 null"), corpSaw);
        assertEquals(1, corpConnections.get());
        assertEquals(List.of("CONNECT " + corpTarget() + " via=-", "connected " + corpTarget() + " through -",
                "GET http://" + authority(origin) + "/a?q=1 via=" + corpTarget(),
                "GET http://" + authority(other) + "/b via=" + corpTarget()), seen);
    }

    @Test
    void aSharedPoolNeverCarriesProxyRequests() throws Exception {
        HttpServer origin = origin("first");
        startCorp(null);
        proxy = microProxy().withSharedServerConnectionPool(true).start();
        Socket session = plainSession();
        for (int i = 0; i < 3; i++) {
            String head = get(session, authority(origin), "/" + i, "Proxy-Authorization: " + CORP_CREDENTIALS);
            assertTrue(head.startsWith("HTTP/1.1 200"), head);
            assertEquals("/" + i, echoedUri(body(session, head)));
        }
        for (String request : corpSaw) assertTrue(request.endsWith(CORP_CREDENTIALS), request);
        assertEquals(3, corpSaw.size());
    }

    // -------------------------------------------------------------------------------------------
    // CONNECT
    // -------------------------------------------------------------------------------------------

    @Test
    void aConnectGoesThroughTheHttpProxy() throws Exception {
        TestSupport.RawServer echo = echoServer();
        String target = "127.0.0.1:" + echo.port();
        startCorp(null);
        proxy = microProxy().withFiltersSource(interceptOnlyTheCorporateProxy()).start();
        Socket session = plainSession();
        String head = request(session, "CONNECT " + target + " HTTP/1.1", target);
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        assertTrue(WebSocketTestSupport.header(head, "Via").contains("corp"), head);
        assertEquals("through the http proxy", echoBack(session, "through the http proxy"));
        assertEquals(List.of("CONNECT " + target + " HTTP/1.1 null"), corpSaw);
        // The connection made for the session carried the tunnel.
        assertEquals(1, corpConnections.get());
    }

    @Test
    void theTunnelsTlsIsInterceptedWithTheHttpProxyAsTheChainedHop() throws Exception {
        HttpsServer origin = httpsOrigin();
        int port = origin.getAddress().getPort();
        String target = "localhost:" + port;
        startCorp(null);
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = microProxy().withFiltersSource(recording(seen)).start();
        Socket session = plainSession();
        String head = request(session, "CONNECT " + target + " HTTP/1.1", target,
                "Proxy-Authorization: " + CORP_CREDENTIALS);
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        // The client trusts only MicroProxy's CA: this works only if the tunnel is intercepted.
        SSLSocket tls = tls(session, "localhost", port, "http/1.1");
        for (String path : List.of("/one", "/two")) {
            String response = request(tls, "GET " + path + " HTTP/1.1", target);
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            String body = body(tls, response);
            assertEquals(path, echoedUri(body));
            assertEquals(List.of("1.1 mp"), echoedHeader(body, "via"));
        }
        assertEquals(List.of("CONNECT " + target + " HTTP/1.1 " + CORP_CREDENTIALS), corpSaw);
        assertEquals(List.of("CONNECT " + corpTarget() + " via=-", "connected " + corpTarget() + " through -",
                "CONNECT " + target + " via=" + corpTarget(), "connected " + target + " through " + corpTarget(),
                "GET /one via=" + corpTarget(), "GET /two via=" + corpTarget()), seen);
    }

    // -------------------------------------------------------------------------------------------
    // Authentication with the HTTP proxy
    // -------------------------------------------------------------------------------------------

    @Test
    void theHttpProxysChallengeAndTheClientsCredentialsPassThrough() throws Exception {
        HttpServer origin = origin("first");
        TestSupport.RawServer echo = echoServer();
        String target = "127.0.0.1:" + echo.port();
        startCorp(basic("corp-user", "corp-secret", "corp"));
        // MicroProxy authenticates its own clients: the CONNECT to it carries its own credentials.
        proxy = microProxy().withFiltersSource(interceptOnlyTheCorporateProxy())
                .withProxyAuthenticator(basic("mp-user", "mp-secret", "mp")).start();
        Socket session = plainSession("Proxy-Authorization: " + PROXY_CREDENTIALS);

        String refusedTunnel = request(session, "CONNECT " + target + " HTTP/1.1", target);
        assertTrue(refusedTunnel.startsWith("HTTP/1.1 407"), refusedTunnel);
        assertEquals("Basic realm=\"corp\"", WebSocketTestSupport.header(refusedTunnel, "Proxy-Authenticate"));
        assertEquals("Proxy Authentication Required\n", body(session, refusedTunnel));

        String refused = get(session, authority(origin), "/private");
        assertTrue(refused.startsWith("HTTP/1.1 407"), refused);
        assertEquals("Basic realm=\"corp\"", WebSocketTestSupport.header(refused, "Proxy-Authenticate"));
        assertEquals("Proxy Authentication Required\n", body(session, refused));
        String allowed = get(session, authority(origin), "/private", "Proxy-Authorization: " + CORP_CREDENTIALS);
        assertTrue(allowed.startsWith("HTTP/1.1 200"), allowed);
        String body = body(session, allowed);
        assertEquals("/private", echoedUri(body));
        // The corporate proxy took its credentials: the origin never sees them.
        assertEquals(List.of(), echoedHeader(body, "proxy-authorization"));

        String tunnel = request(session, "CONNECT " + target + " HTTP/1.1", target,
                "Proxy-Authorization: " + CORP_CREDENTIALS);
        assertTrue(tunnel.startsWith("HTTP/1.1 200"), tunnel);
        assertEquals("authenticated", echoBack(session, "authenticated"));

        // The corporate proxy got its own credentials, never MicroProxy's.
        assertEquals(List.of("CONNECT " + target + " HTTP/1.1 null",
                "GET http://" + authority(origin) + "/private HTTP/1.1 null",
                "GET http://" + authority(origin) + "/private HTTP/1.1 " + CORP_CREDENTIALS,
                "CONNECT " + target + " HTTP/1.1 " + CORP_CREDENTIALS), corpSaw);
    }

    // -------------------------------------------------------------------------------------------
    // WebSockets through the HTTP proxy
    // -------------------------------------------------------------------------------------------

    /** Filters that upper-case every text message the client sends. */
    private static HttpFiltersSource shoutingClientMessages() {
        return (original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public WebSocketMessage filterWebSocketMessage(WebSocketMessage message, boolean fromClient) {
                return fromClient && message.isText() ? message.withText(message.text().toUpperCase(Locale.ROOT))
                        : message;
            }
        };
    }

    /** Asks for a WebSocket upgrade with {@code requestLine}, offering permessage-deflate, over {@code s}. */
    private static WebSocketPeer upgrade(Socket s, String requestLine, String host) throws IOException {
        String head = request(s, requestLine, host, "Upgrade: websocket", "Connection: Upgrade",
                "Sec-WebSocket-Version: 13", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Extensions: permessage-deflate");
        assertTrue(head.startsWith("HTTP/1.1 101"), head);
        return WebSocketPeer.client(s.getInputStream(), s.getOutputStream(),
                WebSocketPeer.Agreement.parse(WebSocketTestSupport.header(head, "Sec-WebSocket-Extensions")));
    }

    @Test
    void anAbsoluteFormWebSocketThroughTheHttpProxyGetsTheMessageHooks() throws Exception {
        startCorp(null);
        proxy = microProxy().withFiltersSource(shoutingClientMessages()).start();
        try (WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate")) {
            String target = "127.0.0.1:" + server.port();
            Socket session = plainSession();
            WebSocketPeer ws = upgrade(session, "GET http://" + target + "/chat HTTP/1.1", target);
            ws.sendText("ping through the http proxy");
            assertEquals("echo:PING THROUGH THE HTTP PROXY", ws.readMessage().text());
            assertEquals(List.of("PING THROUGH THE HTTP PROXY"), server.texts());
            assertEquals(List.of("GET http://" + target + "/chat HTTP/1.1 null"), corpSaw);
        }
    }

    @Test
    void aWebSocketInATunnelThroughTheHttpProxyGetsTheMessageHooks() throws Exception {
        startCorp(null);
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = microProxy().withFiltersSource(HttpFiltersChain.of(recording(seen), shoutingClientMessages())).start();
        try (WebSocketPeer.Server server =
                new WebSocketPeer.Server("permessage-deflate", serverCa.serverContext("localhost", "127.0.0.1"))) {
            String target = "localhost:" + server.port();
            Socket session = plainSession();
            String head = request(session, "CONNECT " + target + " HTTP/1.1", target);
            assertTrue(head.startsWith("HTTP/1.1 200"), head);
            // The TLS in the tunnel the HTTP proxy opened is intercepted, and the upgrade inside it too.
            SSLSocket tls = tls(session, "localhost", server.port(), "http/1.1");
            WebSocketPeer ws = upgrade(tls, "GET /chat HTTP/1.1", target);
            ws.sendText("ping through the tunnel");
            assertEquals("echo:PING THROUGH THE TUNNEL", ws.readMessage().text());
            assertEquals(List.of("PING THROUGH THE TUNNEL"), server.texts());
            assertEquals(List.of("CONNECT " + target + " HTTP/1.1 null"), corpSaw);
            assertTrue(seen.contains("GET /chat via=" + corpTarget()), seen.toString());
        }
    }

    // -------------------------------------------------------------------------------------------
    // Absolute URIs from filters
    // -------------------------------------------------------------------------------------------

    @Test
    void anAbsoluteUriFromAFilterStillGoesStraightToItsServer() throws Exception {
        HttpServer origin = origin("first");
        HttpServer other = origin("other");
        startCorp(null);
        List<String> sent = new CopyOnWriteArrayList<>();
        String elsewhere = "http://" + authority(other);
        proxy = microProxy().withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public HttpResponse clientToProxyRequest(HttpObject o) {
                if (o instanceof HttpRequest r && r.uri().contains("/elsewhere/")) {
                    r.setUri(elsewhere + r.uri().substring(r.uri().indexOf("/elsewhere/") + "/elsewhere".length()));
                }
                return null;
            }

            @Override
            public HttpResponse proxyToServerRequest(HttpObject o) {
                if (o instanceof HttpRequest r) sent.add(r.method() + " " + r.uri() + " via=" + ctx.forwardedVia().orElse("-"));
                return null;
            }
        }).start();
        Socket session = plainSession();
        // A filter's absolute URI, for an origin-form request and for the client's absolute one,
        // takes the request straight to that URI's server: the filter, not the client, chose it.
        String moved = request(session, "GET /elsewhere/a HTTP/1.1", corpTarget());
        assertEquals("other", WebSocketTestSupport.header(moved, "X-Origin"));
        assertEquals("/a", echoedUri(body(session, moved)));
        String movedAbsolute = get(session, authority(origin), "/elsewhere/b");
        assertEquals("other", WebSocketTestSupport.header(movedAbsolute, "X-Origin"));
        String body = body(session, movedAbsolute);
        assertEquals("/b", echoedUri(body));
        assertEquals(List.of("1.1 mp"), echoedHeader(body, "via"));
        // The client's own absolute URI goes through the HTTP proxy.
        String stayed = get(session, authority(origin), "/c");
        assertEquals("first", WebSocketTestSupport.header(stayed, "X-Origin"));
        assertEquals("/c", echoedUri(body(session, stayed)));
        assertEquals(List.of("GET http://" + authority(origin) + "/c HTTP/1.1 null"), corpSaw);
        assertEquals(List.of("CONNECT " + corpTarget() + " via=-", "GET /a via=-", "GET /b via=-",
                "GET http://" + authority(origin) + "/c via=" + corpTarget()), sent);
    }
}
