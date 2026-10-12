package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.http2.HeaderField;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.stats.Counter;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SslContexts;

/**
 * TLS origination: a forward proxy's client that asks for an {@code https://} URI directly, rather
 * than through {@code CONNECT} (an absolute-form request over plain HTTP/1.1, or a {@code :scheme
 * https} stream on an {@code h2c} connection), has it fetched over TLS that the proxy opens to the
 * server: checked with the MITM manager's server trust, pooled, over HTTP/2 or HTTP/3 when the
 * server speaks it, and through a chained proxy's tunnel. {@link
 * HttpProxyServerBootstrap#withTlsOrigination} turns it off, and such requests are refused.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class TlsOriginationTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("TLS Origination Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("TLS Origination Proxy CA");
    static final CertificateAuthority strangerCa = CertificateAuthority.generate("TLS Origination Stranger CA");

    private HttpsServer origin;
    private HttpProxyServer proxy;
    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final RecordedFlows flows = new RecordedFlows();
    /** The servers (host:port) each new server connection went to. */
    private final List<String> connected = new CopyOnWriteArrayList<>();
    /** The URIs the filters saw requests arrive with. */
    private final List<String> seen = new CopyOnWriteArrayList<>();

    @BeforeEach
    void startOrigin() {
        origin = httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"));
    }

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        origin.stop(0);
        for (AutoCloseable c : closeables) c.close();
    }

    private HttpsServer httpsOrigin(javax.net.ssl.SSLContext context) {
        return TestSupport.httpsOrigin(context, exchange -> {
            exchange.getResponseHeaders().set("X-Origin", "tls");
            TestSupport.echo().handle(exchange);
        });
    }

    /** A forward proxy that trusts the origin's CA for its TLS to servers, as intercepted sessions do. */
    private HttpProxyServerBootstrap forward() {
        return forward(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()));
    }

    private HttpProxyServerBootstrap forward(MitmManager mitm) {
        HttpProxyServerBootstrap b = MicroProxy.bootstrap().withPort(0).withProxyAlias("orig")
                .plusActivityTracker(flows)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void serverConnected(FullFlowContext ctx, InetSocketAddress address) {
                        connected.add(ctx.getServerHostAndPort());
                    }
                })
                .withFiltersSource(HttpFilters.builder().onRequest(req -> {
                    seen.add(req.uri());
                    return null;
                }).build());
        return mitm == null ? b : b.withManInTheMiddle(mitm);
    }

    private static String authority(HttpServer server) {
        return "127.0.0.1:" + server.getAddress().getPort();
    }

    private static String https(HttpServer server, String path) {
        return "https://" + authority(server) + path;
    }

    /**
     * Waits until the shared pool holds {@code idle} idle connections: a connection leased for one
     * request goes back to it only after the response has been written.
     */
    private void awaitIdlePooled(int idle) {
        TestSupport.eventually(idle + " idle pooled connections",
                () -> proxy.getServerConnectionPoolMetrics().idleConnections() == idle);
    }

    private static EnumSet<ResponseFlag> flags(ResponseFlag... flags) {
        EnumSet<ResponseFlag> set = EnumSet.noneOf(ResponseFlag.class);
        set.addAll(List.of(flags));
        return set;
    }

    // --- HTTP/1.1 clients --------------------------------------------------------------------

    @Test
    void anAbsoluteHttpsUriOverPlainHttp1IsFetchedOverTls() throws Exception {
        StatsRegistry stats = StatsRegistry.create();
        proxy = forward().withStats(stats).start();
        try (Http1 client = new Http1(proxy)) {
            Http1.Response get = client.send("GET", https(origin, "/a?x=1"), null, "X-Test", "yes");
            assertEquals(200, get.status(), get.toString());
            assertEquals("tls", get.header("x-origin"));
            // The server got the request in origin-form, its Host the URI's authority, with Via.
            assertEquals("/a?x=1", echoedUri(get.body()));
            assertEquals(List.of(authority(origin)), echoedHeader(get.body(), HttpHeaderNames.HOST));
            assertEquals(List.of("yes"), echoedHeader(get.body(), "x-test"));
            assertEquals(List.of("1.1 orig"), echoedHeader(get.body(), HttpHeaderNames.VIA));

            Http1.Response post = client.send("POST", https(origin, "/submit"), "form=1&b=2",
                    "Content-Type", "application/x-www-form-urlencoded");
            assertEquals(200, post.status());
            assertEquals("method: POST", post.body().lines().findFirst().orElseThrow());
            assertEquals("form=1&b=2", echoedBody(post.body()));
        }
        // Filters saw the https:// URIs as the client sent them.
        assertEquals(List.of(https(origin, "/a?x=1"), https(origin, "/submit")), seen);
        // One TLS connection, reused by the client connection's second request.
        assertEquals(List.of(authority(origin)), connected);
        FlowRecord r = flows.await("a 200 record", f -> f.responseCode() == 200);
        assertTrue(r.responseFlags().isEmpty(), r.toString());
        assertEquals(ResponseSource.SERVER, r.source());
        assertNotNull(r.upstreamSslSession(), "the record has the server's TLS session");
        assertEquals(https(origin, "/a?x=1"), r.request().uri());
        assertEquals(1, ((Counter) stats.get("cluster.direct.ssl.handshake")).value());
    }

    @Test
    void aSecondClientReusesThePooledConnectionOfAnInterceptedSession() throws Exception {
        // With the shared pool, TLS connections of intercepted sessions and of TLS origination are
        // the same kind of connection, under the same key: either reuses the other's.
        proxy = forward().withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true)
                .withPoolPerRequestInMitm(true).start();
        assertEquals("tls", TestSupport.get(TestSupport.client(proxy, proxyCa.clientContext()),
                TestSupport.url(origin, "/intercepted")).headers().firstValue("X-Origin").orElseThrow());
        for (int i = 0; i < 3; i++) {
            awaitIdlePooled(1);
            try (Http1 client = new Http1(proxy)) {
                Http1.Response r = client.send("GET", https(origin, "/originated/" + i), null);
                assertEquals(200, r.status());
                assertEquals("/originated/" + i, echoedUri(r.body()));
            }
        }
        assertEquals(List.of(authority(origin)), connected, "one connection for the session and every client");
    }

    @Test
    void connectionsAreKeptApartByRoute() throws Exception {
        // Requests marked X-Route: chain go through a chained proxy; the others directly. Each
        // route has its own pooled connection to the server.
        ChainTestSupport.RequestLog chainLog = new ChainTestSupport.RequestLog();
        HttpProxyServer chain = MicroProxy.bootstrap().withPort(0).plusActivityTracker(chainLog).start();
        closeables.add(chain::abort);
        ChainedProxy viaChain = ChainTestSupport.http(chain.getListenAddress());
        proxy = forward().withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true)
                .withPoolPerRequestInMitm(true)
                .withChainProxyManager((request, queue, details) -> queue.add(
                        request.headers().contains("X-Route") ? viaChain : ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION))
                .start();
        for (int i = 0; i < 2; i++) {
            awaitIdlePooled(2 * i);
            try (Http1 client = new Http1(proxy)) {
                assertEquals(200, client.send("GET", https(origin, "/direct"), null).status());
                Http1.Response chained = client.send("GET", https(origin, "/chained"), null, "X-Route", "chain");
                assertEquals(200, chained.status());
                assertEquals("/chained", echoedUri(chained.body()));
            }
        }
        // Two connections, one per route, each used twice.
        assertEquals(List.of(authority(origin), authority(origin)), connected);
        // The chained proxy was asked for a tunnel, once, and never saw the request itself.
        assertEquals(List.of("CONNECT " + authority(origin)), chainLog.received);
    }

    @Test
    void throughAChainedProxyTheTlsRunsInsideItsTunnel() throws Exception {
        ChainTestSupport.RequestLog chainLog = new ChainTestSupport.RequestLog();
        HttpProxyServer chain = MicroProxy.bootstrap().withPort(0).plusActivityTracker(chainLog).start();
        closeables.add(chain::abort);
        proxy = forward().withChainProxyManager(ChainTestSupport.always(ChainTestSupport.http(chain.getListenAddress())))
                .start();
        try (Http1 client = new Http1(proxy)) {
            Http1.Response r = client.send("GET", https(origin, "/through"), null);
            assertEquals(200, r.status());
            assertEquals("/through", echoedUri(r.body()));
            // As a browser would: CONNECT to the chained proxy, then TLS to the server in the tunnel.
            assertEquals(List.of("CONNECT " + authority(origin)), chainLog.received);
        }
    }

    @Test
    void anHttpsUpstreamProxyIsTheOneForHttpsUris() throws Exception {
        // UpstreamProxyManager picks the HTTPS (CONNECT) upstream for an https:// URI.
        ChainTestSupport.RequestLog plainLog = new ChainTestSupport.RequestLog();
        ChainTestSupport.RequestLog httpsLog = new ChainTestSupport.RequestLog();
        HttpProxyServer forPlain = MicroProxy.bootstrap().withPort(0).plusActivityTracker(plainLog).start();
        HttpProxyServer forHttps = MicroProxy.bootstrap().withPort(0).plusActivityTracker(httpsLog).start();
        closeables.add(forPlain::abort);
        closeables.add(forHttps::abort);
        proxy = forward().withChainProxyManager(new UpstreamProxyManager(
                "http://127.0.0.1:" + forPlain.getListenAddress().getPort(),
                "http://127.0.0.1:" + forHttps.getListenAddress().getPort(), NoProxyRules.none())).start();
        try (Http1 client = new Http1(proxy)) {
            assertEquals(200, client.send("GET", https(origin, "/u"), null).status());
        }
        assertEquals(List.of(), plainLog.received);
        assertEquals(List.of("CONNECT " + authority(origin)), httpsLog.received);
    }

    // --- HTTP/2 (h2c) clients ----------------------------------------------------------------

    private static List<HeaderField> h2Request(String method, String authority, String path, String... extra) {
        List<HeaderField> fields = new ArrayList<>(List.of(new HeaderField(":method", method),
                new HeaderField(":scheme", "https"), new HeaderField(":authority", authority),
                new HeaderField(":path", path)));
        for (int i = 0; i < extra.length; i += 2) fields.add(new HeaderField(extra[i], extra[i + 1]));
        return fields;
    }

    @Test
    void anH2cStreamWithSchemeHttpsIsFetchedOverTls() throws Exception {
        proxy = forward().withHttp2Cleartext(true).start();
        try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), authority(origin)).handshake()) {
            c.headers(1, h2Request("GET", authority(origin), "/h2?q=1", "x-test", "h2"), true);
            H2TestClient.Response get = c.response(1);
            assertEquals(200, get.status());
            assertEquals("tls", get.header("x-origin"));
            assertEquals("/h2?q=1", echoedUri(get.text()));
            assertEquals(List.of(authority(origin)), echoedHeader(get.text(), HttpHeaderNames.HOST));
            assertEquals(List.of("h2"), echoedHeader(get.text(), "x-test"));
            assertEquals(List.of("2 orig"), echoedHeader(get.text(), HttpHeaderNames.VIA));

            c.headers(3, h2Request("POST", authority(origin), "/upload", "content-type", "text/plain"), false);
            c.data(3, "streamed ".getBytes(StandardCharsets.UTF_8), false);
            c.data(3, "body".getBytes(StandardCharsets.UTF_8), true);
            H2TestClient.Response post = c.response(3);
            assertEquals(200, post.status());
            assertEquals("streamed body", echoedBody(post.text()));
        }
        assertEquals(List.of(https(origin, "/h2?q=1"), https(origin, "/upload")), seen);
        // The second stream took the idle connection the first left.
        assertEquals(List.of(authority(origin)), connected);
    }

    // --- HTTP/2 and HTTP/3 to servers --------------------------------------------------------

    @Test
    void anHttp2ServerGetsTheRequestsAsStreamsOfOneConnection() throws Exception {
        H2TestOrigin h2 = new H2TestOrigin(originCa.serverContext("localhost", "127.0.0.1"), Http2UpstreamTest::echo);
        closeables.add(h2);
        proxy = forward().withHttp2Upstream(true).withHttp2Cleartext(true)
                .withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true).start();
        String authority = "localhost:" + h2.port();
        try (Http1 client = new Http1(proxy)) {
            Http1.Response r = client.send("POST", "https://" + authority + "/one", "hello");
            assertEquals(200, r.status());
            assertEquals(List.of("https"), Http2UpstreamTest.lines(r.body(), ":scheme"));
            assertEquals(List.of(authority), Http2UpstreamTest.lines(r.body(), ":authority"));
            assertEquals(List.of("/one"), Http2UpstreamTest.lines(r.body(), ":path"));
            assertTrue(r.body().endsWith("\n\nhello"), r.body());
            assertEquals("2 orig", r.header("via"));
        }
        try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), authority).handshake()) {
            c.headers(1, h2Request("GET", authority, "/two"), true);
            H2TestClient.Response r = c.response(1);
            assertEquals(200, r.status());
            assertEquals(List.of("/two"), Http2UpstreamTest.lines(r.text(), ":path"));
        }
        assertEquals(1, h2.accepts.get(), "both clients' requests went on one HTTP/2 connection");
        assertEquals(List.of(List.of("h2", "http/1.1")), h2.offeredAlpn);
    }

    @Test
    void coalescingAppliesToOriginatedTls() throws Exception {
        H2TestOrigin h2 = new H2TestOrigin(originCa.serverContext("a.test", "b.test"), Http2UpstreamTest::echo);
        closeables.add(h2);
        Map<String, InetSocketAddress> names = new ConcurrentHashMap<>(
                Map.of("a.test", h2.address(), "b.test", h2.address()));
        proxy = forward().withHttp2Upstream(true)
                .withHttp2Options(Http2Options.builder().coalesceConnections(true).build())
                .withServerResolver((host, port) -> {
                    InetSocketAddress a = names.get(host);
                    if (a == null) throw new UnknownHostException(host);
                    return a;
                }).start();
        try (Http1 client = new Http1(proxy)) {
            for (String host : List.of("a.test", "b.test")) {
                Http1.Response r = client.send("GET", "https://" + host + ":" + h2.port() + "/", null);
                assertEquals(200, r.status());
                assertEquals(List.of(host + ":" + h2.port()), Http2UpstreamTest.lines(r.body(), ":authority"));
            }
        }
        assertEquals(1, h2.accepts.get(), "b.test was coalesced onto a.test's connection");
    }

    @Test
    void anHttp3ServerGetsTheRequestOverQuic() throws Exception {
        H3TestOrigin h3 = new H3TestOrigin(originCa, origin.getAddress().getPort());
        closeables.add(h3);
        proxy = forward().withHttp3Upstream(true).withHttp3UpstreamHosts("^localhost:").withHttp2Cleartext(true).start();
        String authority = "localhost:" + origin.getAddress().getPort();
        try (Http1 client = new Http1(proxy)) {
            Http1.Response r = client.send("GET", "https://" + authority + "/hello", null);
            assertEquals(200, r.status());
            assertEquals("hello over h3", r.body());
            assertEquals("h3", r.header("x-origin-protocol"));
        }
        try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), authority).handshake()) {
            c.headers(1, h2Request("GET", authority, "/hello"), true);
            H2TestClient.Response r = c.response(1);
            assertEquals(200, r.status());
            assertEquals("hello over h3", r.text());
        }
        assertEquals(2, h3.requests.get());
        assertEquals(1, h3.connections.get());
        assertTrue(h3.errors().isEmpty(), h3.errors().toString());
    }

    // --- Certificate failures ----------------------------------------------------------------

    @Test
    void anUntrustedCertificateIsATlsFailure() throws Exception {
        HttpsServer untrusted = httpsOrigin(strangerCa.serverContext("localhost", "127.0.0.1"));
        closeables.add(() -> untrusted.stop(0));
        List<ProxyFailure> failures = new CopyOnWriteArrayList<>();
        StatsRegistry stats = StatsRegistry.create();
        proxy = forward().withHttp2Cleartext(true).withStats(stats).withFailureResponder((request, failure) -> {
            failures.add(failure);
            return null;
        }).start();
        try (Http1 client = new Http1(proxy)) {
            Http1.Response r = client.send("GET", https(untrusted, "/x"), null);
            assertEquals(502, r.status());
            assertEquals("Bad Gateway", r.body());
        }
        FlowRecord record = flows.await("a 502 record", f -> f.responseCode() == 502);
        assertEquals(flags(ResponseFlag.UPSTREAM_CONNECTION_FAILURE), record.responseFlags());
        assertEquals("proxy_failure:tls_failed", record.responseCodeDetails());
        assertInstanceOf(ProxyFailure.TlsFailed.class, record.failure().orElseThrow());
        assertTrue(record.upstreamTransportFailureReason().contains("certification path"),
                record.upstreamTransportFailureReason());
        assertInstanceOf(ProxyFailure.TlsFailed.class, failures.getFirst());
        assertEquals(1, ((Counter) stats.get("cluster.direct.ssl.connection_error")).value());

        try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), authority(untrusted)).handshake()) {
            c.headers(1, h2Request("GET", authority(untrusted), "/y"), true);
            assertEquals(502, c.response(1).status());
        }
        assertEquals(2, failures.size());
        assertInstanceOf(ProxyFailure.TlsFailed.class, failures.get(1));
    }

    @Test
    void aCertificateForAnotherNameIsATlsFailure() throws Exception {
        HttpsServer mismatched = httpsOrigin(originCa.serverContext("elsewhere.test"));
        closeables.add(() -> mismatched.stop(0));
        proxy = forward().start();
        try (Http1 client = new Http1(proxy)) {
            assertEquals(502, client.send("GET", https(mismatched, "/x"), null).status());
        }
        FlowRecord record = flows.await("a 502 record", f -> f.responseCode() == 502);
        assertEquals(flags(ResponseFlag.UPSTREAM_CONNECTION_FAILURE), record.responseFlags());
        assertInstanceOf(ProxyFailure.TlsFailed.class, record.failure().orElseThrow());
        assertTrue(record.upstreamTransportFailureReason().contains("subject alternative names"),
                record.upstreamTransportFailureReason());
    }

    @Test
    void withoutAMitmManagerTheJvmsTrustApplies() throws Exception {
        // The test CA is not among the JVM's roots, so its server is refused.
        proxy = forward(null).start();
        try (Http1 client = new Http1(proxy)) {
            assertEquals(502, client.send("GET", https(origin, "/x"), null).status());
        }
        assertInstanceOf(ProxyFailure.TlsFailed.class,
                flows.await("a 502 record", f -> f.responseCode() == 502).failure().orElseThrow());
    }

    @Test
    void aManagerThatTrustsEveryServerAcceptsAnyCertificate() throws Exception {
        // What --mitm-trust-all sets up.
        HttpsServer untrusted = httpsOrigin(strangerCa.serverContext("elsewhere.test"));
        closeables.add(() -> untrusted.stop(0));
        proxy = forward(new CertificateAuthorityMitmManager(proxyCa, SslContexts.trustAll())).start();
        try (Http1 client = new Http1(proxy)) {
            Http1.Response r = client.send("GET", https(untrusted, "/anything"), null);
            assertEquals(200, r.status());
            assertEquals("/anything", echoedUri(r.body()));
        }
    }

    // --- Turned off --------------------------------------------------------------------------

    @Test
    void turnedOffClientsHttpsRequestsAreRefused() throws Exception {
        HttpServer plain = TestSupport.origin(TestSupport.echo());
        closeables.add(() -> plain.stop(0));
        List<ProxyFailure> failures = new CopyOnWriteArrayList<>();
        proxy = forward().withTlsOrigination(false).withHttp2Cleartext(true).withFailureResponder((request, failure) -> {
            failures.add(failure);
            return null;
        }).start();
        try (Http1 client = new Http1(proxy)) {
            Http1.Response refused = client.send("GET", https(origin, "/x"), null);
            assertEquals(400, refused.status());
            assertEquals("Bad Request: https:// URIs need CONNECT (TLS origination is off)", refused.body());
        }
        assertEquals(List.of(), connected, "no connection to the server");
        FlowRecord record = flows.await("a 400 record", f -> f.responseCode() == 400);
        assertEquals(flags(ResponseFlag.DOWNSTREAM_PROTOCOL_ERROR), record.responseFlags());
        assertInstanceOf(ProxyFailure.BadRequest.class, failures.getFirst());

        try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), authority(origin)).handshake()) {
            c.headers(1, h2Request("GET", authority(origin), "/y"), true);
            assertEquals(400, c.response(1).status());
            // A secure WebSocket's extended CONNECT is refused too.
            List<HeaderField> webSocket = h2Request("CONNECT", authority(origin), "/ws", "sec-websocket-version", "13");
            webSocket.add(1, new HeaderField(":protocol", "websocket"));
            c.headers(3, webSocket, false);
            H2TestClient.Response refused = c.response(3);
            assertEquals(400, refused.status());
            assertEquals("Bad Request: https:// URIs need CONNECT (TLS origination is off)", refused.text());
        }
        try (Http1 client = new Http1(proxy)) {
            Http1.Response r = client.send("GET", TestSupport.url(plain, "/plain"), null);
            assertEquals(200, r.status());
            assertEquals("/plain", echoedUri(r.body()));
        }
        // CONNECT, intercepted, is untouched.
        assertEquals("tls", TestSupport.get(TestSupport.client(proxy, proxyCa.clientContext()),
                TestSupport.url(origin, "/intercepted")).headers().firstValue("X-Origin").orElseThrow());
        assertEquals(List.of(authority(plain), authority(origin)), connected);
    }

    @Test
    void turnedOffAFiltersHttpsUriStillGoesOverTls() throws Exception {
        // A filter's (or script's) https:// URI is the operator's choice, not the client's.
        HttpServer plain = TestSupport.origin(TestSupport.echo());
        closeables.add(() -> plain.stop(0));
        proxy = MicroProxy.bootstrap().withPort(0).withTlsOrigination(false)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(HttpFilters.builder().onRequest(req -> {
                    if (req.uri().endsWith("/moved")) req.setUri(https(origin, "/secure"));
                    return null;
                }).build()).start();
        try (Http1 client = new Http1(proxy)) {
            Http1.Response r = client.send("GET", TestSupport.url(plain, "/moved"), null);
            assertEquals(200, r.status());
            assertEquals("tls", r.header("x-origin"));
            assertEquals("/secure", echoedUri(r.body()));
        }
    }

    // --- A hand-written HTTP/1.1 client ------------------------------------------------------

    /**
     * A keep-alive HTTP/1.1 connection to the proxy, written by hand: the JDK's client asks a proxy
     * for {@code https://} URIs with {@code CONNECT}, never in absolute-form.
     */
    static final class Http1 implements AutoCloseable {

        record Response(int status, Map<String, String> headers, String body) {
            String header(String name) {
                return headers.get(name.toLowerCase(Locale.ROOT));
            }
        }

        private final Socket socket;
        private final InputStream in;
        private final OutputStream out;

        Http1(HttpProxyServer proxy) throws IOException {
            socket = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
            socket.setSoTimeout(20_000);
            in = socket.getInputStream();
            out = socket.getOutputStream();
        }

        /** Sends a request for {@code uri} (absolute-form), with {@code body} if not null, and reads the response. */
        Response send(String method, String uri, String body, String... headers) throws IOException {
            String authority = uri.substring(uri.indexOf("://") + 3);
            int slash = authority.indexOf('/');
            if (slash >= 0) authority = authority.substring(0, slash);
            StringBuilder head = new StringBuilder(method + " " + uri + " HTTP/1.1\r\nHost: " + authority + "\r\n");
            for (int i = 0; i < headers.length; i += 2) head.append(headers[i]).append(": ").append(headers[i + 1]).append("\r\n");
            byte[] payload = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
            if (body != null) head.append("Content-Length: ").append(payload.length).append("\r\n");
            head.append("\r\n");
            out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
            out.write(payload);
            out.flush();
            return read();
        }

        private Response read() throws IOException {
            String head = TestSupport.readUntil(in, "\r\n\r\n");
            if (!head.endsWith("\r\n\r\n")) throw new IOException("connection closed: " + head);
            List<String> lines = head.lines().toList();
            int status = Integer.parseInt(lines.getFirst().split(" ")[1]);
            Map<String, String> fields = new TreeMap<>();
            for (String line : lines.subList(1, lines.size())) {
                int colon = line.indexOf(':');
                if (colon > 0) fields.put(line.substring(0, colon).strip().toLowerCase(Locale.ROOT), line.substring(colon + 1).strip());
            }
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            if ("chunked".equalsIgnoreCase(fields.get("transfer-encoding"))) {
                while (true) {
                    String size = TestSupport.readUntil(in, "\r\n").strip();
                    int semi = size.indexOf(';');
                    int n = Integer.parseInt(semi < 0 ? size : size.substring(0, semi), 16);
                    if (n == 0) {
                        // Trailers, if any, then the blank line.
                        while (!TestSupport.readUntil(in, "\r\n").equals("\r\n")) {
                            // skip a trailer field
                        }
                        break;
                    }
                    body.write(in.readNBytes(n));
                    TestSupport.readUntil(in, "\r\n");
                }
            } else if (fields.containsKey("content-length")) {
                body.write(in.readNBytes(Integer.parseInt(fields.get("content-length"))));
            }
            return new Response(status, fields, body.toString(StandardCharsets.UTF_8));
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }
}
