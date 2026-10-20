package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.stats.Counter;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.tls.SslContexts;

/**
 * {@link FullFlowContext#getServerSslSession()}: in {@link ActivityTracker#requestSentToServer}
 * it is the TLS session with the origin server, end to end, of the connection the request is sent
 * on; {@code null} for plain HTTP and for tunnels that are not intercepted, whatever the proxy's
 * own connection to a chained proxy is.
 */
@Timeout(value = 90, unit = TimeUnit.SECONDS)
class ServerSslSessionTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("Server Session Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("Server Session Proxy CA");
    private static final SelfSignedSslContextSource UPSTREAM_TLS = new SelfSignedSslContextSource();

    /** What {@code requestSentToServer} saw: the session is read inside the hook. */
    record Seen(String method, String uri, SSLSession session) {}

    /** What the origin saw of its side of a TLS connection. */
    record OriginView(String protocol, String cipher, Certificate certificate) {}

    private final List<Seen> sent = new CopyOnWriteArrayList<>();
    /** The session of every other server-side hook (connected, bytes sent and received). */
    private final List<SSLSession> otherHooks = new CopyOnWriteArrayList<>();
    private final List<OriginView> originViews = new CopyOnWriteArrayList<>();
    private final StatsRegistry stats = StatsRegistry.create();
    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        proxies.close();
        for (AutoCloseable c : closeables) c.close();
    }

    private final ActivityTracker tracker = new ActivityTrackerAdapter() {
        @Override
        public void requestSentToServer(FullFlowContext ctx, org.microproxy.http.HttpRequest request) {
            sent.add(new Seen(request.method().name(), request.uri(), ctx.getServerSslSession()));
        }

        @Override
        public void serverConnected(FullFlowContext ctx, java.net.InetSocketAddress address) {
            otherHooks.add(ctx.getServerSslSession());
        }

        @Override
        public void bytesSentToServer(FullFlowContext ctx, int bytes) {
            otherHooks.add(ctx.getServerSslSession());
        }

        @Override
        public void bytesReceivedFromServer(FullFlowContext ctx, int bytes) {
            otherHooks.add(ctx.getServerSslSession());
        }
    };

    private HttpsServer httpsOrigin() {
        HttpsServer origin = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), exchange -> {
            SSLSession session = ((HttpsExchange) exchange).getSSLSession();
            originViews.add(new OriginView(session.getProtocol(), session.getCipherSuite(),
                    session.getLocalCertificates()[0]));
            TestSupport.echo().handle(exchange);
        });
        closeables.add(() -> origin.stop(0));
        return origin;
    }

    private HttpServer httpOrigin() {
        HttpServer origin = TestSupport.origin(TestSupport.echo());
        closeables.add(() -> origin.stop(0));
        return origin;
    }

    private HttpProxyServerBootstrap mitm() {
        return MicroProxy.bootstrap().withPort(0).withStats(stats)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .plusActivityTracker(tracker);
    }

    private long counter(String name) {
        return stats.get(name) instanceof Counter c ? c.value() : 0;
    }

    /** A connection leased for one request goes back to the pool only after the response is written. */
    private void awaitIdlePooled() {
        TestSupport.eventually("the connection back in the pool",
                () -> proxy.getServerConnectionPoolMetrics().idleConnections() == 1);
    }

    private static HttpRequest get(String url) {
        return HttpRequest.newBuilder(URI.create(url)).timeout(java.time.Duration.ofSeconds(20)).build();
    }

    private Seen only(String method) {
        List<Seen> matching = sent.stream().filter(s -> s.method().equals(method)).toList();
        assertEquals(1, matching.size(), sent.toString());
        return matching.getFirst();
    }

    /** The session is the one with the origin: the protocol and cipher it negotiated, and its certificate. */
    private void assertWithOrigin(SSLSession session, OriginView origin) throws Exception {
        assertNotNull(session);
        assertEquals(origin.protocol(), session.getProtocol());
        assertEquals(origin.cipher(), session.getCipherSuite());
        assertArrayEquals(origin.certificate().getEncoded(), session.getPeerCertificates()[0].getEncoded());
        assertTrue(((X509Certificate) session.getPeerCertificates()[0]).getIssuerX500Principal().getName()
                .contains("Server Session Origin CA"));
    }

    @Test
    void aDirectTlsServersSessionIsSeenWithItsProtocolAndCipher() throws Exception {
        HttpsServer origin = httpsOrigin();
        proxy = mitm().withTlsProtocols("TLSv1.2").start();
        try (TlsOriginationTest.Http1 client = new TlsOriginationTest.Http1(proxy)) {
            assertEquals(200, client.send("GET", TestSupport.localhostUrl(origin, "/direct"), null).status());
        }
        Seen seen = only("GET");
        assertEquals("TLSv1.2", seen.session().getProtocol());
        assertWithOrigin(seen.session(), originViews.getFirst());
    }

    @Test
    void anInterceptedSessionsServerSessionIsSeenWhicheverWayTheHandshakeRuns() throws Exception {
        for (MitmServerHandshake mode : MitmServerHandshake.values()) {
            sent.clear();
            originViews.clear();
            HttpsServer origin = httpsOrigin();
            proxy = mitm().onAllProtocols(p -> p.mitmServerHandshake(mode)).start();
            HttpResponse<String> r = TestSupport.get(TestSupport.client(proxy, proxyCa.clientContext()),
                    TestSupport.localhostUrl(origin, "/mitm"));
            assertEquals(200, r.statusCode(), mode.toString());
            Seen seen = only("GET");
            assertEquals("/mitm", seen.uri().substring(seen.uri().indexOf("/mitm")), mode.toString());
            assertWithOrigin(seen.session(), originViews.getFirst());
            proxy.abort();
        }
    }

    @Test
    void anHttpServerHasNoSession() throws Exception {
        HttpServer origin = httpOrigin();
        proxy = mitm().start();
        assertEquals(200, TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/plain")).statusCode());
        assertNull(only("GET").session());
    }

    @Test
    void aTunnelThatIsNotInterceptedHasNoSession() throws Exception {
        HttpsServer origin = httpsOrigin();
        proxy = MicroProxy.bootstrap().withPort(0).plusActivityTracker(tracker).start();
        HttpResponse<String> r = TestSupport.get(TestSupport.client(proxy, originCa.clientContext()),
                TestSupport.url(origin, "/tunnel"));
        assertEquals(200, r.statusCode());
        // The client's handshake with the server went through the tunnel; no request was parsed.
        assertEquals(List.of(), sent.stream().filter(s -> !s.method().equals("CONNECT")).toList());
        assertFalse(otherHooks.isEmpty(), "the tunnel's connection and bytes were reported");
        assertTrue(otherHooks.stream().allMatch(java.util.Objects::isNull), otherHooks.toString());
        assertTrue(sent.stream().allMatch(s -> s.session() == null), sent.toString());
    }

    // --- chained proxies --------------------------------------------------------------------

    private java.net.InetSocketAddress tlsUpstream() {
        return proxies.start(MicroProxy.bootstrap().withProxyAlias("upstream").withSslContextSource(UPSTREAM_TLS))
                .getListenAddress();
    }

    private HttpProxyServerBootstrap throughTlsProxy(HttpProxyServerBootstrap bootstrap) {
        ChainedProxy chained = ChainTestSupport.encrypted(tlsUpstream(),
                SslContexts.trusting(UPSTREAM_TLS.getCertificate()));
        return bootstrap.withChainProxyManager(ChainTestSupport.always(chained));
    }

    @Test
    void throughATlsChainedProxyItIsTheServersSessionNotTheProxys() throws Exception {
        HttpsServer origin = httpsOrigin();
        proxy = proxies.start(throughTlsProxy(mitm()));
        HttpResponse<String> r = TestSupport.get(TestSupport.client(proxy, proxyCa.clientContext()),
                TestSupport.localhostUrl(origin, "/chained"));
        assertEquals(200, r.statusCode());
        SSLSession session = only("GET").session();
        assertWithOrigin(session, originViews.getFirst());
        assertFalse(java.util.Arrays.equals(UPSTREAM_TLS.getCertificate().getEncoded(),
                session.getPeerCertificates()[0].getEncoded()), "not the chained proxy's certificate");
    }

    @Test
    void aPlainRequestThroughATlsChainedProxyHasNoServerSession() throws Exception {
        HttpServer origin = httpOrigin();
        proxy = proxies.start(throughTlsProxy(mitm()));
        assertEquals(200, TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/plain")).statusCode());
        assertNull(only("GET").session(), "the TLS session with the chained proxy is not the server's");
    }

    @Test
    void aTunnelThroughATlsChainedProxyThatIsNotInterceptedHasNoServerSession() throws Exception {
        HttpsServer origin = httpsOrigin();
        proxy = proxies.start(throughTlsProxy(MicroProxy.bootstrap().withPort(0).plusActivityTracker(tracker)));
        assertEquals(200, TestSupport.get(TestSupport.client(proxy, originCa.clientContext()),
                TestSupport.url(origin, "/tunnel")).statusCode());
        assertFalse(otherHooks.isEmpty());
        assertTrue(otherHooks.stream().allMatch(java.util.Objects::isNull), otherHooks.toString());
        assertTrue(sent.stream().allMatch(s -> s.session() == null), sent.toString());
    }

    // --- connections the request was not first on ---------------------------------------------

    @Test
    void aRetryWithoutSniReportsTheSessionOfTheConnectionThatWorked() throws Exception {
        for (MitmServerHandshake mode : MitmServerHandshake.values()) {
            sent.clear();
            TlsRetryWithoutSniTest.PickyOrigin origin = new TlsRetryWithoutSniTest.PickyOrigin(
                    TlsRetryWithoutSniTest.originCa.serverContext("localhost", "127.0.0.1"));
            closeables.add(origin);
            proxy = MicroProxy.bootstrap().withPort(0).withTlsRetryWithoutSni(true)
                    .onAllProtocols(p -> p.mitmServerHandshake(mode))
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(TlsRetryWithoutSniTest.proxyCa,
                            TlsRetryWithoutSniTest.originCa.clientContext()))
                    .plusActivityTracker(tracker).start();
            HttpResponse<String> r = TestSupport.get(
                    TestSupport.client(proxy, TlsRetryWithoutSniTest.proxyCa.clientContext()),
                    "https://localhost:" + origin.port() + "/");
            assertEquals(200, r.statusCode(), mode.toString());
            assertEquals("none", r.headers().firstValue("X-Sni").orElseThrow(), mode.toString());
            assertEquals(1, origin.rejected.get(), mode + ": the first connection's name was refused");
            SSLSession session = only("GET").session();
            assertNotNull(session, mode.toString());
            assertTrue(session.isValid(), mode.toString());
            // The connection the request went on is the one that sent no server name.
            assertEquals(List.of(), ((ExtendedSSLSession) session).getRequestedServerNames(), mode.toString());
            proxy.abort();
        }
    }

    @Test
    void aPooledKeepAliveConnectionReportsItsSessionToEveryExchange() throws Exception {
        HttpsServer origin = httpsOrigin();
        proxy = mitm().withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true)
                .withPoolPerRequestInMitm(true).start();
        String url = TestSupport.localhostUrl(origin, "/reuse");
        // One client connection, two exchanges; then another client connection that leases the pooled one.
        try (TlsOriginationTest.Http1 client = new TlsOriginationTest.Http1(proxy)) {
            assertEquals(200, client.send("GET", url, null).status());
            awaitIdlePooled();
            assertEquals(200, client.send("GET", url, null).status());
        }
        awaitIdlePooled();
        try (TlsOriginationTest.Http1 client = new TlsOriginationTest.Http1(proxy)) {
            assertEquals(200, client.send("GET", url, null).status());
        }
        assertEquals(3, sent.size(), sent.toString());
        assertEquals(1, counter("cluster.direct.ssl.handshake"), "one connection to the server served all three");
        assertEquals(1, originViews.stream().map(OriginView::cipher).distinct().count());
        for (Seen seen : sent) assertWithOrigin(seen.session(), originViews.getFirst());
        assertEquals(sent.getFirst().session(), sent.getLast().session());
    }

    @Test
    void aKeepAliveConnectionInsideAnInterceptedSessionReportsItsSession() throws Exception {
        HttpsServer origin = httpsOrigin();
        proxy = mitm().start();
        HttpClient client = TestSupport.client(proxy, proxyCa.clientContext());
        String url = TestSupport.localhostUrl(origin, "/keepalive");
        assertEquals(200, TestSupport.send(client, get(url)).statusCode());
        assertEquals(200, TestSupport.send(client, get(url)).statusCode());
        assertEquals(2, sent.stream().filter(s -> s.method().equals("GET")).count(), sent.toString());
        for (Seen seen : sent) {
            if (seen.method().equals("GET")) assertWithOrigin(seen.session(), originViews.getFirst());
        }
    }

    @Test
    void anHttp2ServersStreamsReportTheirConnectionsSession() throws Exception {
        H2TestOrigin origin = new H2TestOrigin(originCa.serverContext("localhost", "127.0.0.1"),
                Http2UpstreamTest::echo);
        closeables.add(origin);
        proxy = Http2UpstreamTest.mitm().withManInTheMiddle(
                new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .plusActivityTracker(tracker).start();
        HttpClient client = TestSupport.client(proxy, proxyCa.clientContext());
        assertEquals(200, TestSupport.send(client, get(origin.url("/one"))).statusCode());
        assertEquals(200, TestSupport.send(client, get(origin.url("/two"))).statusCode());
        assertEquals(1, origin.accepts.get(), "both requests were streams of one connection");
        List<Seen> gets = sent.stream().filter(s -> s.method().equals("GET")).toList();
        assertEquals(2, gets.size(), sent.toString());
        for (Seen seen : gets) {
            assertNotNull(seen.session());
            assertTrue(((X509Certificate) seen.session().getPeerCertificates()[0]).getIssuerX500Principal()
                    .getName().contains("Server Session Origin CA"));
        }
        assertEquals(gets.getFirst().session(), gets.getLast().session());
    }
}
