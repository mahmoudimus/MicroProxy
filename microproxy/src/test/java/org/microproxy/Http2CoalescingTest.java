package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.FrameInterceptor;
import org.microproxy.frames.Http2Frame;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SslContexts;
import org.microproxy.tls.TrustingTrustManager;

/**
 * HTTP/2 connection coalescing to servers ({@link Http2Options.Builder#coalesceConnections}, RFC
 * 9113 section 9.1.1): an intercepted request for another name takes a stream on an existing
 * connection when the server's certificate covers the name and it resolves (with the proxy's
 * resolver) to the connection's address, or the server named it in an ORIGIN frame (RFC 8336);
 * never across routes, MITM managers or client connections whose connections are private; and a
 * {@code 421} on a coalesced connection sends the request again on a connection of its own.
 *
 * <p>The test server answers on one address for several names, which the proxy's resolver maps to
 * it; it reports the {@code :authority} of each request and which of its connections carried it.
 */
class Http2CoalescingTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("H2 Coalescing Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("H2 Coalescing Proxy CA");
    /** The names the test servers' certificate is valid for. */
    static final String[] CERTIFICATE_NAMES = {"a.test", "b.test", "d.test", "*.wild.test", "elsewhere.test"};

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private H2TestOrigin origin;
    private HttpProxyServer proxy;
    /** What the proxy's resolver answers for each name; others do not resolve. */
    private final Map<String, InetSocketAddress> addresses = new ConcurrentHashMap<>();
    /** How often the proxy's resolver was asked for each name. */
    private final Map<String, AtomicInteger> lookups = new ConcurrentHashMap<>();
    /** Requests a test server answered 421. */
    private final AtomicInteger misdirected = new AtomicInteger();

    private final HostResolver resolver = (host, port) -> {
        lookups.computeIfAbsent(host, h -> new AtomicInteger()).incrementAndGet();
        InetSocketAddress address = addresses.get(host);
        if (address == null) throw new UnknownHostException(host);
        return address;
    };

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.close();
        for (AutoCloseable c : closeables) c.close();
    }

    /** A test server for {@link #CERTIFICATE_NAMES}, whose names in {@code names} resolve to it. */
    private H2TestOrigin origin(H2TestOrigin.Options options, String... names) throws IOException {
        return origin(originCa.serverContext(CERTIFICATE_NAMES), options, names);
    }

    /** A test server with {@code context}, whose names in {@code names} resolve to it. */
    private H2TestOrigin origin(SSLContext context, H2TestOrigin.Options options, String... names) throws IOException {
        H2TestOrigin[] self = new H2TestOrigin[1];
        H2TestOrigin o = new H2TestOrigin(context, options, s -> answer(self[0], s));
        self[0] = o;
        closeables.add(o);
        for (String name : names) addresses.put(name, o.address());
        return o;
    }

    /**
     * Answers {@code :authority} and the index of the connection that carried the request, after
     * its body (if any); or 421 to a request whose name is not the one its connection was made
     * for (its SNI), when this server is to refuse coalesced requests.
     */
    private void answer(H2TestOrigin o, H2TestOrigin.Stream s) throws IOException {
        String authority = s.header(":authority");
        String host = authority.substring(0, authority.lastIndexOf(':'));
        if (refuseCoalesced && !host.equals(s.conn.sni())) {
            misdirected.incrementAndGet();
            s.respond(421, true);
            return;
        }
        byte[] body = s.readBody();
        byte[] out = (authority + " " + o.connections.indexOf(s.conn) + (body.length > 0 ? " " + body.length : ""))
                .getBytes(StandardCharsets.UTF_8);
        s.respond(200, false, "content-length", Integer.toString(out.length));
        s.data(out, true);
    }

    private volatile boolean refuseCoalesced;

    private static MitmManager mitm() {
        return new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext());
    }

    /** An intercepting proxy with coalescing on, its server connections shared between clients. */
    private HttpProxyServerBootstrap coalescing(MitmManager manager) {
        return MicroProxy.bootstrap().withPort(0).withName("h2coalesce").withMetrics(true)
                .withManInTheMiddle(manager)
                .withHttp2Upstream(true)
                .withHttp2Options(Http2Options.builder().coalesceConnections(true).build())
                .withServerResolver(resolver)
                .withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true);
    }

    private HttpClient client() {
        return TestSupport.client(proxy, proxyCa.clientContext());
    }

    /** {@code https://<host>:<the test server's port><path>}. */
    private String url(String host, String path) {
        return "https://" + host + ":" + origin.port() + path;
    }

    private String get(HttpClient client, String host) {
        HttpResponse<String> r = TestSupport.send(client, request(host, "/").build());
        assertEquals(200, r.statusCode(), r.body());
        return r.body();
    }

    private HttpRequest.Builder request(String host, String path) {
        return HttpRequest.newBuilder(URI.create(url(host, path))).timeout(Duration.ofSeconds(30));
    }

    /** What {@link #answer} says for a request for {@code host} on connection {@code connection}. */
    private String answered(String host, int connection) {
        return host + ":" + origin.port() + " " + connection;
    }

    private long stat(String name) {
        return MetricsAssertions.value(proxy.getStats(), name);
    }

    private int lookupsOf(String host) {
        AtomicInteger n = lookups.get(host);
        return n == null ? 0 : n.get();
    }

    @Test
    void namesTheCertificateCoversAtTheSameAddressShareTheConnection() throws Exception {
        origin = origin(new H2TestOrigin.Options(), "a.test", "b.test", "x.wild.test");
        proxy = coalescing(mitm()).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));
        assertEquals(answered("b.test", 0), get(client, "b.test"));
        // A wildcard name of the certificate covers it too.
        assertEquals(answered("x.wild.test", 0), get(client, "x.wild.test"));
        assertEquals(answered("b.test", 0), get(client, "b.test"));
        assertEquals(1, origin.accepts.get(), "one connection for every name");
        StatsRegistry stats = proxy.getStats();
        MetricsAssertions.awaitValue(stats, "http2.upstream.coalesced_streams", 3);
        assertEquals(0, stat("http2.upstream.misdirected_421_retry"));
        // Each name was resolved once, to check its address; a.test to connect.
        assertEquals(1, lookupsOf("a.test"));
        assertEquals(1, lookupsOf("b.test"));
        assertEquals(1, lookupsOf("x.wild.test"));
    }

    @Test
    void coalescingIsOffByDefault() throws Exception {
        origin = origin(new H2TestOrigin.Options(), "a.test", "b.test");
        proxy = coalescing(mitm()).withHttp2Options(Http2Options.DEFAULT).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));
        assertEquals(answered("b.test", 1), get(client, "b.test"));
        assertEquals(2, origin.accepts.get());
        assertEquals(0, stat("http2.upstream.coalesced_streams"));
        // Resolved once each, to connect: nothing more without coalescing.
        assertEquals(1, lookupsOf("a.test"));
        assertEquals(1, lookupsOf("b.test"));
    }

    @Test
    void aNameTheCertificateDoesNotCoverGetsAConnectionOfItsOwn() throws Exception {
        origin = origin(new H2TestOrigin.Options(), "a.test", "c.test");
        // A manager that trusts any server, so c.test's own connection works without a matching
        // name: only the coalescing check looks at it.
        proxy = coalescing(new CertificateAuthorityMitmManager(proxyCa, SslContexts.trustAll())).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));
        assertEquals(answered("c.test", 1), get(client, "c.test"));
        assertEquals(2, origin.accepts.get());
        assertEquals(0, stat("http2.upstream.coalesced_streams"));
        // Its name was never resolved for the check, which the certificate failed first.
        assertEquals(1, lookupsOf("c.test"));
    }

    @Test
    void aNameAtAnotherAddressGetsAConnectionOfItsOwn() throws Exception {
        origin = origin(new H2TestOrigin.Options(), "a.test");
        // elsewhere.test is in the certificate, but resolves to another server.
        H2TestOrigin other = origin(new H2TestOrigin.Options(), "elsewhere.test");
        proxy = coalescing(mitm()).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));
        assertEquals(answered("elsewhere.test", 0), get(client, "elsewhere.test"));
        assertEquals(1, origin.accepts.get());
        assertEquals(1, other.accepts.get());
        assertEquals(0, stat("http2.upstream.coalesced_streams"));
        // Resolved once: the address the check found is the one connected to.
        assertEquals(1, lookupsOf("elsewhere.test"));
    }

    @Test
    void neverAcrossRoutes() throws Exception {
        origin = origin(new H2TestOrigin.Options(), "a.test", "b.test");
        ChainTestSupport.RequestLog upstreamLog = new ChainTestSupport.RequestLog();
        HttpProxyServer upstream = MicroProxy.bootstrap().withPort(0).withServerResolver(resolver)
                .plusActivityTracker(upstreamLog).start();
        closeables.add(upstream::abort);
        ChainedProxy chained = ChainTestSupport.http(upstream.getListenAddress());
        // b.test goes through the chained proxy, a.test directly.
        ChainedProxyManager routes = (request, queue, details) -> queue.add(
                (request.uri() + " " + request.headers().get("Host")).contains("b.test")
                        ? chained : ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        proxy = coalescing(mitm()).withChainProxyManager(routes).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));
        assertEquals(answered("b.test", 1), get(client, "b.test"));
        assertEquals(2, origin.accepts.get());
        assertEquals(List.of("CONNECT b.test:" + origin.port()), upstreamLog.received);
        assertEquals(0, stat("http2.upstream.coalesced_streams"));
    }

    @Test
    void neverAcrossTlsIdentities() throws Exception {
        origin = origin(new H2TestOrigin.Options(), "a.test", "b.test");
        // Requests with X-Tls name the server name (and verification host) of their connection.
        proxy = coalescing(mitm()).withFiltersSource((request, flow) -> new HttpFilters() {
            @Override
            public TlsServerIdentity proxyToServerTlsIdentity(String serverHostAndPort) {
                String name = request.headers().get("X-Tls");
                return name == null ? null : TlsServerIdentity.of(name);
            }
        }).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));
        // With an identity of its own, b.test gets a connection of its own, made with that name,
        // though a.test's certificate and address would have let it coalesce.
        HttpRequest withIdentity = request("b.test", "/").header("X-Tls", "d.test").build();
        assertEquals(answered("b.test", 1), TestSupport.send(client, withIdentity).body());
        assertEquals("d.test", origin.connections.get(1).sni());
        // Without one, it coalesces onto a.test's connection, never the one made with d.test.
        assertEquals(answered("b.test", 0), get(client, "b.test"));
        // With it again, the connection made with it.
        assertEquals(answered("b.test", 1), TestSupport.send(client, withIdentity).body());
        assertEquals(2, origin.accepts.get());
    }

    @Test
    void neverAcrossMitmManagers() throws Exception {
        origin = origin(new H2TestOrigin.Options(), "a.test", "b.test");
        // Each client connection gets the other manager than the one before.
        AtomicInteger next = new AtomicInteger();
        MitmManager first = mitm();
        MitmManager second = mitm();
        MitmManager chooser = new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()) {
            @Override
            public MitmManager forConnection(FlowContext flowContext) {
                return next.getAndIncrement() % 2 == 0 ? first : second;
            }
        };
        proxy = coalescing(chooser).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));
        assertEquals(answered("b.test", 1), get(client, "b.test"));
        assertEquals(2, origin.accepts.get());
        assertEquals(0, stat("http2.upstream.coalesced_streams"));
    }

    @Test
    void neverAcrossMitmManagersThatConfigureServerSockets() throws Exception {
        origin = origin(new H2TestOrigin.Options(), "a.test", "b.test");
        // A manager whose socket settings may differ by name: none of its connections is shared.
        MitmManager configuring = new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()) {
            @Override
            public void configureServerSocket(javax.net.ssl.SSLSocket socket) {
                // the defaults, but it could pin anything per name
            }
        };
        proxy = coalescing(configuring).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));
        assertEquals(answered("b.test", 1), get(client, "b.test"));
        assertEquals(0, stat("http2.upstream.coalesced_streams"));
    }

    @Test
    void neverAcrossClientConnectionsWithPrivateConnections() throws Exception {
        origin = origin(new H2TestOrigin.Options(), "a.test", "b.test");
        // Without the shared pool, a client connection's server connections are its own: each
        // CONNECT (one per name) has its own.
        proxy = coalescing(mitm()).withSharedServerConnectionPool(false).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));
        assertEquals(answered("b.test", 1), get(client, "b.test"));
        assertEquals(2, origin.accepts.get());
        assertEquals(0, stat("http2.upstream.coalesced_streams"));
    }

    @Test
    void anOriginFrameNamesWhatTheConnectionServesInsteadOfDns() throws Exception {
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        origin = origin(options, "a.test", "d.test");
        // b.test is named; d.test, though the certificate covers it and it resolves here, is not.
        // Entries that are no https origin are ignored.
        options.origins = List.of("https://B.test:" + origin.port(), "not an origin", "http://d.test:" + origin.port(),
                "https://d.test:" + origin.port() + "/path");
        // b.test resolves to another server: the ORIGIN frame alone lets it share the connection.
        H2TestOrigin elsewhere = origin(new H2TestOrigin.Options(), "b.test");
        proxy = coalescing(mitm()).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));
        assertEquals(answered("b.test", 0), get(client, "b.test"));
        assertEquals(0, lookupsOf("b.test"), "no DNS for a name the server named");
        assertEquals(0, elsewhere.accepts.get());
        // Once the server has sent ORIGIN, a name it did not send is not served, whatever DNS says.
        assertEquals(answered("d.test", 1), get(client, "d.test"));
        assertEquals(2, origin.accepts.get());
        assertEquals(1, stat("http2.upstream.coalesced_streams"));
    }

    @Test
    void aFrameInterceptorSeesOriginFramesFirst() throws Exception {
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        origin = origin(options, "a.test");
        options.origins = List.of("https://b.test:" + origin.port());
        H2TestOrigin elsewhere = origin(new H2TestOrigin.Options(), "b.test");
        // What the interceptor drops is not acted on: b.test is reached where DNS says.
        List<Integer> seen = new java.util.concurrent.CopyOnWriteArrayList<>();
        FrameInterceptor dropOrigin = (frame, direction, context) -> {
            if (frame instanceof Http2Frame.Unknown u && direction == FrameDirection.FROM_SERVER) {
                seen.add(u.type());
                return null;
            }
            return frame;
        };
        proxy = coalescing(mitm()).withFrameInterceptor(dropOrigin).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));
        assertEquals(answered("b.test", 0), get(client, "b.test"));
        assertEquals(1, elsewhere.accepts.get());
        assertEquals(List.of(0xc), seen);
        assertEquals(0, stat("http2.upstream.coalesced_streams"));
    }

    @Test
    void a421OnACoalescedConnectionIsRetriedOnAConnectionOfItsOwn() throws Exception {
        // The server answers 421 to every request for another name than its connection's SNI.
        origin = origin(new H2TestOrigin.Options(), "a.test", "b.test");
        refuseCoalesced = true;
        proxy = coalescing(mitm()).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));
        // Coalesced, refused, and sent again on b.test's own connection: the client sees none of it.
        assertEquals(answered("b.test", 1), get(client, "b.test"));
        assertEquals(1, misdirected.get());
        MetricsAssertions.awaitValue(proxy.getStats(), "http2.upstream.misdirected_421_retry", 1);
        MetricsAssertions.awaitValue(proxy.getStats(), "http2.upstream.coalesced_streams", 1);
        // b.test is not coalesced onto the first connection again.
        for (int i = 0; i < 3; i++) assertEquals(answered("b.test", 1), get(client, "b.test"));
        assertEquals(1, misdirected.get());
        assertEquals(1, stat("http2.upstream.misdirected_421_retry"));
        assertEquals(2, origin.accepts.get());
    }

    @Test
    void a421IsRetriedOnlyWhenTheRequestCanBeSentAgain() throws Exception {
        origin = origin(new H2TestOrigin.Options(), "a.test", "x.wild.test", "y.wild.test");
        refuseCoalesced = true;
        proxy = coalescing(mitm()).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));

        // A request whose body was streamed to the server cannot go again: the 421 is the client's.
        HttpResponse<String> post = TestSupport.send(client, request("x.wild.test", "/upload")
                .POST(HttpRequest.BodyPublishers.ofString("streamed body")).build());
        assertEquals(421, post.statusCode());
        assertEquals(1, misdirected.get());
        assertEquals(0, stat("http2.upstream.misdirected_421_retry"));
        // ... and that name is not coalesced onto that connection again: it gets one of its own.
        assertEquals(answered("x.wild.test", 1), get(client, "x.wild.test"));
        assertEquals(1, misdirected.get());

        // A body the server refused before it was read (Expect: 100-continue) can go again.
        HttpResponse<String> expect = TestSupport.send(client, request("y.wild.test", "/upload").expectContinue(true)
                .POST(HttpRequest.BodyPublishers.ofString("after continue")).build());
        assertEquals(200, expect.statusCode(), expect.body());
        assertEquals("y.wild.test:" + origin.port() + " 2 " + "after continue".length(), expect.body());
        assertEquals(2, misdirected.get());
        MetricsAssertions.awaitValue(proxy.getStats(), "http2.upstream.misdirected_421_retry", 1);
        assertEquals(3, origin.accepts.get());
    }

    @Test
    void connectionsWithAClientCertificateServeOnlyTheirOwnName() throws Exception {
        // A server that asks for client certificates (taking any), and a proxy that has one: an
        // identity it presented to one name.
        CertificateAuthority clientCa = CertificateAuthority.generate("H2 Coalescing Client CA");
        KeyPair serverKey = ecKeyPair();
        SSLContext serverContext = SslContexts.withKey(serverKey.getPrivate(), new X509Certificate[] {
                originCa.issue(serverKey.getPublic(), List.of(CERTIFICATE_NAMES)), originCa.getCertificate()},
                new TrustManager[] {new TrustingTrustManager()});
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        options.wantClientAuth = true;
        origin = origin(serverContext, options, "a.test", "b.test");
        KeyPair clientKey = ecKeyPair();
        SSLContext withClientCertificate = SslContexts.withKey(clientKey.getPrivate(), new X509Certificate[] {
                clientCa.issue(clientKey.getPublic(), List.of("proxy.client.test")), clientCa.getCertificate()},
                new TrustManager[] {SslContexts.trustManagerOf(originCa.clientContext())});
        proxy = coalescing(new CertificateAuthorityMitmManager(proxyCa, withClientCertificate)).start();
        HttpClient client = client();
        assertEquals(answered("a.test", 0), get(client, "a.test"));
        assertEquals(answered("b.test", 1), get(client, "b.test"));
        assertEquals(0, stat("http2.upstream.coalesced_streams"));
        // The server did get the certificate.
        assertEquals(clientCa.getCertificate().getSubjectX500Principal(),
                ((X509Certificate) origin.connections.getFirst().socket.getSession().getPeerCertificates()[0])
                        .getIssuerX500Principal());
    }

    private static KeyPair ecKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }
}
