package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.ChainTestSupport.connect;
import static org.microproxy.ChainTestSupport.open;
import static org.microproxy.ChainTestSupport.status;
import static org.microproxy.MetricsAssertions.awaitValue;
import static org.microproxy.MetricsAssertions.value;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.stats.TagExtractor;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * HTTP/2 to chained proxies ({@link ChainedProxy#http2()}): {@code CONNECT} tunnels and plain-HTTP
 * proxy requests as streams of shared connections to an HTTP/2 forward proxy (another MicroProxy,
 * on h2c or on its TLS listener with {@code h2}), interception and TLS origination inside such
 * tunnels, the proxy's stream limit, its credentials, failover when it goes away or fails, and
 * HTTP/1.1 when HTTP/2 is not asked for or not chosen.
 */
@Timeout(60)
class Http2ChainedProxyTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("H2 Chain Origin CA");
    /** Signs the chained proxy's TLS listener and MicroProxy's interception certificates. */
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("H2 Chain Proxy CA");

    private static HttpServer origin;
    private static HttpsServer secureOrigin;

    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();
    private final StatsRegistry stats = StatsRegistry.create();
    private final RecordedFlows flows = new RecordedFlows();

    @BeforeAll
    static void startOrigins() {
        origin = TestSupport.origin(echo());
        secureOrigin = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1", "localhost"), echo());
    }

    @AfterAll
    static void stopOrigins() {
        origin.stop(0);
        secureOrigin.stop(0);
    }

    @AfterEach
    void tearDown() throws Exception {
        proxies.close();
        for (AutoCloseable c : closeables) c.close();
    }

    // -------------------------------------------------------------------------------------------
    // The chained proxy, and MicroProxy in front of it
    // -------------------------------------------------------------------------------------------

    /** What the chained proxy received: each request with its protocol and client connection. */
    static final class Received extends ActivityTrackerAdapter {
        record Request(String line, String version, long connection, String proxyAuthorization) {}

        final List<Request> requests = new CopyOnWriteArrayList<>();

        @Override
        public void requestReceivedFromClient(FlowContext ctx, org.microproxy.http.HttpRequest request) {
            requests.add(new Request(request.method() + " " + request.uri(), request.protocolVersion().text(),
                    ctx.getConnectionId(), request.headers().get("Proxy-Authorization")));
        }

        List<String> lines() {
            return requests.stream().map(Request::line).toList();
        }

        Set<String> versions() {
            return new HashSet<>(requests.stream().map(Request::version).toList());
        }

        Set<Long> connections() {
            return new HashSet<>(requests.stream().map(Request::connection).toList());
        }
    }

    /** The chained proxy: h2c with prior knowledge on its plain listener. */
    private HttpProxyServer h2cProxy(Received received) {
        return proxies.start(MicroProxy.bootstrap().withProxyAlias("chained").withHttp2Cleartext(true)
                .plusActivityTracker(received));
    }

    /** The chained proxy: TLS with {@code h2} (if {@code http2}) on its listener. */
    private HttpProxyServer tlsProxy(Received received, boolean http2) {
        return proxies.start(MicroProxy.bootstrap().withProxyAlias("chained")
                .withSslContextSource(() -> proxyCa.serverContext("127.0.0.1", "localhost")).withHttp2(http2)
                .plusActivityTracker(received));
    }

    /** A chained proxy as MicroProxy is told of it. */
    static ChainedProxy chained(InetSocketAddress address, boolean http2, boolean tls, String user, String password) {
        // One context: connections are shared only by proxies with the same one.
        SSLContext context = tls ? proxyCa.clientContext() : null;
        return new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return address;
            }

            @Override
            public boolean http2() {
                return http2;
            }

            @Override
            public boolean requiresEncryption() {
                return tls;
            }

            @Override
            public SSLContext getSslContext() {
                return context;
            }

            @Override
            public String getUsername() {
                return user;
            }

            @Override
            public String getPassword() {
                return password;
            }

            @Override
            public String toString() {
                return (http2 ? "h2" : "http") + (tls ? "s" : "") + "://" + address;
            }
        };
    }

    static ChainedProxy h2c(HttpProxyServer proxy) {
        return chained(proxy.getListenAddress(), true, false, null, null);
    }

    /** MicroProxy, chained to {@code chain}, with stats and flow records. */
    private HttpProxyServer microProxy(ChainedProxy... chain) {
        return proxies.start(MicroProxy.bootstrap().withProxyAlias("micro").withChainProxyManager(always(chain))
                .withStats(stats).plusActivityTracker(flows));
    }

    /** MicroProxy, chained to {@code chain}, intercepting TLS with {@link #proxyCa}. */
    private HttpProxyServer intercepting(ChainedProxy... chain) {
        return proxies.start(MicroProxy.bootstrap().withProxyAlias("micro").withChainProxyManager(always(chain))
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withStats(stats).plusActivityTracker(flows));
    }

    /** The stats prefix of the cluster of the chained proxy {@code proxy}. */
    private static String cluster(HttpProxyServer proxy) {
        return cluster(proxy.getListenAddress());
    }

    private static String cluster(InetSocketAddress address) {
        return "cluster." + TagExtractor.sanitize(address.getHostString() + "_" + address.getPort());
    }

    private static String target(HttpServer server) {
        return "127.0.0.1:" + server.getAddress().getPort();
    }

    private static String basic(String user, String password) {
        return "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    /** A raw TCP server that echoes what it reads until the client half-closes. */
    private TestSupport.RawServer echoServer() {
        TestSupport.RawServer server = TestSupport.rawServer(s -> s.getInputStream().transferTo(s.getOutputStream()));
        closeables.add(server);
        return server;
    }

    /** A tunnel through {@code proxy} to {@code target}: the CONNECT answered 200, or failing. */
    private Socket tunnel(HttpProxyServer proxy, String target) throws IOException {
        Socket s = open(proxy.getListenAddress());
        closeables.add(s);
        assertEquals(200, status(connect(s, target)));
        return s;
    }

    /** Sends {@code text} into the tunnel, ends its output, and reads all that comes back. */
    private static String roundTrip(Socket tunnel, String text) throws IOException {
        tunnel.getOutputStream().write(text.getBytes(StandardCharsets.UTF_8));
        tunnel.getOutputStream().flush();
        tunnel.shutdownOutput();
        return new String(tunnel.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    /**
     * Sends {@code text} into the tunnel and reads its echo, leaving the tunnel open (a TLS
     * connection to an HTTP/1.1 proxy does not half-close).
     */
    private static String echoed(Socket tunnel, String text) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        tunnel.getOutputStream().write(bytes);
        tunnel.getOutputStream().flush();
        return new String(tunnel.getInputStream().readNBytes(bytes.length), StandardCharsets.UTF_8);
    }

    /** Whether {@code record} is that of a request for {@code path}. */
    private static boolean requestFor(FlowRecord record, String path) {
        return record.request() != null && record.request().uri().contains(path);
    }

    /** The tunnel ends: an end of stream, or a reset, whichever the client sees first. */
    private static void assertTunnelEnds(Socket tunnel) {
        try {
            assertEquals(-1, tunnel.getInputStream().read());
        } catch (IOException reset) {
            // as good as an end
        }
    }

    // -------------------------------------------------------------------------------------------
    // Plain-HTTP requests and tunnels as streams
    // -------------------------------------------------------------------------------------------

    @Test
    void plainHttpRequestsAreStreamsOfOneConnection() {
        Received received = new Received();
        HttpProxyServer chained = h2cProxy(received);
        HttpProxyServer proxy = microProxy(h2c(chained));

        HttpResponse<String> response = get(client(proxy), url(origin, "/one?q=1"));
        assertEquals(200, response.statusCode());
        assertEquals("/one?q=1", echoedUri(response.body()));
        // The chained proxy got it over HTTP/2: its Via says so.
        assertEquals(List.of("1.1 micro", "2 chained"), echoedHeader(response.body(), "via"));
        response = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/two")))
                .POST(HttpRequest.BodyPublishers.ofString("over h2c")).build());
        assertEquals(200, response.statusCode());
        assertEquals("over h2c", echoedBody(response.body()));

        // In absolute-form (:scheme http, :authority the server), as a proxy request, on one connection.
        assertEquals(List.of("GET " + url(origin, "/one?q=1"), "POST " + url(origin, "/two")), received.lines());
        assertEquals(Set.of("HTTP/2.0"), received.versions());
        assertEquals(1, received.connections().size());
        assertEquals(1, value(stats, cluster(chained) + ".upstream_cx_http2_total"));
        assertEquals(1, value(stats, cluster(chained) + ".upstream_cx_total"));
        awaitValue(stats, cluster(chained) + ".upstream_rq_2xx", 2);
        FlowRecord record = flows.await("the GET's record", r -> requestFor(r, "/one"));
        assertEquals(chained.getListenAddress().getHostString() + ":" + chained.getListenAddress().getPort(),
                record.upstreamCluster());
        assertEquals("HTTP/2", record.upstreamProtocol());
    }

    @Test
    void concurrentTunnelsAreStreamsOfOneConnection() throws Exception {
        Received received = new Received();
        HttpProxyServer chained = h2cProxy(received);
        HttpProxyServer proxy = microProxy(h2c(chained));
        TestSupport.RawServer echo = echoServer();

        List<Socket> tunnels = new ArrayList<>();
        for (int i = 0; i < 4; i++) tunnels.add(tunnel(proxy, "127.0.0.1:" + echo.port()));
        // All open at once: one connection carries the four streams.
        assertEquals(1, received.connections().size());
        assertEquals(Set.of("HTTP/2.0"), received.versions());
        assertEquals(4, received.lines().size());
        // Each tunnel's bytes, both ways; its end (END_STREAM) reaches the server, whose end comes back.
        byte[] large = H2TestOrigin.bytes(300_000, 7);
        String text = new String(large, StandardCharsets.ISO_8859_1);
        for (int i = 0; i < tunnels.size(); i++) {
            String sent = i == 0 ? text : "tunnel " + i;
            Socket t = tunnels.get(i);
            t.getOutputStream().write(sent.getBytes(StandardCharsets.ISO_8859_1));
            t.getOutputStream().flush();
            t.shutdownOutput();
            assertEquals(sent, new String(t.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1));
        }
        assertEquals(1, value(stats, cluster(chained) + ".upstream_cx_total"));
        FlowRecord record = flows.await(FlowRecord.Kind.TUNNEL);
        assertEquals("HTTP/2", record.upstreamProtocol());
    }

    @Test
    void megabytesFlowBothWaysUnderFlowControl() throws Exception {
        HttpProxyServer chained = h2cProxy(new Received());
        HttpProxyServer proxy = microProxy(h2c(chained));
        TestSupport.RawServer echo = echoServer();

        // Larger than every window on the way: the stream's DATA waits for WINDOW_UPDATEs both ways.
        byte[] payload = H2TestOrigin.bytes(3_000_000, 11);
        Socket t = tunnel(proxy, "127.0.0.1:" + echo.port());
        CompletableFuture<byte[]> back = CompletableFuture.supplyAsync(() -> {
            try {
                return t.getInputStream().readAllBytes();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
        t.getOutputStream().write(payload);
        t.getOutputStream().flush();
        t.shutdownOutput();
        assertArrayEquals(payload, back.get(30, TimeUnit.SECONDS));
    }

    @Test
    void aServerResetEndsItsTunnelOnly() throws Exception {
        HttpProxyServer chained = h2cProxy(new Received());
        HttpProxyServer proxy = microProxy(h2c(chained));
        TestSupport.RawServer echo = echoServer();
        TestSupport.RawServer resetting = TestSupport.rawServer(s -> {
            s.getInputStream().read();
            s.setSoLinger(true, 0); // close with RST
            s.close();
        });
        closeables.add(resetting);

        Socket survivor = tunnel(proxy, "127.0.0.1:" + echo.port());
        Socket doomed = tunnel(proxy, "127.0.0.1:" + resetting.port());
        doomed.getOutputStream().write('x');
        doomed.getOutputStream().flush();
        assertTunnelEnds(doomed);
        // The other stream of the connection is not affected.
        assertEquals("survived", roundTrip(survivor, "survived"));
        assertEquals(1, value(stats, cluster(chained) + ".upstream_cx_total"));
        assertEquals(1, value(stats, cluster(chained) + ".upstream_cx_active"));
    }

    @Test
    void theStreamLimitOpensAnotherConnection() throws Exception {
        Received received = new Received();
        HttpProxyServer chained = proxies.start(MicroProxy.bootstrap().withProxyAlias("chained").withHttp2Cleartext(true)
                .withHttp2Options(Http2Options.builder().maxConcurrentStreams(2).build()).plusActivityTracker(received));
        HttpProxyServer proxy = microProxy(h2c(chained));
        TestSupport.RawServer echo = echoServer();

        List<Socket> tunnels = new ArrayList<>();
        for (int i = 0; i < 3; i++) tunnels.add(tunnel(proxy, "127.0.0.1:" + echo.port()));
        // Two streams fill the first connection; the third takes a second.
        assertEquals(2, received.connections().size());
        assertEquals(2, value(stats, cluster(chained) + ".upstream_cx_http2_total"));
        for (int i = 0; i < tunnels.size(); i++) assertEquals("t" + i, roundTrip(tunnels.get(i), "t" + i));
        // With the streams done, there is room again: a new tunnel takes one of the two connections.
        assertEquals("again", roundTrip(tunnel(proxy, "127.0.0.1:" + echo.port()), "again"));
        assertEquals(2, received.connections().size());
    }

    // -------------------------------------------------------------------------------------------
    // TLS through the tunnels: interception and origination
    // -------------------------------------------------------------------------------------------

    @Test
    void anInterceptedConnectRunsTlsInsideTheStream() {
        Received received = new Received();
        HttpProxyServer chained = h2cProxy(received);
        HttpProxyServer proxy = intercepting(h2c(chained));

        HttpResponse<String> response = get(client(proxy, proxyCa.clientContext()), url(secureOrigin, "/secret"));
        assertEquals(200, response.statusCode());
        assertEquals("/secret", echoedUri(response.body()));
        // The chained proxy saw only the tunnel, over HTTP/2.
        assertEquals(List.of("CONNECT " + target(secureOrigin)), received.lines());
        assertEquals(Set.of("HTTP/2.0"), received.versions());
        FlowRecord record = flows.await("the intercepted GET",
                r -> requestFor(r, "/secret"));
        assertEquals("HTTP/2", record.upstreamProtocol());
    }

    @Test
    void anHttpsUriIsFetchedOverTlsInsideTheStream() throws Exception {
        Received received = new Received();
        HttpProxyServer chained = h2cProxy(received);
        HttpProxyServer proxy = intercepting(h2c(chained));

        try (TlsOriginationTest.Http1 client = new TlsOriginationTest.Http1(proxy)) {
            TlsOriginationTest.Http1.Response r = client.send("GET", url(secureOrigin, "/originated"), null);
            assertEquals(200, r.status());
            assertEquals("/originated", echoedUri(r.body()));
            r = client.send("GET", url(secureOrigin, "/again"), null);
            assertEquals(200, r.status());
        }
        // A CONNECT the proxy made itself, on an HTTP/2 stream; the second request reused its tunnel.
        assertEquals(List.of("CONNECT " + target(secureOrigin)), received.lines());
        assertEquals(Set.of("HTTP/2.0"), received.versions());
    }

    @Test
    void http2ToTheServerRunsInsideTheStream() throws Exception {
        H2TestOrigin h2 = new H2TestOrigin(originCa.serverContext("localhost", "127.0.0.1"), Http2UpstreamTest::echo);
        closeables.add(h2);
        Received received = new Received();
        HttpProxyServer chained = h2cProxy(received);
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withProxyAlias("micro")
                .withChainProxyManager(always(h2c(chained))).withHttp2Upstream(true)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withStats(stats));

        String authority = "localhost:" + h2.port();
        try (TlsOriginationTest.Http1 client = new TlsOriginationTest.Http1(proxy)) {
            for (String path : List.of("/one", "/two")) {
                TlsOriginationTest.Http1.Response r = client.send("GET", "https://" + authority + path, null);
                assertEquals(200, r.status());
                assertEquals(List.of(path), Http2UpstreamTest.lines(r.body(), ":path"));
            }
        }
        // HTTP/2 with the server, in TLS, in the DATA of one stream to the chained proxy.
        assertEquals(1, h2.accepts.get());
        assertEquals(List.of("CONNECT " + authority), received.lines());
        assertEquals(Set.of("HTTP/2.0"), received.versions());
        assertEquals(1, value(stats, cluster(chained) + ".upstream_cx_total"));
        assertEquals(1, value(stats, cluster(chained) + ".upstream_cx_http2_total"));
    }

    @Test
    void aTlsChainedProxyChoosingH2CarriesStreams() throws Exception {
        Received received = new Received();
        HttpProxyServer chained = tlsProxy(received, true);
        HttpProxyServer proxy = microProxy(chained(chained.getListenAddress(), true, true, null, null));
        TestSupport.RawServer echo = echoServer();

        assertEquals(200, get(client(proxy), url(origin, "/tls")).statusCode());
        assertEquals("over tls", roundTrip(tunnel(proxy, "127.0.0.1:" + echo.port()), "over tls"));
        assertEquals(Set.of("HTTP/2.0"), received.versions());
        assertEquals(1, received.connections().size());
        assertEquals(1, value(stats, cluster(chained) + ".ssl.handshake"));
    }

    @Test
    void aTlsChainedProxyChoosingHttp1GetsHttp1() throws Exception {
        Received received = new Received();
        HttpProxyServer chained = tlsProxy(received, false);
        HttpProxyServer proxy = microProxy(chained(chained.getListenAddress(), true, true, null, null));
        TestSupport.RawServer echo = echoServer();

        assertEquals(200, get(client(proxy), url(origin, "/h1")).statusCode());
        Socket tunnel = tunnel(proxy, "127.0.0.1:" + echo.port());
        assertEquals("h1", echoed(tunnel, "h1"));
        tunnel.close();
        assertEquals(List.of("GET " + url(origin, "/h1"), "CONNECT 127.0.0.1:" + echo.port()), received.lines());
        assertEquals(Set.of("HTTP/1.1"), received.versions());
        assertEquals(0, value(stats, cluster(chained) + ".upstream_cx_http2_total"));
        assertEquals("HTTP/1.1", flows.await(FlowRecord.Kind.TUNNEL).upstreamProtocol());
    }

    @Test
    void withoutTheOptInTheProxyGetsHttp1() throws Exception {
        Received received = new Received();
        HttpProxyServer chained = h2cProxy(received);
        HttpProxyServer proxy = microProxy(chained(chained.getListenAddress(), false, false, null, null));
        TestSupport.RawServer echo = echoServer();

        HttpResponse<String> response = get(client(proxy), url(origin, "/off"));
        assertEquals(200, response.statusCode());
        assertEquals(List.of("1.1 micro", "1.1 chained"), echoedHeader(response.body(), "via"));
        assertEquals("off", roundTrip(tunnel(proxy, "127.0.0.1:" + echo.port()), "off"));
        assertEquals(Set.of("HTTP/1.1"), received.versions());
        assertEquals(0, value(stats, cluster(chained) + ".upstream_cx_http2_total"));
    }

    // -------------------------------------------------------------------------------------------
    // Credentials
    // -------------------------------------------------------------------------------------------

    @Test
    void eachStreamCarriesTheProxysCredentials() throws Exception {
        Received received = new Received();
        HttpProxyServer chained = proxies.start(MicroProxy.bootstrap().withProxyAlias("chained").withHttp2Cleartext(true)
                .withProxyAuthenticator((u, p) -> u.equals("user") && p.equals("secret")).plusActivityTracker(received));
        HttpProxyServer proxy = microProxy(chained(chained.getListenAddress(), true, false, "user", "secret"));
        TestSupport.RawServer echo = echoServer();

        assertEquals(200, get(client(proxy), url(origin, "/auth")).statusCode());
        assertEquals("auth", roundTrip(tunnel(proxy, "127.0.0.1:" + echo.port()), "auth"));
        assertEquals(List.of(basic("user", "secret"), basic("user", "secret")),
                received.requests.stream().map(Received.Request::proxyAuthorization).toList());
        assertEquals(1, received.connections().size());
    }

    @Test
    void wrongCredentialsAre407ForRequestsAndBadGatewayForTunnels() throws Exception {
        Received received = new Received();
        HttpProxyServer chained = proxies.start(MicroProxy.bootstrap().withProxyAlias("chained").withHttp2Cleartext(true)
                .withProxyAuthenticator((u, p) -> u.equals("user") && p.equals("secret")).plusActivityTracker(received));
        HttpProxyServer proxy = microProxy(chained(chained.getListenAddress(), true, false, "user", "wrong"));
        TestSupport.RawServer echo = echoServer();

        // As over HTTP/1.1: a request's 407 is relayed (its challenge is not the client's to answer),
        // a tunnel the proxy refused is a 502.
        HttpResponse<String> response = get(client(proxy), url(origin, "/denied"));
        assertEquals(407, response.statusCode());
        assertEquals(List.of(), response.headers().allValues("proxy-authenticate"));
        try (Socket s = open(proxy.getListenAddress())) {
            assertEquals(502, status(connect(s, "127.0.0.1:" + echo.port())));
        }
    }

    // -------------------------------------------------------------------------------------------
    // Failover
    // -------------------------------------------------------------------------------------------

    /**
     * An h2c "proxy" that answers each HEADERS with GOAWAY (last stream 0, NO_ERROR): it processes
     * nothing. Counts the streams it was sent.
     */
    private static final class GoingAwayProxy implements AutoCloseable {
        final AtomicInteger streams = new AtomicInteger();
        final AtomicInteger connections = new AtomicInteger();
        private final TestSupport.RawServer server;

        GoingAwayProxy() {
            server = TestSupport.rawServer(s -> {
                connections.incrementAndGet();
                DataInputStream in = new DataInputStream(s.getInputStream());
                OutputStream out = s.getOutputStream();
                in.readNBytes(24); // the client preface
                out.write(frame(4, 0, 0, new byte[0])); // SETTINGS
                out.flush();
                while (true) {
                    int length = (in.readUnsignedShort() << 8) | in.readUnsignedByte();
                    int type = in.readUnsignedByte();
                    int flags = in.readUnsignedByte();
                    in.readInt();
                    in.readNBytes(length);
                    if (type == 4 && (flags & 1) == 0) {
                        out.write(frame(4, 1, 0, new byte[0])); // SETTINGS ACK
                    } else if (type == 1) {
                        streams.incrementAndGet();
                        out.write(frame(7, 0, 0, ByteBuffer.allocate(8).putInt(0).putInt(0).array()));
                    }
                    out.flush();
                }
            });
        }

        private static byte[] frame(int type, int flags, int stream, byte[] payload) {
            return ByteBuffer.allocate(9 + payload.length).put((byte) (payload.length >>> 16))
                    .put((byte) (payload.length >>> 8)).put((byte) payload.length).put((byte) type).put((byte) flags)
                    .putInt(stream).put(payload).array();
        }

        InetSocketAddress address() {
            return server.address();
        }

        @Override
        public void close() throws IOException {
            server.close();
        }
    }

    @Test
    void streamsAProxyLeftUnprocessedFailOverToTheNextProxy() throws Exception {
        GoingAwayProxy goingAway = new GoingAwayProxy();
        closeables.add(goingAway);
        Received received = new Received();
        HttpProxyServer next = h2cProxy(received);
        HttpProxyServer proxy = microProxy(chained(goingAway.address(), true, false, null, null), h2c(next));
        TestSupport.RawServer echo = echoServer();

        // Each stream above GOAWAY's last stream id never started: sent again on a new
        // connection, then (after two) to the next proxy.
        assertEquals(200, get(client(proxy), url(origin, "/retried")).statusCode());
        assertEquals(2, goingAway.streams.get());
        assertEquals("retried", roundTrip(tunnel(proxy, "127.0.0.1:" + echo.port()), "retried"));
        assertEquals(4, goingAway.streams.get());
        assertEquals(4, goingAway.connections.get());
        assertEquals(List.of("GET " + url(origin, "/retried"), "CONNECT 127.0.0.1:" + echo.port()), received.lines());
        assertEquals(2, value(stats, cluster(goingAway.address()) + ".failover"));
    }

    @Test
    void aProxyThatGoesAwayIsFailedOverWhileItsTunnelsGoOn() throws Exception {
        Received first = new Received();
        Received second = new Received();
        HttpProxyServer going = proxies.start(MicroProxy.bootstrap().withProxyAlias("chained").withHttp2Cleartext(true)
                .withDrainTime(Duration.ofSeconds(30)).plusActivityTracker(first));
        HttpProxyServer staying = h2cProxy(second);
        HttpProxyServer proxy = microProxy(h2c(going), h2c(staying));
        TestSupport.RawServer echo = echoServer();

        Socket open = tunnel(proxy, "127.0.0.1:" + echo.port());
        assertEquals("before", echoed(open, "before"));
        // The first proxy stops gracefully: GOAWAY, and no new connections.
        Thread stopping = Thread.ofVirtual().start(going::stop);
        awaitValue(stats, "http2.upstream.goaway_received", 1);
        assertEquals(200, get(client(proxy), url(origin, "/after")).statusCode());
        assertEquals("after", roundTrip(tunnel(proxy, "127.0.0.1:" + echo.port()), "after"));
        assertEquals(List.of("GET " + url(origin, "/after"), "CONNECT 127.0.0.1:" + echo.port()), second.lines());
        assertEquals(2, value(stats, cluster(going) + ".failover"));
        // The tunnel open on it was processed: it goes on until it ends.
        assertEquals("still open", roundTrip(open, "still open"));
        assertEquals(List.of("CONNECT 127.0.0.1:" + echo.port()), first.lines());
        stopping.join(10_000);
        assertEquals(ServerState.STOPPED, going.state());
    }

    @Test
    void aProxyThatFailsIsFailedOverAndItsTunnelsEnd() throws Exception {
        Received first = new Received();
        Received second = new Received();
        HttpProxyServer failing = h2cProxy(first);
        HttpProxyServer staying = h2cProxy(second);
        HttpProxyServer proxy = microProxy(h2c(failing), h2c(staying));
        TestSupport.RawServer echo = echoServer();

        Socket open = tunnel(proxy, "127.0.0.1:" + echo.port());
        assertEquals(200, get(client(proxy), url(origin, "/before")).statusCode());
        assertEquals(1, first.connections().size());
        // The first proxy goes away at once: its connection fails, and the tunnel on it with it.
        failing.abort();
        awaitValue(stats, cluster(failing) + ".upstream_cx_active", 0);
        assertTunnelEnds(open);
        assertEquals(200, get(client(proxy), url(origin, "/after")).statusCode());
        assertEquals("after", roundTrip(tunnel(proxy, "127.0.0.1:" + echo.port()), "after"));
        assertEquals(List.of("GET " + url(origin, "/after"), "CONNECT 127.0.0.1:" + echo.port()), second.lines());
        assertEquals(2, value(stats, cluster(failing) + ".failover"));
    }

    @Test
    void aStartedRequestFailsWhenTheProxyConnectionDoes() throws Exception {
        CountDownLatch arrived = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        HttpServer slow = TestSupport.origin(exchange -> {
            arrived.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            TestSupport.echo().handle(exchange);
        });
        closeables.add(() -> {
            release.countDown();
            slow.stop(0);
        });
        HttpProxyServer going = h2cProxy(new Received());
        Received received = new Received();
        HttpProxyServer next = h2cProxy(received);
        HttpProxyServer proxy = microProxy(h2c(going), h2c(next));

        CompletableFuture<HttpResponse<String>> response =
                CompletableFuture.supplyAsync(() -> get(client(proxy), url(slow, "/slow")));
        assertTrue(arrived.await(10, TimeUnit.SECONDS));
        // The chained proxy had the request: it is not sent again, to the next proxy or anywhere.
        going.abort();
        assertEquals(502, response.get().statusCode());
        FlowRecord record = flows.await("the failed request", r -> requestFor(r, "/slow"));
        assertTrue(record.responseFlags().contains(ResponseFlag.UPSTREAM_CONNECTION_TERMINATION),
                record.responseFlags()::toString);
        assertEquals(List.of(), received.lines());
    }

    @Test
    void aProxyThatCannotBeReachedIsFailedOver() throws Exception {
        try (Socket refusing = TestSupport.refusingPort()) {
            InetSocketAddress nowhere = (InetSocketAddress) refusing.getLocalSocketAddress();
            Received received = new Received();
            HttpProxyServer next = h2cProxy(received);
            HttpProxyServer proxy = microProxy(chained(nowhere, true, false, null, null), h2c(next));
            assertEquals(200, get(client(proxy), url(origin, "/next")).statusCode());
            assertEquals(List.of("GET " + url(origin, "/next")), received.lines());
            assertEquals(1, value(stats, cluster(nowhere) + ".failover"));
            assertEquals(1, value(stats, cluster(nowhere) + ".upstream_cx_connect_fail"));
        }
    }

    // -------------------------------------------------------------------------------------------
    // Configured by URL
    // -------------------------------------------------------------------------------------------

    @Test
    void anH2cUrlIsAnHttp2Proxy() throws Exception {
        Received received = new Received();
        HttpProxyServer chained = h2cProxy(received);
        String url = "h2c://127.0.0.1:" + chained.getListenAddress().getPort();
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withChainProxyManager(
                new UpstreamProxyManager(url, null, NoProxyRules.none())));
        assertEquals(200, get(client(proxy), url(origin, "/url")).statusCode());
        assertEquals(Set.of("HTTP/2.0"), received.versions());
    }
}
