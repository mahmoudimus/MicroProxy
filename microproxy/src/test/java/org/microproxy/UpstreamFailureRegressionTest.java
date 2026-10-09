package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.send;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.microproxy.impl.DefaultHttpProxyServer;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.tls.SslContexts;

/**
 * Regression tests for upstream failures found in other LittleProxy forks: a chained proxy whose
 * own name does not resolve, and TLS 1.3 peers that refuse a missing client certificate only after
 * the handshake (on the first read).
 */
class UpstreamFailureRegressionTest {

    private static HttpServer origin;
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private final List<ProxyFailure> failures = new CopyOnWriteArrayList<>();

    @BeforeAll
    static void startOrigin() {
        origin = TestSupport.origin(echo());
    }

    @AfterAll
    static void stopOrigin() {
        origin.stop(0);
    }

    @AfterEach
    void tearDown() {
        proxies.close();
    }

    /** Records each failure and keeps the default answer. */
    private HttpProxyServerBootstrap recordingFailures() {
        return MicroProxy.bootstrap().withFailureResponder((request, failure) -> {
            failures.add(failure);
            return null;
        });
    }

    // ---------------------------------------------------------------------------------------
    // A chained proxy whose host name does not resolve
    // ---------------------------------------------------------------------------------------

    private static final ChainedProxy UNRESOLVABLE = () -> InetSocketAddress.createUnresolved("proxy.invalid", 3128);

    @Test
    void unresolvableChainedProxyGivesAPromptBadGateway() throws Exception {
        List<Throwable> reported = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(recordingFailures()
                .withChainProxyManager(always(UNRESOLVABLE))
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void serverConnectionExceptionCaught(FullFlowContext serverContext, Throwable cause) {
                        assertEquals(UNRESOLVABLE, serverContext.getChainedProxy());
                        reported.add(cause);
                    }
                }));
        long start = System.nanoTime();
        assertEquals(502, get(client(proxy), TestSupport.url(origin, "/")).statusCode());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).toSeconds() < 5);
        assertEquals(502, ChainTestSupport.connectStatus(proxy.getListenAddress(), "127.0.0.1:443"));

        // The chained proxy could not be reached; the server's own name was never looked up.
        assertEquals(2, failures.size());
        for (ProxyFailure failure : failures) {
            ProxyFailure.ConnectFailed connectFailed = assertInstanceOf(ProxyFailure.ConnectFailed.class, failure);
            assertTrue(connectFailed.cause().getMessage().contains("proxy.invalid"), connectFailed.cause().toString());
        }
        assertEquals(2, reported.size());
        assertTrue(reported.getFirst().toString().contains("proxy.invalid"), reported.getFirst().toString());

        // The client connection stays usable: two requests on one connection, two answers.
        try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
            for (int i = 0; i < 2; i++) {
                TestSupport.write(s.getOutputStream(), "GET " + TestSupport.url(origin, "/" + i) + " HTTP/1.1\r\nHost: x\r\n\r\n");
                String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
                assertEquals(502, ChainTestSupport.status(head));
                int length = Integer.parseInt(head.lines().filter(l -> l.startsWith("Content-Length: ")).findFirst()
                        .orElseThrow().substring(16));
                s.getInputStream().readNBytes(length);
            }
        }
    }

    @Test
    void unresolvableChainedProxyFallsBackToTheNextCandidate() throws Exception {
        HttpProxyServer upstream = proxies.start(MicroProxy.bootstrap().withProxyAlias("upstream"));
        HttpProxyServer viaUpstream = proxies.start(MicroProxy.bootstrap().withProxyAlias("downstream")
                .withChainProxyManager(always(UNRESOLVABLE, ChainTestSupport.http(upstream.getListenAddress()))));
        HttpResponse<String> response = get(client(viaUpstream), TestSupport.url(origin, "/next"));
        assertEquals(200, response.statusCode());
        assertEquals(List.of("1.1 downstream", "1.1 upstream"), TestSupport.echoedHeader(response.body(), "via"));

        HttpProxyServer direct = proxies.start(MicroProxy.bootstrap()
                .withChainProxyManager(always(UNRESOLVABLE, ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION)));
        assertEquals(200, get(client(direct), TestSupport.url(origin, "/direct")).statusCode());
    }

    @Test
    void unresolvableChainedProxyLeaksNoConnections() throws Exception {
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withSharedServerConnectionPool(true)
                .withChainProxyManager(always(UNRESOLVABLE)));
        String request = "GET " + TestSupport.url(origin, "/") + " HTTP/1.1\r\nHost: x\r\n\r\n";
        try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
            InputStream in = s.getInputStream();
            for (int i = 0; i < 10; i++) {
                assertEquals(502, exchange502(s, in, request));
            }
            long before = openFileDescriptors();
            for (int i = 0; i < 200; i++) {
                assertEquals(502, exchange502(s, in, request));
            }
            long after = openFileDescriptors();
            assertTrue(before < 0 || after - before < 20, "file descriptors grew from " + before + " to " + after);
        }
        PoolMetrics pool = proxy.getServerConnectionPoolMetrics();
        assertEquals(0, pool.totalConnections(), pool.toString());
        assertEquals(0, pool.activeConnections(), pool.toString());
        // Only the client connection that was just closed may still be winding down.
        TestSupport.eventually("the client connection to be gone",
                () -> ((DefaultHttpProxyServer) proxy).getOpenConnectionCount() == 0);
    }

    private static int exchange502(Socket s, InputStream in, String request) throws IOException {
        TestSupport.write(s.getOutputStream(), request);
        String head = TestSupport.readUntil(in, "\r\n\r\n");
        int length = Integer.parseInt(head.lines().filter(l -> l.startsWith("Content-Length: ")).findFirst()
                .orElseThrow().substring(16));
        in.readNBytes(length);
        return ChainTestSupport.status(head);
    }

    /** Open file descriptors of this JVM, or -1 where the platform does not say. */
    private static long openFileDescriptors() {
        return ManagementFactory.getOperatingSystemMXBean() instanceof com.sun.management.UnixOperatingSystemMXBean unix
                ? unix.getOpenFileDescriptorCount() : -1;
    }

    // ---------------------------------------------------------------------------------------
    // TLS 1.3 peers that require a client certificate
    // ---------------------------------------------------------------------------------------

    /**
     * An HTTPS origin that speaks only TLS 1.3 and requires a client certificate. With TLS 1.3 the
     * client's side of the handshake completes before the server checks the (empty) certificate,
     * so the refusal reaches the proxy as an alert on its first read.
     */
    private static HttpsServer clientAuthOrigin(SSLContext context, AtomicInteger served) throws IOException {
        HttpsServer server = HttpsServer.create(new InetSocketAddress(TestSupport.LOOPBACK, 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters p = getSSLContext().getDefaultSSLParameters();
                p.setProtocols(new String[] {"TLSv1.3"});
                p.setNeedClientAuth(true);
                params.setSSLParameters(p);
            }
        });
        server.createContext("/", exchange -> {
            served.incrementAndGet();
            echo().handle(exchange);
        });
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        return server;
    }

    @Test
    void interceptedOriginRefusingTheMissingClientCertificateGivesBadGateway() throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("Client Auth Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Client Auth Proxy CA");
        AtomicInteger served = new AtomicInteger();
        HttpsServer secure = clientAuthOrigin(originCa.serverContext("127.0.0.1"), served);
        try {
            // The manager's upstream context trusts the origin but holds no client certificate.
            HttpProxyServer proxy = proxies.start(recordingFailures()
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext())));
            var client = client(proxy, proxyCa.clientContext());
            long start = System.nanoTime();
            HttpResponse<String> response = get(client, TestSupport.url(secure, "/get"));
            assertEquals(502, response.statusCode(), response.body());
            assertEquals("Bad Gateway", response.body());
            response = send(client, HttpRequest.newBuilder(URI.create(TestSupport.url(secure, "/post")))
                    .timeout(Duration.ofSeconds(20)).POST(HttpRequest.BodyPublishers.ofString("body")).build());
            assertEquals(502, response.statusCode(), response.body());
            assertTrue(Duration.ofNanos(System.nanoTime() - start).toSeconds() < 10, "no hang");
            assertEquals(0, served.get());
            assertTrue(failures.size() >= 2, failures.toString());
            for (ProxyFailure failure : failures) {
                assertTrue(failure instanceof ProxyFailure.BadServerResponse || failure instanceof ProxyFailure.TlsFailed,
                        failure.toString());
            }
        } finally {
            secure.stop(0);
        }
    }

    @Test
    void tlsChainedProxyRefusingTheMissingClientCertificateGivesBadGateway() throws Exception {
        SelfSignedSslContextSource upstreamTls = new SelfSignedSslContextSource() {
            @Override
            public void configure(SSLSocket socket, boolean clientMode) {
                socket.setEnabledProtocols(new String[] {"TLSv1.3"});
            }
        };
        List<String> received = new CopyOnWriteArrayList<>();
        HttpProxyServer upstream = proxies.start(MicroProxy.bootstrap().withSslContextSource(upstreamTls)
                .withAuthenticateSslClients(true)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void requestReceivedFromClient(FlowContext ctx, org.microproxy.http.HttpRequest request) {
                        received.add(request.method() + " " + request.uri());
                    }
                }));
        ChainedProxy withoutCertificate = ChainTestSupport.encrypted(upstream.getListenAddress(),
                SslContexts.trusting(upstreamTls.getCertificate()));
        HttpProxyServer proxy = proxies.start(recordingFailures().withChainProxyManager(always(withoutCertificate)));

        long start = System.nanoTime();
        HttpResponse<String> response = get(client(proxy), TestSupport.url(origin, "/get"));
        assertEquals(502, response.statusCode(), response.body());
        response = send(client(proxy), HttpRequest.newBuilder(URI.create(TestSupport.url(origin, "/post")))
                .timeout(Duration.ofSeconds(20)).POST(HttpRequest.BodyPublishers.ofString("body")).build());
        assertEquals(502, response.statusCode(), response.body());
        assertEquals(502, ChainTestSupport.connectStatus(proxy.getListenAddress(), "127.0.0.1:443"));
        assertTrue(Duration.ofNanos(System.nanoTime() - start).toSeconds() < 10, "no hang");
        assertEquals(List.of(), received);
        assertEquals(3, failures.size(), failures.toString());
        for (ProxyFailure failure : failures) {
            assertTrue(failure instanceof ProxyFailure.BadServerResponse || failure instanceof ProxyFailure.TlsFailed
                    || failure instanceof ProxyFailure.ConnectFailed, failure.toString());
        }
    }
}
