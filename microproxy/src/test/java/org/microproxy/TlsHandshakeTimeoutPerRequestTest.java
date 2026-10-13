package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.tls.SslContexts;

/**
 * {@link HttpFilters#proxyToServerTlsHandshakeTimeout()}: an upstream TLS handshake timeout per
 * request, with TLS chained proxies and with servers. The peers either never answer the
 * ClientHello or answer it only after a second, so which timeout applied shows in how the
 * handshake ended (the timeout's message names its length), not in how long it took.
 */
class TlsHandshakeTimeoutPerRequestTest {

    /** How long the slow peers wait before starting their side of the handshake. */
    private static final long SLOW_MILLIS = 1000;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<ProxyFailure> failures = new CopyOnWriteArrayList<>();
    private final List<Throwable> handshakeErrors = new CopyOnWriteArrayList<>();
    private final List<FlowContext> flows = new CopyOnWriteArrayList<>();
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    /** A server that accepts connections and never says anything: the handshake never completes. */
    private InetSocketAddress silent() {
        TestSupport.RawServer server = TestSupport.rawServer(s -> s.getInputStream().readAllBytes());
        closeables.add(server);
        return server.address();
    }

    /**
     * A TLS server (self-signed) that starts its handshake only after {@link #SLOW_MILLIS}, then
     * answers any request with {@code 200 ok}: as an HTTP proxy or as an origin.
     */
    private InetSocketAddress slowTls() {
        SSLContext context = new SelfSignedSslContextSource().getSslContext();
        TestSupport.RawServer server = TestSupport.rawServer(s -> {
            Thread.sleep(SLOW_MILLIS);
            try (SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(s, null, s.getPort(), true)) {
                tls.setUseClientMode(false);
                tls.startHandshake();
                TestSupport.readUntil(tls.getInputStream(), "\r\n\r\n");
                TestSupport.write(tls.getOutputStream(),
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            }
        });
        closeables.add(server);
        return server.address();
    }

    /** Filters that ask for {@code timeout}, and record the failures and the exchanges. */
    private HttpFiltersSource timeout(Duration timeout) {
        return (request, flow) -> {
            flows.add(flow);
            return new HttpFilters() {
                @Override
                public Duration proxyToServerTlsHandshakeTimeout() {
                    return timeout;
                }

                @Override
                public HttpResponse proxyToServerFailure(ProxyFailure failure) {
                    failures.add(failure);
                    return null;
                }
            };
        };
    }

    private HttpProxyServerBootstrap bootstrap(Duration serverTimeout) {
        return MicroProxy.bootstrap().withPort(0).withTlsHandshakeTimeout(serverTimeout)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void tlsHandshakeFailed(FlowContext flowContext, boolean clientSide, Throwable cause) {
                        if (!clientSide) handshakeErrors.add(cause);
                    }
                });
    }

    /** Sends {@code request} (a whole head) on a new connection to the proxy; returns the status. */
    private int send(String request) throws IOException {
        try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(20_000);
            TestSupport.write(s.getOutputStream(), request);
            return ChainTestSupport.status(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n"));
        }
    }

    private int getVia(String url) throws IOException {
        return send("GET " + url + " HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n");
    }

    /** Asserts that the request failed on a TLS handshake that ran out of {@code millis}. */
    private void assertTimedOutAfter(long millis) {
        TestSupport.eventually("the handshake failure", () -> !handshakeErrors.isEmpty());
        Throwable cause = handshakeErrors.getFirst();
        assertInstanceOf(SocketTimeoutException.class, cause);
        assertEquals("TLS handshake not finished within " + millis + " ms", cause.getMessage());
        // (Each filter of a chain is told of the failure.)
        assertFalse(failures.isEmpty());
        for (ProxyFailure f : failures) {
            ProxyFailure.TlsFailed failure = assertInstanceOf(ProxyFailure.TlsFailed.class, f);
            assertInstanceOf(SocketTimeoutException.class, failure.cause());
        }
        FlowContext flow = flows.getLast();
        TestSupport.eventually("the response flags",
                () -> flow.responseFlags().contains(ResponseFlag.UPSTREAM_CONNECTION_FAILURE));
    }

    @Test
    void aFilterShortensTheHandshakeWithATlsChainedProxy() throws Exception {
        InetSocketAddress silent = silent();
        proxy = bootstrap(Duration.ofSeconds(60))
                .withChainProxyManager(ChainTestSupport.always(ChainTestSupport.encrypted(silent, SslContexts.trustAll())))
                .withFiltersSource(timeout(Duration.ofMillis(200))).start();
        assertEquals(502, getVia("http://example.test/"));
        assertTimedOutAfter(200);
    }

    @Test
    void aFilterShortensTheHandshakeWithTheServer() throws Exception {
        InetSocketAddress silent = silent();
        proxy = bootstrap(Duration.ofSeconds(60))
                .withFiltersSource(timeout(Duration.ofMillis(200))).start();
        assertEquals(502, getVia("https://127.0.0.1:" + silent.getPort() + "/"));
        assertTimedOutAfter(200);
    }

    @Test
    void aFilterShortensTheHandshakeWithAnInterceptedServer() throws Exception {
        InetSocketAddress silent = silent();
        proxy = bootstrap(Duration.ofSeconds(60))
                .withManInTheMiddle(new CertificateAuthorityMitmManager(CertificateAuthority.generate("Handshake CA"),
                        SslContexts.trustAll()))
                .withFiltersSource(timeout(Duration.ofMillis(200))).start();
        String target = "127.0.0.1:" + silent.getPort();
        // Whether the proxy meets the server before or after the client's handshake, the request
        // inside the tunnel needs the server.
        try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
            if (ChainTestSupport.status(ChainTestSupport.connect(s, target)) == 200) {
                SSLSocket tls = (SSLSocket) SslContexts.trustAll().getSocketFactory()
                        .createSocket(s, "127.0.0.1", silent.getPort(), false);
                tls.startHandshake();
                TestSupport.write(tls.getOutputStream(), "GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
                TestSupport.readUntil(tls.getInputStream(), "\r\n\r\n");
            }
        } catch (IOException failed) {
            // the proxy closed the connection or the tunnel rather than answering
        }
        TestSupport.eventually("the handshake failure", () -> !handshakeErrors.isEmpty());
        Throwable cause = handshakeErrors.getFirst();
        assertInstanceOf(SocketTimeoutException.class, cause);
        assertEquals("TLS handshake not finished within 200 ms", cause.getMessage());
    }

    @Test
    void lambdaBuiltFiltersSetItWithTlsHandshakeTimeout() throws Exception {
        InetSocketAddress silent = silent();
        proxy = bootstrap(Duration.ofSeconds(60))
                .withChainProxyManager(ChainTestSupport.always(ChainTestSupport.encrypted(silent, SslContexts.trustAll())))
                .withFiltersSource(timeout(null))
                .plusFiltersSource(HttpFilters.builder().tlsHandshakeTimeout(Duration.ofMillis(250)).build())
                .start();
        assertEquals(502, getVia("http://example.test/"));
        assertTimedOutAfter(250);
        assertThrows(IllegalArgumentException.class, () -> HttpFilters.builder().tlsHandshakeTimeout(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> HttpFilters.builder().tlsHandshakeTimeout(null));
    }

    @Test
    void withoutAFilterTimeoutTheServersApplies() throws Exception {
        InetSocketAddress slow = slowTls();
        proxy = bootstrap(Duration.ofMillis(200))
                .withChainProxyManager(ChainTestSupport.always(ChainTestSupport.encrypted(slow, SslContexts.trustAll())))
                .withFiltersSource(timeout(null))
                .plusFiltersSource(timeout(Duration.ZERO))
                .plusFiltersSource(timeout(Duration.ofSeconds(-1))).start();
        assertEquals(502, getVia("http://example.test/"));
        assertTimedOutAfter(200);
    }

    @Test
    void aLongerFilterTimeoutLetsASlowChainedProxyFinish() throws Exception {
        InetSocketAddress slow = slowTls();
        proxy = bootstrap(Duration.ofMillis(200))
                .withChainProxyManager(ChainTestSupport.always(ChainTestSupport.encrypted(slow, SslContexts.trustAll())))
                .withFiltersSource(timeout(Duration.ofSeconds(30))).start();
        assertEquals(200, getVia("http://example.test/"));
        assertEquals(List.of(), handshakeErrors);
        assertEquals(List.of(), failures);
    }

    @Test
    void aLongerFilterTimeoutLetsASlowServerFinish() throws Exception {
        InetSocketAddress slow = slowTls();
        proxy = bootstrap(Duration.ofMillis(200))
                .withManInTheMiddle(new CertificateAuthorityMitmManager(CertificateAuthority.generate("Handshake CA"),
                        SslContexts.trustAll()))
                .withFiltersSource(timeout(Duration.ofSeconds(30))).start();
        assertEquals(200, getVia("https://127.0.0.1:" + slow.getPort() + "/"));
        assertEquals(List.of(), handshakeErrors);
        assertEquals(List.of(), failures);
    }

    @Test
    void chainsReportTheShortestPositiveTimeout() {
        var request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "http://example.com/");
        HttpFiltersSource chain = HttpFiltersChain.of(timeout(Duration.ofSeconds(5)), timeout(null),
                timeout(Duration.ofSeconds(2)), timeout(Duration.ofSeconds(-3)));
        assertEquals(Duration.ofSeconds(2), chain.filterRequest(request, null).proxyToServerTlsHandshakeTimeout());
        assertNull(HttpFiltersChain.of(timeout(null), timeout(Duration.ZERO)).filterRequest(request, null)
                .proxyToServerTlsHandshakeTimeout());
        assertNull(new HttpFilters() {}.proxyToServerTlsHandshakeTimeout(), "the server's by default");
    }
}
