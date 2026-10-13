package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.ActivityTrackerAdapter;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyAdapter;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.MitmServerHandshake;
import org.microproxy.ProtocolPolicy;
import org.microproxy.ProxyAuthenticator;
import org.microproxy.ProxyFailure;
import org.microproxy.ResponseFlag;
import org.microproxy.ResponseSource;
import org.microproxy.RetryBackoff;
import org.microproxy.TestSupport;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * {@link ProtocolPolicy#mitmServerHandshake()}: the server's TLS handshake for an intercepted
 * {@code CONNECT}, deferred until the client's ClientHello (the default) or run before the {@code
 * CONNECT} is answered (eager, as LittleProxy). Either way a failed handshake fails over to the next
 * route after the backoff wait, recorded here ({@link DefaultHttpProxyServer#backoffSleeper})
 * instead of waited out; the final failure is a {@code 502} inside the session, or on the {@code
 * CONNECT} itself.
 *
 * <p>Each route is a chained proxy (another MicroProxy) that takes every {@code CONNECT} to one
 * backend: a server whose certificate the intercepting proxy trusts, or one it does not.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class MitmServerHandshakeTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("Handshake Origin CA");
    static final CertificateAuthority strangerCa = CertificateAuthority.generate("Handshake Stranger CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("Handshake Proxy CA");

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private DefaultHttpProxyServer proxy;
    private final List<Duration> waits = new CopyOnWriteArrayList<>();
    private final List<ProxyFailure> failures = new CopyOnWriteArrayList<>();
    /** "<status> <flags>" of every response sent to the client. */
    private final List<String> sent = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    /** An HTTPS server presenting {@code ca}'s certificate for localhost, answering {@code body}. */
    private HttpsServer backend(CertificateAuthority ca, String body) {
        HttpsServer server = TestSupport.httpsOrigin(ca.serverContext("localhost", "127.0.0.1"),
                TestSupport.fixed(200, body));
        closeables.add(() -> server.stop(0));
        return server;
    }

    /** A chained proxy that takes every CONNECT to {@code backend}. */
    private ChainedProxy routeTo(HttpsServer backend) {
        InetSocketAddress target = new InetSocketAddress(TestSupport.LOOPBACK, backend.getAddress().getPort());
        HttpProxyServer chained = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(HttpFilters.builder().resolveWith(h -> target).build()).start();
        closeables.add(chained::abort);
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, chained.getListenAddress().getPort());
        return () -> address;
    }

    private ChainedProxy untrusted() {
        return routeTo(backend(strangerCa, "stranger"));
    }

    private ChainedProxy trusted() {
        return routeTo(backend(originCa, "trusted"));
    }

    /** The intercepting proxy, its routes {@code route}, a fixed 100 ms backoff, the waits recorded. */
    private void start(HttpProxyServerBootstrap bootstrap, ChainedProxy... route) {
        proxy = (DefaultHttpProxyServer) bootstrap.withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withChainProxyManager((request, queue, details) -> queue.addAll(List.of(route)))
                .withChainedProxyRetryBackoff(RetryBackoff.fixed(Duration.ofMillis(100)))
                .withFailureResponder((request, failure) -> {
                    failures.add(failure);
                    return null;
                })
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void responseSentToClient(FlowContext ctx, HttpResponse response, ResponseSource source) {
                        sent.add(response.status().code() + " " + ctx.responseFlags());
                    }
                })
                .start();
        proxy.backoffSleeper = nanos -> waits.add(Duration.ofNanos(nanos));
    }

    private static HttpProxyServerBootstrap eager() {
        return MicroProxy.bootstrap().onAllProtocols(p -> p.mitmServerHandshake(MitmServerHandshake.EAGER));
    }

    /** A client's CONNECT, and, if answered 200, a GET inside the intercepted session. */
    private record Outcome(int connectStatus, String inside) {}

    private Outcome connectAndGet(String credentials) throws IOException {
        try (Socket raw = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            raw.setSoTimeout(20_000);
            TestSupport.write(raw.getOutputStream(), "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n"
                    + (credentials == null ? "" : "Proxy-Authorization: Basic "
                    + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)) + "\r\n")
                    + "\r\n");
            InputStream in = raw.getInputStream();
            String head = TestSupport.readUntil(in, "\r\n\r\n");
            int status = Integer.parseInt(head.substring(9, 12));
            if (status != 200) return new Outcome(status, null);
            SSLSocket tls = (SSLSocket) proxyCa.clientContext().getSocketFactory()
                    .createSocket(raw, "localhost", 443, true);
            SSLParameters params = tls.getSSLParameters();
            params.setApplicationProtocols(new String[] {"http/1.1"});
            tls.setSSLParameters(params);
            tls.startHandshake();
            TestSupport.write(tls.getOutputStream(), "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            return new Outcome(status, new String(tls.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1));
        }
    }

    private static List<Duration> millis(long... values) {
        return java.util.Arrays.stream(values).mapToObj(Duration::ofMillis).toList();
    }

    private void assertTlsFailure() {
        ProxyFailure.TlsFailed failure = assertInstanceOf(ProxyFailure.TlsFailed.class, failures.getFirst());
        assertEquals(ProxyFailure.TlsFailed.Reason.CERTIFICATE_UNTRUSTED, failure.reason());
    }

    @Test
    void deferredFailsOverToTheNextRouteAfterTheBackoff() throws Exception {
        start(MicroProxy.bootstrap(), untrusted(), trusted());
        Outcome outcome = connectAndGet(null);
        assertEquals(200, outcome.connectStatus());
        assertTrue(outcome.inside().startsWith("HTTP/1.1 200"), outcome.inside());
        assertTrue(outcome.inside().endsWith("trusted"), outcome.inside());
        assertEquals(millis(100), waits);
        assertEquals(List.of(), failures);
    }

    @Test
    void deferredAnswersTheFirstRequestInTheSessionWhenEveryRouteFails() throws Exception {
        start(MicroProxy.bootstrap(), untrusted(), untrusted());
        Outcome outcome = connectAndGet(null);
        assertEquals(200, outcome.connectStatus(), "the CONNECT was answered before the server's handshake");
        assertTrue(outcome.inside().startsWith("HTTP/1.1 502"), outcome.inside());
        assertEquals(millis(100), waits);
        assertEquals(1, failures.size(), "one answer, made from the session's failure");
        assertTlsFailure();
        TestSupport.eventually("the 502's record", () -> sent.stream().anyMatch(s -> s.startsWith("502")));
        String record = sent.stream().filter(s -> s.startsWith("502")).findFirst().orElseThrow();
        assertTrue(record.contains(ResponseFlag.UPSTREAM_CONNECTION_FAILURE.name()), record);
        assertTrue(record.contains(ResponseFlag.UPSTREAM_RETRY_LIMIT_EXCEEDED.name()), record);
    }

    @Test
    void eagerFailsOverBeforeAnsweringTheConnect() throws Exception {
        start(eager(), untrusted(), trusted());
        Outcome outcome = connectAndGet(null);
        assertEquals(200, outcome.connectStatus());
        assertTrue(outcome.inside().endsWith("trusted"), outcome.inside());
        assertEquals(millis(100), waits);
        assertEquals(List.of(), failures);
    }

    @Test
    void eagerAnswersTheConnectWith502WhenEveryRouteFails() throws Exception {
        start(eager(), untrusted(), untrusted(), untrusted());
        Outcome outcome = connectAndGet(null);
        assertEquals(502, outcome.connectStatus());
        assertEquals(millis(100, 100), waits);
        assertTlsFailure();
        TestSupport.eventually("the 502's record", () -> !sent.isEmpty());
        assertTrue(sent.getFirst().startsWith("502"), sent.toString());
        assertTrue(sent.getFirst().contains(ResponseFlag.UPSTREAM_CONNECTION_FAILURE.name()), sent.toString());
        assertTrue(sent.getFirst().contains(ResponseFlag.UPSTREAM_RETRY_LIMIT_EXCEEDED.name()), sent.toString());
    }

    @Test
    void eagerWithASingleRouteNeitherWaitsNorRetries() throws Exception {
        start(eager(), untrusted());
        assertEquals(502, connectAndGet(null).connectStatus());
        assertEquals(List.of(), waits);
        assertTlsFailure();
    }

    @Test
    void aFilterChoosesPerRequestOverThePolicy() throws Exception {
        // EAGER for HTTP/1 clients, but users named "deferred" get the default.
        ChainedProxy bad = untrusted();
        start(eager().withProxyAuthenticator(new ProxyAuthenticator() {
                    @Override
                    public boolean authenticate(String userName, String password) {
                        return true;
                    }

                    @Override
                    public String getRealm() {
                        return "test";
                    }
                })
                .withFiltersSource((request, ctx) -> new HttpFilters() {
                    @Override
                    public MitmServerHandshake proxyToServerMitmHandshake() {
                        return "deferred".equals(ctx.getClientDetails().getUserName())
                                ? MitmServerHandshake.DEFERRED : null;
                    }
                }), bad);
        assertEquals(502, connectAndGet("eager:x").connectStatus());
        Outcome deferred = connectAndGet("deferred:x");
        assertEquals(200, deferred.connectStatus());
        assertTrue(deferred.inside().startsWith("HTTP/1.1 502"), deferred.inside());
        var connect = new org.microproxy.http.DefaultHttpRequest(HttpVersion.HTTP_1_1,
                org.microproxy.http.HttpMethod.CONNECT, "localhost:443");
        assertEquals(MitmServerHandshake.EAGER, HttpFilters.builder().mitmServerHandshake(MitmServerHandshake.EAGER)
                .build().filterRequest(connect, null).proxyToServerMitmHandshake());
        org.microproxy.HttpFiltersSource none = (r, f) -> new HttpFilters() {};
        assertEquals(MitmServerHandshake.DEFERRED, org.microproxy.HttpFiltersChain.of(none,
                HttpFilters.builder().mitmServerHandshake(MitmServerHandshake.DEFERRED).build(),
                HttpFilters.builder().mitmServerHandshake(MitmServerHandshake.EAGER).build())
                .filterRequest(connect, null).proxyToServerMitmHandshake(), "the first choice wins");
    }

    @Test
    void littleProxysPresetIsEagerForHttp1Only() throws Exception {
        start(MicroProxy.bootstrap().withLittleProxyCompatibility(), untrusted());
        assertEquals(502, connectAndGet(null).connectStatus());
        assertEquals(Optional.of(MitmServerHandshake.EAGER),
                proxy.getProtocolPolicy(HttpVersion.HTTP_1_1).mitmServerHandshake());
        assertEquals(Optional.of(MitmServerHandshake.DEFERRED),
                proxy.getProtocolPolicy(HttpVersion.HTTP_2_0).mitmServerHandshake());
        assertEquals(Optional.of(MitmServerHandshake.DEFERRED), BootstrapView.protocolPolicy(
                MicroProxy.bootstrap().withLittleProxyCompatibility()
                        .onHttp1(p -> p.mitmServerHandshake(MitmServerHandshake.DEFERRED)), 1).mitmServerHandshake());
    }

    @Test
    void aConnectThatIsNotInterceptedIsTunnelledWhateverTheSetting() throws Exception {
        start(eager().withFiltersSource((request, ctx) -> new HttpFilters() {
            @Override
            public boolean proxyToServerAllowMitm() {
                return false;
            }
        }), untrusted());
        try (Socket raw = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            raw.setSoTimeout(20_000);
            TestSupport.write(raw.getOutputStream(), "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n");
            assertTrue(TestSupport.readUntil(raw.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
            // The client gets the server's own certificate, untouched.
            SSLSocket tls = (SSLSocket) strangerCa.clientContext().getSocketFactory()
                    .createSocket(raw, "localhost", 443, true);
            tls.startHandshake();
            TestSupport.write(tls.getOutputStream(), "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            assertTrue(new String(tls.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1).endsWith("stranger"));
        }
        assertEquals(List.of(), failures);
    }

    @Test
    void eachEagerAttemptHasTheRequestsHandshakeTimeout() throws Exception {
        // A server that accepts the connection and never answers the ClientHello.
        TestSupport.RawServer silent = TestSupport.rawServer(socket -> socket.getInputStream().readAllBytes());
        closeables.add(silent);
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, silent.port());
        start(eager().withFiltersSource(HttpFilters.builder().resolveWith(h -> address)
                        .tlsHandshakeTimeout(Duration.ofMillis(200)).build()),
                ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        assertEquals(502, connectAndGet(null).connectStatus());
        ProxyFailure.TlsFailed failure = assertInstanceOf(ProxyFailure.TlsFailed.class, failures.getFirst());
        assertEquals(ProxyFailure.TlsFailed.Reason.TIMEOUT, failure.reason());
    }

    @Test
    void deferredWithASingleRouteAnswersInsideWithoutWaiting() throws Exception {
        start(MicroProxy.bootstrap(), untrusted());
        Outcome outcome = connectAndGet(null);
        assertEquals(200, outcome.connectStatus());
        assertTrue(outcome.inside().startsWith("HTTP/1.1 502"), outcome.inside());
        assertEquals(List.of(), waits);
        assertTlsFailure();
        TestSupport.eventually("the 502's record", () -> sent.stream().anyMatch(r -> r.startsWith("502")));
        String record = sent.stream().filter(r -> r.startsWith("502")).findFirst().orElseThrow();
        assertTrue(!record.contains(ResponseFlag.UPSTREAM_RETRY_LIMIT_EXCEEDED.name()), record);
    }
}
