package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.StandardConstants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.impl.BootstrapView;
import org.microproxy.stats.Counter;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * {@link HttpProxyServerBootstrap#withTlsRetryWithoutSni}: a server that answers the server name
 * the proxy sends with a fatal {@code unrecognized_name} alert gets one more handshake without
 * SNI, on a new connection, with the certificate checked as before. The test server is the JDK's,
 * with an {@link javax.net.ssl.SNIMatcher} that recognizes {@code known.test} only: the JDK
 * answers any other name with that alert, and a ClientHello without SNI is accepted.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class TlsRetryWithoutSniTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("SNI Retry Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("SNI Retry Proxy CA");

    private HttpProxyServer proxy;
    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final RecordedFlows flows = new RecordedFlows();
    private final List<ProxyFailure> failures = new CopyOnWriteArrayList<>();
    private final StatsRegistry stats = StatsRegistry.create();

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    /**
     * An HTTPS server presenting {@code context}'s certificate that recognizes only {@code
     * known.test} as SNI, and answers every request with the server name its client sent in
     * {@code X-Sni} ({@code none} without one). A JDK {@link SSLServerSocket}: unlike the JDK's
     * {@code HttpsServer}, it sends the alert before closing.
     */
    private PickyOrigin pickyOrigin(SSLContext context) {
        try {
            PickyOrigin origin = new PickyOrigin(context);
            closeables.add(origin);
            return origin;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private PickyOrigin pickyOrigin() {
        return pickyOrigin(originCa.serverContext("localhost", "127.0.0.1"));
    }

    /** See {@link #pickyOrigin(SSLContext)}. */
    static final class PickyOrigin implements AutoCloseable {
        final SSLServerSocket socket;
        /** Handshakes the server refused for their SNI. */
        final AtomicInteger rejected = new AtomicInteger();

        PickyOrigin(SSLContext context) throws IOException {
            socket = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 50, TestSupport.LOOPBACK);
            SSLParameters params = socket.getSSLParameters();
            // Counts the refusals itself: the text of the handshake exception the server side
            // sees differs between JDK releases ("unrecognized_name" in some, "Unrecognized
            // server name indication" in others), the matcher's verdict does not.
            SNIMatcher known = SNIHostName.createSNIMatcher("known\\.test");
            params.setSNIMatchers(List.of(new SNIMatcher(StandardConstants.SNI_HOST_NAME) {
                @Override
                public boolean matches(SNIServerName name) {
                    boolean ok = known.matches(name);
                    if (!ok) rejected.incrementAndGet();
                    return ok;
                }
            }));
            socket.setSSLParameters(params);
            Thread.ofVirtual().start(() -> {
                while (!socket.isClosed()) {
                    try {
                        SSLSocket client = (SSLSocket) socket.accept();
                        Thread.ofPlatform().daemon().start(() -> serve(client));
                    } catch (IOException e) {
                        return;
                    }
                }
            });
        }

        int port() {
            return socket.getLocalPort();
        }

        private void serve(SSLSocket client) {
            try (client) {
                client.setSoTimeout(20_000);
                try {
                    client.startHandshake();
                } catch (SSLHandshakeException e) {
                    return;
                }
                String sni = "none";
                if (client.getSession() instanceof ExtendedSSLSession session) {
                    for (SNIServerName name : session.getRequestedServerNames()) {
                        if (name instanceof SNIHostName host) sni = host.getAsciiName();
                    }
                }
                InputStream in = client.getInputStream();
                OutputStream out = client.getOutputStream();
                while (true) {
                    String head = TestSupport.readUntil(in, "\r\n\r\n");
                    if (!head.endsWith("\r\n\r\n")) return;
                    out.write(("HTTP/1.1 200 OK\r\nX-Sni: " + sni + "\r\nContent-Length: 5\r\n\r\npicky")
                            .getBytes(StandardCharsets.ISO_8859_1));
                    out.flush();
                }
            } catch (IOException e) {
                // the client left
            }
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    /** A forward proxy that trusts the origin's CA, records flows and failures, and counts. */
    private HttpProxyServerBootstrap forward() {
        return MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withStats(stats)
                .plusActivityTracker(flows)
                .withFailureResponder((request, failure) -> {
                    failures.add(failure);
                    return null;
                });
    }

    /** {@code https://localhost:<port>/}: a name the proxy sends as SNI, which the server rejects. */
    private static String url(PickyOrigin server) {
        return "https://localhost:" + server.port() + "/";
    }

    private long stat(String name) {
        return ((Counter) stats.get(name)).value();
    }

    private TlsOriginationTest.Http1.Response originate(String url) throws IOException {
        try (TlsOriginationTest.Http1 client = new TlsOriginationTest.Http1(proxy)) {
            return client.send("GET", url, null);
        }
    }

    @Test
    void offByDefaultTheRejectionIsATlsFailureWithTheAlert() throws Exception {
        PickyOrigin origin = pickyOrigin();
        proxy = forward().start();
        assertEquals(502, originate(url(origin)).status());
        ProxyFailure.TlsFailed failure = assertInstanceOf(ProxyFailure.TlsFailed.class, failures.getFirst());
        assertEquals("unrecognized_name", failure.alert());
        assertEquals(ProxyFailure.TlsFailed.Reason.ALERT_RECEIVED, failure.reason());
        assertEquals(0, stat("cluster.direct.ssl.retry_without_sni"));
        assertEquals(1, stat("cluster.direct.ssl.connection_error"));
        FlowRecord record = flows.await("a 502 record", r -> r.responseCode() == 502);
        assertTrue(record.upstreamTransportFailureReason().startsWith("alert_received: "),
                record.upstreamTransportFailureReason());
    }

    @Test
    void whenOnTheServerGetsAHandshakeWithoutSni() throws Exception {
        PickyOrigin origin = pickyOrigin();
        proxy = forward().withTlsRetryWithoutSni(true).start();
        TlsOriginationTest.Http1.Response r = originate(url(origin));
        assertEquals(200, r.status(), r.toString());
        assertEquals("none", r.header("x-sni"));
        assertEquals(List.of(), failures);
        TestSupport.eventually("the server's refusal", () -> origin.rejected.get() == 1);
        assertEquals(1, stat("cluster.direct.ssl.retry_without_sni"));
        assertEquals(1, stat("cluster.direct.ssl.handshake"));
        assertEquals(1, stat("cluster.direct.ssl.connection_error"));
        // The exchange succeeded: the first attempt's failure is not its transport failure.
        FlowRecord record = flows.await("a 200 record", f -> f.responseCode() == 200);
        assertEquals(null, record.upstreamTransportFailureReason());
    }

    @Test
    void aNameTheServerKnowsIsNeverRetried() throws Exception {
        PickyOrigin origin = pickyOrigin(originCa.serverContext("known.test"));
        // known.test resolves to the server, for the proxy only.
        proxy = forward().withTlsRetryWithoutSni(true).withFiltersSource(HttpFilters.builder()
                .resolveWith(h -> new InetSocketAddress(TestSupport.LOOPBACK, origin.port())).build())
                .start();
        TlsOriginationTest.Http1.Response r = originate("https://known.test:" + origin.port() + "/");
        assertEquals(200, r.status(), r.toString());
        assertEquals("known.test", r.header("x-sni"));
        assertEquals(0, stat("cluster.direct.ssl.retry_without_sni"));
    }

    @Test
    void littleProxyCompatibilityTurnsItOnUnlessSetOtherwise() throws Exception {
        PickyOrigin origin = pickyOrigin();
        proxy = forward().withLittleProxyCompatibility(true).start();
        assertEquals("none", originate(url(origin)).header("x-sni"));
        proxy.abort();

        proxy = forward().withLittleProxyCompatibility(true).withTlsRetryWithoutSni(false).start();
        assertEquals(502, originate(url(origin)).status());
    }

    @Test
    void theRetryChecksTheCertificateAgainstTheSameHost() throws Exception {
        // Without SNI the server presents a certificate for another name: still refused.
        PickyOrigin origin = pickyOrigin(originCa.serverContext("default.test"));
        proxy = forward().withTlsRetryWithoutSni(true).start();
        assertEquals(502, originate(url(origin)).status());
        assertEquals(1, stat("cluster.direct.ssl.retry_without_sni"));
        ProxyFailure.TlsFailed failure = assertInstanceOf(ProxyFailure.TlsFailed.class, failures.getFirst());
        assertEquals(ProxyFailure.TlsFailed.Reason.HOSTNAME_MISMATCH, failure.reason());
        assertEquals(2, stat("cluster.direct.ssl.connection_error"));
    }

    @Test
    void anInterceptedSessionsServerIsRetriedToo() throws Exception {
        // The CONNECT's handshake with the server waits for the client's ClientHello; when the
        // server rejects the name, the proxy dials again and runs it without SNI.
        PickyOrigin origin = pickyOrigin();
        proxy = forward().withTlsRetryWithoutSni(true).start();
        HttpResponse<String> r = TestSupport.get(TestSupport.client(proxy, proxyCa.clientContext()), url(origin));
        assertEquals(200, r.statusCode(), r.body());
        assertEquals("none", r.headers().firstValue("X-Sni").orElseThrow());
        assertEquals(1, stat("cluster.direct.ssl.retry_without_sni"));
        assertEquals(List.of(), failures);
    }

    @Test
    void anEagerHandshakeSendsTheConnectsHostAndIsRetriedToo() throws Exception {
        // The server's handshake runs before the CONNECT is answered: the retry without SNI happens
        // then too, and the CONNECT is answered once it worked.
        PickyOrigin origin = pickyOrigin();
        proxy = forward().withTlsRetryWithoutSni(true)
                .onAllProtocols(p -> p.mitmServerHandshake(MitmServerHandshake.EAGER)).start();
        HttpResponse<String> r = TestSupport.get(TestSupport.client(proxy, proxyCa.clientContext()), url(origin));
        assertEquals(200, r.statusCode(), r.body());
        assertEquals("none", r.headers().firstValue("X-Sni").orElseThrow());
        assertEquals(1, origin.rejected.get(), "the first handshake sent the CONNECT's host");
        assertEquals(1, stat("cluster.direct.ssl.retry_without_sni"));
    }

    /** What the hooks and trackers were told of failed attempts at the server, and what the client got. */
    private record Reported(int connectionFailed, int serverFailures, int tlsFailures, String answer) {}

    /**
     * A CONNECT to a server that rejects the name it is sent, with {@code mode} running the
     * handshake; the proxy's first connection reaches the server, and later ones go to {@code
     * redialTo} (a refusing port, or the server again). Then a GET inside the session, if any.
     */
    private Reported connectThroughRejection(MitmServerHandshake mode, PickyOrigin origin, InetSocketAddress redialTo)
            throws IOException {
        AtomicInteger resolutions = new AtomicInteger();
        AtomicInteger connectionFailed = new AtomicInteger();
        AtomicInteger serverFailures = new AtomicInteger();
        AtomicInteger tlsFailures = new AtomicInteger();
        InetSocketAddress first = new InetSocketAddress(TestSupport.LOOPBACK, origin.port());
        proxy = forward().withTlsRetryWithoutSni(true).onAllProtocols(p -> p.mitmServerHandshake(mode))
                .withFiltersSource((request, ctx) -> new HttpFilters() {
                    @Override
                    public InetSocketAddress proxyToServerResolutionStarted(String hostAndPort) {
                        return resolutions.getAndIncrement() == 0 ? first : redialTo;
                    }

                    @Override
                    public void proxyToServerConnectionFailed() {
                        connectionFailed.incrementAndGet();
                    }
                })
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void serverConnectionExceptionCaught(FullFlowContext serverContext, Throwable cause) {
                        serverFailures.incrementAndGet();
                    }

                    @Override
                    public void tlsHandshakeFailed(FlowContext ctx, boolean clientSide, Throwable cause) {
                        if (!clientSide) tlsFailures.incrementAndGet();
                    }
                })
                .start();
        String target = "localhost:" + origin.port();
        String answer;
        try (java.net.Socket raw = new java.net.Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            raw.setSoTimeout(20_000);
            TestSupport.write(raw.getOutputStream(), "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
            answer = TestSupport.readUntil(raw.getInputStream(), "\r\n\r\n");
            if (answer.startsWith("HTTP/1.1 200")) {
                SSLSocket tls = (SSLSocket) proxyCa.clientContext().getSocketFactory()
                        .createSocket(raw, "localhost", origin.port(), true);
                tls.startHandshake();
                TestSupport.write(tls.getOutputStream(), "GET / HTTP/1.1\r\nHost: " + target
                        + "\r\nConnection: close\r\n\r\n");
                answer = new String(tls.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
            }
        }
        return new Reported(connectionFailed.get(), serverFailures.get(), tlsFailures.get(), answer);
    }

    private long counter(String name) {
        return stats.get(name) instanceof Counter c ? c.value() : 0;
    }

    @Test
    void aRetryWithoutSniThatCannotConnectIsOneFailedAttempt() throws Exception {
        // The redial without SNI belongs to the attempt the server rejected: when it cannot
        // connect, that attempt failed once, and only its last failure is reported.
        for (MitmServerHandshake mode : MitmServerHandshake.values()) {
            PickyOrigin origin = pickyOrigin();
            java.net.Socket refusing = TestSupport.refusingPort();
            closeables.add(refusing);
            long connectFailBefore = counter("cluster.direct.upstream_cx_connect_fail");
            failures.clear();
            Reported reported = connectThroughRejection(mode, origin,
                    new InetSocketAddress(TestSupport.LOOPBACK, refusing.getLocalPort()));
            assertTrue(reported.answer().startsWith("HTTP/1.1 502"), mode + ": " + reported.answer());
            assertEquals(1, reported.connectionFailed(), mode + ": proxyToServerConnectionFailed");
            assertEquals(1, reported.serverFailures(), mode + ": serverConnectionExceptionCaught");
            assertEquals(0, reported.tlsFailures(), mode + ": the attempt's last failure was not TLS's");
            assertEquals(1, counter("cluster.direct.upstream_cx_connect_fail") - connectFailBefore, mode.toString());
            assertEquals(1, failures.size(), mode.toString());
            assertInstanceOf(ProxyFailure.ConnectFailed.class, failures.getFirst(), mode.toString());
            proxy.abort();
        }
    }

    @Test
    void aRetryWithoutSniThatWorksReportsNoFailure() throws Exception {
        for (MitmServerHandshake mode : MitmServerHandshake.values()) {
            PickyOrigin origin = pickyOrigin();
            long connectFailBefore = counter("cluster.direct.upstream_cx_connect_fail");
            long retriesBefore = counter("cluster.direct.ssl.retry_without_sni");
            Reported reported = connectThroughRejection(mode, origin,
                    new InetSocketAddress(TestSupport.LOOPBACK, origin.port()));
            assertTrue(reported.answer().startsWith("HTTP/1.1 200"), mode + ": " + reported.answer());
            assertTrue(reported.answer().contains("X-Sni: none"), mode + ": " + reported.answer());
            assertEquals(0, reported.connectionFailed(), mode.toString());
            assertEquals(0, reported.serverFailures(), mode.toString());
            assertEquals(0, reported.tlsFailures(), mode.toString());
            assertEquals(0, counter("cluster.direct.upstream_cx_connect_fail") - connectFailBefore, mode.toString());
            assertEquals(1, counter("cluster.direct.ssl.retry_without_sni") - retriesBefore, mode.toString());
            proxy.abort();
        }
    }

    @Test
    void configuredFromTheBootstrapPropertiesAndCommandLine() throws IOException {
        assertFalse(BootstrapView.retriesTlsWithoutSni(MicroProxy.bootstrap()));
        assertTrue(BootstrapView.retriesTlsWithoutSni(MicroProxy.bootstrap().withLittleProxyCompatibility()));
        assertFalse(BootstrapView.retriesTlsWithoutSni(
                MicroProxy.bootstrap().withTlsRetryWithoutSni(false).withLittleProxyCompatibility()));
        assertTrue(BootstrapView.retriesTlsWithoutSni(MicroProxy.bootstrap().withTlsRetryWithoutSni(true)));

        Properties props = new Properties();
        props.setProperty("tls_retry_without_sni", "true");
        assertTrue(BootstrapView.retriesTlsWithoutSni(BootstrapView.fromProperties(props)));
        props.setProperty("littleproxy_compatibility", "true");
        props.setProperty("tls_retry_without_sni", "false");
        assertFalse(BootstrapView.retriesTlsWithoutSni(BootstrapView.fromProperties(props)));

        PrintStream quiet = new PrintStream(OutputStream.nullOutputStream());
        assertTrue(BootstrapView.retriesTlsWithoutSni(
                Launcher.parse(new String[] {"--tls-retry-without-sni"}, quiet).bootstrap()));
        assertTrue(BootstrapView.retriesTlsWithoutSni(
                Launcher.parse(new String[] {"--littleproxy-compat"}, quiet).bootstrap()));
        assertFalse(BootstrapView.retriesTlsWithoutSni(Launcher.parse(
                new String[] {"--littleproxy-compat", "--no-tls-retry-without-sni"}, quiet).bootstrap()));
    }
}
