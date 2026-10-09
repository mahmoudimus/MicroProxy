package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.write;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.ActivityTrackerAdapter;
import org.microproxy.ChainedProxyAdapter;
import org.microproxy.FlowContext;
import org.microproxy.FullFlowContext;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.tls.SslContexts;

/** TLS handshake log lines, the tracker events for failed handshakes, and connection ids in logs. */
class TlsDiagnosticsTest {

    private static final SelfSignedSslContextSource PROXY_TLS = new SelfSignedSslContextSource();
    private static final SelfSignedSslContextSource OTHER_TLS = new SelfSignedSslContextSource();

    private final List<HttpProxyServer> proxies = new CopyOnWriteArrayList<>();
    private final Events events = new Events();
    private Captured tlsLog;
    private Captured connectionLog;

    /** Captures a java.util.logging logger's records at FINE and above. */
    static final class Captured extends Handler {
        final List<LogRecord> records = new CopyOnWriteArrayList<>();
        private final Logger logger;
        private final Level previous;

        Captured(String name) {
            logger = Logger.getLogger(name);
            previous = logger.getLevel();
            logger.setLevel(Level.FINE);
            setLevel(Level.ALL);
            logger.addHandler(this);
        }

        @Override
        public void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {}

        @Override
        public void close() {
            logger.removeHandler(this);
            logger.setLevel(previous);
        }

        LogRecord await(Predicate<String> matching) throws InterruptedException {
            for (int i = 0; i < 300; i++) {
                for (LogRecord r : records) {
                    if (matching.test(r.getMessage())) return r;
                }
                Thread.sleep(10);
            }
            throw new AssertionError("no matching log line in " + records.stream().map(LogRecord::getMessage).toList());
        }
    }

    /** Records connections and failed handshakes. */
    static final class Events extends ActivityTrackerAdapter {
        final List<FlowContext> connected = new CopyOnWriteArrayList<>();
        final List<FlowContext> failedContexts = new CopyOnWriteArrayList<>();
        final List<Boolean> failedClientSide = new CopyOnWriteArrayList<>();
        final List<Throwable> failedCauses = new CopyOnWriteArrayList<>();

        @Override
        public void clientConnected(FlowContext ctx) {
            connected.add(ctx);
        }

        @Override
        public void tlsHandshakeFailed(FlowContext ctx, boolean clientSide, Throwable cause) {
            failedContexts.add(ctx);
            failedClientSide.add(clientSide);
            failedCauses.add(cause);
        }

        void awaitFailure() throws InterruptedException {
            for (int i = 0; i < 300 && failedCauses.isEmpty(); i++) Thread.sleep(10);
        }
    }

    @BeforeEach
    void captureLogs() {
        tlsLog = new Captured(Tls.class.getName());
        connectionLog = new Captured(ClientConnection.class.getName());
    }

    @AfterEach
    void tearDown() {
        tlsLog.close();
        connectionLog.close();
        proxies.forEach(HttpProxyServer::abort);
    }

    private HttpProxyServer start(org.microproxy.HttpProxyServerBootstrap bootstrap) {
        HttpProxyServer proxy = bootstrap.withPort(0).plusActivityTracker(events).start();
        proxies.add(proxy);
        return proxy;
    }

    private static String prefix(FlowContext ctx) {
        return "[conn " + ctx.getConnectionId() + "] ";
    }

    @Test
    void untrustedChainedProxyIsAWarningWithTheCertificatesAndTheConnectionId() throws Exception {
        // The upstream is not tracked: only the downstream's failure is of interest.
        HttpProxyServer upstreamProxy = MicroProxy.bootstrap().withPort(0).withSslContextSource(PROXY_TLS).start();
        proxies.add(upstreamProxy);
        InetSocketAddress upstream = upstreamProxy.getListenAddress();
        HttpProxyServer proxy = start(MicroProxy.bootstrap().withChainProxyManager((request, queue, details) ->
                queue.add(new ChainedProxyAdapter() {
                    @Override
                    public InetSocketAddress getChainedProxyAddress() {
                        return upstream;
                    }

                    @Override
                    public boolean requiresEncryption() {
                        return true;
                    }

                    @Override
                    public javax.net.ssl.SSLContext getSslContext() {
                        return OTHER_TLS.getSslContext();
                    }
                })));
        assertEquals(502, TestSupport.get(TestSupport.client(proxy), "http://127.0.0.1:1/").statusCode());

        events.awaitFailure();
        FullFlowContext ctx = assertInstanceOf(FullFlowContext.class, events.failedContexts.getFirst());
        assertFalse(events.failedClientSide.getFirst());
        assertInstanceOf(SSLHandshakeException.class, events.failedCauses.getFirst());
        assertEquals(upstream, ctx.getRemoteAddress());

        LogRecord line = tlsLog.await(m -> m.contains("TLS handshake with chained proxy failed"));
        String message = line.getMessage();
        assertEquals(Level.WARNING, line.getLevel());
        assertTrue(message.startsWith(prefix(ctx)), message);
        assertTrue(message.contains(" peer=" + ctx.getRemoteAddress()), message);
        assertTrue(message.contains(" mode=client "), message);
        assertTrue(message.contains("error=\"SSLHandshakeException: "), message);
        assertTrue(message.contains("root=\"CertPathValidatorException: "), message);
        // The JDK does not keep a chain it rejected for an unknown issuer, so there is nothing to list.
        assertTrue(message.endsWith("; local cert: none; peer chain: none"), message);
        assertNull(line.getThrown(), "expected failures carry no stack trace");
    }

    @Test
    void clientsThatRejectTheProxysCertificateAreLoggedAtDebug() throws Exception {
        HttpProxyServer proxy = start(MicroProxy.bootstrap().withSslContextSource(PROXY_TLS));
        InetSocketAddress address = proxy.getListenAddress();
        try (Socket plain = new Socket(address.getAddress(), address.getPort())) {
            plain.setSoTimeout(10_000);
            // Without autoClose the connection outlives the failed handshake, so the proxy finishes
            // writing its flight and reads the client's alert rather than a reset.
            SSLSocket tls = (SSLSocket) OTHER_TLS.getSslContext().getSocketFactory()
                    .createSocket(plain, "proxy.test", address.getPort(), false);
            assertThrows(SSLException.class, tls::startHandshake);
            events.awaitFailure();
        }
        events.awaitFailure();
        FlowContext ctx = events.failedContexts.getFirst();
        assertTrue(events.failedClientSide.getFirst());

        LogRecord line = tlsLog.await(m -> m.contains("TLS handshake with client failed"));
        assertEquals(Level.FINE, line.getLevel());
        String message = line.getMessage();
        assertTrue(message.startsWith(prefix(ctx)), message);
        assertTrue(message.contains(" mode=server"), message);
        assertTrue(message.contains("certificate_unknown"), message);
        String subject = PROXY_TLS.getCertificate().getSubjectX500Principal().getName();
        assertTrue(message.contains("local cert: [subject=\"" + subject + "\""), message);
        assertNull(line.getThrown());
        LogRecord started = tlsLog.await(m -> m.contains("TLS handshake with client started"));
        assertTrue(started.getMessage().contains(" clientAuth=none"), started.getMessage());
    }

    @Test
    void successfulHandshakesLogTheNegotiatedProtocolAtDebug() throws Exception {
        HttpProxyServer proxy = start(MicroProxy.bootstrap().withSslContextSource(PROXY_TLS));
        InetSocketAddress address = proxy.getListenAddress();
        try (Socket plain = new Socket(address.getAddress(), address.getPort())) {
            plain.setSoTimeout(10_000);
            SSLSocket tls = (SSLSocket) SslContexts.trusting(PROXY_TLS.getCertificate()).getSocketFactory()
                    .createSocket(plain, "proxy.test", address.getPort(), true);
            tls.startHandshake();
            String protocol = tls.getSession().getProtocol();
            LogRecord line = tlsLog.await(m -> m.contains("TLS handshake with client succeeded"));
            assertEquals(Level.FINE, line.getLevel());
            assertTrue(line.getMessage().startsWith(prefix(events.connected.getFirst())), line.getMessage());
            assertTrue(line.getMessage().contains(" protocol=" + protocol + " cipher="), line.getMessage());
            assertTrue(line.getMessage().contains(" sni=proxy.test "), line.getMessage());
        }
        assertTrue(events.failedCauses.isEmpty());
    }

    @Test
    void parseErrorsCarryTheConnectionIdAndConnectionsTheirAcceptTime() throws Exception {
        Instant before = Instant.now();
        HttpProxyServer proxy = start(MicroProxy.bootstrap());
        try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(10_000);
            write(s.getOutputStream(), "NOT A REQUEST LINE AT ALL\r\n\r\n");
            assertTrue(new String(s.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.ISO_8859_1)
                    .startsWith("HTTP/1.1 400 "));
        }
        for (int i = 0; i < 100 && events.connected.isEmpty(); i++) Thread.sleep(10);
        FlowContext ctx = events.connected.getFirst();
        assertFalse(ctx.acceptedAt().isBefore(before));
        assertFalse(ctx.acceptedAt().isAfter(Instant.now()));
        LogRecord line = connectionLog.await(m -> m.contains("bad request from client"));
        assertTrue(line.getMessage().startsWith(prefix(ctx)), line.getMessage());
        assertEquals(new FullFlowContext(ctx, "h:1", null, null).acceptedAt(), ctx.acceptedAt());
    }

    @Test
    void diagnosticsThatThrowAreSwallowed() throws Exception {
        TlsLog.Peer peer = new TlsLog.Peer("[conn 0] ", "server", "example.test");
        Socket broken = new Socket() {
            @Override
            public SocketAddress getRemoteSocketAddress() {
                throw new IllegalStateException("no address");
            }
        };
        TlsLog.started(peer, broken, true, false);
        TlsLog.failed(peer, broken, null, true, new SSLHandshakeException("handshake failed"));
        tlsLog.await(m -> m.equals("[conn 0] TLS diagnostics failed: java.lang.IllegalStateException: no address"));

        String summary = TlsLog.describe(new Certificate[] {new UnreadableCertificate(), PROXY_TLS.getCertificate()});
        assertTrue(summary.startsWith("[unreadable certificate: IllegalStateException] <- [subject=\""), summary);
        assertEquals("none", TlsLog.describe(null));
    }

    @Test
    void failureLevels() {
        TlsLog.Peer client = new TlsLog.Peer("", "client", null);
        TlsLog.Peer server = new TlsLog.Peer("", "server", "h");
        System.Logger.Level debug = System.Logger.Level.DEBUG;
        assertEquals(debug, TlsLog.level(client, new SSLHandshakeException("PKIX path building failed")));
        assertEquals(System.Logger.Level.WARNING, TlsLog.level(server, new SSLHandshakeException("PKIX path building failed")));
        assertEquals(System.Logger.Level.WARNING,
                TlsLog.level(server, new SSLHandshakeException("Received fatal alert: bad_certificate")));
        assertEquals(System.Logger.Level.INFO,
                TlsLog.level(server, new java.net.SocketTimeoutException("TLS handshake not finished within 10 ms")));
        assertEquals(System.Logger.Level.INFO, TlsLog.level(server, new SSLHandshakeException("no cipher suites in common")));
        assertEquals(debug, TlsLog.level(server, new SSLException("Unrecognized SSL message, plaintext connection?")));
    }

    @Test
    void interceptedHttpsStillWorksWithDebugLogging() throws Exception {
        org.microproxy.tls.CertificateAuthority originCa = org.microproxy.tls.CertificateAuthority.generate("Diag Origin CA");
        org.microproxy.tls.CertificateAuthority proxyCa = org.microproxy.tls.CertificateAuthority.generate("Diag Proxy CA");
        com.sun.net.httpserver.HttpsServer origin =
                TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), TestSupport.fixed(200, "ok"));
        try {
            HttpProxyServer proxy = start(MicroProxy.bootstrap().withManInTheMiddle(
                    new org.microproxy.tls.CertificateAuthorityMitmManager(proxyCa, originCa.clientContext())));
            HttpClient client = TestSupport.client(proxy, proxyCa.clientContext());
            HttpResponse<String> response = client.send(HttpRequest.newBuilder(URI.create(TestSupport.url(origin, "/")))
                    .timeout(Duration.ofSeconds(20)).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals("ok", response.body());
            tlsLog.await(m -> m.contains("TLS handshake with server succeeded") && m.contains(" host=127.0.0.1 "));
            tlsLog.await(m -> m.contains("TLS handshake with client succeeded") && m.contains(" host=127.0.0.1 "));
        } finally {
            origin.stop(0);
        }
    }

    /** A certificate whose every accessor fails. */
    private static final class UnreadableCertificate extends X509Certificate {
        private static RuntimeException broken() {
            return new IllegalStateException("unreadable");
        }

        @Override public void checkValidity() { throw broken(); }
        @Override public void checkValidity(Date date) { throw broken(); }
        @Override public int getVersion() { throw broken(); }
        @Override public BigInteger getSerialNumber() { throw broken(); }
        @Override public Principal getIssuerDN() { throw broken(); }
        @Override public Principal getSubjectDN() { throw broken(); }
        @Override public javax.security.auth.x500.X500Principal getSubjectX500Principal() { throw broken(); }
        @Override public Date getNotBefore() { throw broken(); }
        @Override public Date getNotAfter() { throw broken(); }
        @Override public byte[] getTBSCertificate() { throw broken(); }
        @Override public byte[] getSignature() { throw broken(); }
        @Override public String getSigAlgName() { throw broken(); }
        @Override public String getSigAlgOID() { throw broken(); }
        @Override public byte[] getSigAlgParams() { throw broken(); }
        @Override public boolean[] getIssuerUniqueID() { throw broken(); }
        @Override public boolean[] getSubjectUniqueID() { throw broken(); }
        @Override public boolean[] getKeyUsage() { throw broken(); }
        @Override public int getBasicConstraints() { throw broken(); }
        @Override public byte[] getEncoded() { throw broken(); }
        @Override public void verify(PublicKey key) { throw broken(); }
        @Override public void verify(PublicKey key, String sigProvider) { throw broken(); }
        @Override public String toString() { return "unreadable"; }
        @Override public PublicKey getPublicKey() { throw broken(); }
        @Override public boolean hasUnsupportedCriticalExtension() { throw broken(); }
        @Override public Set<String> getCriticalExtensionOIDs() { throw broken(); }
        @Override public Set<String> getNonCriticalExtensionOIDs() { throw broken(); }
        @Override public byte[] getExtensionValue(String oid) { throw broken(); }
        @Override public int hashCode() { return 0; }
        @Override public boolean equals(Object o) { return o == this; }
    }
}
