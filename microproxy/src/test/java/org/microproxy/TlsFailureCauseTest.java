package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.http.HttpResponse;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateRevokedException;
import java.security.cert.X509CRL;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.ProxyFailure.TlsFailed.Reason;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.TestPki;

/**
 * {@link ProxyFailure.TlsFailed#cause()} is the handshake's own exception with its whole cause
 * chain, the same object for the failure responder, the filters, the access-log record and the
 * activity trackers; {@link ProxyFailure.TlsFailed#reason()} reads it. Each test fails a server
 * handshake a different way: a revoked certificate (checked against a CRL the test signs), an
 * expired one, an untrusted one, one for another name, and an alert from the server.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class TlsFailureCauseTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("TLS Failure Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("TLS Failure Proxy CA");
    static final CertificateAuthority strangerCa = CertificateAuthority.generate("TLS Failure Stranger CA");

    private HttpProxyServer proxy;
    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final RecordedFlows flows = new RecordedFlows();
    private final List<ProxyFailure> responderSaw = new CopyOnWriteArrayList<>();
    private final List<ProxyFailure> filtersSaw = new CopyOnWriteArrayList<>();
    private final List<Throwable> trackersSaw = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    private HttpsServer origin(SSLContext context) {
        HttpsServer server = TestSupport.httpsOrigin(context, TestSupport.fixed(200, "ok"));
        closeables.add(() -> server.stop(0));
        return server;
    }

    /** A forward proxy validating servers with {@code serverTrust}, recording what sees each failure. */
    private HttpProxyServer start(SSLContext serverTrust) {
        return MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, serverTrust))
                .plusActivityTracker(flows)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void tlsHandshakeFailed(FlowContext flowContext, boolean clientSide, Throwable cause) {
                        if (!clientSide) trackersSaw.add(cause);
                    }
                })
                .withFiltersSource(HttpFilters.builder().onFailure(failure -> {
                    filtersSaw.add(failure);
                    return null;
                }).build())
                .withFailureResponder((request, failure) -> {
                    responderSaw.add(failure);
                    return null;
                })
                .start();
    }

    private int originate(HttpsServer server) throws IOException {
        try (TlsOriginationTest.Http1 client = new TlsOriginationTest.Http1(proxy)) {
            return client.send("GET", "https://localhost:" + server.getAddress().getPort() + "/", null).status();
        }
    }

    /**
     * The failure everyone saw: one {@link ProxyFailure.TlsFailed}, the same for the filters and the
     * responder and the record, whose cause is the exception the trackers got for the handshake.
     */
    private ProxyFailure.TlsFailed theFailure() {
        ProxyFailure.TlsFailed failure = assertInstanceOf(ProxyFailure.TlsFailed.class, responderSaw.getLast());
        assertSame(failure, filtersSaw.getLast());
        FlowRecord record = flows.await("a 502 record", r -> r.responseCode() == 502);
        assertSame(failure, record.failure().orElseThrow());
        assertTrue(record.upstreamTransportFailureReason().startsWith(failure.reason().code() + ": "),
                record.upstreamTransportFailureReason());
        assertSame(failure.cause(), trackersSaw.getLast(), "the handshake's own exception, not a wrapper");
        return failure;
    }

    private static <T extends Throwable> T inChain(Throwable failure, Class<T> type) {
        for (Throwable t = failure; t != null; t = t.getCause()) {
            if (type.isInstance(t)) return type.cast(t);
        }
        throw new AssertionError("no " + type.getSimpleName() + " in the cause chain of " + failure);
    }

    @Test
    void aRevokedCertificateKeepsTheValidatorsReason() throws Exception {
        TestPki.Server server = TestPki.server(originCa, "localhost");
        X509CRL crl = TestPki.crl(originCa, server.leaf());
        HttpsServer origin = origin(server.context());
        proxy = start(TestPki.revocationCheckingClientContext(originCa, crl));
        assertEquals(502, originate(origin));
        ProxyFailure.TlsFailed failure = theFailure();
        assertInstanceOf(SSLHandshakeException.class, failure.cause());
        CertPathValidatorException validator = inChain(failure.cause(), CertPathValidatorException.class);
        assertEquals(CertPathValidatorException.BasicReason.REVOKED, validator.getReason());
        CertificateRevokedException revoked = inChain(failure.cause(), CertificateRevokedException.class);
        assertEquals(server.leaf().getIssuerX500Principal(), revoked.getAuthorityName());
        assertEquals(Reason.CERTIFICATE_REVOKED, failure.reason());
        assertNull(failure.alert());
    }

    @Test
    void aCrlThatDoesNotListTheCertificateLetsItThrough() throws Exception {
        // The same setup with nothing revoked: revocation checking itself works.
        TestPki.Server server = TestPki.server(originCa, "localhost");
        HttpsServer origin = origin(server.context());
        proxy = start(TestPki.revocationCheckingClientContext(originCa, TestPki.crl(originCa)));
        assertEquals(200, originate(origin));
    }

    @Test
    void anExpiredCertificate() throws Exception {
        Instant now = Instant.now();
        HttpsServer origin = origin(TestPki.server(originCa, now.minus(Duration.ofDays(30)),
                now.minus(Duration.ofDays(1)), "localhost").context());
        proxy = start(originCa.clientContext());
        assertEquals(502, originate(origin));
        ProxyFailure.TlsFailed failure = theFailure();
        inChain(failure.cause(), CertificateExpiredException.class);
        assertEquals(Reason.CERTIFICATE_EXPIRED, failure.reason());
    }

    @Test
    void anUntrustedCertificate() throws Exception {
        HttpsServer origin = origin(strangerCa.serverContext("localhost"));
        proxy = start(originCa.clientContext());
        assertEquals(502, originate(origin));
        ProxyFailure.TlsFailed failure = theFailure();
        inChain(failure.cause(), CertPathBuilderException.class);
        assertEquals(Reason.CERTIFICATE_UNTRUSTED, failure.reason());
    }

    @Test
    void aCertificateForAnotherName() throws Exception {
        HttpsServer origin = origin(originCa.serverContext("elsewhere.test"));
        proxy = start(originCa.clientContext());
        assertEquals(502, originate(origin));
        ProxyFailure.TlsFailed failure = theFailure();
        assertTrue(inChain(failure.cause(), CertificateException.class).getMessage().startsWith("No subject alternative"));
        assertEquals(Reason.HOSTNAME_MISMATCH, failure.reason());
    }

    @Test
    void aRevokedCertificateInsideAnInterceptedSession() throws Exception {
        // The CONNECT's handshake fails first; the session is intercepted anyway and its request
        // fails the same way, through the same filters and responder.
        TestPki.Server server = TestPki.server(originCa, "localhost");
        HttpsServer origin = origin(server.context());
        proxy = start(TestPki.revocationCheckingClientContext(originCa, TestPki.crl(originCa, server.leaf())));
        HttpResponse<String> r = TestSupport.get(TestSupport.client(proxy, proxyCa.clientContext()),
                "https://localhost:" + origin.getAddress().getPort() + "/");
        assertEquals(502, r.statusCode());
        ProxyFailure.TlsFailed failure = theFailure();
        assertEquals(CertPathValidatorException.BasicReason.REVOKED,
                inChain(failure.cause(), CertPathValidatorException.class).getReason());
    }

    @Test
    void reasonsReadFromChains() {
        assertEquals(Reason.OTHER, Reason.of(null));
        assertEquals(Reason.OTHER, Reason.of(new SSLHandshakeException("No appropriate protocol")));
        assertEquals(Reason.ALERT_RECEIVED, Reason.of(new SSLHandshakeException("Received fatal alert: handshake_failure")));
        assertEquals("handshake_failure", Reason.alertOf(new SSLHandshakeException("Received fatal alert: handshake_failure")));
        assertEquals("unrecognized_name", Reason.alertOf(
                new IOException("wrapped", new SSLHandshakeException("Received handshake warning: unrecognized_name"))));
        assertNull(Reason.alertOf(new IOException("Received fatal alert: not an SSLException")));
        SocketTimeoutException timeout = new SocketTimeoutException("TLS handshake not finished within 10 ms");
        assertEquals(Reason.TIMEOUT, Reason.of(timeout));
        SSLHandshakeException undetermined = new SSLHandshakeException("PKIX path validation failed");
        undetermined.initCause(new CertificateException("x", new CertPathValidatorException("no CRL", null, null, -1,
                CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS)));
        assertEquals(Reason.REVOCATION_STATUS_UNKNOWN, Reason.of(undetermined));
        assertEquals("revocation_status_unknown", Reason.REVOCATION_STATUS_UNKNOWN.code());
        SSLHandshakeException notYet = new SSLHandshakeException("PKIX path validation failed");
        notYet.initCause(new CertPathValidatorException("validity check failed",
                new java.security.cert.CertificateNotYetValidException("NotBefore"), null, -1,
                CertPathValidatorException.BasicReason.NOT_YET_VALID));
        assertEquals(Reason.CERTIFICATE_NOT_YET_VALID, Reason.of(notYet));
        assertNotNull(new ProxyFailure.TlsFailed("h:1", notYet).reason());
    }
}
