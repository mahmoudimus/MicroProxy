// Ported from rustls src/webpki/server_verifier.rs, src/webpki/client_verifier.rs and
// src/webpki/mod.rs (pki_error: which alert each certificate error becomes) (Apache-2.0); chain
// building and path validation are the JDK's X509TrustManager.
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateEntry;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateRevokedException;
import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/** Parses and validates peer certificate chains, turning each failure into the right alert. */
final class CertificateChecks {

    /**
     * The authentication type JDK trust managers get for TLS 1.3 servers: it asks only for the
     * digitalSignature key usage, which is what TLS 1.3 needs.
     */
    private static final String TLS13_AUTH_TYPE = "UNKNOWN";

    private CertificateChecks() {}

    /** The JDK's default trust manager, loaded once (initialization-on-demand holder). */
    private static final class DefaultTrust {
        static final X509TrustManager INSTANCE = load();

        private static X509TrustManager load() {
            try {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init((KeyStore) null);
                for (TrustManager tm : tmf.getTrustManagers()) {
                    if (tm instanceof X509TrustManager x509) return x509;
                }
                throw new IllegalStateException("no default X509TrustManager");
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("cannot load the default trust manager", e);
            }
        }
    }

    static X509TrustManager defaultTrustManager() {
        return DefaultTrust.INSTANCE;
    }

    static List<X509Certificate> parse(List<CertificateEntry> entries) throws QuicException {
        List<X509Certificate> chain = new ArrayList<>(entries.size());
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (CertificateEntry entry : entries) {
                Certificate cert = factory.generateCertificate(new ByteArrayInputStream(entry.certificate()));
                if (!(cert instanceof X509Certificate x509)) {
                    throw TlsAlert.error(TlsAlert.BAD_CERTIFICATE, "not an X.509 certificate");
                }
                chain.add(x509);
            }
        } catch (CertificateException | RuntimeException e) {
            throw TlsAlert.error(TlsAlert.BAD_CERTIFICATE, "cannot parse certificate: " + e.getMessage());
        }
        return chain;
    }

    /** Validates a server's chain and, when {@code hostname} is not null, that it names the host. */
    static void verifyServer(X509TrustManager trust, List<X509Certificate> chain, String hostname)
            throws QuicException {
        try {
            trust.checkServerTrusted(chain.toArray(X509Certificate[]::new), TLS13_AUTH_TYPE);
        } catch (CertificateException | RuntimeException e) {
            throw untrusted(e);
        }
        if (hostname != null && !HostnameChecker.matches(chain.get(0), hostname)) {
            throw TlsAlert.error(TlsAlert.BAD_CERTIFICATE, "certificate is not valid for " + hostname);
        }
    }

    static void verifyClient(X509TrustManager trust, List<X509Certificate> chain) throws QuicException {
        try {
            trust.checkClientTrusted(
                    chain.toArray(X509Certificate[]::new), chain.get(0).getPublicKey().getAlgorithm());
        } catch (CertificateException | RuntimeException e) {
            throw untrusted(e);
        }
    }

    private static QuicException untrusted(Exception e) {
        int alert = TlsAlert.CERTIFICATE_UNKNOWN;
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof CertificateExpiredException || t instanceof CertificateNotYetValidException) {
                alert = TlsAlert.CERTIFICATE_EXPIRED;
                break;
            }
            if (t instanceof CertificateRevokedException) {
                alert = TlsAlert.CERTIFICATE_REVOKED;
                break;
            }
            if (t instanceof CertPathValidatorException cpve) {
                if (cpve.getReason() == CertPathValidatorException.BasicReason.EXPIRED
                        || cpve.getReason() == CertPathValidatorException.BasicReason.NOT_YET_VALID) {
                    alert = TlsAlert.CERTIFICATE_EXPIRED;
                    break;
                }
                if (cpve.getReason() == CertPathValidatorException.BasicReason.REVOKED) {
                    alert = TlsAlert.CERTIFICATE_REVOKED;
                    break;
                }
            }
            if (t instanceof CertPathBuilderException) {
                // No path to a trust anchor.
                alert = TlsAlert.UNKNOWN_CA;
                break;
            }
        }
        return TlsAlert.error(alert, "certificate rejected: " + e.getMessage());
    }
}
