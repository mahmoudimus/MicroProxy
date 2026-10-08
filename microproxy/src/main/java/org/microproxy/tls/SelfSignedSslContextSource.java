package org.microproxy.tls;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.microproxy.SslContextSource;

/**
 * An {@link SslContextSource} backed by a self-signed certificate generated in memory for {@code
 * localhost}, {@code 127.0.0.1} and {@code ::1} (or the names given). The same instance can serve
 * both ends of a connection, e.g. an encrypted chained proxy and the proxy it chains to, because
 * its trust store contains its own certificate.
 */
public class SelfSignedSslContextSource implements SslContextSource {

    private final X509Certificate certificate;
    private final SSLContext sslContext;

    public SelfSignedSslContextSource() {
        this(false, true);
    }

    public SelfSignedSslContextSource(boolean trustAllServers) {
        this(trustAllServers, true);
    }

    /**
     * @param trustAllServers trust any peer instead of only this certificate
     * @param sendCerts present the certificate (needed on the server side and for client auth)
     */
    public SelfSignedSslContextSource(boolean trustAllServers, boolean sendCerts, String... names) {
        String[] subjectNames = names.length == 0 ? new String[] {"localhost", "127.0.0.1", "::1"} : names;
        try {
            KeyPair keyPair = CertificateAuthority.newEcKeyPair();
            Instant now = Instant.now();
            CertificateBuilder builder = new CertificateBuilder()
                    .subject(subjectNames[0], "MicroProxy")
                    .publicKey(keyPair.getPublic())
                    .validity(now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(3650)));
            for (String name : subjectNames) {
                builder.addSubjectAltName(name);
            }
            certificate = builder.sign(keyPair.getPrivate());
            KeyManager[] keyManagers = sendCerts
                    ? SslContexts.keyManagers(keyPair.getPrivate(), new X509Certificate[] {certificate})
                    : null;
            TrustManager[] trustManagers = trustAllServers
                    ? new TrustManager[] {new TrustingTrustManager()}
                    : SslContexts.trustManagers(certificate);
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers, trustManagers, null);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("unable to create self-signed certificate", e);
        }
    }

    @Override
    public SSLContext getSslContext() {
        return sslContext;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }
}
