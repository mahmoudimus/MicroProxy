package org.microproxy.tls;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.microproxy.KeyMaterial;
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
    /** The certificate and its key, when they are presented (sendCerts); else null. */
    private final KeyMaterial keyMaterial;

    /**
     * Creates a TLS context source with a generated self-signed certificate.
     */
    public SelfSignedSslContextSource() {
        this(false, true);
    }

    /**
     * Creates a TLS context source with a generated self-signed certificate.
     *
     * @param trustAllServers whether to trust all peer certificates instead of only the generated certificate
     */
    public SelfSignedSslContextSource(boolean trustAllServers) {
        this(trustAllServers, true);
    }

    /**
     * Creates a TLS context source with a generated self-signed certificate.
     *
     * @param trustAllServers trust any peer instead of only this certificate
     * @param sendCerts present the certificate (needed on the server side and for client auth)
     *
     * @param names the DNS names or IP literals to include in the certificate
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
            keyMaterial = sendCerts ? new KeyMaterial(List.of(certificate), keyPair.getPrivate()) : null;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("unable to create self-signed certificate", e);
        }
    }

    @Override
    public SSLContext getSslContext() {
        return sslContext;
    }

    /**
     * The generated certificate and its key, for the HTTP/3 listener; null when this source does
     * not present its certificate.
     */
    @Override
    public KeyMaterial getKeyMaterial(String serverName) {
        return keyMaterial;
    }

    /** {@return the certificate presented by this source} */
    public X509Certificate getCertificate() {
        return certificate;
    }
}
