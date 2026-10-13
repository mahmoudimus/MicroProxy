package org.microproxy.tls;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Certificates the TLS tests need beyond {@link CertificateAuthority#serverContext}: server
 * certificates with a chosen validity, certificate revocation lists (RFC 5280 section 5), and a
 * client context that checks revocation against such a list.
 */
public final class TestPki {

    private TestPki() {}

    /**
     * A server's TLS context and its certificate.
     *
     * @param context presents {@code leaf} and its CA's certificate
     * @param leaf the server's certificate
     */
    public record Server(SSLContext context, X509Certificate leaf) {}

    /** A server certificate from {@code ca} for {@code names}, valid from {@code notBefore} to {@code notAfter}. */
    public static Server server(CertificateAuthority ca, Instant notBefore, Instant notAfter, String... names) {
        try {
            KeyPair keyPair = CertificateAuthority.newEcKeyPair();
            CertificateBuilder builder = new CertificateBuilder()
                    .subject(names[0], "MicroProxy")
                    .issuer(ca.getCertificate())
                    .publicKey(keyPair.getPublic())
                    .validity(notBefore, notAfter);
            for (String name : names) builder.addSubjectAltName(name);
            X509Certificate leaf = builder.sign(ca.getPrivateKey());
            SSLContext context = SslContexts.withKey(keyPair.getPrivate(),
                    new X509Certificate[] {leaf, ca.getCertificate()}, null);
            return new Server(context, leaf);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A server certificate from {@code ca} for {@code names}, valid now. */
    public static Server server(CertificateAuthority ca, String... names) {
        Instant now = Instant.now();
        return server(ca, now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(30)), names);
    }

    /** A CRL that {@code ca} signed, valid now, listing {@code revoked} as revoked an hour ago. */
    public static X509CRL crl(CertificateAuthority ca, X509Certificate... revoked) {
        try {
            boolean ec = ca.getPrivateKey().getAlgorithm().equals("EC");
            byte[] algorithmId = ec
                    ? Der.sequence(Der.oid("1.2.840.10045.4.3.2"))
                    : Der.sequence(Der.oid("1.2.840.113549.1.1.11"), Der.nullValue());
            Instant now = Instant.now();
            List<byte[]> entries = new ArrayList<>();
            for (X509Certificate cert : revoked) {
                entries.add(Der.sequence(Der.integer(cert.getSerialNumber()), Der.time(now.minus(Duration.ofHours(1)))));
            }
            List<byte[]> tbs = new ArrayList<>(List.of(
                    // v2
                    Der.integer(BigInteger.ONE),
                    algorithmId,
                    ca.getCertificate().getSubjectX500Principal().getEncoded(),
                    Der.time(now.minus(Duration.ofHours(2))),
                    Der.time(now.plus(Duration.ofDays(1)))));
            if (!entries.isEmpty()) tbs.add(Der.sequence(entries.toArray(byte[][]::new)));
            byte[] tbsCertList = Der.sequence(tbs.toArray(byte[][]::new));
            java.security.Signature signature = java.security.Signature.getInstance(ec ? "SHA256withECDSA" : "SHA256withRSA");
            signature.initSign(ca.getPrivateKey());
            signature.update(tbsCertList);
            byte[] der = Der.sequence(tbsCertList, algorithmId, Der.bitString(signature.sign(), 0));
            return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(der));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A client context that trusts {@code ca} and checks the revocation of server certificates
     * against {@code crl} only (no OCSP, no fetching, no fallback): a certificate it lists fails
     * with a {@link java.security.cert.CertPathValidatorException} whose reason is {@code REVOKED}.
     */
    public static SSLContext revocationCheckingClientContext(CertificateAuthority ca, X509CRL crl) {
        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(
                    Set.of(new TrustAnchor(ca.getCertificate(), null)), null);
            PKIXRevocationChecker checker = (PKIXRevocationChecker) CertPathValidator.getInstance("PKIX")
                    .getRevocationChecker();
            checker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.PREFER_CRLS,
                    PKIXRevocationChecker.Option.NO_FALLBACK, PKIXRevocationChecker.Option.ONLY_END_ENTITY));
            params.addCertPathChecker(checker);
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(List.of(crl))));
            TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
            factory.init(new CertPathTrustManagerParameters(params));
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, factory.getTrustManagers(), null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
