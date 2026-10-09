package org.microproxy.tls;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Builds and signs X.509 v3 certificates with nothing but the JDK, which has no public
 * certificate-generation API. Supports what a TLS-intercepting proxy needs: CA certificates and
 * server certificates with subject alternative names, signed with ECDSA or RSA (SHA-256).
 */
public final class CertificateBuilder {

    private static final SecureRandom RANDOM = new SecureRandom();

    private String subjectCommonName = "MicroProxy";
    private String subjectOrganization;
    private X509Certificate issuer;
    private PublicKey publicKey;
    private Instant notBefore = Instant.now().minusSeconds(86_400);
    private Instant notAfter = Instant.now().plusSeconds(365L * 86_400);
    private boolean certificateAuthority;
    private final List<String> subjectAltNames = new ArrayList<>();

    public CertificateBuilder subject(String commonName, String organization) {
        this.subjectCommonName = commonName;
        this.subjectOrganization = organization;
        return this;
    }

    /** The issuing CA certificate; leave unset for a self-signed certificate. */
    public CertificateBuilder issuer(X509Certificate issuer) {
        this.issuer = issuer;
        return this;
    }

    public CertificateBuilder publicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public CertificateBuilder validity(Instant notBefore, Instant notAfter) {
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        return this;
    }

    public CertificateBuilder certificateAuthority(boolean ca) {
        this.certificateAuthority = ca;
        return this;
    }

    /** Adds a DNS name or IP literal to the subject alternative names. */
    public CertificateBuilder addSubjectAltName(String nameOrIp) {
        if (!subjectAltNames.contains(nameOrIp)) {
            subjectAltNames.add(nameOrIp);
        }
        return this;
    }

    /** Signs the certificate with {@code signingKey} (the issuer's key, or the subject's own). */
    public X509Certificate sign(PrivateKey signingKey) throws GeneralSecurityException {
        if (publicKey == null) throw new IllegalStateException("publicKey not set");
        boolean ec = signingKey.getAlgorithm().equals("EC");
        String jcaAlgorithm = ec ? "SHA256withECDSA" : "SHA256withRSA";
        byte[] algorithmId = ec
                ? Der.sequence(Der.oid("1.2.840.10045.4.3.2"))
                : Der.sequence(Der.oid("1.2.840.113549.1.1.11"), Der.nullValue());

        byte[] subjectName = name(subjectCommonName, subjectOrganization);
        byte[] issuerName = issuer != null ? issuer.getSubjectX500Principal().getEncoded() : subjectName;
        byte[] subjectKeyId = keyIdentifier(publicKey);
        byte[] authorityKeyId = issuer != null ? keyIdentifier(issuer.getPublicKey()) : subjectKeyId;

        List<byte[]> extensions = new ArrayList<>();
        extensions.add(extension("2.5.29.19", true, certificateAuthority
                ? Der.sequence(Der.bool(true), Der.integer(0))
                : Der.sequence()));
        extensions.add(extension("2.5.29.15", true, certificateAuthority
                // digitalSignature, keyCertSign, cRLSign
                ? Der.bitString(new byte[] {(byte) 0x86}, 1)
                // digitalSignature, keyEncipherment
                : Der.bitString(new byte[] {(byte) 0xa0}, 5)));
        if (!certificateAuthority) {
            extensions.add(extension("2.5.29.37", false, Der.sequence(Der.oid("1.3.6.1.5.5.7.3.1"))));
        }
        if (!subjectAltNames.isEmpty()) {
            List<byte[]> names = new ArrayList<>();
            for (String san : subjectAltNames) {
                names.add(generalName(san));
            }
            extensions.add(extension("2.5.29.17", false, Der.sequence(names.toArray(byte[][]::new))));
        }
        extensions.add(extension("2.5.29.14", false, Der.octetString(subjectKeyId)));
        extensions.add(extension("2.5.29.35", false, Der.sequence(Der.implicitPrimitive(0, authorityKeyId))));

        byte[] tbs = Der.sequence(
                Der.explicit(0, Der.integer(2)),
                Der.integer(new BigInteger(63, RANDOM).add(BigInteger.ONE)),
                algorithmId,
                issuerName,
                Der.sequence(Der.time(notBefore), Der.time(notAfter)),
                subjectName,
                publicKey.getEncoded(),
                Der.explicit(3, Der.sequence(extensions.toArray(byte[][]::new))));

        Signature signature = Signature.getInstance(jcaAlgorithm);
        signature.initSign(signingKey);
        signature.update(tbs);
        byte[] certificate = Der.sequence(tbs, algorithmId, Der.bitString(signature.sign(), 0));
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificate));
    }

    private static byte[] name(String commonName, String organization) {
        List<byte[]> rdns = new ArrayList<>();
        if (organization != null) {
            rdns.add(Der.set(Der.sequence(Der.oid("2.5.4.10"), Der.utf8String(organization))));
        }
        rdns.add(Der.set(Der.sequence(Der.oid("2.5.4.3"), Der.utf8String(commonName))));
        return Der.sequence(rdns.toArray(byte[][]::new));
    }

    private static byte[] extension(String oid, boolean critical, byte[] value) {
        return critical
                ? Der.sequence(Der.oid(oid), Der.bool(true), Der.octetString(value))
                : Der.sequence(Der.oid(oid), Der.octetString(value));
    }

    private static byte[] generalName(String san) {
        if (isIpLiteral(san)) {
            try {
                // Literal parsing only, no lookup.
                return Der.implicitPrimitive(7, InetAddress.getByName(san).getAddress());
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("invalid IP literal: " + san, e);
            }
        }
        return Der.implicitPrimitive(2, san.getBytes(StandardCharsets.US_ASCII));
    }

    static boolean isIpLiteral(String host) {
        if (host.indexOf(':') >= 0) return true;
        if (host.isEmpty()) return false;
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c != '.' && (c < '0' || c > '9')) return false;
        }
        return true;
    }

    private static byte[] keyIdentifier(PublicKey key) throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-1").digest(key.getEncoded());
        return Arrays.copyOf(digest, 20);
    }
}
