package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.QuicException;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

/**
 * A server's delegated credential (RFC 9345): a short-lived key its certificate signed, which the
 * server's CertificateVerify is then made with, sent in the end-entity CertificateEntry's {@code
 * delegated_credentials} extension to a client that offered the extension (as Firefox does).
 * Checked as NSS checks one ({@code tls13_ClientHandleDelegatedCredentialsXtn}, {@code
 * tls13_VerifyDelegatedCredential}).
 *
 * @param validTime seconds from the certificate's notBefore until the credential expires
 * @param expectedCertVerifyAlgorithm the scheme of the CertificateVerify made with the credential
 * @param publicKeyInfo the credential's DER SubjectPublicKeyInfo
 * @param algorithm the scheme the certificate's key signed the credential with
 * @param signature that signature
 */
record DelegatedCredential(long validTime, int expectedCertVerifyAlgorithm, byte[] publicKeyInfo, int algorithm,
        byte[] signature) {

    /** The DelegationUsage certificate extension (RFC 9345 section 4.2). */
    static final String DELEGATION_USAGE_OID = "1.3.6.1.4.1.44363.44";
    /** The longest a credential may still be valid for (RFC 9345 section 4.1.3). */
    static final Duration MAX_VALIDITY = Duration.ofDays(7);

    /** Reads a {@code delegated_credentials} extension body (RFC 9345 section 4). */
    static DelegatedCredential decode(byte[] body) throws QuicException {
        Reader r = new Reader(body);
        long validTime = r.u32("valid_time");
        int expected = r.u16("dc_cert_verify_algorithm");
        byte[] spki = r.vector24(1, "ASN1_subjectPublicKeyInfo");
        int algorithm = r.u16("algorithm");
        byte[] signature = r.vector16(1, "signature");
        r.expectEnd("DelegatedCredential");
        return new DelegatedCredential(validTime, expected, spki, algorithm, signature);
    }

    /**
     * The checks made when the credential arrives: both its schemes are ones the client offered
     * for delegated credentials, and its CertificateVerify scheme is not an {@code rsa_pss_rsae}
     * one (a credential's key may not be an {@code rsaEncryption} key).
     *
     * @param offered the schemes of the client's {@code delegated_credentials} extension
     */
    void checkOffered(int[] offered) throws QuicException {
        SignatureScheme expected = SignatureScheme.forCode(expectedCertVerifyAlgorithm);
        if (expected == SignatureScheme.RSA_PSS_RSAE_SHA256 || expected == SignatureScheme.RSA_PSS_RSAE_SHA384
                || expected == SignatureScheme.RSA_PSS_RSAE_SHA512) {
            throw TlsAlert.illegalParameter("delegated credential for an rsaEncryption key");
        }
        if (Arrays.stream(offered).noneMatch(c -> c == expectedCertVerifyAlgorithm)
                || Arrays.stream(offered).noneMatch(c -> c == algorithm)) {
            throw TlsAlert.illegalParameter("delegated credential with a signature scheme that was not offered");
        }
    }

    /**
     * The checks made at the server's CertificateVerify, which is to be checked with the
     * credential's key: the CertificateVerify's scheme is the one the credential names; the
     * certificate's key signed the credential; the certificate allows delegation; and the
     * credential has not expired and is valid for no more than seven days more.
     *
     * @param leaf the server's end-entity certificate
     * @param certificateVerifyScheme the scheme of the server's CertificateVerify
     * @param now the time now
     * @return the credential's public key, to check the CertificateVerify with
     */
    PublicKey verify(X509Certificate leaf, int certificateVerifyScheme, Instant now) throws QuicException {
        if (certificateVerifyScheme != expectedCertVerifyAlgorithm) {
            throw TlsAlert.illegalParameter("CertificateVerify scheme is not the delegated credential's");
        }
        SignatureScheme scheme = SignatureScheme.forCode(algorithm);
        if (scheme == null || !scheme.compatibleWith(leaf.getPublicKey())) {
            throw TlsAlert.illegalParameter("delegated credential signed with a scheme that does not fit the certificate");
        }
        byte[] content;
        try {
            content = signedContent(leaf.getEncoded());
        } catch (CertificateEncodingException e) {
            throw TlsAlert.error(TlsAlert.INTERNAL_ERROR, "cannot encode the certificate: " + e.getMessage());
        }
        if (!Signatures.verify(scheme, leaf.getPublicKey(), content, signature)) {
            throw TlsAlert.illegalParameter("delegated credential signature is invalid");
        }
        boolean[] usage = leaf.getKeyUsage();
        boolean delegation = (leaf.getNonCriticalExtensionOIDs() != null
                        && leaf.getNonCriticalExtensionOIDs().contains(DELEGATION_USAGE_OID))
                || (leaf.getCriticalExtensionOIDs() != null && leaf.getCriticalExtensionOIDs().contains(DELEGATION_USAGE_OID));
        if (!delegation || usage == null || !usage[0]) {
            throw TlsAlert.illegalParameter("the certificate does not allow delegated credentials");
        }
        Instant end = leaf.getNotBefore().toInstant().plusSeconds(validTime);
        if (now.isAfter(end)) throw TlsAlert.illegalParameter("delegated credential has expired");
        if (Duration.between(now, end).compareTo(MAX_VALIDITY) > 0) {
            throw TlsAlert.illegalParameter("delegated credential is valid for more than seven days");
        }
        SignatureScheme verifyScheme = SignatureScheme.forCode(expectedCertVerifyAlgorithm);
        PublicKey key = publicKey(verifyScheme);
        if (verifyScheme == null || !verifyScheme.compatibleWith(key)) {
            throw TlsAlert.illegalParameter("delegated credential key does not fit its CertificateVerify scheme");
        }
        return key;
    }

    /**
     * What the certificate's key signs (RFC 9345 section 4): 64 spaces, the context string and a
     * zero byte, the certificate, and the credential without its signature.
     */
    byte[] signedContent(byte[] certificate) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < 64; i++) out.write(0x20);
        out.writeBytes("TLS, server delegated credentials".getBytes(StandardCharsets.US_ASCII));
        out.write(0);
        out.writeBytes(certificate);
        Writer w = new Writer();
        w.u32(validTime).u16(expectedCertVerifyAlgorithm).vector24(publicKeyInfo).u16(algorithm);
        out.writeBytes(w.toByteArray());
        return out.toByteArray();
    }

    private PublicKey publicKey(SignatureScheme scheme) throws QuicException {
        String type = scheme == SignatureScheme.ED25519 ? "Ed25519" : scheme != null && scheme.jcaAlgorithm().contains("ECDSA") ? "EC" : "RSA";
        try {
            return KeyFactory.getInstance(type).generatePublic(new X509EncodedKeySpec(publicKeyInfo));
        } catch (GeneralSecurityException e) {
            throw TlsAlert.illegalParameter("delegated credential key cannot be read: " + e.getMessage());
        }
    }
}
