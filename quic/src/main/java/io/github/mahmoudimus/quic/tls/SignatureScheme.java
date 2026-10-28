// Ported from rustls src/enums.rs (SignatureScheme, supported_in_tls13) and src/webpki/verify.rs
// (which public keys each scheme can verify with) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.interfaces.EdECKey;
import java.security.interfaces.RSAKey;

/**
 * The signature schemes (RFC 8446 section 4.2.3) the handshake knows. All but the {@code
 * rsa_pkcs1} schemes can sign a TLS 1.3 {@code CertificateVerify}; the {@code rsa_pkcs1} ones are
 * only advertised for the signatures in certificate chains, as RFC 8446 requires.
 */
public enum SignatureScheme {
    /** ECDSA on P-256 with SHA-256. */
    ECDSA_SECP256R1_SHA256(0x0403, "SHA256withECDSA", null, "secp256r1", true),
    /** ECDSA on P-384 with SHA-384. */
    ECDSA_SECP384R1_SHA384(0x0503, "SHA384withECDSA", null, "secp384r1", true),
    /** ECDSA on P-521 with SHA-512. */
    ECDSA_SECP521R1_SHA512(0x0603, "SHA512withECDSA", null, "secp521r1", true),
    /** RSASSA-PSS with SHA-256, for an {@code rsaEncryption} key. */
    RSA_PSS_RSAE_SHA256(0x0804, "RSASSA-PSS", "SHA-256", null, true),
    /** RSASSA-PSS with SHA-384, for an {@code rsaEncryption} key. */
    RSA_PSS_RSAE_SHA384(0x0805, "RSASSA-PSS", "SHA-384", null, true),
    /** RSASSA-PSS with SHA-512, for an {@code rsaEncryption} key. */
    RSA_PSS_RSAE_SHA512(0x0806, "RSASSA-PSS", "SHA-512", null, true),
    /** Ed25519 (RFC 8032). */
    ED25519(0x0807, "Ed25519", null, null, true),
    /** RSASSA-PKCS1-v1_5 with SHA-256: certificate signatures only. */
    RSA_PKCS1_SHA256(0x0401, "SHA256withRSA", null, null, false),
    /** RSASSA-PKCS1-v1_5 with SHA-384: certificate signatures only. */
    RSA_PKCS1_SHA384(0x0501, "SHA384withRSA", null, null, false),
    /** RSASSA-PKCS1-v1_5 with SHA-512: certificate signatures only. */
    RSA_PKCS1_SHA512(0x0601, "SHA512withRSA", null, null, false),
    /**
     * ECDSA with SHA-1, on any of the curves: never in TLS 1.3 (RFC 8446 section 4.2.3), but a
     * TLS 1.2 server may sign its ServerKeyExchange with it when the client offers it, as Firefox does.
     */
    ECDSA_SHA1(0x0203, "SHA1withECDSA", null, "*", false),
    /** RSASSA-PKCS1-v1_5 with SHA-1: TLS 1.2 ServerKeyExchange signatures only, as {@link #ECDSA_SHA1}. */
    RSA_PKCS1_SHA1(0x0201, "SHA1withRSA", null, null, false);

    /** In place of a curve name: a scheme for an EC key on any of {@link EcCurves}' curves. */
    private static final String ANY_CURVE = "*";

    private final int code;
    private final String jcaAlgorithm;
    private final String pssHash;
    private final String curve;
    private final boolean certificateVerify;

    SignatureScheme(int code, String jcaAlgorithm, String pssHash, String curve, boolean certificateVerify) {
        this.code = code;
        this.jcaAlgorithm = jcaAlgorithm;
        this.pssHash = pssHash;
        this.curve = curve;
        this.certificateVerify = certificateVerify;
    }

    /**
     * The scheme's TLS code point.
     *
     * @return the two-byte code, such as {@code 0x0403}
     */
    public int code() {
        return code;
    }

    /**
     * Whether TLS 1.3 allows the scheme in a {@code CertificateVerify} message.
     *
     * @return false for the {@code rsa_pkcs1} schemes
     */
    public boolean allowedInCertificateVerify() {
        return certificateVerify;
    }

    String jcaAlgorithm() {
        return jcaAlgorithm;
    }

    /** The PSS hash, or null if this is not a PSS scheme. */
    String pssHash() {
        return pssHash;
    }

    /**
     * Whether a key (public or private) can make or check this scheme's signatures: an EC key on
     * the scheme's curve, an {@code rsaEncryption} RSA key, or an Ed25519 key.
     *
     * @param key the key
     * @return true if the key fits the scheme
     */
    public boolean compatibleWith(Key key) {
        if (key == null) return false;
        if (curve != null) {
            String name = key instanceof ECKey ec ? EcCurves.nameOf(ec.getParams()) : null;
            return name != null && (curve.equals(ANY_CURVE) || curve.equals(name));
        }
        if (this == ED25519) {
            return key instanceof EdECKey ed && "Ed25519".equalsIgnoreCase(ed.getParams().getName());
        }
        // RSASSA-PSS-only keys (id-RSASSA-PSS) need the rsa_pss_pss schemes, which are not supported.
        return key instanceof RSAKey && "RSA".equals(key.getAlgorithm());
    }

    /**
     * The scheme with a TLS code point.
     *
     * @param code the code point
     * @return the scheme, or null if it is not one of these
     */
    public static SignatureScheme forCode(int code) {
        for (SignatureScheme scheme : values()) {
            if (scheme.code == code) return scheme;
        }
        return null;
    }
}
