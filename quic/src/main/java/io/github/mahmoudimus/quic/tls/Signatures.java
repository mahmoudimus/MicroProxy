// Ported from rustls src/tls13/mod.rs (construct_client_verify_message,
// construct_server_verify_message), src/verify.rs and src/webpki/verify.rs
// (verify_tls13_signature: the scheme must match the key) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;

/** CertificateVerify signatures (RFC 8446 section 4.4.3), made and checked with the JDK. */
final class Signatures {

    private static final byte[] SERVER_CONTEXT =
            "TLS 1.3, server CertificateVerify\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CLIENT_CONTEXT =
            "TLS 1.3, client CertificateVerify\0".getBytes(StandardCharsets.US_ASCII);

    private Signatures() {}

    /** 64 spaces, the context string with its zero byte, then the transcript hash. */
    static byte[] content(boolean server, byte[] transcriptHash) {
        byte[] context = server ? SERVER_CONTEXT : CLIENT_CONTEXT;
        byte[] out = new byte[64 + context.length + transcriptHash.length];
        Arrays.fill(out, 0, 64, (byte) 0x20);
        System.arraycopy(context, 0, out, 64, context.length);
        System.arraycopy(transcriptHash, 0, out, 64 + context.length, transcriptHash.length);
        return out;
    }

    private static void configure(Signature sig, SignatureScheme scheme) throws GeneralSecurityException {
        String hash = scheme.pssHash();
        if (hash != null) {
            MGF1ParameterSpec mgf = switch (hash) {
                case "SHA-256" -> MGF1ParameterSpec.SHA256;
                case "SHA-384" -> MGF1ParameterSpec.SHA384;
                default -> MGF1ParameterSpec.SHA512;
            };
            int saltLength = switch (hash) {
                case "SHA-256" -> 32;
                case "SHA-384" -> 48;
                default -> 64;
            };
            // RFC 8446 section 4.2.3: the salt is as long as the digest, with MGF1 over the same hash.
            sig.setParameter(new PSSParameterSpec(hash, "MGF1", mgf, saltLength, 1));
        }
    }

    static byte[] sign(SignatureScheme scheme, PrivateKey key, byte[] content, SecureRandom random)
            throws GeneralSecurityException {
        Signature sig = Signature.getInstance(scheme.jcaAlgorithm());
        sig.initSign(key, random);
        configure(sig, scheme);
        sig.update(content);
        return sig.sign();
    }

    /** Whether {@code signature} is valid; malformed signatures are simply invalid. */
    static boolean verify(SignatureScheme scheme, PublicKey key, byte[] content, byte[] signature) {
        try {
            Signature sig = Signature.getInstance(scheme.jcaAlgorithm());
            sig.initVerify(key);
            configure(sig, scheme);
            sig.update(content);
            return sig.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }
}
