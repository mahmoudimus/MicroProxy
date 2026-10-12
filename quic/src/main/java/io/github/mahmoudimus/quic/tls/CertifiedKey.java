// Ported from rustls src/crypto/signer.rs (CertifiedKey / Credentials: a certificate chain and the
// key that signs for its end-entity certificate) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import javax.net.ssl.X509KeyManager;

/**
 * A certificate chain, end-entity certificate first, and the private key for that certificate:
 * what a server, or a client asked for a certificate, presents and signs with.
 *
 * @param chain the certificates, end-entity first; never empty
 * @param privateKey the end-entity certificate's private key: EC (P-256 or P-384), RSA or Ed25519
 */
public record CertifiedKey(List<X509Certificate> chain, PrivateKey privateKey) {

    /**
     * Validates and copies the chain.
     *
     * @param chain the certificates, end-entity first; never empty
     * @param privateKey the end-entity certificate's private key
     */
    public CertifiedKey {
        Objects.requireNonNull(privateKey, "privateKey");
        chain = List.copyOf(chain);
        if (chain.isEmpty()) throw new IllegalArgumentException("empty certificate chain");
    }

    /**
     * A certified key from a chain given as varargs.
     *
     * @param privateKey the end-entity certificate's private key
     * @param chain the certificates, end-entity first
     * @return the certified key
     */
    public static CertifiedKey of(PrivateKey privateKey, X509Certificate... chain) {
        return new CertifiedKey(List.of(chain), privateKey);
    }

    /**
     * The chain and key a key manager holds under an alias.
     *
     * @param keyManager the key manager, such as one from a {@code KeyManagerFactory}
     * @param alias the alias of the key entry
     * @return the certified key
     * @throws IllegalArgumentException if the key manager has no chain or key for the alias
     */
    public static CertifiedKey fromKeyManager(X509KeyManager keyManager, String alias) {
        X509Certificate[] chain = keyManager.getCertificateChain(alias);
        PrivateKey key = keyManager.getPrivateKey(alias);
        if (chain == null || key == null) throw new IllegalArgumentException("no key entry for alias " + alias);
        return new CertifiedKey(List.of(chain), key);
    }
}
