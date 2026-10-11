package org.microproxy;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * A certificate chain and the private key of its first certificate: what a TLS server presents.
 * Listeners that run a TLS handshake of their own rather than the JDK's, such as the HTTP/3
 * listener (QUIC carries TLS 1.3 itself), take their certificate in this form, from {@link
 * SslContextSource#getKeyMaterial(String)}.
 *
 * @param chain the certificate chain, end-entity certificate first, then its issuers; not empty
 * @param privateKey the private key of the end-entity certificate
 */
public record KeyMaterial(List<X509Certificate> chain, PrivateKey privateKey) {

    /**
     * Creates key material.
     *
     * @param chain the certificate chain, end-entity certificate first; copied
     * @param privateKey the end-entity certificate's private key
     * @throws IllegalArgumentException if the chain is empty
     */
    public KeyMaterial {
        chain = List.copyOf(chain);
        Objects.requireNonNull(privateKey, "privateKey");
        if (chain.isEmpty()) throw new IllegalArgumentException("empty certificate chain");
    }

    /**
     * The key entry {@code alias} of a key store, or its first key entry when {@code alias} is
     * null.
     *
     * @param keyStore the loaded key store
     * @param alias the entry's alias, or null for the first key entry
     * @param password the entry's password
     * @return the entry's chain and private key
     * @throws GeneralSecurityException if the key store has no such key entry, or it cannot be read
     */
    public static KeyMaterial fromKeyStore(KeyStore keyStore, String alias, char[] password)
            throws GeneralSecurityException {
        String name = alias;
        if (name == null) {
            for (String a : Collections.list(keyStore.aliases())) {
                if (keyStore.isKeyEntry(a)) {
                    name = a;
                    break;
                }
            }
            if (name == null) throw new GeneralSecurityException("the key store has no key entry");
        }
        Key key = keyStore.getKey(name, password);
        if (!(key instanceof PrivateKey privateKey)) {
            throw new GeneralSecurityException("no private key under alias " + name);
        }
        Certificate[] certificates = keyStore.getCertificateChain(name);
        if (certificates == null || certificates.length == 0) {
            throw new GeneralSecurityException("no certificate chain under alias " + name);
        }
        List<X509Certificate> chain = new ArrayList<>(certificates.length);
        for (Certificate c : certificates) {
            if (!(c instanceof X509Certificate x509)) throw new GeneralSecurityException("not an X.509 certificate: " + c.getType());
            chain.add(x509);
        }
        return new KeyMaterial(chain, privateKey);
    }
}
