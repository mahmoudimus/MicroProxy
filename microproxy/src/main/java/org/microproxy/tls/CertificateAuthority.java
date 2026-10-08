package org.microproxy.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import javax.net.ssl.SSLContext;

/**
 * A certificate authority that issues server certificates on the fly. Install its certificate
 * ({@link #getCertificatePem()}) in clients that should accept intercepted connections.
 */
public final class CertificateAuthority {

    private static final String ALIAS = "microproxy-ca";

    private final PrivateKey privateKey;
    private final X509Certificate certificate;

    public CertificateAuthority(PrivateKey privateKey, X509Certificate certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
    }

    /** Generates a new CA with an EC P-256 key, valid for ten years. */
    public static CertificateAuthority generate(String commonName) {
        try {
            KeyPair keyPair = newEcKeyPair();
            Instant now = Instant.now();
            X509Certificate cert = new CertificateBuilder()
                    .subject(commonName, "MicroProxy")
                    .publicKey(keyPair.getPublic())
                    .validity(now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(3650)))
                    .certificateAuthority(true)
                    .sign(keyPair.getPrivate());
            return new CertificateAuthority(keyPair.getPrivate(), cert);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("unable to generate CA", e);
        }
    }

    /** Loads the first key entry of a PKCS#12 (or JKS) key store. */
    public static CertificateAuthority load(Path keyStore, char[] password) throws IOException {
        try (InputStream in = Files.newInputStream(keyStore)) {
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(in, password);
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (store.isKeyEntry(alias)) {
                    Key key = store.getKey(alias, password);
                    Certificate cert = store.getCertificate(alias);
                    if (key instanceof PrivateKey pk && cert instanceof X509Certificate x509) {
                        return new CertificateAuthority(pk, x509);
                    }
                }
            }
            throw new IOException("no private key entry in " + keyStore);
        } catch (GeneralSecurityException e) {
            throw new IOException("unable to load " + keyStore, e);
        }
    }

    /** Loads the CA from {@code keyStore}, generating and saving a new one if it does not exist. */
    public static CertificateAuthority loadOrCreate(Path keyStore, char[] password, String commonName)
            throws IOException {
        if (Files.isRegularFile(keyStore)) {
            return load(keyStore, password);
        }
        CertificateAuthority ca = generate(commonName);
        ca.save(keyStore, password);
        return ca;
    }

    /** Saves key and certificate as PKCS#12. */
    public void save(Path keyStore, char[] password) throws IOException {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            store.setKeyEntry(ALIAS, privateKey, password, new Certificate[] {certificate});
            Path parent = keyStore.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            try (OutputStream out = Files.newOutputStream(keyStore)) {
                store.store(out, password);
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("unable to save " + keyStore, e);
        }
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /** The CA certificate in PEM format. */
    public String getCertificatePem() {
        try {
            String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                    .encodeToString(certificate.getEncoded());
            return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public void writeCertificatePem(Path file) throws IOException {
        Files.writeString(file, getCertificatePem(), StandardCharsets.US_ASCII);
    }

    /**
     * Issues a server certificate for {@code names} (DNS names or IP literals; the first is also
     * the common name), valid for at most a year and never beyond the CA's own expiry.
     */
    public X509Certificate issue(PublicKey subjectKey, Collection<String> names) {
        if (names.isEmpty()) throw new IllegalArgumentException("at least one name required");
        try {
            Instant now = Instant.now();
            Instant notAfter = now.plus(Duration.ofDays(365));
            Instant caExpiry = certificate.getNotAfter().toInstant();
            if (notAfter.isAfter(caExpiry)) notAfter = caExpiry;
            CertificateBuilder builder = new CertificateBuilder()
                    .subject(names.iterator().next(), "MicroProxy")
                    .issuer(certificate)
                    .publicKey(subjectKey)
                    .validity(now.minus(Duration.ofDays(1)), notAfter);
            names.forEach(builder::addSubjectAltName);
            return builder.sign(privateKey);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("unable to issue certificate for " + names, e);
        }
    }

    /** A server-side SSLContext presenting a fresh certificate for {@code names}. */
    public SSLContext serverContext(String... names) {
        KeyPair keyPair = newEcKeyPair();
        X509Certificate leaf = issue(keyPair.getPublic(), List.of(names));
        return SslContexts.withKey(keyPair.getPrivate(), new X509Certificate[] {leaf, certificate}, null);
    }

    /** A client-side SSLContext that trusts only this CA. */
    public SSLContext clientContext() {
        return SslContexts.trusting(certificate);
    }

    static KeyPair newEcKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
