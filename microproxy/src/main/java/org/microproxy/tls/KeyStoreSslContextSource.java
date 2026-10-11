package org.microproxy.tls;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import org.microproxy.KeyMaterial;
import org.microproxy.SslContextSource;

/**
 * An {@link SslContextSource} for the proxy's own TLS listener, presenting the certificate of a key
 * store entry (PKCS#12 or JKS): the HTTPS and HTTP/2 listener ({@code withSslContextSource}), and,
 * through {@link #getKeyMaterial}, the HTTP/3 listener of a reverse proxy. Peer certificates are
 * checked against the JDK's default trust store, which matters only with client authentication.
 *
 * <pre>{@code
 * MicroProxy.bootstrap()
 *         .withReverseProxy("https://backend.internal")
 *         .withSslContextSource(new KeyStoreSslContextSource(Path.of("site.p12"), "secret".toCharArray()))
 *         .withHttp3(true)
 *         .start();
 * }</pre>
 */
public class KeyStoreSslContextSource implements SslContextSource {

    private final KeyMaterial keyMaterial;
    private final SSLContext sslContext;

    /**
     * Presents the first key entry of a key store file, whose type (PKCS#12 or JKS) is detected.
     *
     * @param keyStore the key store file
     * @param password the key store's password, which is also the entry's
     * @throws IOException if the file cannot be read, or holds no usable key entry
     */
    public KeyStoreSslContextSource(Path keyStore, char[] password) throws IOException {
        this(load(keyStore, password), null, password);
    }

    /**
     * Presents a key store entry.
     *
     * @param keyStore the loaded key store
     * @param alias the key entry's alias, or null for the first key entry
     * @param password the entry's password
     * @throws IOException if the key store has no such key entry, or it cannot be read
     */
    public KeyStoreSslContextSource(KeyStore keyStore, String alias, char[] password) throws IOException {
        try {
            this.keyMaterial = KeyMaterial.fromKeyStore(keyStore, alias, password);
            this.sslContext = SslContexts.withKey(keyMaterial.privateKey(),
                    keyMaterial.chain().toArray(X509Certificate[]::new), null);
        } catch (GeneralSecurityException | IllegalStateException e) {
            throw new IOException("unusable key store entry: " + e.getMessage(), e);
        }
    }

    private static KeyStore load(Path file, char[] password) throws IOException {
        if (!Files.isRegularFile(file)) throw new IOException("key store not found: " + file.toAbsolutePath());
        try {
            return KeyStore.getInstance(file.toFile(), password);
        } catch (GeneralSecurityException e) {
            throw new IOException("unable to read the key store " + file + ": " + e.getMessage(), e);
        }
    }

    @Override
    public SSLContext getSslContext() {
        return sslContext;
    }

    /** The entry's chain and key, whatever name the client asks for. */
    @Override
    public KeyMaterial getKeyMaterial(String serverName) {
        return keyMaterial;
    }
}
