package org.microproxy.tls;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/** Small factory methods for {@link SSLContext}s. */
public final class SslContexts {

    private static final char[] EPHEMERAL_PASSWORD = "microproxy".toCharArray();

    private SslContexts() {}

    /** A context using the JDK's default trust store and no client certificate. */
    public static SSLContext systemDefault() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A context that trusts every server. Insecure; for tests and debugging. */
    public static SSLContext trustAll() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] {new TrustingTrustManager()}, null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A context that trusts only the given certificates. */
    public static SSLContext trusting(X509Certificate... anchors) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustManagers(anchors), null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A context that trusts the JDK's default trust store and, in addition, {@code extraAnchors}
     * (e.g. a corporate or test CA). Host names are still verified where endpoint identification
     * is enabled.
     */
    public static SSLContext systemDefaultPlus(X509Certificate... extraAnchors) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] {systemDefaultPlusTrustManager(extraAnchors)}, null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static javax.net.ssl.X509ExtendedTrustManager systemDefaultPlusTrustManager(X509Certificate... extraAnchors)
            throws GeneralSecurityException {
        TrustManagerFactory system = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        system.init((KeyStore) null);
        java.util.List<javax.net.ssl.X509ExtendedTrustManager> delegates = new java.util.ArrayList<>();
        for (TrustManager tm : trustManagers(extraAnchors)) {
            if (tm instanceof javax.net.ssl.X509ExtendedTrustManager x) delegates.add(x);
        }
        for (TrustManager tm : system.getTrustManagers()) {
            if (tm instanceof javax.net.ssl.X509ExtendedTrustManager x) delegates.add(x);
        }
        return new MergedTrustManager(delegates);
    }

    /**
     * A context presenting {@code chain} (leaf first) with {@code key}, trusting {@code trustAnchors}
     * (or the system default when none are given).
     */
    public static SSLContext withKey(PrivateKey key, X509Certificate[] chain, TrustManager[] trustManagers) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers(key, chain), trustManagers, null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static KeyManager[] keyManagers(PrivateKey key, X509Certificate[] chain) throws GeneralSecurityException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try {
            store.load(null, null);
        } catch (java.io.IOException e) {
            throw new GeneralSecurityException(e);
        }
        store.setKeyEntry("key", key, EPHEMERAL_PASSWORD, chain);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(store, EPHEMERAL_PASSWORD);
        return kmf.getKeyManagers();
    }

    static TrustManager[] trustManagers(X509Certificate... anchors) throws GeneralSecurityException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try {
            store.load(null, null);
        } catch (java.io.IOException e) {
            throw new GeneralSecurityException(e);
        }
        for (int i = 0; i < anchors.length; i++) {
            store.setCertificateEntry("anchor-" + i, anchors[i]);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(store);
        return tmf.getTrustManagers();
    }
}
