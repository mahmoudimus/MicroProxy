package org.microproxy.tls;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Small factory methods for {@link SSLContext}s. The contexts made here remember how they validate
 * servers ({@link #trustManagerOf}), so that TLS stacks other than the JDK's, such as QUIC's to
 * HTTP/3 servers, can validate servers the same way.
 */
public final class SslContexts {

    private static final char[] EPHEMERAL_PASSWORD = "microproxy".toCharArray();

    /** The trust manager of each context made here; weak, so contexts can be collected. */
    private static final Map<SSLContext, X509TrustManager> TRUST = new WeakHashMap<>();
    private static final ReentrantLock TRUST_LOCK = new ReentrantLock();

    private SslContexts() {}

    /**
     * How a context made by this class validates servers: its trust manager, which trusts every
     * server for {@link #trustAll()}. Contexts made elsewhere are unknown, except the JDK's
     * default context ({@link SSLContext#getDefault()}), whose trust is the JDK's default trust
     * store.
     *
     * @param context the context
     * @return its trust manager, or null if it is unknown
     */
    public static X509TrustManager trustManagerOf(SSLContext context) {
        if (context == null) return null;
        TRUST_LOCK.lock();
        try {
            X509TrustManager known = TRUST.get(context);
            if (known != null) return known;
        } finally {
            TRUST_LOCK.unlock();
        }
        try {
            if (context == SSLContext.getDefault()) return remember(context, defaultTrustManager());
        } catch (GeneralSecurityException e) {
            return null;
        }
        return null;
    }

    /**
     * Whether {@code trustManager} trusts every server without checking, as {@link #trustAll()}'s does.
     *
     * @param trustManager the trust manager
     * @return whether it accepts any server certificate
     */
    public static boolean trustsAll(X509TrustManager trustManager) {
        return trustManager instanceof TrustingTrustManager;
    }

    private static X509TrustManager remember(SSLContext context, X509TrustManager trustManager) {
        if (trustManager == null) return null;
        TRUST_LOCK.lock();
        try {
            TRUST.put(context, trustManager);
        } finally {
            TRUST_LOCK.unlock();
        }
        return trustManager;
    }

    private static X509TrustManager firstX509(TrustManager[] managers) {
        if (managers == null) return null;
        for (TrustManager tm : managers) {
            if (tm instanceof X509TrustManager x) return x;
        }
        return null;
    }

    private static X509TrustManager defaultTrustManager() throws GeneralSecurityException {
        TrustManagerFactory system = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        system.init((KeyStore) null);
        return firstX509(system.getTrustManagers());
    }

    /** {@return a context using the JDK's default trust store and no client certificate} */
    public static SSLContext systemDefault() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            remember(context, defaultTrustManager());
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A context that trusts every server. Insecure; for tests and debugging.
     *
     * @return a context that trusts every server
     */
    public static SSLContext trustAll() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            TrustingTrustManager trusting = new TrustingTrustManager();
            context.init(null, new TrustManager[] {trusting}, null);
            remember(context, trusting);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A context that trusts only the given certificates.
     *
     * @param anchors the trusted CA certificates
     * @return a context that trusts only the given certificates
     */
    public static SSLContext trusting(X509Certificate... anchors) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            TrustManager[] managers = trustManagers(anchors);
            context.init(null, managers, null);
            remember(context, firstX509(managers));
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A context that trusts the JDK's default trust store and, in addition, {@code extraAnchors}
     * (e.g. a corporate or test CA). Host names are still verified where endpoint identification
     * is enabled.
     *
     * @param extraAnchors the CA certificates trusted in addition to the system defaults
     * @return a context that trusts the JDK's default trust store and, in addition, {@code extraAnchors} (e.g. a corporate or test CA)
     */
    public static SSLContext systemDefaultPlus(X509Certificate... extraAnchors) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            X509ExtendedTrustManager merged = systemDefaultPlusTrustManager(extraAnchors);
            context.init(null, new TrustManager[] {merged}, null);
            remember(context, merged);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static X509ExtendedTrustManager systemDefaultPlusTrustManager(X509Certificate... extraAnchors)
            throws GeneralSecurityException {
        TrustManagerFactory system = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        system.init((KeyStore) null);
        List<X509ExtendedTrustManager> delegates = new ArrayList<>();
        for (TrustManager tm : trustManagers(extraAnchors)) {
            if (tm instanceof X509ExtendedTrustManager x) delegates.add(x);
        }
        for (TrustManager tm : system.getTrustManagers()) {
            if (tm instanceof X509ExtendedTrustManager x) delegates.add(x);
        }
        return new MergedTrustManager(delegates);
    }

    /**
     * A context presenting {@code chain} (leaf first) with {@code key}, trusting {@code trustAnchors}
     * (or the system default when none are given).
     *
     * @param key the private key matching the leaf certificate
     * @param chain the certificate chain, leaf first
     * @param trustManagers the peer certificate validators, or {@code null} for system defaults
     * @return a TLS context using the supplied private key, chain and peer validators
     */
    public static SSLContext withKey(PrivateKey key, X509Certificate[] chain, TrustManager[] trustManagers) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers(key, chain), trustManagers, null);
            remember(context, trustManagers == null ? defaultTrustManager() : firstX509(trustManagers));
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static KeyManager[] keyManagers(PrivateKey key, X509Certificate[] chain) throws GeneralSecurityException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try {
            store.load(null, null);
        } catch (IOException e) {
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
        } catch (IOException e) {
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
