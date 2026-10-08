package org.microproxy.tls;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Trusts a certificate chain if any of several trust managers does, e.g. the JDK's default trust
 * store plus a private CA. Each delegate is an {@link X509ExtendedTrustManager}, so endpoint
 * identification (host-name checks) still applies.
 */
final class MergedTrustManager extends X509ExtendedTrustManager {

    @FunctionalInterface
    private interface Check {
        void run(X509ExtendedTrustManager tm) throws CertificateException;
    }

    private final List<X509ExtendedTrustManager> delegates;

    MergedTrustManager(List<X509ExtendedTrustManager> delegates) {
        if (delegates.isEmpty()) throw new IllegalArgumentException("no trust managers");
        this.delegates = List.copyOf(delegates);
    }

    private void anyAccepts(Check check) throws CertificateException {
        CertificateException first = null;
        for (X509ExtendedTrustManager tm : delegates) {
            try {
                check.run(tm);
                return;
            } catch (CertificateException e) {
                if (first == null) first = e;
            }
        }
        throw first;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        anyAccepts(tm -> tm.checkClientTrusted(chain, authType));
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        anyAccepts(tm -> tm.checkServerTrusted(chain, authType));
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        anyAccepts(tm -> tm.checkClientTrusted(chain, authType, socket));
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        anyAccepts(tm -> tm.checkServerTrusted(chain, authType, socket));
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        anyAccepts(tm -> tm.checkClientTrusted(chain, authType, engine));
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        anyAccepts(tm -> tm.checkServerTrusted(chain, authType, engine));
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        List<X509Certificate> all = new ArrayList<>();
        for (X509ExtendedTrustManager tm : delegates) {
            all.addAll(List.of(tm.getAcceptedIssuers()));
        }
        return all.toArray(X509Certificate[]::new);
    }
}
