package org.microproxy.tls;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import org.microproxy.MitmManager;
import org.microproxy.http.HttpRequest;

/**
 * A {@link MitmManager} that impersonates servers with certificates issued on demand by a {@link
 * CertificateAuthority}. Each certificate covers the CONNECT host plus the DNS names in the real
 * server's certificate, and is cached per host.
 */
public class CertificateAuthorityMitmManager implements MitmManager {

    private static final int MAX_SANS = 100;
    private static final int MAX_CACHED_HOSTS = 10_000;

    private final CertificateAuthority authority;
    private final SSLContext upstreamContext;
    private final KeyPair leafKeyPair = CertificateAuthority.newEcKeyPair();
    private final Map<String, SSLContext> contexts = new ConcurrentHashMap<>();

    /** Intercepts with {@code authority}, validating real servers against the JDK trust store. */
    public CertificateAuthorityMitmManager(CertificateAuthority authority) {
        this(authority, SslContexts.systemDefault());
    }

    /**
     * @param upstreamContext how real servers are validated, e.g. {@link SslContexts#trustAll()}
     *     to accept any server
     */
    public CertificateAuthorityMitmManager(CertificateAuthority authority, SSLContext upstreamContext) {
        this.authority = authority;
        this.upstreamContext = upstreamContext;
    }

    public CertificateAuthority getCertificateAuthority() {
        return authority;
    }

    @Override
    public SSLContext serverSslContext(String peerHost, int peerPort) {
        return upstreamContext;
    }

    @Override
    public SSLContext clientSslContextFor(HttpRequest connectRequest, SSLSession serverSslSession) {
        String host = hostOf(connectRequest.uri());
        SSLContext context = contexts.get(host);
        if (context == null) {
            if (contexts.size() >= MAX_CACHED_HOSTS) {
                contexts.clear();
            }
            Set<String> names = new LinkedHashSet<>();
            names.add(host);
            names.addAll(serverDnsNames(serverSslSession));
            X509Certificate leaf = authority.issue(leafKeyPair.getPublic(), List.copyOf(names));
            context = SslContexts.withKey(leafKeyPair.getPrivate(),
                    new X509Certificate[] {leaf, authority.getCertificate()}, null);
            SSLContext raced = contexts.putIfAbsent(host, context);
            if (raced != null) {
                context = raced;
            }
        }
        return context;
    }

    private static String hostOf(String authority) {
        String host = authority;
        if (host.startsWith("[")) {
            int close = host.indexOf(']');
            return close > 0 ? host.substring(1, close) : host;
        }
        int colon = host.lastIndexOf(':');
        if (colon > 0 && host.indexOf(':') == colon) {
            host = host.substring(0, colon);
        }
        return host;
    }

    private static Set<String> serverDnsNames(SSLSession session) {
        Set<String> names = new LinkedHashSet<>();
        if (session == null) return names;
        try {
            Certificate[] chain = session.getPeerCertificates();
            if (chain.length > 0 && chain[0] instanceof X509Certificate leaf) {
                Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
                if (sans != null) {
                    for (List<?> san : sans) {
                        if (names.size() >= MAX_SANS) break;
                        if (Integer.valueOf(2).equals(san.get(0)) && san.get(1) instanceof String dns) {
                            names.add(dns);
                        }
                    }
                }
            }
        } catch (SSLPeerUnverifiedException | CertificateParsingException ignored) {
            // fall back to the CONNECT host alone
        }
        return names;
    }
}
