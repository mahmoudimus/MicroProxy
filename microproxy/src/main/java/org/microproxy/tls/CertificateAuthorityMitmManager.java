package org.microproxy.tls;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import org.microproxy.MitmManager;
import org.microproxy.http.HttpRequest;

/**
 * A {@link MitmManager} that impersonates servers with certificates issued on demand by a {@link
 * CertificateAuthority}. Each certificate covers the CONNECT host plus the DNS names and IP
 * addresses in the real server's certificate. Certificates are cached per host in a bounded LRU
 * cache and re-issued after a day, well before they expire.
 */
public class CertificateAuthorityMitmManager implements MitmManager {

    private static final int MAX_SANS = 100;
    private static final int DEFAULT_MAX_CACHED_HOSTS = 1_000;
    private static final long MAX_CACHE_AGE_MILLIS = 24 * 3_600_000L;

    private record CachedContext(SSLContext context, long createdMillis) {}

    private final CertificateAuthority authority;
    private final SSLContext upstreamContext;
    private final KeyPair leafKeyPair = CertificateAuthority.newEcKeyPair();
    private final ReentrantLock cacheLock = new ReentrantLock();
    private final int maxCachedHosts;
    private final Map<String, CachedContext> contexts;

    /** Intercepts with {@code authority}, validating real servers against the JDK trust store. */
    public CertificateAuthorityMitmManager(CertificateAuthority authority) {
        this(authority, SslContexts.systemDefault());
    }

    /**
     * @param upstreamContext how real servers are validated, e.g. {@link SslContexts#trustAll()}
     *     to accept any server
     */
    public CertificateAuthorityMitmManager(CertificateAuthority authority, SSLContext upstreamContext) {
        this(authority, upstreamContext, DEFAULT_MAX_CACHED_HOSTS);
    }

    /** @param maxCachedHosts how many hosts' certificates to keep (least recently used are dropped) */
    public CertificateAuthorityMitmManager(CertificateAuthority authority, SSLContext upstreamContext, int maxCachedHosts) {
        if (maxCachedHosts <= 0) throw new IllegalArgumentException("maxCachedHosts must be positive");
        this.authority = authority;
        this.upstreamContext = upstreamContext;
        this.maxCachedHosts = maxCachedHosts;
        this.contexts = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, CachedContext> eldest) {
                return size() > CertificateAuthorityMitmManager.this.maxCachedHosts;
            }
        };
    }

    /** Number of hosts with a cached certificate. */
    public int cachedHostCount() {
        cacheLock.lock();
        try {
            return contexts.size();
        } finally {
            cacheLock.unlock();
        }
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
        long now = System.currentTimeMillis();
        cacheLock.lock();
        try {
            CachedContext cached = contexts.get(host);
            if (cached != null && now - cached.createdMillis() < MAX_CACHE_AGE_MILLIS) {
                return cached.context();
            }
        } finally {
            cacheLock.unlock();
        }
        // Issue outside the lock: signing is CPU work that other hosts need not wait for.
        Set<String> names = new LinkedHashSet<>();
        names.add(host);
        names.addAll(serverNames(serverSslSession));
        X509Certificate leaf = authority.issue(leafKeyPair.getPublic(), List.copyOf(names));
        SSLContext context = SslContexts.withKey(leafKeyPair.getPrivate(),
                new X509Certificate[] {leaf, authority.getCertificate()}, null);
        cacheLock.lock();
        try {
            contexts.put(host, new CachedContext(context, now));
        } finally {
            cacheLock.unlock();
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

    /** DNS names and IP addresses from the real server's certificate. */
    private static Set<String> serverNames(SSLSession session) {
        Set<String> names = new LinkedHashSet<>();
        if (session == null) return names;
        try {
            Certificate[] chain = session.getPeerCertificates();
            if (chain.length > 0 && chain[0] instanceof X509Certificate leaf) {
                Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
                if (sans != null) {
                    for (List<?> san : sans) {
                        if (names.size() >= MAX_SANS) break;
                        // 2 = dNSName, 7 = iPAddress (both reported as strings by the JDK).
                        Object type = san.get(0);
                        if ((Integer.valueOf(2).equals(type) || Integer.valueOf(7).equals(type))
                                && san.get(1) instanceof String name) {
                            names.add(name);
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
