package org.microproxy.impl;

import java.net.IDN;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Connection coalescing (RFC 9113 section 9.1.1, RFC 8336): which other server names an HTTP/2
 * connection to a server may carry requests for, with {@link
 * org.microproxy.Http2Options#coalesceConnections()} on.
 *
 * <p>{@link Http2Origins} only looks at connections whose {@link Http2Origins.Key#isolation()} is
 * the exchange's: the same route, MITM manager and, for private connections, client connection.
 * Among those, a connection made for {@code a.example.com} serves {@code b.example.com} when
 *
 * <ul>
 *   <li>the certificate the server presented is valid for {@code b.example.com}: one of its DNS
 *       subject alternative names matches it as the JDK's HTTPS hostname verification matches
 *       them (a wildcard only as, or in, the left-most label), with no fallback to the subject's
 *       common name;
 *   <li>its TLS was set up as {@code b.example.com}'s would be: with the same {@link SSLContext}
 *       (trust, client certificate, versions and ciphers the context pins), with the server's
 *       name as SNI, and without a client certificate (an identity tied to the name it was
 *       presented to); and
 *   <li>{@code b.example.com} resolves, with the proxy's own resolver, to the address the
 *       connection went to (direct connections only: through a chained proxy the proxy does not
 *       resolve names), or the server named {@code https://b.example.com} in an ORIGIN frame. Once
 *       a server has sent an ORIGIN frame, its origin set (its own name and those it named) says
 *       which names it serves, and DNS is no longer consulted.
 * </ul>
 *
 * <p>A name that the server answered {@code 421 Misdirected Request} for is never coalesced onto
 * that connection again ({@link Peer#misdirected}).
 */
final class Http2Coalescing {

    /** The most names a connection remembers as served, refused, or named in ORIGIN frames. */
    static final int MAX_NAMES = 1024;

    private Http2Coalescing() {}

    /** The server's TLS context for a name, as the exchange's MITM manager would choose it. */
    @FunctionalInterface
    interface TlsContext {
        SSLContext get() throws Exception;
    }

    /** The address the proxy would connect to for a name, resolved as it would be for connecting. */
    @FunctionalInterface
    interface Resolver {
        InetSocketAddress resolve() throws Exception;
    }

    /**
     * An exchange's wish to take a stream for {@code authority} on a connection made for another
     * name. Its functions run outside {@link Http2Origins}' lock, each at most once a lookup.
     *
     * @param authority the server's {@code host:port}, as {@link #authority} normalizes it
     * @param host the server's host name
     * @param tlsContext the TLS context a connection to the server would be made with
     * @param resolver the server's address, or null when the route does not resolve names (then
     *     only an ORIGIN frame lets a connection serve it)
     */
    record Request(String authority, String host, TlsContext tlsContext, Resolver resolver) {

        /**
         * A request for {@code target}, or null when no other connection may serve it: its host is
         * not a name the server's certificate and SNI can carry (an IP address, say).
         */
        static Request of(HostAndPort target, TlsContext tlsContext, Resolver resolver) {
            String host = asciiHost(target.host());
            if (host == null || Tls.isIpLiteral(host)) return null;
            try {
                new SNIHostName(host);
            } catch (IllegalArgumentException e) {
                return null;
            }
            return new Request(host + ":" + target.port(), host, tlsContext, resolver);
        }
    }

    /** How a connection stands toward a request's name. */
    enum Verdict {
        /** It serves the name already: no more checks. */
        SERVES,
        /** The server named it in an ORIGIN frame: it serves it if the TLS context matches. */
        CHECK_TLS,
        /** It serves it if the TLS context matches and the name resolves to its address. */
        CHECK_ADDRESS,
        /** It does not serve the name. */
        REFUSED
    }

    /**
     * {@code host:port} with the host in lower case (and as ASCII), the form names are compared
     * in; null if it is not a valid authority.
     */
    static String authority(String hostAndPort) {
        try {
            HostAndPort parsed = HostAndPort.parse(hostAndPort, 443);
            String host = asciiHost(parsed.host());
            return host == null ? null : new HostAndPort(host, parsed.port()).toString();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** {@code host} in lower-case ASCII, without a trailing dot; null if it is not a valid name. */
    private static String asciiHost(String host) {
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (host.isEmpty()) return null;
        try {
            return IDN.toASCII(host, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * The authority an ORIGIN frame's entry names: an {@code https} origin's {@code host:port}
     * (443 when it names none); null for anything else, which is ignored.
     */
    static String originAuthority(String origin) {
        String prefix = "https://";
        if (!origin.regionMatches(true, 0, prefix, 0, prefix.length())) return null;
        String rest = origin.substring(prefix.length());
        // An origin is scheme, host and port: a path (even "/"), user info or query is no origin.
        if (rest.isEmpty() || rest.indexOf('/') >= 0 || rest.indexOf('@') >= 0 || rest.indexOf('?') >= 0
                || rest.indexOf('#') >= 0) {
            return null;
        }
        return authority(rest);
    }

    // ---------------------------------------------------------------------------------------
    // Hostname verification
    // ---------------------------------------------------------------------------------------

    /**
     * Whether {@code cert} is valid for {@code host}, as the JDK's HTTPS hostname verification
     * decides from the subject alternative names: an IP address against the {@code iPAddress}
     * names, a host name against the {@code dNSName} ones ({@link #matchesName}). Unlike the JDK,
     * a certificate without DNS names is valid for no host name (no common name fallback).
     */
    static boolean certificateCovers(X509Certificate cert, String host) {
        Names names = Names.of(cert);
        return names != null && names.cover(host);
    }

    /**
     * Whether a certificate's DNS name {@code pattern} matches {@code host}, as RFC 6125 and the
     * JDK match them: case-insensitively, with one wildcard allowed only in the left-most label
     * (as all of it, {@code *.example.com}, or part of it, {@code w*.example.com}) and matching
     * within that label only. A wildcard directly above a top-level domain ({@code *.com}), or in
     * an A-label ({@code xn--*}), matches nothing.
     */
    static boolean matchesName(String pattern, String host) {
        String p = asciiHost(pattern);
        String h = asciiHost(host);
        if (p == null || h == null) return false;
        int star = p.indexOf('*');
        if (star < 0) return p.equals(h);
        int firstDot = p.indexOf('.');
        if (firstDot < 0 || star > firstDot || p.indexOf('*', star + 1) >= 0 || p.startsWith("xn--")) return false;
        String suffix = p.substring(firstDot);
        if (suffix.indexOf('.', 1) < 0) return false;
        int hostDot = h.indexOf('.');
        if (hostDot <= 0 || !h.substring(hostDot).equals(suffix)) return false;
        String label = h.substring(0, hostDot);
        String before = p.substring(0, star);
        String after = p.substring(star + 1, firstDot);
        return label.length() >= before.length() + after.length() && label.startsWith(before) && label.endsWith(after);
    }

    /** A certificate's subject alternative names. */
    private record Names(List<String> dns, List<InetAddress> ip) {

        static Names of(X509Certificate cert) {
            Collection<List<?>> sans;
            try {
                sans = cert.getSubjectAlternativeNames();
            } catch (CertificateParsingException e) {
                return null;
            }
            List<String> dns = new ArrayList<>();
            List<InetAddress> ip = new ArrayList<>();
            if (sans != null) {
                for (List<?> san : sans) {
                    // 2 = dNSName, 7 = iPAddress (both reported as strings by the JDK).
                    if (!(san.get(1) instanceof String value)) continue;
                    if (Integer.valueOf(2).equals(san.get(0))) {
                        dns.add(value);
                    } else if (Integer.valueOf(7).equals(san.get(0))) {
                        InetAddress address = literal(value);
                        if (address != null) ip.add(address);
                    }
                }
            }
            return new Names(List.copyOf(dns), List.copyOf(ip));
        }

        boolean cover(String host) {
            if (Tls.isIpLiteral(host)) {
                InetAddress address = literal(host);
                return address != null && ip.contains(address);
            }
            for (String pattern : dns) {
                if (matchesName(pattern, host)) return true;
            }
            return false;
        }

        /** An IP address literal (never a name to resolve); null if {@code text} is not one. */
        private static InetAddress literal(String text) {
            String t = text.startsWith("[") && text.endsWith("]") ? text.substring(1, text.length() - 1) : text;
            if (!Tls.isIpLiteral(t)) return null;
            try {
                return InetAddress.getByName(t);
            } catch (UnknownHostException e) {
                return null;
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // A connection's side
    // ---------------------------------------------------------------------------------------

    /**
     * What one connection may serve besides the name it was made for: fixed facts from its TLS
     * handshake, and the names it has been found to serve, been refused for, or been named in
     * ORIGIN frames. Guarded by its own lock, which may be taken under {@link Http2Origins}' lock
     * and never the other way round.
     */
    static final class Peer {
        private final String authority;
        private final SSLContext tlsContext;
        private final InetSocketAddress address;
        private final Names names;
        private final ReentrantLock lock = new ReentrantLock();
        // Guarded by lock.
        /** The server's origin set from its ORIGIN frames (its own name included); null before the first. */
        private Set<String> originSet;
        /** Names found to be served (and indexed under by Http2Origins). */
        private final Set<String> serving = new HashSet<>();
        /** Names the server answered 421 for: never served again. */
        private final Set<String> misdirected = new HashSet<>();
        /** Too many names were refused with 421: the connection serves only its own. */
        private boolean ownOnly;

        private Peer(String authority, SSLContext tlsContext, InetSocketAddress address, Names names) {
            this.authority = authority;
            this.tlsContext = tlsContext;
            this.address = address;
            this.names = names;
        }

        /**
         * The coalescing side of {@code carrier}, an HTTP/2 connection made for {@code
         * hostAndPort}; null if it serves only that name: it is not TLS made with a known
         * context, the proxy presented a client certificate on it, it did not send the name as
         * SNI, or the server's certificate is not an X.509 one.
         */
        static Peer of(ServerConnection carrier, String hostAndPort) {
            String own = authority(hostAndPort);
            if (own == null || carrier.tlsContext == null || !(carrier.socket instanceof SSLSocket tls)) return null;
            SSLSession session = tls.getSession();
            if (session.getLocalCertificates() != null) return null;
            List<SNIServerName> sni = tls.getSSLParameters().getServerNames();
            String host = HostAndPort.parse(own, 443).host();
            if (sni == null || sni.size() != 1 || !(sni.getFirst() instanceof SNIHostName name)
                    || !host.equals(asciiHost(name.getAsciiName()))) {
                return null;
            }
            Certificate[] chain;
            try {
                chain = session.getPeerCertificates();
            } catch (SSLPeerUnverifiedException e) {
                return null;
            }
            if (chain.length == 0 || !(chain[0] instanceof X509Certificate leaf)) return null;
            Names names = Names.of(leaf);
            return names == null ? null : new Peer(own, carrier.tlsContext, carrier.remoteAddress, names);
        }

        /** What is left to check before the connection serves {@code request}'s name. */
        Verdict verdict(Request request) {
            String name = request.authority();
            if (name.equals(authority)) return Verdict.SERVES;
            lock.lock();
            try {
                if (ownOnly || misdirected.contains(name)) return Verdict.REFUSED;
                if (serving.contains(name)) return Verdict.SERVES;
                if (!names.cover(request.host())) return Verdict.REFUSED;
                if (originSet != null) return originSet.contains(name) ? Verdict.CHECK_TLS : Verdict.REFUSED;
                return Verdict.CHECK_ADDRESS;
            } finally {
                lock.unlock();
            }
        }

        /**
         * The last checks for {@code request}'s name, given the TLS context a connection for it
         * would use and, for {@link Verdict#CHECK_ADDRESS}, the address it resolved to: when they
         * pass, the connection serves the name from now on.
         *
         * @return whether the connection serves the name
         */
        boolean admit(Request request, SSLContext context, InetSocketAddress resolved) {
            if (context == null || context != tlsContext) return false;
            String name = request.authority();
            lock.lock();
            try {
                if (ownOnly || misdirected.contains(name)) return false;
                if (serving.contains(name)) return true;
                if (!names.cover(request.host())) return false;
                boolean named = originSet != null && originSet.contains(name);
                if (!named && (originSet != null || resolved == null || !resolved.equals(address))) return false;
                if (serving.size() < MAX_NAMES) serving.add(name);
                return true;
            } finally {
                lock.unlock();
            }
        }

        /** Whether the connection serves {@code name} (normalized) now, its own name included. */
        boolean serves(String name) {
            if (name.equals(authority)) return true;
            lock.lock();
            try {
                return serving.contains(name);
            } finally {
                lock.unlock();
            }
        }

        /**
         * The server answered {@code 421 Misdirected Request} for a request for {@code
         * hostAndPort} on the connection: the name is no longer served there (RFC 8336 section
         * 2.3 removes it from the origin set).
         */
        void misdirected(String hostAndPort) {
            String name = authority(hostAndPort);
            if (name == null || name.equals(authority)) return;
            lock.lock();
            try {
                serving.remove(name);
                if (originSet != null) originSet.remove(name);
                if (misdirected.size() < MAX_NAMES) {
                    misdirected.add(name);
                } else {
                    ownOnly = true;
                }
            } finally {
                lock.unlock();
            }
        }

        /**
         * An ORIGIN frame named {@code origins}: the first starts the origin set with the
         * connection's own name, and each adds to it (RFC 8336 section 2.3). Names served because
         * they resolved to the connection's address and that the set does not hold are served no
         * more.
         */
        void origins(List<String> origins) {
            lock.lock();
            try {
                if (originSet == null) {
                    originSet = new HashSet<>();
                    originSet.add(authority);
                }
                for (String origin : origins) {
                    String name = originAuthority(origin);
                    if (name != null && originSet.size() < MAX_NAMES && !misdirected.contains(name)) {
                        originSet.add(name);
                    }
                }
                serving.retainAll(originSet);
            } finally {
                lock.unlock();
            }
        }

        /** Whether the server has sent an ORIGIN frame (for tests). */
        boolean hasOriginSet() {
            lock.lock();
            try {
                return originSet != null;
            } finally {
                lock.unlock();
            }
        }
    }

    /**
     * The TLS context and, when {@code needsAddress}, the address that {@code request} needs for
     * its last checks, each looked up once; null where the lookup failed (the check then fails).
     */
    record Lookup(SSLContext context, InetSocketAddress address) {

        static Lookup of(Request request, boolean needsAddress) {
            SSLContext context;
            try {
                context = request.tlsContext().get();
            } catch (Exception e) {
                interrupted(e);
                return new Lookup(null, null);
            }
            InetSocketAddress address = null;
            if (needsAddress && request.resolver() != null) {
                try {
                    address = request.resolver().resolve();
                } catch (Exception e) {
                    // Not coalesced by address (connecting will report the failure).
                    interrupted(e);
                }
            }
            return new Lookup(context, address);
        }

        private static void interrupted(Exception e) {
            if (e instanceof InterruptedException || e instanceof java.io.InterruptedIOException) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
