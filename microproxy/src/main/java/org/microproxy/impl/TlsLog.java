package org.microproxy.impl;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Log lines about TLS handshakes, one per event, on the logger {@code org.microproxy.impl.Tls}:
 *
 * <ul>
 *   <li>start and success at DEBUG, with the peer, the proxy's TLS role, whether a client
 *       certificate is required, and on success the negotiated protocol and cipher suite;
 *   <li>failure with the cause, its root cause and a summary of the certificates involved (the
 *       proxy's own first, then the peer's chain), without a stack trace. The JDK keeps neither
 *       for every failure: when it rejects the peer's chain itself, the chain is only known if the
 *       validation error carries it (an expired certificate does, an unknown issuer does not). Handshakes with clients fail at DEBUG: clients that
 *       give up, scanners and clients that do not trust the interception CA are routine. With
 *       servers and chained proxies, certificate problems are WARNING (the request fails and the
 *       configuration or the server needs fixing), servers that turn out not to speak TLS DEBUG
 *       (the proxy tunnels to them instead), and everything else, such as timeouts, INFO.
 * </ul>
 *
 * <p>Diagnostics never change a handshake's outcome: anything they throw is swallowed.
 */
final class TlsLog {

    private static final System.Logger LOG = System.getLogger(Tls.class.getName());

    /**
     * Who a handshake is with, for log lines.
     *
     * @param logPrefix names the client connection, e.g. {@code [conn 42] }
     * @param peer {@code client}, {@code server} or {@code chained proxy}
     * @param host the host name expected or sent as SNI, or {@code null}
     */
    record Peer(String logPrefix, String peer, String host) {}

    private TlsLog() {}

    static void started(Peer peer, Socket plain, boolean clientMode, boolean needClientAuth) {
        if (peer == null || !LOG.isLoggable(Level.DEBUG)) return;
        try {
            LOG.log(Level.DEBUG, peer.logPrefix() + "TLS handshake with " + peer.peer() + " started: "
                    + describePeer(peer, plain, null) + " mode=" + (clientMode ? "client" : "server")
                    + (clientMode ? "" : needClientAuth ? " clientAuth=required" : " clientAuth=none"));
        } catch (RuntimeException e) {
            diagnosticsFailed(peer, e);
        }
    }

    static void succeeded(Peer peer, Socket plain, SSLSocket socket, boolean clientMode, long startNanos) {
        if (peer == null || !LOG.isLoggable(Level.DEBUG)) return;
        try {
            SSLSession session = socket.getSession();
            LOG.log(Level.DEBUG, peer.logPrefix() + "TLS handshake with " + peer.peer() + " succeeded in "
                    + (System.nanoTime() - startNanos) / 1_000_000 + " ms: " + describePeer(peer, plain, session)
                    + " mode=" + (clientMode ? "client" : "server") + " protocol=" + session.getProtocol()
                    + " cipher=" + session.getCipherSuite()
                    + (!clientMode && socket.getNeedClientAuth() ? " clientAuth=required" : ""));
        } catch (RuntimeException e) {
            diagnosticsFailed(peer, e);
        }
    }

    /** Logs a failed handshake; {@code socket} is already closed, so asking it cannot start another. */
    static void failed(Peer peer, Socket plain, SSLSocket socket, boolean clientMode, IOException error) {
        if (peer == null) return;
        try {
            Level level = level(peer, error);
            if (!LOG.isLoggable(level)) return;
            SSLSession session = session(socket);
            StringBuilder line = new StringBuilder(256).append(peer.logPrefix()).append("TLS handshake with ")
                    .append(peer.peer()).append(" failed: ").append(describePeer(peer, plain, session))
                    .append(" mode=").append(clientMode ? "client" : "server");
            if (session != null && !"NONE".equals(session.getProtocol())) {
                line.append(" protocol=").append(session.getProtocol()).append(" cipher=").append(session.getCipherSuite());
            }
            line.append(" error=\"").append(message(error)).append('"');
            Throwable root = root(error);
            if (root != error) {
                line.append(" root=\"").append(message(root)).append('"');
            }
            line.append("; local cert: ").append(describe(localCertificates(session)));
            line.append("; peer chain: ").append(describe(peerCertificates(session, error)));
            LOG.log(level, line.toString());
        } catch (RuntimeException e) {
            diagnosticsFailed(peer, e);
        }
    }

    /** The level for a failure: see the class comment. */
    static Level level(Peer peer, IOException error) {
        if ("client".equals(peer.peer())) return Level.DEBUG;
        if (error instanceof SSLException ssl && Tls.looksLikePlaintextPeer(ssl)) return Level.DEBUG;
        return isCertificateProblem(error) ? Level.WARNING : Level.INFO;
    }

    static boolean isCertificateProblem(Throwable error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            if (t instanceof CertificateException || t instanceof CertPathValidatorException
                    || t instanceof CertPathBuilderException) {
                return true;
            }
            String message = String.valueOf(t.getMessage()).toLowerCase(Locale.ROOT);
            if (message.contains("certificate") || message.contains("pkix")) return true;
            if (t.getCause() == t) break;
        }
        return false;
    }

    /**
     * Summarizes certificates: subject, issuer, expiry and subject alternative names of each, the
     * end-entity first. A certificate that cannot be read is named as such rather than failing.
     */
    static String describe(Certificate[] chain) {
        if (chain == null || chain.length == 0) return "none";
        StringBuilder sb = new StringBuilder();
        for (Certificate certificate : chain) {
            if (!sb.isEmpty()) sb.append(" <- ");
            String described;
            try {
                if (certificate instanceof X509Certificate x509) {
                    described = "subject=\"" + x509.getSubjectX500Principal().getName() + '"'
                            + " issuer=\"" + x509.getIssuerX500Principal().getName() + '"'
                            + " notAfter=" + x509.getNotAfter().toInstant()
                            + " san=" + alternativeNames(x509);
                } else {
                    described = certificate == null ? "null" : certificate.getType();
                }
            } catch (RuntimeException | java.security.cert.CertificateParsingException e) {
                described = "unreadable certificate: " + e.getClass().getSimpleName();
            }
            sb.append('[').append(described).append(']');
        }
        return sb.toString();
    }

    private static List<String> alternativeNames(X509Certificate certificate)
            throws java.security.cert.CertificateParsingException {
        Collection<List<?>> names = certificate.getSubjectAlternativeNames();
        List<String> out = new ArrayList<>();
        if (names == null) return out;
        for (List<?> name : names) {
            if (name.size() < 2) continue;
            Object type = name.get(0);
            String prefix = Integer.valueOf(2).equals(type) ? "DNS:" : Integer.valueOf(7).equals(type) ? "IP:" : "";
            out.add(prefix + name.get(1));
        }
        return out;
    }

    private static String describePeer(Peer peer, Socket plain, SSLSession session) {
        SocketAddress address = plain == null ? null : plain.getRemoteSocketAddress();
        String host = peer.host();
        String sni = requestedServerName(session);
        return "peer=" + (address == null ? "-" : address) + (host != null ? " host=" + host : "")
                + (sni != null && !sni.equals(host) ? " sni=" + sni : "");
    }

    /** The server name a client asked for, when the proxy was the TLS server. */
    private static String requestedServerName(SSLSession session) {
        if (!(session instanceof ExtendedSSLSession extended)) return null;
        try {
            for (SNIServerName name : extended.getRequestedServerNames()) {
                if (name instanceof SNIHostName host) return host.getAsciiName();
            }
        } catch (UnsupportedOperationException e) {
            // not recorded
        }
        return null;
    }

    private static SSLSession session(SSLSocket socket) {
        if (socket == null) return null;
        SSLSession handshake = socket.getHandshakeSession();
        return handshake != null ? handshake : socket.getSession();
    }

    private static Certificate[] localCertificates(SSLSession session) {
        return session == null ? null : session.getLocalCertificates();
    }

    /** The peer's chain from the session, or else from a certificate validation error. */
    private static Certificate[] peerCertificates(SSLSession session, Throwable error) {
        if (session != null) {
            try {
                return session.getPeerCertificates();
            } catch (SSLPeerUnverifiedException expected) {
                // No chain received, or it was rejected: look at the validation error instead.
            }
        }
        for (Throwable t = error; t != null && t.getCause() != t; t = t.getCause()) {
            if (t instanceof CertPathValidatorException invalid && invalid.getCertPath() != null) {
                return invalid.getCertPath().getCertificates().toArray(new Certificate[0]);
            }
        }
        return null;
    }

    private static Throwable root(Throwable error) {
        Throwable root = error;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        return root;
    }

    private static String message(Throwable t) {
        String message = t.getMessage();
        return (t.getClass().getSimpleName() + (message == null ? "" : ": " + message)).replace('"', '\'');
    }

    private static void diagnosticsFailed(Peer peer, RuntimeException e) {
        try {
            LOG.log(Level.DEBUG, peer.logPrefix() + "TLS diagnostics failed: " + e);
        } catch (RuntimeException ignored) {
            // nothing more to do
        }
    }
}
