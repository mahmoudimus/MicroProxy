package org.microproxy;

import java.util.Locale;
import javax.net.ssl.SNIHostName;

/**
 * Who the proxy expects at the other end of a TLS connection to a server, when that is not simply
 * the request's host: the server name it sends in the ClientHello (SNI, RFC 6066 section 3) and
 * the host name the server's certificate is verified against (HTTPS endpoint identification, RFC
 * 9110 section 4.3.4). {@link HttpFilters#proxyToServerTlsIdentity} returns one for requests whose
 * connection goes somewhere other than the name they are for: a reverse-proxy route or a chained
 * setup that dials an IP address or an internal load balancer, while the service behind it
 * presents a certificate for its public name.
 *
 * <p>A null component keeps the default: the server name is the request's host (or, for an
 * intercepted {@code CONNECT} to an IP address, the server name the client sent), and the
 * verification host is the server name. Setting the server name alone thus verifies the
 * certificate against that name too; setting the verification host alone keeps the default SNI.
 *
 * <p>The identity is part of what keeps server connections apart: a connection made with one
 * identity is never reused, pooled or coalesced (HTTP/2, RFC 9113 section 9.1.1) for a request
 * with another.
 *
 * @param serverName the host name sent as SNI, or null for the default; never an IP address (SNI
 *     carries host names only)
 * @param verificationHost the host name or IP address the certificate must be valid for, or null
 *     for the server name
 */
public record TlsServerIdentity(String serverName, String verificationHost) {

    /**
     * Checks and normalizes the names: lower case, without a trailing dot.
     *
     * @param serverName the host name sent as SNI, or null for the default
     * @param verificationHost the host the certificate must be valid for, or null for the server name
     * @throws IllegalArgumentException if {@code serverName} is not a valid SNI host name, a
     *     component is blank, or both are null
     */
    public TlsServerIdentity {
        if (serverName == null && verificationHost == null) {
            throw new IllegalArgumentException("a TLS server identity needs a server name or a verification host");
        }
        if (serverName != null) {
            serverName = normalize(serverName, "server name");
            if (serverName.indexOf(':') >= 0 || isIpv4(serverName)) {
                throw new IllegalArgumentException("SNI carries host names, not IP addresses: " + serverName);
            }
            // Throws IllegalArgumentException for a name SNI cannot carry.
            new SNIHostName(serverName);
        }
        if (verificationHost != null) verificationHost = normalize(verificationHost, "verification host");
    }

    /**
     * An identity whose server name and verification host are both {@code serverName}.
     *
     * @param serverName the host name sent as SNI and that the certificate must be valid for
     * @return the identity
     */
    public static TlsServerIdentity of(String serverName) {
        return new TlsServerIdentity(serverName, null);
    }

    /**
     * An identity with the given server name and verification host.
     *
     * @param serverName the host name sent as SNI, or null for the default
     * @param verificationHost the host the certificate must be valid for, or null for the server name
     * @return the identity
     */
    public static TlsServerIdentity of(String serverName, String verificationHost) {
        return new TlsServerIdentity(serverName, verificationHost);
    }

    private static String normalize(String name, String what) {
        String n = name.strip().toLowerCase(Locale.ROOT);
        if (n.startsWith("[") && n.endsWith("]")) n = n.substring(1, n.length() - 1);
        if (n.endsWith(".")) n = n.substring(0, n.length() - 1);
        if (n.isEmpty()) throw new IllegalArgumentException("blank " + what);
        return n;
    }

    private static boolean isIpv4(String host) {
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c != '.' && (c < '0' || c > '9')) return false;
        }
        return true;
    }
}
