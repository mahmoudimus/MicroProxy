// Ported from rustls src/webpki/server_verifier.rs and its use of webpki's
// EndEntityCert::verify_is_valid_for_subject_name (Apache-2.0), with the common-name fallback of
// HTTPS endpoint identification (RFC 2818 section 3.1, RFC 6125 section 6).
package io.github.mahmoudimus.quic.tls;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

/**
 * Whether a certificate is valid for a host name or IP address, as HTTPS endpoint identification
 * checks: the subject alternative names, and the most specific common name only when there are no
 * DNS names. A wildcard may only be a whole leftmost label, above at least two more labels.
 */
final class HostnameChecker {

    private static final int SAN_DNS = 2;
    private static final int SAN_IP = 7;

    private HostnameChecker() {}

    static boolean isIpLiteral(String host) {
        if (host.indexOf(':') >= 0) return true;
        if (host.isEmpty()) return false;
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c != '.' && (c < '0' || c > '9')) return false;
        }
        return true;
    }

    static boolean matches(X509Certificate cert, String host) {
        String name = host.toLowerCase(Locale.ROOT);
        if (name.startsWith("[") && name.endsWith("]")) name = name.substring(1, name.length() - 1);
        if (name.endsWith(".")) name = name.substring(0, name.length() - 1);
        Collection<List<?>> sans;
        try {
            sans = cert.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            return false;
        }
        if (isIpLiteral(name)) {
            InetAddress address = literal(name);
            if (address == null || sans == null) return false;
            for (List<?> san : sans) {
                if (san.size() >= 2 && Integer.valueOf(SAN_IP).equals(san.get(0))
                        && address.equals(literal(String.valueOf(san.get(1))))) {
                    return true;
                }
            }
            return false;
        }
        boolean sawDns = false;
        if (sans != null) {
            for (List<?> san : sans) {
                if (san.size() >= 2 && Integer.valueOf(SAN_DNS).equals(san.get(0))) {
                    sawDns = true;
                    if (matchesPattern(String.valueOf(san.get(1)), name)) return true;
                }
            }
        }
        if (sawDns) return false;
        String cn = mostSpecificCommonName(cert.getSubjectX500Principal());
        return cn != null && matchesPattern(cn, name);
    }

    private static InetAddress literal(String ip) {
        if (!isIpLiteral(ip)) return null;
        try {
            // A literal never causes a lookup.
            return InetAddress.getByName(ip);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    static boolean matchesPattern(String pattern, String host) {
        String p = pattern.toLowerCase(Locale.ROOT);
        if (p.endsWith(".")) p = p.substring(0, p.length() - 1);
        if (p.isEmpty() || host.isEmpty()) return false;
        if (!p.startsWith("*.")) return p.equals(host);
        String suffix = p.substring(1);
        // "*.example.com" but not "*.com": the wildcard needs two labels below it.
        if (suffix.indexOf('.', 1) < 0 || suffix.contains("*")) return false;
        if (!host.endsWith(suffix)) return false;
        String label = host.substring(0, host.length() - suffix.length());
        return !label.isEmpty() && label.indexOf('.') < 0;
    }

    private static String mostSpecificCommonName(X500Principal principal) {
        try {
            LdapName name = new LdapName(principal.getName(X500Principal.RFC2253));
            // LdapName lists RDNs from least to most specific.
            List<Rdn> rdns = name.getRdns();
            for (int i = rdns.size() - 1; i >= 0; i--) {
                Rdn rdn = rdns.get(i);
                if ("CN".equalsIgnoreCase(rdn.getType()) && rdn.getValue() instanceof String cn) return cn;
            }
        } catch (InvalidNameException e) {
            return null;
        }
        return null;
    }
}
