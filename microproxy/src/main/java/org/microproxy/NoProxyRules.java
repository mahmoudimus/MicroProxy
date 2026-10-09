package org.microproxy;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Hosts that bypass the upstream proxy, in the comma-separated {@code NO_PROXY} syntax used by
 * curl and most HTTP clients:
 *
 * <ul>
 *   <li>{@code *} matches every host;
 *   <li>{@code example.com}, {@code .example.com} and {@code *.example.com} match the domain and
 *       all its subdomains;
 *   <li>an IP literal matches that address, and CIDR notation ({@code 10.0.0.0/8}, {@code
 *       fd00::/8}) matches a range; addresses are compared only when the request names an IP
 *       literal (no DNS lookups);
 *   <li>any entry may end in {@code :port} to apply to that port only.
 * </ul>
 */
public final class NoProxyRules {

    // @value-candidate: becomes a value class in the valhalla build profile
    private record Rule(String domain, byte[] network, int prefixLength, int port, boolean all) {}

    private final List<Rule> rules;

    private NoProxyRules(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    /**
     * Returns rules that never bypass the upstream proxy.
     *
     * @return rules that never match a destination
     */
    public static NoProxyRules none() {
        return new NoProxyRules(List.of());
    }

    /**
     * Parses a comma-separated NO_PROXY rule list.
     *
     * @param list the comma-separated NO_PROXY rule list
     * @return the parsed bypass rules
     */
    public static NoProxyRules parse(String list) {
        List<Rule> rules = new ArrayList<>();
        if (list == null) return new NoProxyRules(rules);
        for (String raw : list.split("[,\\s]+")) {
            String entry = raw.strip().toLowerCase(Locale.ROOT);
            if (entry.isEmpty()) continue;
            if (entry.equals("*")) {
                rules.add(new Rule(null, null, 0, -1, true));
                continue;
            }
            int port = -1;
            // host:port, [v6]:port; a bare IPv6 address has several colons and no port.
            if (entry.startsWith("[")) {
                int close = entry.indexOf(']');
                if (close < 0) continue;
                String rest = entry.substring(close + 1);
                if (rest.startsWith(":")) port = parsePort(rest.substring(1));
                entry = entry.substring(1, close) + (rest.startsWith("/") ? rest : "");
            } else if (entry.indexOf(':') == entry.lastIndexOf(':') && entry.indexOf(':') > 0) {
                int colon = entry.indexOf(':');
                port = parsePort(entry.substring(colon + 1));
                entry = entry.substring(0, colon);
            }
            int slash = entry.indexOf('/');
            String address = slash >= 0 ? entry.substring(0, slash) : entry;
            if (isIpLiteral(address)) {
                byte[] network = literal(address);
                if (network == null) continue;
                int prefix = network.length * 8;
                if (slash >= 0) {
                    try {
                        prefix = Integer.parseInt(entry.substring(slash + 1));
                    } catch (NumberFormatException e) {
                        continue;
                    }
                    if (prefix < 0 || prefix > network.length * 8) continue;
                }
                rules.add(new Rule(null, network, prefix, port, false));
            } else {
                String domain = entry.startsWith("*.") ? entry.substring(2)
                        : entry.startsWith(".") ? entry.substring(1) : entry;
                if (domain.endsWith(".")) domain = domain.substring(0, domain.length() - 1);
                if (!domain.isEmpty()) rules.add(new Rule(domain, null, 0, port, false));
            }
        }
        return new NoProxyRules(rules);
    }

    /**
     * Reports whether there are no bypass rules.
     *
     * @return whether there are no bypass rules
     */
    public boolean isEmpty() {
        return rules.isEmpty();
    }

    /**
     * Whether requests to {@code host:port} should bypass the proxy.
     *
     * @param host the destination host name
     * @param port the destination port
     * @return whether requests to {@code host:port} should bypass the proxy
     */
    public boolean matches(String host, int port) {
        if (rules.isEmpty() || host == null) return false;
        String h = host.toLowerCase(Locale.ROOT);
        if (h.startsWith("[") && h.endsWith("]")) h = h.substring(1, h.length() - 1);
        if (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        byte[] address = isIpLiteral(h) ? literal(h) : null;
        for (Rule rule : rules) {
            if (rule.port() >= 0 && rule.port() != port) continue;
            if (rule.all()) return true;
            if (rule.domain() != null) {
                if (h.equals(rule.domain()) || h.endsWith("." + rule.domain())) return true;
            } else if (address != null && address.length == rule.network().length
                    && samePrefix(address, rule.network(), rule.prefixLength())) {
                return true;
            }
        }
        return false;
    }

    private static boolean samePrefix(byte[] a, byte[] b, int bits) {
        BigInteger mask = BigInteger.ONE.shiftLeft(a.length * 8).subtract(BigInteger.ONE)
                .shiftRight(bits).not();
        return new BigInteger(1, a).and(mask).equals(new BigInteger(1, b).and(mask));
    }

    private static int parsePort(String text) {
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    static boolean isIpLiteral(String host) {
        if (host.indexOf(':') >= 0) return true;
        if (host.isEmpty()) return false;
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c != '.' && (c < '0' || c > '9')) return false;
        }
        return true;
    }

    private static byte[] literal(String text) {
        try {
            // Only literals reach here, so this never performs a lookup.
            return InetAddress.getByName(text).getAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
