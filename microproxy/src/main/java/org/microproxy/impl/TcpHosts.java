// Ported from mitmproxy (MIT License, see META-INF/LICENSE-mitmproxy.txt):
// mitmproxy/addons/next_layer.py, NextLayer._is_destination_in_hosts: matching tcp_hosts against
// the server's host and the client's SNI.
// Changes: the server's host is the CONNECT target's (the proxy does not see the original
// destination address).
package org.microproxy.impl;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Hosts whose connections are relayed as raw TCP even when they look like HTTP: mitmproxy's
 * {@code tcp_hosts}. Each rule is a regular expression searched for (not matched whole),
 * ignoring case, in the target's host name and the client's SNI, without ports.
 */
final class TcpHosts {

    private final List<Pattern> patterns;

    private TcpHosts(List<Pattern> patterns) {
        this.patterns = patterns;
    }

    /** The rules, or null when there are none. */
    static TcpHosts of(List<String> rules) {
        return rules.isEmpty() ? null : new TcpHosts(HostRules.compile(rules));
    }

    /** Whether a connection to {@code host}, with {@code sni} (or null), is relayed as raw TCP. */
    boolean matches(String host, String sni) {
        for (Pattern p : patterns) {
            if ((host != null && p.matcher(host).find()) || (sni != null && p.matcher(sni).find())) return true;
        }
        return false;
    }
}
