package org.microproxy.impl;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The URI template CONNECT-UDP requests name their target with (RFC 9298 section 2), such as the
 * default {@code /.well-known/masque/udp/{target_host}/{target_port}/}: a path, and optionally a
 * query, with the variables {@code target_host} and {@code target_port}, each once. A template
 * given as an absolute URI ({@code https://proxy.example/masque?h={target_host}&p={target_port}})
 * is matched by its path and query: the authority is the proxy's own, which the request reached.
 *
 * <p>A variable matches the characters of one path segment or query value; its value is
 * percent-decoded, so an IPv6 address's colons may be encoded ({@code 2001%3Adb8%3A%3A1}). The
 * port must be a number from 1 to 65535.
 */
final class ConnectUdpTemplate {

    /** The well-known template (RFC 9298 section 3). */
    static final String DEFAULT = "/.well-known/masque/udp/{target_host}/{target_port}/";

    private static final String HOST = "{target_host}";
    private static final String PORT = "{target_port}";

    private final String template;
    private final Pattern pattern;
    private final boolean hostFirst;

    private ConnectUdpTemplate(String template, Pattern pattern, boolean hostFirst) {
        this.template = template;
        this.pattern = pattern;
        this.hostFirst = hostFirst;
    }

    /**
     * Parses a template.
     *
     * @throws IllegalArgumentException if it does not have each variable once, or its path does
     *     not start with {@code /}
     */
    static ConnectUdpTemplate parse(String template) {
        String path = template.strip();
        int scheme = path.indexOf("://");
        if (scheme > 0 && path.substring(0, scheme).chars().allMatch(c -> Character.isLetterOrDigit(c) || c == '+' || c == '-' || c == '.')) {
            int slash = path.indexOf('/', scheme + 3);
            path = slash < 0 ? "/" : path.substring(slash);
        }
        if (!path.startsWith("/")) {
            throw new IllegalArgumentException("a CONNECT-UDP template's path must start with /: " + template);
        }
        int host = path.indexOf(HOST);
        int port = path.indexOf(PORT);
        if (host < 0 || port < 0 || path.indexOf(HOST, host + 1) >= 0 || path.indexOf(PORT, port + 1) >= 0) {
            throw new IllegalArgumentException("a CONNECT-UDP template needs " + HOST + " and " + PORT + " once each: "
                    + template);
        }
        int first = Math.min(host, port);
        int second = Math.max(host, port);
        String a = path.substring(0, first);
        String b = path.substring(first + (first == host ? HOST : PORT).length(), second);
        String c = path.substring(second + (second == host ? HOST : PORT).length());
        String value = "([^/?&#]*)";
        Pattern pattern = Pattern.compile(Pattern.quote(a) + value + Pattern.quote(b) + value + Pattern.quote(c));
        return new ConnectUdpTemplate(template, pattern, host < port);
    }

    /** The target a request's URI names, or null when it does not match or names no valid target. */
    HostAndPort match(String uri) {
        String path = uri;
        if (ProxyUtils.isAbsoluteUri(path)) path = ProxyUtils.stripHost(path);
        Matcher m = pattern.matcher(path);
        if (!m.matches()) return null;
        String host = decode(m.group(hostFirst ? 1 : 2));
        String port = decode(m.group(hostFirst ? 2 : 1));
        if (host == null || port == null || host.isEmpty() || port.isEmpty() || port.length() > 5) return null;
        for (int i = 0; i < port.length(); i++) {
            if (port.charAt(i) < '0' || port.charAt(i) > '9') return null;
        }
        int number = Integer.parseInt(port);
        if (number < 1 || number > 65535) return null;
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        for (int i = 0; i < host.length(); i++) {
            char ch = host.charAt(i);
            boolean ok = Character.isLetterOrDigit(ch) || ch == '.' || ch == '-' || ch == ':' || ch == '_';
            if (!ok || ch > 0x7f) return null;
        }
        return new HostAndPort(host.toLowerCase(Locale.ROOT), number);
    }

    private static String decode(String s) {
        try {
            return URLDecoder.decode(s.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    @Override
    public String toString() {
        return template;
    }
}
