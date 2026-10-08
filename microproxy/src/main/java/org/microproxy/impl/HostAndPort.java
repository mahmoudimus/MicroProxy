package org.microproxy.impl;

/** A host (name or literal, IPv6 without brackets) and port. */
record HostAndPort(String host, int port) {

    /**
     * Parses {@code host}, {@code host:port}, {@code [v6]} or {@code [v6]:port}.
     *
     * @throws IllegalArgumentException if malformed
     */
    static HostAndPort parse(String text, int defaultPort) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("empty authority");
        }
        String host;
        String portText = null;
        if (text.startsWith("[")) {
            int close = text.indexOf(']');
            if (close < 0) throw new IllegalArgumentException("unterminated IPv6 literal: " + text);
            host = text.substring(1, close);
            String rest = text.substring(close + 1);
            if (!rest.isEmpty()) {
                if (!rest.startsWith(":")) throw new IllegalArgumentException("malformed authority: " + text);
                portText = rest.substring(1);
            }
        } else {
            int colon = text.lastIndexOf(':');
            if (colon >= 0 && text.indexOf(':') != colon) {
                // Bare IPv6 literal without brackets.
                host = text;
            } else if (colon >= 0) {
                host = text.substring(0, colon);
                portText = text.substring(colon + 1);
            } else {
                host = text;
            }
        }
        if (host.isEmpty()) throw new IllegalArgumentException("empty host: " + text);
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c <= ' ' || c == '/' || c == '@' || c == '?' || c == '#') {
                throw new IllegalArgumentException("invalid host: " + text);
            }
        }
        int port = defaultPort;
        if (portText != null && !portText.isEmpty()) {
            try {
                port = Integer.parseInt(portText);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("invalid port: " + text);
            }
        }
        if (port < 1 || port > 65535) throw new IllegalArgumentException("invalid port: " + text);
        return new HostAndPort(host, port);
    }

    @Override
    public String toString() {
        return (host.indexOf(':') >= 0 ? "[" + host + "]" : host) + ":" + port;
    }
}
