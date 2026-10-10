// Ported from mitmproxy (MIT License, see META-INF/LICENSE-mitmproxy.txt):
// - mitmproxy/proxy/mode_specs.py: ReverseMode, the "reverse:" mode specification;
// - mitmproxy/net/server_spec.py: parse, the syntax of the upstream server.
// Changes: only the http, https and tcp schemes, and the "regular" and "transparent" mode names.
package org.microproxy;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reverse proxy mode: every request on the listener goes to one fixed upstream server, whatever
 * its target, as a server of its own rather than a forward proxy. Origin-form requests ({@code GET
 * /path}) are accepted, and the {@code Host} field is set to the upstream's unless {@link
 * HttpProxyServerBootstrap#withKeepHostHeader} keeps the client's. Filters, scripts, the cache and
 * logging apply as to any request.
 *
 * <p>The specification follows mitmproxy's {@code reverse:} mode: {@code [scheme://]host[:port]}
 * with an optional trailing slash and no path.
 *
 * <ul>
 *   <li>{@code https://host[:port]} (the default scheme): TLS to the upstream, validated with the
 *       {@link MitmManager}'s server context when one is configured ({@link
 *       MitmManager#serverSslContext(String, int, FlowContext)}), else the JVM's default trust.
 *       HTTP/2 to the upstream with {@link HttpProxyServerBootstrap#withHttp2Upstream}.
 *   <li>{@code http://host[:port]}: plain HTTP to the upstream.
 *   <li>{@code tcp://host:port}: each client connection is relayed to the upstream as raw bytes,
 *       without parsing.
 * </ul>
 *
 * <p>The listener may itself speak TLS ({@link HttpProxyServerBootstrap#withSslContextSource}),
 * which terminates TLS for the upstream, with HTTP/2 to clients when {@link
 * HttpProxyServerBootstrap#withHttp2} is on.
 *
 * @param scheme {@code http}, {@code https} or {@code tcp}
 * @param host the upstream host name or IP address (IPv6 without brackets)
 * @param port the upstream port
 */
public record ReverseProxyMode(String scheme, String host, int port) {

    /** {@code [scheme://]host[:port][/]}, as mitmproxy's server specifications. */
    private static final Pattern SPEC = Pattern.compile(
            "^(?:(?<scheme>\\w+)://)?(?<host>[^:/]+|\\[.+])(?::(?<port>\\d+))?/?$");

    /**
     * Checks the components.
     *
     * @param scheme {@code http}, {@code https} or {@code tcp}
     * @param host the upstream host
     * @param port the upstream port, 1 to 65535
     * @throws IllegalArgumentException if a component is invalid
     */
    public ReverseProxyMode {
        scheme = scheme.toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https") && !scheme.equals("tcp")) {
            throw new IllegalArgumentException("unsupported reverse proxy scheme: " + scheme
                    + " (expected http, https or tcp)");
        }
        if (host.isEmpty()) throw new IllegalArgumentException("reverse proxy host missing");
        if (port < 1 || port > 65535) throw new IllegalArgumentException("invalid reverse proxy port: " + port);
    }

    /**
     * Parses an upstream server specification, {@code [scheme://]host[:port]}: the scheme defaults
     * to {@code https}, the port to 443 for {@code https} and 80 for {@code http}; {@code tcp}
     * needs a port.
     *
     * @param spec the upstream, such as {@code https://example.com} or {@code http://10.0.0.1:8080}
     * @return the reverse proxy mode
     * @throws IllegalArgumentException if the specification is invalid
     */
    public static ReverseProxyMode parse(String spec) {
        Matcher m = SPEC.matcher(spec.strip());
        if (!m.matches()) throw new IllegalArgumentException("invalid server specification: " + spec);
        String scheme = m.group("scheme") == null ? "https" : m.group("scheme").toLowerCase(Locale.ROOT);
        String host = m.group("host");
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        int port;
        if (m.group("port") != null) {
            try {
                port = Integer.parseInt(m.group("port"));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("invalid port in " + spec);
            }
        } else {
            port = switch (scheme) {
                case "https" -> 443;
                case "http" -> 80;
                default -> throw new IllegalArgumentException("port specification missing: " + spec);
            };
        }
        return new ReverseProxyMode(scheme, host, port);
    }

    /**
     * Parses a mitmproxy-style mode: {@code reverse:<spec>} (see {@link #parse}); {@code regular}
     * and {@code transparent}, the modes without a fixed upstream, give {@code null}.
     *
     * @param mode the mode, such as {@code reverse:https://example.com}
     * @return the reverse proxy mode, or {@code null} for {@code regular} and {@code transparent}
     * @throws IllegalArgumentException for other modes
     */
    public static ReverseProxyMode parseMode(String mode) {
        String m = mode.strip();
        if (m.equals("regular") || m.equals("transparent")) return null;
        if (m.startsWith("reverse:")) return parse(m.substring("reverse:".length()));
        throw new IllegalArgumentException("unsupported mode: " + mode
                + " (expected regular, transparent or reverse:<scheme>://<host>[:<port>])");
    }

    /** {@return whether the upstream is reached over TLS ({@code https})} */
    public boolean tls() {
        return scheme.equals("https");
    }

    /** {@return whether client connections are relayed as raw bytes ({@code tcp})} */
    public boolean rawTcp() {
        return scheme.equals("tcp");
    }

    /** {@return the upstream as {@code host:port}, with IPv6 addresses in brackets} */
    public String hostAndPort() {
        return (host.indexOf(':') >= 0 ? "[" + host + "]" : host) + ":" + port;
    }

    /**
     * The {@code Host} field requests get: the host, with the port unless it is the scheme's
     * default, as mitmproxy's {@code url.hostport} writes it.
     *
     * @return the authority for the {@code Host} field
     */
    public String hostHeader() {
        String h = host.indexOf(':') >= 0 ? "[" + host + "]" : host;
        boolean defaultPort = (scheme.equals("https") && port == 443) || (scheme.equals("http") && port == 80);
        return defaultPort ? h : h + ":" + port;
    }

    @Override
    public String toString() {
        return "reverse:" + scheme + "://" + hostHeader();
    }
}
