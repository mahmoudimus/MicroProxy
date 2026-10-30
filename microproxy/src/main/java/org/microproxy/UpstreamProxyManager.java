package org.microproxy;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;
import java.util.Queue;
import javax.net.ssl.SSLContext;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.tls.SslContexts;

/**
 * A {@link ChainedProxyManager} configured like command-line HTTP clients: an upstream proxy URL
 * for plain HTTP, one for HTTPS (CONNECT), and {@link NoProxyRules} for hosts reached directly.
 *
 * <p>Proxy URLs take the forms {@code http://[user:password@]host[:port]}, {@code https://...}
 * (TLS to the proxy itself), {@code h2://...} (TLS, offering HTTP/2 with ALPN), {@code h2c://...}
 * (HTTP/2 with prior knowledge over plain TCP), {@code socks4://...}, {@code socks4a://...},
 * {@code socks5://...} and {@code socks5h://...}. An HTTP/2 proxy carries tunnels and plain-HTTP
 * requests as streams of shared connections ({@link ChainedProxy#http2()}); an {@code h2://} proxy
 * that chooses HTTP/1.1 is spoken to in HTTP/1.1. SOCKS proxies always receive host names, so the
 * {@code a}/{@code h} variants behave like the plain ones. Default ports are 80 (http, h2c), 443
 * (https, h2) and 1080 (SOCKS).
 *
 * <pre>{@code
 * bootstrap.withChainProxyManager(UpstreamProxyManager.fromEnvironment(System.getenv()));
 * bootstrap.withChainProxyManager(new UpstreamProxyManager(
 *         "http://user:secret@proxy.corp:3128", null, NoProxyRules.parse("localhost,.corp,10.0.0.0/8")));
 * }</pre>
 */
public final class UpstreamProxyManager implements ChainedProxyManager {

    private final ChainedProxy httpProxy;
    private final ChainedProxy httpsProxy;
    private final NoProxyRules noProxy;
    private volatile boolean fallbackToDirect;

    /**
     * Creates upstream routing with protocol-specific proxies and bypass rules.
     *
     * @param httpProxyUrl proxy for plain HTTP requests, or {@code null} for direct
     * @param httpsProxyUrl proxy for CONNECT / HTTPS, or {@code null} to use {@code httpProxyUrl}
     *
     * @param noProxy the rules identifying destinations that bypass upstream proxies
     */
    public UpstreamProxyManager(String httpProxyUrl, String httpsProxyUrl, NoProxyRules noProxy) {
        this.httpProxy = httpProxyUrl == null || httpProxyUrl.isBlank() ? null : proxy(httpProxyUrl);
        ChainedProxy https = httpsProxyUrl == null || httpsProxyUrl.isBlank() ? httpProxy : proxy(httpsProxyUrl);
        // (The same URL twice is one proxy, whose HTTP/2 connections both kinds of request share.)
        this.httpsProxy = https != null && https.equals(httpProxy) ? httpProxy : https;
        this.noProxy = noProxy == null ? NoProxyRules.none() : noProxy;
    }

    /**
     * Reads {@code http_proxy}, {@code https_proxy}/{@code HTTPS_PROXY}, {@code all_proxy}/{@code
     * ALL_PROXY} and {@code no_proxy}/{@code NO_PROXY}, like curl. Upper-case {@code HTTP_PROXY} is
     * ignored, as curl does, because CGI servers set it from the request's {@code Proxy} header.
     *
     * @return the manager, or {@code null} when no proxy variable is set
     *
     * @param env the environment variable map
     */
    public static UpstreamProxyManager fromEnvironment(Map<String, String> env) {
        String all = first(env, "all_proxy", "ALL_PROXY");
        String http = first(env, "http_proxy");
        String https = first(env, "https_proxy", "HTTPS_PROXY");
        if (http == null) http = all;
        if (https == null) https = all;
        if (http == null && https == null) return null;
        return new UpstreamProxyManager(http, https, NoProxyRules.parse(first(env, "no_proxy", "NO_PROXY")));
    }

    /**
     * Also try a direct connection when the upstream proxy cannot be reached.
     *
     * @param fallbackToDirect whether to try connecting directly after upstream proxy failure
     * @return this manager
     */
    public UpstreamProxyManager withFallbackToDirect(boolean fallbackToDirect) {
        this.fallbackToDirect = fallbackToDirect;
        return this;
    }

    @Override
    public void lookupChainedProxies(HttpRequest request, Queue<ChainedProxy> chainedProxies, ClientDetails clientDetails) {
        Target target = target(request);
        ChainedProxy proxy = target.secure() ? httpsProxy : httpProxy;
        if (proxy == null || noProxy.matches(target.host(), target.port())) {
            chainedProxies.add(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
            return;
        }
        chainedProxies.add(proxy);
        if (fallbackToDirect) {
            chainedProxies.add(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        }
    }

    /** {@return whether any of the upstream proxies is spoken to in HTTP/2 ({@code h2://} or {@code h2c://})} */
    public boolean usesHttp2() {
        return httpProxy != null && httpProxy.http2() || httpsProxy != null && httpsProxy.http2();
    }

    /** {@return the upstream proxies, their credentials masked ({@code http://***@host:port}), and whether direct is a fallback} */
    @Override
    public String toString() {
        return "UpstreamProxyManager[http=" + httpProxy + ", https=" + httpsProxy + ", fallbackToDirect="
                + fallbackToDirect + "]";
    }

    private record Target(String host, int port, boolean secure) {}

    /**
     * The request's destination. CONNECT and {@code https://} targets are secure; origin-form
     * requests only reach a chained proxy from inside an intercepted TLS session, so they count as
     * secure too.
     */
    private static Target target(HttpRequest request) {
        String uri = request.uri();
        if (HttpMethod.CONNECT.equals(request.method())) {
            return authority(uri, 443, true);
        }
        String lower = uri.toLowerCase(Locale.ROOT);
        if (lower.startsWith("http://") || lower.startsWith("https://")) {
            boolean secure = lower.startsWith("https://");
            try {
                URI parsed = URI.create(uri);
                if (parsed.getHost() != null) {
                    int port = parsed.getPort() >= 0 ? parsed.getPort() : secure ? 443 : 80;
                    return new Target(parsed.getHost(), port, secure);
                }
            } catch (IllegalArgumentException ignored) {
                // fall back to the Host header
            }
        }
        String host = request.headers().get(HttpHeaderNames.HOST);
        return authority(host == null ? "" : host, 443, true);
    }

    private static Target authority(String authority, int defaultPort, boolean secure) {
        String host = authority;
        int port = defaultPort;
        int colon = authority.lastIndexOf(':');
        if (colon > 0 && (authority.indexOf(':') == colon || authority.startsWith("["))
                && !authority.endsWith("]")) {
            host = authority.substring(0, colon);
            try {
                port = Integer.parseInt(authority.substring(colon + 1));
            } catch (NumberFormatException ignored) {
                // keep the default
            }
        }
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        return new Target(host, port, secure);
    }

    private static String first(Map<String, String> env, String... names) {
        for (String name : names) {
            String v = env.get(name);
            if (v != null && !v.isBlank()) return v.strip();
        }
        return null;
    }

    /**
     * Parses a proxy URL into a {@link ChainedProxy}.
     *
     * @param url the upstream proxy URL
     * @return the parsed upstream proxy
     */
    public static ChainedProxy proxy(String url) {
        String text = url.strip();
        if (!text.contains("://")) text = "http://" + text;
        URI uri = URI.create(text);
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        ChainedProxyType type = switch (scheme) {
            case "http", "https", "h2", "h2c" -> ChainedProxyType.HTTP;
            case "socks4", "socks4a" -> ChainedProxyType.SOCKS4;
            case "socks5", "socks5h", "socks" -> ChainedProxyType.SOCKS5;
            default -> throw new IllegalArgumentException("unsupported proxy scheme: " + scheme);
        };
        if (uri.getHost() == null) throw new IllegalArgumentException("proxy URL has no host: " + url);
        boolean tls = scheme.equals("https") || scheme.equals("h2");
        int port = uri.getPort() >= 0 ? uri.getPort()
                : scheme.equals("http") || scheme.equals("h2c") ? 80 : tls ? 443 : 1080;
        String user = null;
        String password = null;
        if (uri.getRawUserInfo() != null) {
            String info = uri.getRawUserInfo();
            int colon = info.indexOf(':');
            user = decode(colon >= 0 ? info.substring(0, colon) : info);
            password = colon >= 0 ? decode(info.substring(colon + 1)) : "";
        }
        String host = uri.getHost().startsWith("[") ? uri.getHost().substring(1, uri.getHost().length() - 1) : uri.getHost();
        return new UrlProxy(InetSocketAddress.createUnresolved(host, port), type, user, password, tls,
                scheme.startsWith("h2"), text);
    }

    private static String decode(String s) {
        return URLDecoder.decode(s.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    /**
     * The JVM's default trust for TLS to proxies, made once for every URL: HTTP/2 connections are
     * shared only by proxies with the same TLS context.
     */
    private static final class SystemTls {
        static final SSLContext CONTEXT = SslContexts.systemDefault();
    }

    /** A chained proxy described by a URL. */
    private static final class UrlProxy extends ChainedProxyAdapter {
        private final InetSocketAddress address;
        private final ChainedProxyType type;
        private final String user;
        private final String password;
        private final byte[] userBytes;
        private final byte[] passwordBytes;
        private final boolean tls;
        private final boolean http2;
        private final String display;

        UrlProxy(InetSocketAddress address, ChainedProxyType type, String user, String password, boolean tls,
                boolean http2, String url) {
            this.address = address;
            this.type = type;
            this.user = user;
            this.password = password;
            this.userBytes = user == null ? null : user.getBytes(StandardCharsets.UTF_8);
            this.passwordBytes = password == null ? null : password.getBytes(StandardCharsets.UTF_8);
            this.tls = tls;
            this.http2 = http2;
            this.display = url.replaceAll("//[^@/]*@", "//***@");
        }

        @Override
        public InetSocketAddress getChainedProxyAddress() {
            return address;
        }

        @Override
        public ChainedProxyType getChainedProxyType() {
            return type;
        }

        @Override
        public String getUsername() {
            return user;
        }

        @Override
        public String getPassword() {
            return password;
        }

        @Override
        public boolean requiresEncryption() {
            return tls;
        }

        @Override
        public boolean http2() {
            return http2;
        }

        @Override
        public SSLContext getSslContext() {
            return tls ? SystemTls.CONTEXT : null;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof UrlProxy p) || !display.equals(p.display)) return false;
            // The redacted display omits the account. Compare both credentials, without a
            // content-dependent String.equals or skipping the password on a username mismatch.
            return MessageDigest.isEqual(userBytes, p.userBytes) & MessageDigest.isEqual(passwordBytes, p.passwordBytes);
        }

        @Override
        public int hashCode() {
            return display.hashCode();
        }

        @Override
        public String toString() {
            return display;
        }
    }
}
