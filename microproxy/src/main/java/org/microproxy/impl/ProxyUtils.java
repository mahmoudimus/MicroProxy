package org.microproxy.impl;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMessage;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpUtil;
import org.microproxy.http.HttpVersion;

/** Header rewriting and URI helpers shared by the proxy implementation. */
public final class ProxyUtils {

    /**
     * Hop-by-hop headers (RFC 9110 7.6.1) removed when forwarding. Transfer-Encoding is kept
     * because the proxy re-emits the same framing it received.
     */
    private static final String[] HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate",
        "proxy-authorization", "proxy-connection", "te", "trailer", "upgrade"};

    /** Whether {@code uri} starts with {@code http://}, {@code https://}, {@code ws://} or {@code wss://}. */
    private static boolean hasHttpScheme(String uri) {
        return uri.regionMatches(true, 0, "http://", 0, 7) || uri.regionMatches(true, 0, "https://", 0, 8)
                || uri.regionMatches(true, 0, "ws://", 0, 5) || uri.regionMatches(true, 0, "wss://", 0, 6);
    }

    private static final DateTimeFormatter HTTP_DATE =
            DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US);

    private ProxyUtils() {}

    /** Turns {@code http://host/path?q} into {@code /path?q}; other URIs are returned as is. */
    public static String stripHost(String uri) {
        if (!hasHttpScheme(uri)) {
            return uri;
        }
        String noScheme = uri.substring(uri.indexOf("://") + 3);
        int slash = indexOfPathStart(noScheme);
        if (slash < 0) {
            return "/";
        }
        String rest = noScheme.substring(slash);
        return rest.startsWith("?") ? "/" + rest : rest;
    }

    private static int indexOfPathStart(String afterScheme) {
        for (int i = 0; i < afterScheme.length(); i++) {
            char c = afterScheme.charAt(i);
            if (c == '/' || c == '?') return i;
        }
        return -1;
    }

    /** Whether {@code uri} starts with a scheme followed by {@code ://}. */
    public static boolean isAbsoluteUri(String uri) {
        if (uri.isEmpty() || !isAsciiLetter(uri.charAt(0))) return false;
        for (int i = 1; i < uri.length(); i++) {
            char c = uri.charAt(i);
            if (c == ':') return uri.startsWith("//", i + 1);
            if (!(isAsciiLetter(c) || (c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-')) return false;
        }
        return false;
    }

    private static boolean isAsciiLetter(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    /**
     * Extracts {@code host[:port]} from an absolute URI (without user info), or returns {@code
     * null} if the URI is not absolute.
     */
    public static String parseHostAndPort(String uri) {
        if (!hasHttpScheme(uri)) {
            return null;
        }
        String noScheme = uri.substring(uri.indexOf("://") + 3);
        int end = indexOfPathStart(noScheme);
        String authority = end < 0 ? noScheme : noScheme.substring(0, end);
        int hash = authority.indexOf('#');
        if (hash >= 0) authority = authority.substring(0, hash);
        int at = authority.lastIndexOf('@');
        return at >= 0 ? authority.substring(at + 1) : authority;
    }

    /** The default port for the scheme of an absolute URI (443 for https/wss, else 80). */
    static int defaultPort(String uri) {
        String lower = uri.toLowerCase(Locale.ROOT);
        return lower.startsWith("https://") || lower.startsWith("wss://") ? 443 : 80;
    }

    public static boolean isCONNECT(HttpRequest request) {
        return HttpMethod.CONNECT.equals(request.method());
    }

    public static boolean isHEAD(HttpRequest request) {
        return HttpMethod.HEAD.equals(request.method());
    }

    /** Appends {@code <version> <alias>} to the {@code Via} header (RFC 9110 7.6.3). */
    public static void addVia(HttpMessage message, String alias) {
        HttpVersion v = message.protocolVersion();
        message.headers().add(HttpHeaderNames.VIA, v.majorVersion() + "." + v.minorVersion() + " " + alias);
    }

    public static boolean shouldRemoveHopByHopHeader(String name) {
        for (String h : HOP_BY_HOP) {
            if (h.equalsIgnoreCase(name)) return true;
        }
        return false;
    }

    /** Removes the fixed set of hop-by-hop headers. */
    public static void stripHopByHopHeaders(HttpHeaders headers) {
        headers.removeIf(ProxyUtils::shouldRemoveHopByHopHeader);
    }

    /**
     * Removes headers named as connection options in {@code Connection} (RFC 9110 7.6.1) or in the
     * non-standard {@code Proxy-Connection}, except {@code Transfer-Encoding}, whose framing the
     * proxy preserves.
     */
    public static void stripConnectionTokens(HttpHeaders headers) {
        if (!headers.contains(HttpHeaderNames.CONNECTION) && !headers.contains(HttpHeaderNames.PROXY_CONNECTION)) {
            return;
        }
        List<String> tokens = new ArrayList<>(headers.getAllElements(HttpHeaderNames.CONNECTION));
        tokens.addAll(headers.getAllElements(HttpHeaderNames.PROXY_CONNECTION));
        for (String token : tokens) {
            if (!token.equalsIgnoreCase(HttpHeaderNames.TRANSFER_ENCODING)) {
                headers.remove(token);
            }
        }
    }

    /** Removes the {@code sdch} coding, which the proxy cannot decode, from Accept-Encoding. */
    static void removeSdchEncoding(HttpHeaders headers) {
        String first = headers.get(HttpHeaderNames.ACCEPT_ENCODING);
        if (first == null) return;
        boolean sdch = false;
        for (int i = 0; i < headers.size() && !sdch; i++) {
            if (headers.nameAt(i).equalsIgnoreCase(HttpHeaderNames.ACCEPT_ENCODING)) {
                String v = headers.valueAt(i);
                for (int k = 0; k + 4 <= v.length() && !sdch; k++) sdch = v.regionMatches(true, k, "sdch", 0, 4);
            }
        }
        if (!sdch) return;
        List<String> values = headers.getAll(HttpHeaderNames.ACCEPT_ENCODING);
        List<String> kept = new ArrayList<>();
        for (String v : values) {
            for (String coding : HttpHeaders.splitList(v)) {
                if (!coding.toLowerCase(Locale.ROOT).startsWith("sdch")) {
                    kept.add(coding);
                }
            }
        }
        headers.remove(HttpHeaderNames.ACCEPT_ENCODING);
        if (!kept.isEmpty()) {
            headers.set(HttpHeaderNames.ACCEPT_ENCODING, String.join(", ", kept));
        }
    }

    /** Whether the client keeps the connection open, honouring {@code Proxy-Connection} too. */
    static boolean isClientKeepAlive(HttpRequest request) {
        HttpHeaders h = request.headers();
        if (h.containsValue(HttpHeaderNames.CONNECTION, "close", true)
                || h.containsValue(HttpHeaderNames.PROXY_CONNECTION, "close", true)) {
            return false;
        }
        if (request.protocolVersion().isKeepAliveDefault()) {
            return true;
        }
        return h.containsValue(HttpHeaderNames.CONNECTION, "keep-alive", true)
                || h.containsValue(HttpHeaderNames.PROXY_CONNECTION, "keep-alive", true);
    }

    public static boolean isSwitchingToWebSocketProtocol(HttpRequest request) {
        return request.headers().containsValue(HttpHeaderNames.UPGRADE, "websocket", true)
                && request.headers().containsValue(HttpHeaderNames.CONNECTION, "upgrade", true);
    }

    public static boolean isSwitchingToWebSocketProtocol(HttpResponse response) {
        return response.status().code() == 101
                && response.headers().containsValue(HttpHeaderNames.UPGRADE, "websocket", true);
    }

    /**
     * Whether a response delimits its own body (rather than by closing the connection). See RFC
     * 9112 6.3.
     */
    public static boolean isResponseSelfTerminating(HttpResponse response) {
        int code = response.status().code();
        if ((code >= 100 && code < 200) || code == 204 || code == 304) {
            return true;
        }
        if (response.headers().contains(HttpHeaderNames.TRANSFER_ENCODING)) {
            return HttpUtil.isTransferEncodingChunked(response);
        }
        return response.headers().contains(HttpHeaderNames.CONTENT_LENGTH);
    }

    /** The current time as an IMF-fixdate. */
    public static String httpDate() {
        long second = System.currentTimeMillis() / 1000;
        CachedDate cached = lastDate;
        if (cached == null || cached.second() != second) {
            cached = new CachedDate(second, HTTP_DATE.format(
                    Instant.ofEpochSecond(second).atZone(ZoneOffset.UTC)));
            lastDate = cached;
        }
        return cached.text();
    }

    private record CachedDate(long second, String text) {}

    /** The last formatted date: one string per second however many responses need it. */
    private static volatile CachedDate lastDate;

    /**
     * Creates a plain-text response with {@code body}, a Date and an exact Content-Length. The
     * proxy's own error bodies never repeat request input and are marked {@code nosniff}, so a
     * crafted URL cannot become markup in a browser.
     */
    public static FullHttpResponse createFullHttpResponse(
            HttpVersion version, HttpResponseStatus status, String body) {
        byte[] bytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        FullHttpResponse response = new DefaultFullHttpResponse(version, status, bytes);
        HttpHeaders headers = response.headers();
        headers.set(HttpHeaderNames.DATE, httpDate());
        if (bytes.length > 0) {
            headers.set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=utf-8");
            headers.set("X-Content-Type-Options", "nosniff");
        }
        headers.set(HttpHeaderNames.CONTENT_LENGTH, bytes.length);
        return response;
    }

    /** The local host name, used as the default {@code Via} alias. */
    public static String getHostName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            return "microproxy";
        }
    }
}
