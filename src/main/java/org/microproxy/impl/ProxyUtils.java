package org.microproxy.impl;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
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
    private static final Set<String> HOP_BY_HOP =
            Set.of("connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                    "proxy-connection", "te", "trailer", "upgrade");

    private static final Pattern ABSOLUTE_URI =
            Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.-]*://.*");

    private static final Pattern HTTP_PREFIX =
            Pattern.compile("^(http|ws)s?://.*", Pattern.CASE_INSENSITIVE);

    private static final DateTimeFormatter HTTP_DATE =
            DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US);

    private ProxyUtils() {}

    /** Turns {@code http://host/path?q} into {@code /path?q}; other URIs are returned as is. */
    public static String stripHost(String uri) {
        if (!HTTP_PREFIX.matcher(uri).matches()) {
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

    public static boolean isAbsoluteUri(String uri) {
        return ABSOLUTE_URI.matcher(uri).matches();
    }

    /**
     * Extracts {@code host[:port]} from an absolute URI (without user info), or returns {@code
     * null} if the URI is not absolute.
     */
    public static String parseHostAndPort(String uri) {
        if (!HTTP_PREFIX.matcher(uri).matches()) {
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
        return HOP_BY_HOP.contains(name.toLowerCase(Locale.ROOT));
    }

    /** Removes the fixed set of hop-by-hop headers. */
    public static void stripHopByHopHeaders(HttpHeaders headers) {
        for (String name : List.copyOf(headers.names())) {
            if (shouldRemoveHopByHopHeader(name)) {
                headers.remove(name);
            }
        }
    }

    /**
     * Removes headers named as connection options in {@code Connection} (RFC 9110 7.6.1) or in the
     * non-standard {@code Proxy-Connection}, except {@code Transfer-Encoding}, whose framing the
     * proxy preserves.
     */
    public static void stripConnectionTokens(HttpHeaders headers) {
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
        List<String> values = headers.getAll(HttpHeaderNames.ACCEPT_ENCODING);
        if (values.isEmpty()) return;
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
        return HTTP_DATE.format(ZonedDateTime.now(ZoneOffset.UTC));
    }

    /** Creates an HTML-ish response with {@code body}, a Date and an exact Content-Length. */
    public static FullHttpResponse createFullHttpResponse(
            HttpVersion version, HttpResponseStatus status, String body) {
        byte[] bytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        FullHttpResponse response = new DefaultFullHttpResponse(version, status, bytes);
        HttpHeaders headers = response.headers();
        headers.set(HttpHeaderNames.DATE, httpDate());
        if (bytes.length > 0) {
            headers.set(HttpHeaderNames.CONTENT_TYPE, "text/html; charset=utf-8");
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
