package org.microproxy.impl;

import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3Headers;
import io.github.mahmoudimus.http3.RequestHeaders;
import io.github.mahmoudimus.http3.ResponseHeaders;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/**
 * Converts between the HTTP/1-style messages the exchange logic handles and HTTP/3 field sections
 * (RFC 9114 section 4.3): pseudo-headers from the request line or status, names in lower case,
 * without the connection-specific fields HTTP/3 forbids. Fields HTTP/3 cannot carry are dropped.
 */
final class Http3Messages {

    private Http3Messages() {}

    /**
     * The field section of a response head with {@code status}, or, without the {@code :status},
     * its trailers ({@link #trailerFields}).
     */
    static List<HeaderField> responseFields(int status, HttpHeaders headers) {
        List<HeaderField> fields = new ArrayList<>(headers.size() + 1);
        fields.add(new HeaderField(":status", Integer.toString(status)));
        addRegular(fields, headers, false);
        return fields;
    }

    /** A trailer section: regular fields only. */
    static List<HeaderField> trailerFields(HttpHeaders trailers) {
        List<HeaderField> fields = new ArrayList<>(trailers.size());
        addRegular(fields, trailers, false);
        return fields;
    }

    /**
     * The field section for {@code request}: {@code :method}, {@code :scheme} ({@code https}, or
     * an absolute-form URI's), {@code :authority} (from {@code Host}, else the target without the
     * default port) and {@code :path}, then the regular fields, with {@code te} only as {@code
     * trailers} (added when the client accepts trailers: the proxy relays them).
     */
    static List<HeaderField> requestFields(HttpRequest request, String hostAndPort, boolean trailersAccepted) {
        String uri = request.uri();
        String path = ProxyUtils.isAbsoluteUri(uri) ? ProxyUtils.stripHost(uri) : uri;
        if (path.isEmpty()) path = "/";
        String authority = request.headers().get(HttpHeaderNames.HOST);
        if (authority == null || authority.isBlank()) {
            authority = hostAndPort.endsWith(":443") ? hostAndPort.substring(0, hostAndPort.length() - 4) : hostAndPort;
        }
        String scheme = uri.regionMatches(true, 0, "http://", 0, 7) ? "http" : "https";
        List<HeaderField> fields = new ArrayList<>(request.headers().size() + 4);
        fields.add(new HeaderField(":method", request.method().name()));
        fields.add(new HeaderField(":scheme", scheme));
        fields.add(new HeaderField(":authority", authority.strip()));
        fields.add(new HeaderField(":path", path));
        addRegular(fields, request.headers(), true);
        if (trailersAccepted && fields.stream().noneMatch(f -> f.name().equals("te"))) {
            fields.add(new HeaderField("te", "trailers"));
        }
        return fields;
    }

    private static void addRegular(List<HeaderField> fields, HttpHeaders headers, boolean request) {
        for (Map.Entry<String, String> e : headers.entries()) {
            String name = e.getKey().toLowerCase(Locale.ROOT);
            String value = e.getValue();
            if (Http3Headers.CONNECTION_SPECIFIC.contains(name) || name.equals("host") || !validName(name)
                    || !validValue(value)) {
                continue;
            }
            if (name.equals("te")) {
                if (!request || !value.strip().equalsIgnoreCase("trailers")) continue;
                value = "trailers";
            }
            fields.add(new HeaderField(name, value));
        }
    }

    private static boolean validName(String name) {
        if (name.isEmpty()) return false;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean token = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
            if (!token) return false;
        }
        return true;
    }

    private static boolean validValue(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\r' || c == '\n' || c == 0 || c > 0xff) return false;
        }
        return true;
    }

    /**
     * The HTTP/1-style request the exchange logic handles for a request stream's head: origin-form
     * with {@code Host} from {@code :authority} (or, for a proxy, absolute-form from {@code :scheme}
     * and {@code :authority}, as an HTTP/1 client sends a proxy), version HTTP/3, and, for a body of
     * unknown length, chunked towards an HTTP/1.1 server.
     *
     * @param bodyFollows whether the stream goes on after its head
     * @param absolute whether the request is a proxy's: in absolute-form when its scheme is {@code
     *     http} or {@code https}
     * @throws IllegalArgumentException for a method the proxy does not know
     */
    static HttpRequest toHttp1(RequestHeaders head, boolean bodyFollows, boolean absolute) {
        HttpMethod method = HttpMethod.valueOf(head.method());
        HttpHeaders headers = new HttpHeaders();
        if (head.authority() != null && head.get("host") == null) {
            headers.add(HttpHeaderNames.HOST, head.authority());
        }
        for (HeaderField f : head.fields()) headers.add(f.name(), f.value());
        if (bodyFollows && head.contentLength() < 0) {
            headers.set(HttpHeaderNames.TRANSFER_ENCODING, "chunked");
        }
        String uri = head.path();
        boolean httpScheme = "http".equalsIgnoreCase(head.scheme()) || "https".equalsIgnoreCase(head.scheme());
        if (absolute && httpScheme && head.authority() != null && uri != null && uri.startsWith("/")) {
            uri = head.scheme().toLowerCase(Locale.ROOT) + "://" + head.authority() + uri;
        }
        return new DefaultHttpRequest(HttpVersion.HTTP_3_0, method, uri, headers);
    }

    /**
     * The HTTP/1-style response the exchange logic relays: version HTTP/3, and, when the server
     * gave no {@code content-length}, a chunked body (with trailers, if any) or an empty one.
     */
    static HttpResponse toHttp1(ResponseHeaders head, boolean endsHere, boolean bodyless) {
        HttpHeaders headers = new HttpHeaders();
        for (HeaderField f : head.fields()) headers.add(f.name(), f.value());
        if (!bodyless && !head.isInformational() && head.contentLength() < 0) {
            if (endsHere) {
                headers.set(HttpHeaderNames.CONTENT_LENGTH, "0");
            } else {
                headers.set(HttpHeaderNames.TRANSFER_ENCODING, "chunked");
            }
        }
        return new DefaultHttpResponse(HttpVersion.HTTP_3_0, HttpResponseStatus.valueOf(head.status()), headers);
    }
}
