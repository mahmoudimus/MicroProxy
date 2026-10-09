package org.microproxy.http;

import java.util.Objects;

/** Mutable {@link HttpRequest} head. */
public non-sealed class DefaultHttpRequest implements HttpRequest {

    private HttpVersion version;
    private HttpMethod method;
    private String uri;
    private final HttpHeaders headers;

    public DefaultHttpRequest(HttpVersion version, HttpMethod method, String uri) {
        this(version, method, uri, new HttpHeaders());
    }

    public DefaultHttpRequest(HttpVersion version, HttpMethod method, String uri, HttpHeaders headers) {
        this.version = Objects.requireNonNull(version, "version");
        this.method = Objects.requireNonNull(method, "method");
        this.uri = validateUri(uri);
        this.headers = Objects.requireNonNull(headers, "headers");
    }

    @Override
    public HttpVersion protocolVersion() {
        return version;
    }

    @Override
    public HttpRequest setProtocolVersion(HttpVersion version) {
        this.version = Objects.requireNonNull(version, "version");
        return this;
    }

    @Override
    public HttpHeaders headers() {
        return headers;
    }

    @Override
    public HttpMethod method() {
        return method;
    }

    @Override
    public HttpRequest setMethod(HttpMethod method) {
        this.method = Objects.requireNonNull(method, "method");
        return this;
    }

    @Override
    public String uri() {
        return uri;
    }

    @Override
    public HttpRequest setUri(String uri) {
        this.uri = validateUri(uri);
        return this;
    }

    private static String validateUri(String uri) {
        Objects.requireNonNull(uri, "uri");
        if (uri.isEmpty()) {
            throw new IllegalArgumentException("empty request-target");
        }
        for (int i = 0; i < uri.length(); i++) {
            char c = uri.charAt(i);
            if (c <= ' ' || c == 0x7f) {
                throw new IllegalArgumentException("invalid character in request-target");
            }
        }
        return uri;
    }

    @Override
    public String toString() {
        return method + " " + uri + " " + version + "\r\n" + headers;
    }
}
