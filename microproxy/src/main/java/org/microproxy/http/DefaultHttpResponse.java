package org.microproxy.http;

import java.util.Objects;

/** Mutable {@link HttpResponse} head. */
public non-sealed class DefaultHttpResponse implements HttpResponse {

    private HttpVersion version;
    private HttpResponseStatus status;
    private final HttpHeaders headers;

    /**
     * Creates a response with empty headers.
     *
     * @param version protocol version
     * @param status response status
     */
    public DefaultHttpResponse(HttpVersion version, HttpResponseStatus status) {
        this(version, status, new HttpHeaders());
    }

    /**
     * Creates a response head using the supplied headers.
     *
     * @param version protocol version
     * @param status response status
     * @param headers mutable headers, retained without copying
     */
    public DefaultHttpResponse(HttpVersion version, HttpResponseStatus status, HttpHeaders headers) {
        this.version = Objects.requireNonNull(version, "version");
        this.status = Objects.requireNonNull(status, "status");
        this.headers = Objects.requireNonNull(headers, "headers");
    }

    @Override
    public HttpVersion protocolVersion() {
        return version;
    }

    @Override
    public HttpResponse setProtocolVersion(HttpVersion version) {
        this.version = Objects.requireNonNull(version, "version");
        return this;
    }

    @Override
    public HttpHeaders headers() {
        return headers;
    }

    @Override
    public HttpResponseStatus status() {
        return status;
    }

    @Override
    public HttpResponse setStatus(HttpResponseStatus status) {
        this.status = Objects.requireNonNull(status, "status");
        return this;
    }

    @Override
    public String toString() {
        return version + " " + status + "\r\n" + headers;
    }
}
