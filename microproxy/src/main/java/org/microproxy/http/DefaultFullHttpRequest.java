package org.microproxy.http;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/** A complete request with its body. */
public non-sealed class DefaultFullHttpRequest extends DefaultHttpRequest implements FullHttpRequest {

    private byte[] content;
    private final HttpHeaders trailingHeaders = new HttpHeaders();

    /**
     * Creates a complete request with empty headers and an empty body.
     *
     * @param version protocol version
     * @param method request method
     * @param uri request-target, without whitespace or control characters
     */
    public DefaultFullHttpRequest(HttpVersion version, HttpMethod method, String uri) {
        this(version, method, uri, new byte[0]);
    }

    /**
     * Creates a complete request with empty headers.
     *
     * @param version protocol version
     * @param method request method
     * @param uri request-target, without whitespace or control characters
     * @param content body backing array, retained without copying
     */
    public DefaultFullHttpRequest(HttpVersion version, HttpMethod method, String uri, byte[] content) {
        this(version, method, uri, new HttpHeaders(), content);
    }

    /**
     * Creates a complete request using the supplied headers and body.
     *
     * @param version protocol version
     * @param method request method
     * @param uri request-target, without whitespace or control characters
     * @param headers mutable headers, retained without copying
     * @param content body backing array, retained without copying
     */
    public DefaultFullHttpRequest(
            HttpVersion version, HttpMethod method, String uri, HttpHeaders headers, byte[] content) {
        super(version, method, uri, headers);
        this.content = Objects.requireNonNull(content, "content");
    }

    /**
     * Creates a complete request with a UTF-8 body and empty headers.
     *
     * @param version protocol version
     * @param method request method
     * @param uri request-target, without whitespace or control characters
     * @param body body text to encode as UTF-8
     */
    public DefaultFullHttpRequest(HttpVersion version, HttpMethod method, String uri, String body) {
        this(version, method, uri, body.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public byte[] content() {
        return content;
    }

    @Override
    public FullHttpRequest setContent(byte[] content) {
        this.content = Objects.requireNonNull(content, "content");
        return this;
    }

    @Override
    public HttpHeaders trailingHeaders() {
        return trailingHeaders;
    }

    @Override
    public FullHttpRequest setProtocolVersion(HttpVersion version) {
        super.setProtocolVersion(version);
        return this;
    }
}
