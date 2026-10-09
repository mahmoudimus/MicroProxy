package org.microproxy.http;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/** A complete response with its body. */
public non-sealed class DefaultFullHttpResponse extends DefaultHttpResponse implements FullHttpResponse {

    private byte[] content;
    private final HttpHeaders trailingHeaders = new HttpHeaders();

    /**
     * Creates a complete response with empty headers and an empty body.
     *
     * @param version protocol version
     * @param status response status
     */
    public DefaultFullHttpResponse(HttpVersion version, HttpResponseStatus status) {
        this(version, status, new byte[0]);
    }

    /**
     * Creates a complete response with empty headers.
     *
     * @param version protocol version
     * @param status response status
     * @param content body backing array, retained without copying
     */
    public DefaultFullHttpResponse(HttpVersion version, HttpResponseStatus status, byte[] content) {
        this(version, status, new HttpHeaders(), content);
    }

    /**
     * Creates a complete response using the supplied headers and body.
     *
     * @param version protocol version
     * @param status response status
     * @param headers mutable headers, retained without copying
     * @param content body backing array, retained without copying
     */
    public DefaultFullHttpResponse(
            HttpVersion version, HttpResponseStatus status, HttpHeaders headers, byte[] content) {
        super(version, status, headers);
        this.content = Objects.requireNonNull(content, "content");
    }

    /**
     * Creates a complete response with a UTF-8 body and empty headers.
     *
     * @param version protocol version
     * @param status response status
     * @param body body text to encode as UTF-8
     */
    public DefaultFullHttpResponse(HttpVersion version, HttpResponseStatus status, String body) {
        this(version, status, body.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public byte[] content() {
        return content;
    }

    @Override
    public FullHttpResponse setContent(byte[] content) {
        this.content = Objects.requireNonNull(content, "content");
        return this;
    }

    @Override
    public HttpHeaders trailingHeaders() {
        return trailingHeaders;
    }

    @Override
    public FullHttpResponse setProtocolVersion(HttpVersion version) {
        super.setProtocolVersion(version);
        return this;
    }
}
