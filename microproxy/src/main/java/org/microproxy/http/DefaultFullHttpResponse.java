package org.microproxy.http;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/** A complete response with its body. */
public class DefaultFullHttpResponse extends DefaultHttpResponse implements FullHttpResponse {

    private byte[] content;
    private final HttpHeaders trailingHeaders = new HttpHeaders();

    public DefaultFullHttpResponse(HttpVersion version, HttpResponseStatus status) {
        this(version, status, new byte[0]);
    }

    public DefaultFullHttpResponse(HttpVersion version, HttpResponseStatus status, byte[] content) {
        this(version, status, new HttpHeaders(), content);
    }

    public DefaultFullHttpResponse(
            HttpVersion version, HttpResponseStatus status, HttpHeaders headers, byte[] content) {
        super(version, status, headers);
        this.content = Objects.requireNonNull(content, "content");
    }

    /** A response whose body is {@code body} encoded as UTF-8. */
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
