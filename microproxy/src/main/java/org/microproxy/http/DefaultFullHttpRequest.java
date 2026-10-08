package org.microproxy.http;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/** A complete request with its body. */
public class DefaultFullHttpRequest extends DefaultHttpRequest implements FullHttpRequest {

    private byte[] content;
    private final HttpHeaders trailingHeaders = new HttpHeaders();

    public DefaultFullHttpRequest(HttpVersion version, HttpMethod method, String uri) {
        this(version, method, uri, new byte[0]);
    }

    public DefaultFullHttpRequest(HttpVersion version, HttpMethod method, String uri, byte[] content) {
        this(version, method, uri, new HttpHeaders(), content);
    }

    public DefaultFullHttpRequest(
            HttpVersion version, HttpMethod method, String uri, HttpHeaders headers, byte[] content) {
        super(version, method, uri, headers);
        this.content = Objects.requireNonNull(content, "content");
    }

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
