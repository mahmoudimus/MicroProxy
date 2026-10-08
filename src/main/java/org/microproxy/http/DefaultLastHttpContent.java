package org.microproxy.http;

import java.util.Objects;

/** The last piece of a message body, with optional trailers. */
public class DefaultLastHttpContent extends DefaultHttpContent implements LastHttpContent {

    private static final byte[] EMPTY = new byte[0];

    private final HttpHeaders trailingHeaders;

    public DefaultLastHttpContent() {
        this(EMPTY);
    }

    public DefaultLastHttpContent(byte[] content) {
        this(content, new HttpHeaders());
    }

    public DefaultLastHttpContent(byte[] content, HttpHeaders trailingHeaders) {
        super(content);
        this.trailingHeaders = Objects.requireNonNull(trailingHeaders, "trailingHeaders");
    }

    @Override
    public HttpHeaders trailingHeaders() {
        return trailingHeaders;
    }

    @Override
    public LastHttpContent setContent(byte[] content) {
        super.setContent(content);
        return this;
    }
}
