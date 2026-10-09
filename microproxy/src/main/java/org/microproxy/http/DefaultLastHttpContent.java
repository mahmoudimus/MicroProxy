package org.microproxy.http;

import java.util.Objects;

/** The last piece of a message body, with optional trailers. */
public non-sealed class DefaultLastHttpContent extends DefaultHttpContent implements LastHttpContent {

    private static final byte[] EMPTY = new byte[0];

    private final HttpHeaders trailingHeaders;

    /**
     * Creates an empty last-content marker with no trailers.
     */
    public DefaultLastHttpContent() {
        this(EMPTY);
    }

    /**
     * Creates a final body piece with no trailers.
     *
     * @param content body bytes, retained without copying
     */
    public DefaultLastHttpContent(byte[] content) {
        this(content, new HttpHeaders());
    }

    /**
     * Creates a final body piece with the supplied trailers.
     *
     * @param content body bytes, retained without copying
     * @param trailingHeaders mutable trailer fields, retained without copying
     */
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
