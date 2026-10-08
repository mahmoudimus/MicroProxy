package org.microproxy.http;

import java.util.Objects;

/** A piece of message body. */
public class DefaultHttpContent implements HttpContent {

    private byte[] content;

    public DefaultHttpContent(byte[] content) {
        this.content = Objects.requireNonNull(content, "content");
    }

    @Override
    public byte[] content() {
        return content;
    }

    @Override
    public HttpContent setContent(byte[] content) {
        this.content = Objects.requireNonNull(content, "content");
        return this;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "(" + content.length + " bytes)";
    }
}
