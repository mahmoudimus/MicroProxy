package org.microproxy.http;

/** The final piece of an HTTP message body, optionally carrying trailer fields. */
public sealed interface LastHttpContent extends HttpContent permits FullHttpMessage, DefaultLastHttpContent {

    HttpHeaders trailingHeaders();

    @Override
    LastHttpContent setContent(byte[] content);

    /** Returns a new, empty last-content marker. */
    static LastHttpContent empty() {
        return new DefaultLastHttpContent();
    }
}
