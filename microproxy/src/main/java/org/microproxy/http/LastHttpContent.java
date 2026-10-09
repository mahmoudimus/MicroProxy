package org.microproxy.http;

/** The final piece of an HTTP message body, optionally carrying trailer fields. */
public sealed interface LastHttpContent extends HttpContent permits FullHttpMessage, DefaultLastHttpContent {

    /** {@return the mutable trailer fields following the body} */
    HttpHeaders trailingHeaders();

    @Override
    LastHttpContent setContent(byte[] content);

    /** {@return a new, empty last-content marker with no trailer fields} */
    static LastHttpContent empty() {
        return new DefaultLastHttpContent();
    }
}
