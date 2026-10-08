package org.microproxy.http;

/** The final piece of an HTTP message body, optionally carrying trailer fields. */
public interface LastHttpContent extends HttpContent {

    HttpHeaders trailingHeaders();

    @Override
    LastHttpContent setContent(byte[] content);

    /** Returns a new, empty last-content marker. */
    static LastHttpContent empty() {
        return new DefaultLastHttpContent();
    }
}
