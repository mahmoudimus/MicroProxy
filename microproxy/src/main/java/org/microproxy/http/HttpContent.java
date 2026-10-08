package org.microproxy.http;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/** A piece of an HTTP message body. */
public sealed interface HttpContent extends HttpObject permits LastHttpContent, DefaultHttpContent {

    /** The body bytes. The returned array is the live backing array, not a copy. */
    byte[] content();

    /** Replaces the body bytes of this piece. */
    HttpContent setContent(byte[] content);

    default int contentLength() {
        return content().length;
    }

    default String contentAsString(Charset charset) {
        return new String(content(), charset);
    }

    default String contentAsString() {
        return contentAsString(StandardCharsets.UTF_8);
    }
}
