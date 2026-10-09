package org.microproxy.http;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/** A piece of an HTTP message body. */
public sealed interface HttpContent extends HttpObject permits LastHttpContent, DefaultHttpContent {

    /** {@return the live backing array of body bytes, not a copy} */
    byte[] content();

    /**
     * Replaces the body bytes of this piece.
     * @param content new backing array, retained without copying
     * @return this content object
     */
    HttpContent setContent(byte[] content);

    /** {@return the number of bytes in this body piece} */
    default int contentLength() {
        return content().length;
    }

    /**
     * Decodes this body piece as text.
     * @param charset character encoding to use
     * @return the decoded text
     */
    default String contentAsString(Charset charset) {
        return new String(content(), charset);
    }

    /** {@return this body piece decoded as UTF-8} */
    default String contentAsString() {
        return contentAsString(StandardCharsets.UTF_8);
    }
}
