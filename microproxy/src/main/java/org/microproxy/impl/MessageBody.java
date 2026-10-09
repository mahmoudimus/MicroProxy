package org.microproxy.impl;

import java.io.IOException;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.LastHttpContent;

/**
 * The body of a message as it arrives, independent of how the transport delimits it: HTTP/1
 * {@code Content-Length} or chunked coding ({@link HttpCodec.BodyReader}), or an HTTP/2 stream's
 * DATA frames: a client's request ({@link Http2StreamChannel}) or a server's response ({@link
 * Http2UpstreamConnection}).
 *
 * <p>A body is read either piece by piece ({@link #next()}, for filters that inspect it) or as
 * bytes ({@link #read}, the fast path that relays bodies no filter looks at), never both.
 */
interface MessageBody {

    /** Whether the message has a body at all (a zero length counts as none). */
    boolean hasBody();

    /** The body's length in bytes when the message declares it up front; -1 otherwise. */
    long declaredLength();

    /** Whether the whole body has been read. */
    boolean isDone();

    /**
     * Returns the next body piece, ending with a {@link LastHttpContent} that carries the
     * trailers; {@code null} once the last piece has been returned.
     */
    HttpContent next() throws IOException;

    /**
     * Reads body bytes into {@code dst}, without framing; -1 once the body is complete, when
     * {@link #trailers()} become available.
     */
    int read(byte[] dst, int off, int len) throws IOException;

    /** The trailer fields, once {@link #read} has returned -1; empty if there are none. */
    HttpHeaders trailers();

    /** Whether more of the body is already buffered, so that a flush downstream can wait. */
    boolean hasBufferedInput();
}
