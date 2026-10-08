package org.microproxy.http;

/**
 * Base type of everything that flows through {@link org.microproxy.HttpFilters}: a message head
 * ({@link HttpRequest} / {@link HttpResponse}), a piece of body ({@link HttpContent}), the end of a
 * body ({@link LastHttpContent}), or a whole message ({@link FullHttpRequest} / {@link
 * FullHttpResponse}).
 *
 * <p>This mirrors the object model LittleProxy inherited from Netty, so filters port over with
 * little more than an import change.
 */
public interface HttpObject {}
