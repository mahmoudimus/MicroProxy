package org.microproxy.http;

/**
 * Base type of everything that flows through {@link org.microproxy.HttpFilters}: a message head
 * ({@link HttpRequest} / {@link HttpResponse}), a piece of body ({@link HttpContent}), the end of a
 * body ({@link LastHttpContent}), or a whole message ({@link FullHttpRequest} / {@link
 * FullHttpResponse}).
 *
 * <p>This mirrors the object model LittleProxy inherited from Netty, so filters port over with
 * little more than an import change.
 *
 * <p>The hierarchy is sealed: its implementations are the {@code Default*} classes, which filters
 * construct and may subclass. A {@code switch} over these types can therefore be exhaustive; put
 * the {@code FullHttp*} cases before {@code HttpRequest}/{@code HttpResponse}, and {@code
 * LastHttpContent} before {@code HttpContent}:
 *
 * <pre>{@code
 * switch (httpObject) {
 *     case FullHttpResponse full -> ...;   // a whole buffered response
 *     case HttpResponse head -> ...;       // a streamed response's head
 *     case LastHttpContent last -> ...;    // the end of a body (with trailers)
 *     case HttpContent piece -> ...;       // a piece of a body
 *     case HttpRequest request -> ...;
 * }
 * }</pre>
 */
public sealed interface HttpObject permits HttpMessage, HttpContent {}
