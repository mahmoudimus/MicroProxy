package org.microproxy.http;

/** The head of an HTTP request. */
public sealed interface HttpRequest extends HttpMessage permits FullHttpRequest, DefaultHttpRequest {

    /** {@return the request method} */
    HttpMethod method();

    /**
     * Changes the request method.
     * @param method new request method
     * @return this request
     */
    HttpRequest setMethod(HttpMethod method);

    /** {@return the request-target exactly as it appears on the request line} */
    String uri();

    /**
     * Changes the request-target.
     * @param uri new request-target, without whitespace or control characters
     * @return this request
     * @throws IllegalArgumentException if the target is empty or contains invalid characters
     */
    HttpRequest setUri(String uri);

    @Override
    HttpRequest setProtocolVersion(HttpVersion version);
}
