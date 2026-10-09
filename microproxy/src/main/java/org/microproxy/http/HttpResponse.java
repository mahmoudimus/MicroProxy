package org.microproxy.http;

/** The head of an HTTP response. */
public sealed interface HttpResponse extends HttpMessage permits FullHttpResponse, DefaultHttpResponse {

    /** {@return the response's status code and reason phrase} */
    HttpResponseStatus status();

    /**
     * Changes the response status.
     * @param status new status code and reason phrase
     * @return this response
     */
    HttpResponse setStatus(HttpResponseStatus status);

    @Override
    HttpResponse setProtocolVersion(HttpVersion version);
}
