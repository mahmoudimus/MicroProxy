package org.microproxy.http;

/** The head of an HTTP request. */
public interface HttpRequest extends HttpMessage {

    HttpMethod method();

    HttpRequest setMethod(HttpMethod method);

    /** The request-target exactly as it appears on the request line. */
    String uri();

    HttpRequest setUri(String uri);

    @Override
    HttpRequest setProtocolVersion(HttpVersion version);
}
