package org.microproxy.http;

/** The head of an HTTP response. */
public sealed interface HttpResponse extends HttpMessage permits FullHttpResponse, DefaultHttpResponse {

    HttpResponseStatus status();

    HttpResponse setStatus(HttpResponseStatus status);

    @Override
    HttpResponse setProtocolVersion(HttpVersion version);
}
