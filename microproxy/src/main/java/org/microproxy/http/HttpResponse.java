package org.microproxy.http;

/** The head of an HTTP response. */
public interface HttpResponse extends HttpMessage {

    HttpResponseStatus status();

    HttpResponse setStatus(HttpResponseStatus status);

    @Override
    HttpResponse setProtocolVersion(HttpVersion version);
}
