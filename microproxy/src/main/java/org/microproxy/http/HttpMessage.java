package org.microproxy.http;

/** The head of an HTTP message: protocol version and headers. */
public sealed interface HttpMessage extends HttpObject permits HttpRequest, HttpResponse, FullHttpMessage {

    HttpVersion protocolVersion();

    HttpMessage setProtocolVersion(HttpVersion version);

    HttpHeaders headers();
}
