package org.microproxy.http;

/** The head of an HTTP message: protocol version and headers. */
public interface HttpMessage extends HttpObject {

    HttpVersion protocolVersion();

    HttpMessage setProtocolVersion(HttpVersion version);

    HttpHeaders headers();
}
