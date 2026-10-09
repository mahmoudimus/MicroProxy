package org.microproxy.http;

/** The head of an HTTP message: protocol version and headers. */
public sealed interface HttpMessage extends HttpObject permits HttpRequest, HttpResponse, FullHttpMessage {

    /** {@return the message's protocol version} */
    HttpVersion protocolVersion();

    /**
     * Changes the message's protocol version.
     * @param version new protocol version
     * @return this message
     */
    HttpMessage setProtocolVersion(HttpVersion version);

    /** {@return the mutable header fields of this message} */
    HttpHeaders headers();
}
