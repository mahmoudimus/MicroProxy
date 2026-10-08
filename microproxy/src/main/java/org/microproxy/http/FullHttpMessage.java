package org.microproxy.http;

/** A complete HTTP message: head and whole body in one object. */
public sealed interface FullHttpMessage extends HttpMessage, LastHttpContent permits FullHttpRequest, FullHttpResponse {

    @Override
    FullHttpMessage setContent(byte[] content);
}
