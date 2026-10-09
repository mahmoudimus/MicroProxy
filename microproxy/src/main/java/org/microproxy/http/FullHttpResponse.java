package org.microproxy.http;

/** A complete HTTP response. */
public sealed interface FullHttpResponse extends HttpResponse, FullHttpMessage permits DefaultFullHttpResponse {

    @Override
    FullHttpResponse setContent(byte[] content);
}
