package org.microproxy.http;

/** A complete HTTP request. */
public sealed interface FullHttpRequest extends HttpRequest, FullHttpMessage permits DefaultFullHttpRequest {

    @Override
    FullHttpRequest setContent(byte[] content);
}
