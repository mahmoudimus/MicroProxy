package org.microproxy.http;

/** A complete HTTP request. */
public interface FullHttpRequest extends HttpRequest, FullHttpMessage {

    @Override
    FullHttpRequest setContent(byte[] content);
}
