package org.microproxy.http;

/** A complete HTTP response. */
public interface FullHttpResponse extends HttpResponse, FullHttpMessage {

    @Override
    FullHttpResponse setContent(byte[] content);
}
