package org.microproxy.http;

/** A complete HTTP message: head and whole body in one object. */
public interface FullHttpMessage extends HttpMessage, LastHttpContent {

    @Override
    FullHttpMessage setContent(byte[] content);
}
