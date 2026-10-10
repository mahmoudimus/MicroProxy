package org.microproxy.frames;

import java.net.InetSocketAddress;
import org.microproxy.FlowContext;

/**
 * Where an intercepted frame travels, and a way to add frames next to it. A context is valid only
 * during the {@link FrameInterceptor#intercept} call it is given to.
 */
public interface FrameContext {

    /**
     * The frame's protocol.
     *
     * @return {@link FrameProtocol#HTTP_2} or {@link FrameProtocol#HTTP_3}
     */
    FrameProtocol protocol();

    /**
     * The client connection the frame belongs to ({@link FlowContext#getConnectionId()}), or -1 for
     * a frame of a connection to a server that serves several clients (one not about a stream) or
     * a pipeline given no id.
     *
     * @return the client connection's id, or -1
     */
    long connectionId();

    /**
     * The client's address, or null when the frame belongs to no single client.
     *
     * @return the client address, or null
     */
    InetSocketAddress clientAddress();

    /**
     * The server's {@code host:port} for frames to and from a server, null on the client side.
     *
     * @return the server, or null
     */
    String server();

    /**
     * The stream the frame belongs to: for HTTP/2 the frame's stream id, 0 for the connection; for
     * HTTP/3 the QUIC stream's id, or -1 when the pipeline was given none.
     *
     * @return the stream id
     */
    long streamId();

    /**
     * The exchange the frame belongs to, or null for connection frames and for frames that come
     * before their exchange exists (the HEADERS that open a stream from a client, any HTTP/3
     * frame).
     *
     * @return the exchange's flow context, or null
     */
    FlowContext flowContext();

    /**
     * Adds a frame after the one being intercepted, on the same hop and in the same direction:
     * going out, it is sent after the intercepted frame (or what replaced it); coming in, the proxy
     * processes it as if the peer had sent it next. Frames are added in the order of the calls.
     * What may be added is described in {@link FrameInterceptor}; a result that breaks those rules
     * is discarded together with the interceptor's return value.
     *
     * @param frame the frame to add
     * @throws IllegalStateException if the interceptor call this context was given to has returned
     * @throws NullPointerException if {@code frame} is null
     */
    void send(HttpFrame frame);
}
