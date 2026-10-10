package org.microproxy.frames;

/**
 * Where a frame is going, as a {@link FrameInterceptor} sees it. The proxy terminates HTTP/2 on
 * each side, so a request travels as two sets of frames: the client's, seen {@link #FROM_CLIENT}
 * after the proxy decoded them, and the proxy's own towards the server, seen {@link #TO_SERVER}
 * before it encodes them. They are different frames: their stream ids, header blocks, DATA
 * boundaries and connection-level frames are each side's own.
 */
public enum FrameDirection {

    /** Received from the client, after decoding and before the proxy acts on it. */
    FROM_CLIENT,
    /** Sent by the proxy to the client, before encoding. */
    TO_CLIENT,
    /** Received from a server, after decoding and before the proxy acts on it. */
    FROM_SERVER,
    /** Sent by the proxy to a server, before encoding. */
    TO_SERVER;

    /**
     * Whether the proxy received the frame ({@link #FROM_CLIENT}, {@link #FROM_SERVER}) rather than
     * being about to send it.
     *
     * @return true for frames the proxy received
     */
    public boolean inbound() {
        return this == FROM_CLIENT || this == FROM_SERVER;
    }

    /**
     * Whether the frame travels between the proxy and the client ({@link #FROM_CLIENT}, {@link
     * #TO_CLIENT}) rather than a server.
     *
     * @return true for the client side
     */
    public boolean clientSide() {
        return this == FROM_CLIENT || this == TO_CLIENT;
    }
}
