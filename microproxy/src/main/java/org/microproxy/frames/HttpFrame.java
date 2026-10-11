package org.microproxy.frames;

/**
 * A decoded HTTP/2 or HTTP/3 frame, as a {@link FrameInterceptor} sees it: {@link Http2Frame} or
 * {@link Http3Frame}. Frames are records; edit one with its {@code with...} methods, which return
 * a copy. Byte arrays are not copied: whoever creates a frame hands its arrays over.
 */
public sealed interface HttpFrame permits Http2Frame, Http3Frame {

    /**
     * The protocol the frame belongs to.
     *
     * @return {@link FrameProtocol#HTTP_2} or {@link FrameProtocol#HTTP_3}
     */
    FrameProtocol protocol();

    /**
     * The frame type's name as the protocol's RFC spells it ({@code DATA}, {@code HEADERS}, {@code
     * SETTINGS}, ...), or {@code UNKNOWN} for an extension or reserved type.
     *
     * @return the frame type name
     */
    String typeName();

    /**
     * The frame type's code on the wire.
     *
     * @return the unsigned type code
     */
    long typeCode();
}
