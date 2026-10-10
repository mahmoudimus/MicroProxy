package org.microproxy.frames;

/** The protocol of an intercepted frame. */
public enum FrameProtocol {

    /** HTTP/2 (RFC 9113): {@link Http2Frame}. */
    HTTP_2("h2"),
    /** HTTP/3 (RFC 9114): {@link Http3Frame}. */
    HTTP_3("h3");

    private final String alpn;

    FrameProtocol(String alpn) {
        this.alpn = alpn;
    }

    /**
     * The protocol's ALPN token, {@code h2} or {@code h3}.
     *
     * @return the ALPN identifier
     */
    public String alpn() {
        return alpn;
    }
}
