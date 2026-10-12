package org.microproxy.quic;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;

/**
 * One datagram's payload (RFC 9221) of an intercepted QUIC connection, as a {@link QuicInterceptor}
 * sees it.
 */
public final class QuicDatagram {

    private final byte[] data;
    private final boolean fromClient;
    private final Instant timestamp;

    /**
     * A datagram.
     *
     * @param data the payload, which the datagram holds as it is (not copied)
     * @param fromClient whether the client sent it, rather than the server
     * @param timestamp when the proxy received it
     */
    public QuicDatagram(byte[] data, boolean fromClient, Instant timestamp) {
        this.data = Objects.requireNonNull(data, "data");
        this.fromClient = fromClient;
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp");
    }

    /**
     * The payload as received. The array is the datagram's own, not a copy: an interceptor may
     * change it in place and return it.
     *
     * @return the payload
     */
    public byte[] data() {
        return data;
    }

    /** {@return the number of bytes} */
    public int length() {
        return data.length;
    }

    /** {@return whether the client sent the datagram (going to the server), rather than the server} */
    public boolean fromClient() {
        return fromClient;
    }

    /** {@return when the proxy received the datagram} */
    public Instant timestamp() {
        return timestamp;
    }

    /**
     * The payload decoded as UTF-8, malformed sequences replaced with U+FFFD.
     *
     * @return the text
     */
    public String text() {
        return new String(data, StandardCharsets.UTF_8);
    }

    /**
     * A copy of this datagram with another payload, the same direction and timestamp.
     *
     * @param data the payload of the copy (not copied)
     * @return the copy
     */
    public QuicDatagram withData(byte[] data) {
        return new QuicDatagram(data, fromClient, timestamp);
    }

    @Override
    public String toString() {
        return (fromClient ? "-> " : "<- ") + data.length + " bytes";
    }
}
