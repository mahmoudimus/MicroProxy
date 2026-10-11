package org.microproxy.udp;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;

/** One datagram's payload in a UDP flow the proxy relays, as a {@link UdpInterceptor} sees it. */
public final class UdpMessage {

    private final byte[] data;
    private final boolean fromClient;
    private final Instant timestamp;

    /**
     * A message.
     *
     * @param data the payload, which the message holds as it is (not copied)
     * @param fromClient whether the client sent it, rather than the target
     * @param timestamp when the proxy received it
     */
    public UdpMessage(byte[] data, boolean fromClient, Instant timestamp) {
        this.data = Objects.requireNonNull(data, "data");
        this.fromClient = fromClient;
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp");
    }

    /**
     * The payload as received. The array is the message's own, not a copy: an interceptor may
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

    /** {@return whether the client sent the datagram (going to the target), rather than the target} */
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
     * A copy of this message with another payload, the same direction and timestamp.
     *
     * @param data the payload of the copy (not copied)
     * @return the copy
     */
    public UdpMessage withData(byte[] data) {
        return new UdpMessage(data, fromClient, timestamp);
    }

    @Override
    public String toString() {
        return (fromClient ? "-> " : "<- ") + data.length + " bytes";
    }
}
