package org.microproxy.quic;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;

/**
 * Bytes the proxy read from one side of a stream of an intercepted QUIC connection, as a {@link
 * QuicInterceptor} sees them.
 *
 * <p>A QUIC stream is a byte stream, not a sequence of messages: a message is whatever one read
 * returned (at most 16 KiB), so the peer's writes may arrive split into several messages or joined
 * into one, differently from one run to the next. A hook that looks for a message of the protocol
 * must allow for it starting in one message and ending in the next.
 */
public final class QuicStreamMessage {

    private final byte[] data;
    private final boolean fromClient;
    private final Instant timestamp;

    /**
     * A message.
     *
     * @param data the bytes, which the message holds as they are (not copied)
     * @param fromClient whether the client sent them, rather than the server
     * @param timestamp when the proxy read them
     */
    public QuicStreamMessage(byte[] data, boolean fromClient, Instant timestamp) {
        this.data = Objects.requireNonNull(data, "data");
        this.fromClient = fromClient;
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp");
    }

    /**
     * The bytes as read. The array is the message's own, not a copy: an interceptor may change it
     * in place and return it.
     *
     * @return the bytes
     */
    public byte[] data() {
        return data;
    }

    /** {@return the number of bytes} */
    public int length() {
        return data.length;
    }

    /** {@return whether the client sent the bytes (going to the server), rather than the server} */
    public boolean fromClient() {
        return fromClient;
    }

    /** {@return when the proxy read the bytes} */
    public Instant timestamp() {
        return timestamp;
    }

    /**
     * The bytes decoded as UTF-8, malformed sequences replaced with U+FFFD. A character split
     * between two messages shows as replacement characters in both.
     *
     * @return the text
     */
    public String text() {
        return new String(data, StandardCharsets.UTF_8);
    }

    /**
     * A copy of this message with other bytes, the same direction and timestamp.
     *
     * @param data the bytes of the copy (not copied)
     * @return the copy
     */
    public QuicStreamMessage withData(byte[] data) {
        return new QuicStreamMessage(data, fromClient, timestamp);
    }

    /**
     * A copy of this message with the UTF-8 encoding of {@code text}.
     *
     * @param text the text of the copy
     * @return the copy
     */
    public QuicStreamMessage withText(String text) {
        return withData(text.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String toString() {
        return (fromClient ? "-> " : "<- ") + data.length + " bytes";
    }
}
