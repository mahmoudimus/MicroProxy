package org.microproxy.quic;

/**
 * Finds the messages of a protocol in the bytes of a QUIC stream, so that {@link
 * QuicInterceptor#streamMessage} sees whole messages rather than whatever each read returned (see
 * {@link QuicFraming}, which chooses a framer for each connection).
 *
 * <p>The proxy keeps the bytes of each direction of a stream that do not make a whole message yet,
 * and asks {@link #frameLength} how long the message at their start is: once that is known and all
 * of it has arrived, the message is cut off, its {@link #payload} goes to the hook, and what the hook
 * returns goes on as {@link #frame}{@code (payload)}, so a length prefix is computed again for an
 * edited payload. A framer that is only a lambda gives the hook whole messages and sends what it
 * returns as it is.
 *
 * <pre>{@code
 * // Messages that end with a zero byte, given to the hook with it.
 * MessageFramer zeroTerminated = (data, offset, length) -> {
 *     for (int i = 0; i < length; i++) if (data[offset + i] == 0) return i + 1;
 *     return MessageFramer.NEED_MORE;
 * };
 * }</pre>
 *
 * <p>Framers are called from many threads at once, one stream direction each, and must keep no
 * state between calls.
 */
@FunctionalInterface
public interface MessageFramer {

    /** What {@link #frameLength} returns while the bytes do not yet say how long the next message is. */
    long NEED_MORE = -1;

    /**
     * The length of the message that starts at {@code data[offset]}, its prefix or delimiter
     * included, as soon as the bytes say it: a length-prefixed framer knows it from the prefix
     * alone, before the rest of the message has arrived, which lets the proxy refuse a message
     * larger than {@link QuicFraming#maxMessageSize()} at once; a delimited one when it finds the
     * delimiter.
     *
     * @param data the bytes kept for the stream direction
     * @param offset where the next message starts
     * @param length how many bytes there are from {@code offset} (at least one)
     * @return the message's length, at least 1, which may be more than {@code length} while the rest
     *     is still to come; or {@link #NEED_MORE}
     * @throws IllegalArgumentException if the bytes cannot start a message of the protocol: the
     *     proxy then resets the stream, as for a message that is too large
     */
    long frameLength(byte[] data, int offset, int length);

    /**
     * What the hooks see of a whole message: the message without its length prefix or delimiter.
     * The default is the message itself.
     *
     * @param message a whole message, as long as {@link #frameLength} said
     * @return the payload
     */
    default byte[] payload(byte[] message) {
        return message;
    }

    /**
     * The message for a payload, the reverse of {@link #payload}: the payload with its length
     * prefix, or with the delimiter after it. The default is the payload itself.
     *
     * @param payload the payload
     * @return the bytes to send
     * @throws IllegalArgumentException if the payload cannot be framed, such as one longer than a
     *     two-byte prefix can say
     */
    default byte[] frame(byte[] payload) {
        return payload;
    }

    /**
     * A two-byte big-endian length prefix, as DNS over QUIC (RFC 9250 section 4.2) and DNS over TCP
     * frame their messages: payloads up to 65535 bytes.
     *
     * @return the framer
     */
    static MessageFramer u16() {
        return Framers.U16;
    }

    /**
     * A four-byte big-endian length prefix: payloads up to 2<sup>32</sup> - 1 bytes, bounded by
     * {@link QuicFraming#maxMessageSize()}.
     *
     * @return the framer
     */
    static MessageFramer u32() {
        return Framers.U32;
    }

    /**
     * A QUIC variable-length integer (RFC 9000 section 16) as the length prefix: one, two, four or
     * eight bytes. Payloads are framed with the shortest encoding.
     *
     * @return the framer
     */
    static MessageFramer varint() {
        return Framers.VARINT;
    }

    /**
     * Lines that end with a line feed: the payload is the line without it, and a line feed is added
     * after each payload sent (a carriage return before it stays in the payload).
     *
     * @return the framer
     */
    static MessageFramer lines() {
        return Framers.LF;
    }

    /**
     * Lines that end with a carriage return and a line feed: the payload is the line without them,
     * and they are added after each payload sent. A line feed alone does not end a line.
     *
     * @return the framer
     */
    static MessageFramer crlfLines() {
        return Framers.CRLF;
    }

    /**
     * A built-in framer by name: {@code u16}, {@code u32}, {@code varint}, {@code lf} (also {@code
     * line} and {@code newline}) or {@code crlf}.
     *
     * @param name the name (any case)
     * @return the framer
     * @throws IllegalArgumentException for another name
     */
    static MessageFramer named(String name) {
        MessageFramer f = Framers.named(name);
        if (f == null) {
            throw new IllegalArgumentException("no message framer " + name + "; there are u16, u32, varint, lf and crlf");
        }
        return f;
    }
}
