package org.microproxy.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * The permessage-deflate extension (RFC 7692), for relays whose hooks read and rewrite payloads.
 *
 * <p>The proxy keeps two separate compression contexts per direction, one on each hop: it
 * inflates what the client sent with the client's context and deflates what it forwards with its
 * own context towards the server, and the same the other way. A hook may change a payload, so the
 * proxy cannot forward compressed bytes and keep the receiver's window in step with the sender's.
 *
 * <p>Window sizes: inflating with the JDK's 32 KiB window (15 bits) reads anything a peer sends,
 * whatever {@code *_max_window_bits} it agreed to. Deflating is the problem: {@link Deflater}
 * always uses a 15-bit window, and a peer that agreed to a smaller window may keep only that much
 * history, so a back-reference further than {@code 2^bits} bytes would corrupt its output.
 * Resetting the context after each message ({@code no_context_takeover}) is not enough, since a
 * single message longer than the window can refer back across it. So towards a peer whose window
 * is under 15 bits the proxy deflates with {@link Deflater#HUFFMAN_ONLY}: Huffman-coded literals
 * and no back-references at all, which any window decodes. The parameters stay negotiated end to
 * end as the client and server agreed them; only the proxy's own output compresses less.
 */
final class PerMessageDeflate {

    static final String NAME = "permessage-deflate";

    /** The empty stored block that ends a flushed DEFLATE stream; removed from each message. */
    private static final byte[] TAIL = {0x00, 0x00, (byte) 0xff, (byte) 0xff};

    private PerMessageDeflate() {}

    /**
     * The parameters a server agreed to in its {@code Sec-WebSocket-Extensions} response.
     *
     * @param serverNoContextTakeover the server resets its compressor after each message
     * @param clientNoContextTakeover the client resets its compressor after each message
     * @param serverMaxWindowBits the largest window the server compresses with (8-15)
     * @param clientMaxWindowBits the largest window the client compresses with (8-15)
     */
    record Params(boolean serverNoContextTakeover, boolean clientNoContextTakeover, int serverMaxWindowBits,
            int clientMaxWindowBits) {

        static final Params DEFAULT = new Params(false, false, 15, 15);
    }

    /** A {@code Sec-WebSocket-Extensions} value the relay cannot interpret. */
    static final class UnsupportedException extends Exception {
        UnsupportedException(String message) {
            super(message);
        }
    }

    /**
     * The offers among {@code elements} (a request's {@code Sec-WebSocket-Extensions}) that the
     * relay can inflate and deflate: permessage-deflate with only the four parameters RFC 7692
     * defines, each at most once and with a valid value. Other extensions are dropped, since a
     * relay that rewrites payloads would not understand their frames.
     *
     * @return the remaining offers joined by commas, or null if none remains
     */
    static String supportedOffers(List<String> elements) {
        List<String> kept = new ArrayList<>();
        for (String offer : elements) {
            try {
                parse(offer, true);
                kept.add(offer.strip());
            } catch (UnsupportedException e) {
                // dropped
            }
        }
        return kept.isEmpty() ? null : String.join(", ", kept);
    }

    /**
     * The parameters agreed in a response's {@code Sec-WebSocket-Extensions} elements.
     *
     * @return the parameters, or null if no extension is in use
     * @throws UnsupportedException if the response names anything but one permessage-deflate
     */
    static Params agreed(List<String> elements) throws UnsupportedException {
        if (elements.isEmpty()) return null;
        if (elements.size() > 1) throw new UnsupportedException("more than one extension: " + elements);
        return parse(elements.getFirst(), false);
    }

    /** Parses one {@code permessage-deflate; param[=value]...} element. */
    private static Params parse(String element, boolean offer) throws UnsupportedException {
        String[] parts = element.split(";");
        if (!parts[0].strip().equalsIgnoreCase(NAME)) {
            throw new UnsupportedException("unsupported extension " + parts[0].strip());
        }
        boolean serverNoContext = false;
        boolean clientNoContext = false;
        int serverBits = 15;
        int clientBits = 15;
        Set<String> seen = new HashSet<>();
        for (int i = 1; i < parts.length; i++) {
            String param = parts[i].strip();
            if (param.isEmpty()) continue;
            int eq = param.indexOf('=');
            String name = (eq < 0 ? param : param.substring(0, eq)).strip().toLowerCase(Locale.ROOT);
            String value = eq < 0 ? null : unquote(param.substring(eq + 1).strip());
            if (!seen.add(name)) throw new UnsupportedException("repeated parameter " + name);
            switch (name) {
                case "server_no_context_takeover" -> {
                    if (value != null) throw new UnsupportedException(name + " takes no value");
                    serverNoContext = true;
                }
                case "client_no_context_takeover" -> {
                    if (value != null) throw new UnsupportedException(name + " takes no value");
                    clientNoContext = true;
                }
                case "server_max_window_bits" -> {
                    if (value == null) throw new UnsupportedException(name + " needs a value");
                    serverBits = windowBits(name, value);
                }
                case "client_max_window_bits" -> {
                    // Valueless in an offer: the client accepts a limit. A response must give one;
                    // read a valueless one as no limit.
                    if (value != null) clientBits = windowBits(name, value);
                }
                default -> throw new UnsupportedException("unknown parameter " + name);
            }
        }
        return new Params(serverNoContext, clientNoContext, serverBits, clientBits);
    }

    private static String unquote(String value) {
        return value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")
                ? value.substring(1, value.length() - 1) : value;
    }

    private static int windowBits(String name, String value) throws UnsupportedException {
        if (value.length() > 2 || value.isEmpty() || !Character.isDigit(value.charAt(0))
                || !Character.isDigit(value.charAt(value.length() - 1))) {
            throw new UnsupportedException(name + "=" + value);
        }
        int bits = Integer.parseInt(value);
        if (bits < 8 || bits > 15) throw new UnsupportedException(name + "=" + value);
        return bits;
    }

    /** A message larger than the relay's limit, compressed or not. */
    static final class TooBigException extends Exception {
        TooBigException() {
            super("message too big", null, false, false);
        }
    }

    /**
     * Inflates the messages one peer sends on its hop. Owned by the thread reading from that peer.
     */
    static final class Decompressor {
        private final Inflater inflater = new Inflater(true);
        private final boolean resetAfterMessage;
        private final byte[] chunk = new byte[16 * 1024];

        /**
         * @param resetAfterMessage whether the sender agreed to {@code no_context_takeover}
         */
        Decompressor(boolean resetAfterMessage) {
            this.resetAfterMessage = resetAfterMessage;
        }

        /**
         * Inflates one frame's payload of a compressed message into {@code out}, and at the end
         * of the message the empty block the sender removed.
         *
         * @param limit the most bytes {@code out} may hold afterwards
         * @throws TooBigException if the message inflates past {@code limit}
         * @throws DataFormatException if the payload is not valid DEFLATE data
         */
        void inflate(byte[] data, boolean endOfMessage, Buffer out, long limit)
                throws TooBigException, DataFormatException {
            run(data, out, limit);
            if (endOfMessage) {
                if (!inflater.finished()) run(TAIL, out, limit);
                if (resetAfterMessage || inflater.finished()) {
                    // A final block (BFINAL) ends the stream: the next message starts afresh.
                    inflater.reset();
                }
            }
        }

        private void run(byte[] data, Buffer out, long limit) throws TooBigException, DataFormatException {
            if (inflater.finished()) return;
            inflater.setInput(data);
            while (true) {
                int n = inflater.inflate(chunk);
                if (n > 0) {
                    if (out.size() + (long) n > limit) throw new TooBigException();
                    out.append(chunk, 0, n);
                } else if (inflater.finished() || inflater.needsInput()) {
                    return;
                } else if (inflater.needsDictionary()) {
                    throw new DataFormatException("preset dictionary");
                }
            }
        }

        void end() {
            inflater.end();
        }
    }

    /**
     * Deflates the messages the proxy sends on one hop. Used under that output's lock.
     */
    static final class Compressor {
        private final Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        private final boolean resetAfterMessage;
        private final byte[] chunk = new byte[16 * 1024];

        /**
         * @param resetAfterMessage whether the proxy, as this hop's sender, agreed to {@code
         *     no_context_takeover}
         * @param windowBits the largest window the receiver accepts
         */
        Compressor(boolean resetAfterMessage, int windowBits) {
            this.resetAfterMessage = resetAfterMessage;
            if (windowBits < 15) {
                // No back-references, so the receiver's smaller window cannot be exceeded.
                deflater.setStrategy(Deflater.HUFFMAN_ONLY);
            }
        }

        /**
         * Compresses the next part of a message (a whole message, or one frame's worth when
         * frames are relayed one at a time). The parts of a message concatenate to its
         * compressed payload.
         *
         * @param endOfMessage whether this part ends the message
         * @return the compressed bytes, in a buffer of their own
         */
        Buffer deflate(byte[] data, int off, int len, boolean endOfMessage) {
            deflater.setInput(data, off, len);
            Buffer out = new Buffer(Math.max(64, len / 2));
            while (true) {
                int n = deflater.deflate(chunk, 0, chunk.length, Deflater.SYNC_FLUSH);
                out.append(chunk, 0, n);
                if (n < chunk.length && deflater.needsInput()) break;
            }
            if (endOfMessage) {
                out.removeTail(TAIL);
                if (resetAfterMessage) deflater.reset();
            }
            return out;
        }

        void end() {
            deflater.end();
        }
    }

    /** A growable byte array. */
    static final class Buffer {
        private byte[] bytes;
        private int size;

        Buffer(int capacity) {
            bytes = new byte[Math.max(16, capacity)];
        }

        int size() {
            return size;
        }

        void append(byte[] b, int off, int len) {
            if (size + len > bytes.length) {
                long wanted = Math.max((long) size + len, (long) bytes.length * 2);
                bytes = Arrays.copyOf(bytes, (int) Math.min(wanted, Integer.MAX_VALUE - 8));
            }
            System.arraycopy(b, off, bytes, size, len);
            size += len;
        }

        /** Removes {@code tail} from the end, if the buffer ends with it. */
        void removeTail(byte[] tail) {
            if (size < tail.length) return;
            for (int i = 0; i < tail.length; i++) {
                if (bytes[size - tail.length + i] != tail[i]) return;
            }
            size -= tail.length;
        }

        /** The backing array, whose first {@link #size()} bytes are the content, until the next change. */
        byte[] array() {
            return bytes;
        }

        /** A copy of the content. */
        byte[] toArray() {
            return Arrays.copyOf(bytes, size);
        }

        /** Empties the buffer, letting go of a large array. */
        void clear(int keep) {
            size = 0;
            if (bytes.length > keep) bytes = new byte[Math.max(16, keep)];
        }
    }
}
