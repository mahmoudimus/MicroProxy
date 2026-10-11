package org.microproxy.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.microproxy.quic.MessageFramer;

/**
 * Cuts the bytes of one direction of a stream into whole messages with a {@link MessageFramer},
 * whatever pieces they are read in: it keeps the bytes that do not make a whole message yet, up to
 * a limit on a message's size. One per stream direction, used by its reading thread only.
 */
final class MessageAssembler {

    /** Above this, an empty buffer is let go rather than kept for the next message. */
    private static final int KEEP = 64 * 1024;

    private final MessageFramer framer;
    private final int maxMessageSize;
    private byte[] kept = new byte[0];
    private int keptLength;
    private String failure;

    /**
     * @param framer how messages are delimited
     * @param maxMessageSize the most bytes a message may have, its prefix or delimiter included
     */
    MessageAssembler(MessageFramer framer, int maxMessageSize) {
        this.framer = framer;
        this.maxMessageSize = maxMessageSize;
    }

    /**
     * Adds bytes read, and returns the whole messages they complete, in order, each with its prefix
     * or delimiter. When the bytes cannot go on (a message too large, or bytes the framer cannot
     * read), the messages before them are returned, {@link #failure()} says why, and later bytes
     * are ignored.
     *
     * @param data the bytes read
     * @param offset where they start
     * @param length how many there are
     * @return the whole messages, possibly none
     */
    List<byte[]> add(byte[] data, int offset, int length) {
        if (failure != null || length == 0) return List.of();
        if (kept.length - keptLength < length) {
            long grown = Math.min(2L * kept.length, (long) maxMessageSize + length);
            kept = Arrays.copyOf(kept, (int) Math.max((long) keptLength + length, grown));
        }
        System.arraycopy(data, offset, kept, keptLength, length);
        keptLength += length;
        List<byte[]> messages = new ArrayList<>(1);
        int start = 0;
        while (start < keptLength) {
            int available = keptLength - start;
            long size;
            try {
                size = framer.frameLength(kept, start, available);
            } catch (RuntimeException e) {
                fail("bytes that do not start a message (" + e.getMessage() + ")");
                return messages;
            }
            if (size == MessageFramer.NEED_MORE) {
                if (available >= maxMessageSize) {
                    fail("a message of more than " + maxMessageSize + " bytes");
                    return messages;
                }
                break;
            }
            if (size < 1) {
                fail("bytes that do not start a message (a length of " + size + ")");
                return messages;
            }
            if (size > maxMessageSize) {
                fail("a message of " + size + " bytes, more than " + maxMessageSize);
                return messages;
            }
            if (size > available) break;
            messages.add(Arrays.copyOfRange(kept, start, start + (int) size));
            start += (int) size;
        }
        int rest = keptLength - start;
        if (rest == 0 && kept.length > KEEP) {
            kept = new byte[0];
        } else if (start > 0 && rest > 0) {
            System.arraycopy(kept, start, kept, 0, rest);
        }
        keptLength = rest;
        return messages;
    }

    /** {@return why the bytes could not be cut into messages, or null while they can} */
    String failure() {
        return failure;
    }

    /** {@return how many bytes are kept, not yet a whole message} */
    int kept() {
        return keptLength;
    }

    /**
     * Takes the bytes kept: those of a message that has not ended, when the stream does.
     *
     * @return the bytes, possibly none
     */
    byte[] rest() {
        byte[] rest = Arrays.copyOf(kept, keptLength);
        kept = new byte[0];
        keptLength = 0;
        return rest;
    }

    private void fail(String why) {
        failure = why;
        kept = new byte[0];
        keptLength = 0;
    }
}
