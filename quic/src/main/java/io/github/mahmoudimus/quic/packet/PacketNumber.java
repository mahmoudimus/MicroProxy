/*
 * Ported from quinn-proto src/packet.rs (PacketNumber) (Apache-2.0), following the pseudocode of
 * RFC 9000 appendices A.2 and A.3.
 */
package io.github.mahmoudimus.quic.packet;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * Packet number truncation and recovery (RFC 9000 section 17.1 and appendix A). A packet carries
 * the 1 to 4 least significant bytes of its 62-bit packet number; the receiver recovers the rest
 * from the largest packet number it has processed in the same space.
 *
 * <p>All methods are static and thread-safe.
 */
public final class PacketNumber {

    /** The largest packet number, 2<sup>62</sup>-1. */
    public static final long MAX = (1L << 62) - 1;

    private PacketNumber() {}

    /**
     * The number of bytes needed to send a packet number so that the peer recovers it: enough to
     * represent twice the distance from the largest acknowledged packet (RFC 9000 appendix A.2).
     *
     * @param fullPacketNumber the packet number to send
     * @param largestAcked the largest packet number the peer has acknowledged in this space, or
     *     -1 if none
     * @return 1 to 4
     * @throws IllegalArgumentException if the distance needs more than four bytes
     */
    public static int encodedLength(long fullPacketNumber, long largestAcked) {
        long unacked = largestAcked < 0 ? fullPacketNumber + 1 : fullPacketNumber - largestAcked;
        if (unacked <= 0) {
            throw new IllegalArgumentException("packet number " + fullPacketNumber + " not above " + largestAcked);
        }
        long range = unacked * 2;
        if (range < (1L << 8)) {
            return 1;
        } else if (range < (1L << 16)) {
            return 2;
        } else if (range < (1L << 24)) {
            return 3;
        } else if (range < (1L << 32)) {
            return 4;
        }
        throw new IllegalArgumentException("packet number too far ahead of the largest acknowledged");
    }

    /**
     * The low bytes of a packet number.
     *
     * @param fullPacketNumber the full packet number
     * @param length the encoded length, 1 to 4
     * @return the truncated value
     */
    public static long truncate(long fullPacketNumber, int length) {
        checkLength(length);
        return fullPacketNumber & ((1L << (8 * length)) - 1);
    }

    /**
     * Recovers a full packet number from its truncated value (RFC 9000 appendix A.3): the value
     * closest to one more than the largest packet number processed so far.
     *
     * @param largestPacketNumber the largest packet number successfully processed in this
     *     space, or -1 if none
     * @param truncated the value of the Packet Number field
     * @param length the field's length in bytes, 1 to 4
     * @return the full packet number
     */
    public static long decode(long largestPacketNumber, long truncated, int length) {
        checkLength(length);
        long expected = largestPacketNumber + 1;
        long win = 1L << (8 * length);
        long hwin = win / 2;
        long mask = win - 1;
        long candidate = (expected & ~mask) | (truncated & mask);
        if (candidate <= expected - hwin && candidate < (1L << 62) - win) {
            return candidate + win;
        }
        if (candidate > expected + hwin && candidate >= win) {
            return candidate - win;
        }
        return candidate;
    }

    /**
     * Writes a truncated packet number in big-endian order.
     *
     * @param out the buffer, written at its position
     * @param fullPacketNumber the full packet number; only its low {@code length} bytes are written
     * @param length the encoded length, 1 to 4
     */
    public static void write(ByteBuffer out, long fullPacketNumber, int length) {
        checkLength(length);
        for (int i = length - 1; i >= 0; i--) {
            out.put((byte) (fullPacketNumber >>> (8 * i)));
        }
    }

    /**
     * Reads a truncated packet number.
     *
     * @param in the buffer; its position moves past the field
     * @param length the encoded length, 1 to 4
     * @return the truncated value
     * @throws BufferUnderflowException if fewer than {@code length} bytes remain
     */
    public static long read(ByteBuffer in, int length) {
        checkLength(length);
        if (in.remaining() < length) {
            throw new BufferUnderflowException();
        }
        long v = 0;
        for (int i = 0; i < length; i++) {
            v = (v << 8) | (in.get() & 0xff);
        }
        return v;
    }

    private static void checkLength(int length) {
        if (length < 1 || length > 4) {
            throw new IllegalArgumentException("packet number length " + length);
        }
    }
}
