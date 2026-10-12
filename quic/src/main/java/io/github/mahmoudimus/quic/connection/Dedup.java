/*
 * Ported from quinn-proto src/connection/spaces.rs (Dedup) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.math.BigInteger;

/**
 * A sliding-window detector of duplicate packet numbers, in the style of RFC 4303: a 128-bit
 * field, one bit per packet number below the highest authenticated one. Packet numbers left of the
 * window count as received. Since QUIC never reuses packet numbers, the window only needs to cover
 * reordering.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class Dedup {

    /** The packet numbers tracked: the highest plus the 128-bit window. */
    static final long WINDOW_SIZE = 1 + 128;

    /** The high and low words of the window; bit {@code i} is packet {@code highest - 1 - i}. */
    private long hi;
    private long lo;
    /** One past the highest packet number authenticated. */
    private long next;

    /** An empty window at packet number zero. */
    public Dedup() {}

    private long highest() {
        return next - 1;
    }

    /**
     * Records an authenticated packet number.
     *
     * @param packet the packet number
     * @return true if the packet may be a duplicate
     */
    public boolean insert(long packet) {
        if (packet >= next) {
            long diff = packet - next;
            // window = ((window << 1) | 1) << diff, or zero if that shifts everything out
            shiftLeft(1);
            lo |= 1;
            if (diff >= 128) {
                hi = 0;
                lo = 0;
            } else {
                shiftLeft((int) diff);
            }
            next = packet + 1;
            return false;
        } else if (highest() - packet < WINDOW_SIZE) {
            long d = highest() - packet;
            if (d == 0) {
                return true; // the highest
            }
            int bit = (int) (d - 1);
            boolean duplicate = testBit(bit);
            setBit(bit);
            return duplicate;
        }
        return true; // left of the window
    }

    /**
     * The smallest packet number missing strictly between two received ones.
     *
     * @param lowerBound a received packet number
     * @param upperBound a received packet number, at least {@code lowerBound} and at most the
     *     highest
     * @return the smallest missing packet number, or -1 if none is missing
     */
    long smallestMissingInInterval(long lowerBound, long upperBound) {
        // The boundaries are received, so only the packets between them matter
        long lower = lowerBound + 1;
        long upper = Math.max(upperBound - 1, 0);
        // Offsets count from the right; the highest packet is not in the field
        long startOffset = Math.max(highest() - upper, 1) - 1;
        if (startOffset >= 128) {
            return -1; // outside the window: counted as received
        }
        long endOffsetExclusive = Math.max(highest() - lower, 0);
        long rangeLength = Math.min(Math.max(endOffsetExclusive - startOffset, 0), 128);
        if (rangeLength == 0) {
            return -1;
        }
        // mask = ((1 << rangeLength) - 1) << startOffset
        long maskHi;
        long maskLo;
        if (rangeLength == 128) {
            maskHi = -1;
            maskLo = -1;
        } else if (rangeLength >= 64) {
            maskHi = rangeLength == 64 ? 0 : (1L << (rangeLength - 64)) - 1;
            maskLo = -1;
        } else {
            maskHi = 0;
            maskLo = (1L << rangeLength) - 1;
        }
        int s = (int) startOffset;
        if (s >= 64) {
            maskHi = maskLo << (s - 64);
            maskLo = 0;
        } else if (s > 0) {
            maskHi = (maskHi << s) | (maskLo >>> (64 - s));
            maskLo = maskLo << s;
        }
        long gapsHi = ~hi & maskHi;
        long gapsLo = ~lo & maskLo;
        int leadingZeros = gapsHi != 0 ? Long.numberOfLeadingZeros(gapsHi) : 64 + Long.numberOfLeadingZeros(gapsLo);
        long smallestMissingOffset = 128 - leadingZeros;
        long smallestMissing = highest() - smallestMissingOffset;
        return smallestMissing <= upper ? smallestMissing : -1;
    }

    /** Whether any packet between two received ones is missing. */
    boolean missingInInterval(long lowerBound, long upperBound) {
        return smallestMissingInInterval(lowerBound, upperBound) >= 0;
    }

    /** The window as a number, for tests. */
    BigInteger window() {
        return new BigInteger(Long.toUnsignedString(hi)).shiftLeft(64).or(new BigInteger(Long.toUnsignedString(lo)));
    }

    /** The next packet number expected, for tests. */
    long next() {
        return next;
    }

    private void shiftLeft(int n) {
        if (n == 0) {
            return;
        }
        if (n >= 64) {
            hi = lo << (n - 64);
            lo = 0;
        } else {
            hi = (hi << n) | (lo >>> (64 - n));
            lo = lo << n;
        }
    }

    private boolean testBit(int bit) {
        return bit >= 64 ? (hi & (1L << (bit - 64))) != 0 : (lo & (1L << bit)) != 0;
    }

    private void setBit(int bit) {
        if (bit >= 64) {
            hi |= 1L << (bit - 64);
        } else {
            lo |= 1L << bit;
        }
    }
}
