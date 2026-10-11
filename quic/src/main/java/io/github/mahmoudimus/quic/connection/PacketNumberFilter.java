/*
 * Ported from quinn-proto src/connection/spaces.rs (PacketNumberFilter) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.QuicException;
import java.util.random.RandomGenerator;

/**
 * Mitigates optimistic ACK attacks (RFC 9000 section 21.4) by occasionally skipping a packet
 * number in the application data space: an ACK of a skipped number proves the peer acknowledges
 * packets it never received. Skips get exponentially rarer, since a peer that behaved for long is
 * less likely to start misbehaving.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class PacketNumberFilter {

    /** The next packet number to skip. */
    private long nextSkippedPacketNumber;
    /** The most recently skipped packet number, or -1. */
    private long prevSkippedPacketNumber = -1;
    /** The next skip is drawn from {@code [2^exponent, 2^(exponent + 1))}. */
    private int exponent;

    /**
     * A filter whose first skip is somewhere in packet numbers 0 to 63.
     *
     * @param random the source of randomness
     */
    public PacketNumberFilter(RandomGenerator random) {
        exponent = 6;
        nextSkippedPacketNumber = random.nextLong(0, pow2(exponent));
    }

    private PacketNumberFilter(long next, int exponent) {
        this.nextSkippedPacketNumber = next;
        this.exponent = exponent;
    }

    /**
     * A filter that never skips, for tests.
     *
     * @return the filter
     */
    public static PacketNumberFilter disabled() {
        return new PacketNumberFilter(Long.MAX_VALUE, Integer.MAX_VALUE);
    }

    /**
     * The packet number {@link #allocate} would return next.
     *
     * @param space the application data space
     * @return the packet number
     */
    public long peek(PacketSpace space) {
        long n = space.nextPacketNumber();
        return n != nextSkippedPacketNumber ? n : n + 1;
    }

    /**
     * Allocates the next packet number, skipping it if it is the chosen one.
     *
     * @param random the source of randomness
     * @param space the application data space
     * @return the packet number to send
     */
    public long allocate(RandomGenerator random, PacketSpace space) {
        long n = space.getTxNumber();
        if (n != nextSkippedPacketNumber) {
            return n;
        }
        // Skip this one and choose the next to skip
        prevSkippedPacketNumber = nextSkippedPacketNumber;
        int nextExponent = exponent == Integer.MAX_VALUE ? exponent : exponent + 1;
        long lo = pow2(exponent);
        long hi = pow2(nextExponent);
        nextSkippedPacketNumber = lo < hi ? random.nextLong(lo, hi) : Long.MAX_VALUE;
        exponent = nextExponent;
        return space.getTxNumber();
    }

    /**
     * Rejects an ACK of the skipped packet number.
     *
     * @param space the space the ACK arrived in
     * @param smallest the smallest packet number of an acknowledged range
     * @param largest the largest packet number of the range
     * @throws QuicException {@code PROTOCOL_VIOLATION} if the range covers a skipped packet number
     */
    public void checkAck(SpaceId space, long smallest, long largest) throws QuicException {
        if (space == SpaceId.DATA && prevSkippedPacketNumber >= 0 && prevSkippedPacketNumber >= smallest
                && prevSkippedPacketNumber <= largest) {
            throw new QuicException(QuicException.PROTOCOL_VIOLATION, "unsent packet acked");
        }
    }

    /** {@code 2^e}, saturating at {@link Long#MAX_VALUE}. */
    private static long pow2(int e) {
        return e >= 63 ? Long.MAX_VALUE : 1L << e;
    }
}
