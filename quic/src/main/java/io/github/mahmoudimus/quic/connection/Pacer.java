/*
 * Ported from quinn-proto src/connection/pacing.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

/**
 * A token-bucket pacer (RFC 9002 section 7.7). Its capacity is the part of the congestion window
 * sent in one burst; the bucket refills at 1.25 congestion windows per RTT, and an empty bucket
 * delays the next packet. Times and durations are nanoseconds.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class Pacer {

    /** The burst interval aimed for on a reasonably fast connection, 2 ms. */
    static final long TARGET_BURST_INTERVAL = 2_000_000L;
    /** The longest burst interval on a slow connection, 10 ms; takes precedence over the minimum burst. */
    static final long MAX_BURST_INTERVAL = 10_000_000L;
    /** The fewest datagrams batched, unless that exceeds {@link #MAX_BURST_INTERVAL}. */
    static final long MIN_BURST_SIZE = 10;
    /** The most datagrams batched. */
    static final long MAX_BURST_SIZE = 256;

    long capacity;
    private long lastWindow;
    private int lastMtu;
    long tokens;
    /** The rate limit in bytes per second, or -1 for none. */
    private final long maxBytesPerSecond;
    private long prev;

    /**
     * A pacer with a full bucket.
     *
     * @param smoothedRtt the smoothed RTT, in nanoseconds
     * @param window the congestion window, in bytes
     * @param mtu the path's maximum UDP payload size
     * @param maxBytesPerSecond a sending rate limit in bytes per second, or -1 for none
     * @param now the current time
     */
    public Pacer(long smoothedRtt, long window, int mtu, long maxBytesPerSecond, long now) {
        long w = rateLimitedWindow(smoothedRtt, window, maxBytesPerSecond);
        this.capacity = optimalCapacity(smoothedRtt, w, mtu);
        this.lastWindow = w;
        this.lastMtu = mtu;
        this.tokens = capacity;
        this.maxBytesPerSecond = maxBytesPerSecond;
        this.prev = now;
    }

    /**
     * The rate limit this pacer was built with.
     *
     * @return bytes per second, or -1 for none
     */
    public long maxBytesPerSecond() {
        return maxBytesPerSecond;
    }

    /**
     * Records that a packet was sent.
     *
     * @param packetLength the packet's size in bytes
     */
    public void onTransmit(int packetLength) {
        tokens = Math.max(0, tokens - packetLength);
    }

    /**
     * When the next packet may be sent.
     *
     * @param smoothedRtt the smoothed RTT, in nanoseconds
     * @param bytesToSend the size of the next packet
     * @param mtu the path's maximum UDP payload size
     * @param window the congestion window, nonzero
     * @param now the current time
     * @return the time to try again, or {@link NanoClock#NONE} if the packet may be sent now
     */
    public long delay(long smoothedRtt, long bytesToSend, int mtu, long window, long now) {
        long w = rateLimitedWindow(smoothedRtt, window, maxBytesPerSecond);
        if (w != lastWindow || mtu != lastMtu) {
            capacity = optimalCapacity(smoothedRtt, w, mtu);
            tokens = Math.min(capacity, tokens); // clamp
            lastWindow = w;
            lastMtu = mtu;
        }
        if (tokens >= bytesToSend) {
            return NanoClock.NONE;
        }
        if (w > 0xffff_ffffL) {
            return NanoClock.NONE; // pacing is disabled for extremely large windows
        }
        long elapsed = Math.max(0, now - prev); // a time before `prev` counts as no time
        if (smoothedRtt == 0) {
            return NanoClock.NONE;
        }
        double elapsedRtts = (double) elapsed / smoothedRtt;
        long newTokens = Math.round(w * 1.25 * elapsedRtts);
        tokens = Math.min(saturatingAdd(tokens, newTokens), capacity);
        // If polled faster than tokens accrue, let elapsed time build up until progress is made
        if (newTokens > 0) {
            prev = now;
        }
        if (tokens >= bytesToSend) {
            return NanoClock.NONE;
        }
        long deficit = Math.max(bytesToSend, capacity) - tokens;
        long unscaledDelay;
        try {
            unscaledDelay = Math.multiplyExact(smoothedRtt, deficit) / w;
        } catch (ArithmeticException e) {
            unscaledDelay = Long.MAX_VALUE / w;
        }
        // Divide before multiplying to avoid overflow; this is when the bucket empties
        return now + (unscaledDelay / 5) * 4;
    }

    /**
     * The burst capacity for a window and RTT: about {@link #TARGET_BURST_INTERVAL} of traffic, at
     * least {@link #MIN_BURST_SIZE} and at most {@link #MAX_BURST_SIZE} datagrams, and never more
     * than {@link #MAX_BURST_INTERVAL} of traffic nor less than one datagram.
     */
    static long optimalCapacity(long smoothedRtt, long window, int mtu) {
        long rtt = Math.max(smoothedRtt, 1);
        long target = mulDiv(window, TARGET_BURST_INTERVAL, rtt);
        long maxCapacity = Math.max(mulDiv(window, MAX_BURST_INTERVAL, rtt), mtu);
        return Math.min(maxCapacity, Math.clamp(target, MIN_BURST_SIZE * mtu, MAX_BURST_SIZE * mtu));
    }

    /** Limits the window to {@code maxBytesPerSecond}, allowing for the 1.25 refill speed-up. */
    static long rateLimitedWindow(long smoothedRtt, long window, long maxBytesPerSecond) {
        if (maxBytesPerSecond < 0) {
            return window;
        }
        double rateWindow = maxBytesPerSecond * (smoothedRtt / 1e9);
        double adjusted = Math.round(rateWindow / 1.25);
        return Math.min(window, Math.max((long) adjusted, 1));
    }

    /** {@code a * b / c} without intermediate overflow, saturating the result. */
    private static long mulDiv(long a, long b, long c) {
        long hi = Math.multiplyHigh(a, b);
        long lo = a * b;
        if (hi == 0 && lo >= 0) {
            return lo / c;
        }
        return java.math.BigInteger.valueOf(a).multiply(java.math.BigInteger.valueOf(b))
                .divide(java.math.BigInteger.valueOf(c)).min(java.math.BigInteger.valueOf(Long.MAX_VALUE))
                .longValue();
    }

    private static long saturatingAdd(long a, long b) {
        long r = a + b;
        return ((a ^ r) & (b ^ r)) < 0 ? Long.MAX_VALUE : r;
    }
}
