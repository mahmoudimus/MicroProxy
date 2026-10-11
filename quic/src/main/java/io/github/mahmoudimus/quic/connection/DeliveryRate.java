package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.congestion.RateSample;

/**
 * Delivery rate estimation as draft-cheng-iccrg-delivery-rate-estimation describes it, the
 * sampler BBR is built on. Each packet sent in flight is stamped with the connection's delivered
 * bytes, the time they were last updated, the send time of the packet that started the current
 * flight and whether sending was application limited; acknowledging packets yields one sample
 * per ACK, from the newest packet acknowledged. quinn has no such sampler: its BBR estimates the
 * rate from per-packet send and ACK intervals.
 *
 * <p>Times are nanoseconds. <b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class DeliveryRate {

    /** An unset time. */
    private static final long NONE = Long.MIN_VALUE;

    /** Bytes delivered on the connection: {@code C.delivered}. */
    private long delivered;
    /** When {@link #delivered} last changed: {@code C.delivered_time}. */
    private long deliveredTime = NONE;
    /** The send time of the newest packet acknowledged, or of the first after an idle period: {@code C.first_sent_time}. */
    private long firstSentTime = NONE;
    /**
     * The delivered count past which the application-limited period ends, or 0 when sending is not
     * application limited: {@code C.app_limited}.
     */
    private long appLimitedUntil;

    // The sample being built from the current ACK
    private boolean hasSample;
    private long priorDelivered;
    private long priorTime;
    private long sendElapsed;
    private long ackElapsed;
    private long newestSentTime;
    private long rtt;
    private boolean sampleAppLimited;

    /** A sampler for a connection that has delivered nothing yet. */
    public DeliveryRate() {}

    /**
     * Stamps a packet about to go in flight.
     *
     * @param now the current time
     * @param packet the packet
     * @param bytesInFlight the bytes in flight before it
     */
    public void onPacketSent(long now, SentPacket packet, long bytesInFlight) {
        if (bytesInFlight == 0 || firstSentTime == NONE) {
            // Nothing in flight: the flight, and its intervals, start now
            firstSentTime = now;
            deliveredTime = now;
        }
        packet.setDeliveryState(delivered, deliveredTime, firstSentTime, appLimitedUntil != 0);
    }

    /**
     * Records that sending is application limited: samples from packets sent until the bytes now
     * in flight are delivered are marked application limited.
     *
     * @param bytesInFlight the bytes in flight
     */
    public void onAppLimited(long bytesInFlight) {
        appLimitedUntil = Math.max(delivered + bytesInFlight, 1);
    }

    /**
     * Records an acknowledged packet that was stamped by {@link #onPacketSent}.
     *
     * @param now the current time
     * @param packet the packet
     */
    public void onPacketAcked(long now, SentPacket packet) {
        if (packet.deliveredTime() == NONE) {
            return; // never stamped: not in flight
        }
        delivered += packet.size();
        deliveredTime = now;
        // Keep the sample of the newest packet: the most recently sent, the last delivered
        if (!hasSample || packet.delivered() > priorDelivered
                || (packet.delivered() == priorDelivered && packet.timeSent() >= newestSentTime)) {
            hasSample = true;
            priorDelivered = packet.delivered();
            priorTime = packet.deliveredTime();
            sampleAppLimited = packet.isAppLimited();
            sendElapsed = packet.timeSent() - packet.firstSentTime();
            ackElapsed = now - packet.deliveredTime();
            newestSentTime = packet.timeSent();
            rtt = Math.max(0, now - packet.timeSent());
            firstSentTime = packet.timeSent();
        }
        if (appLimitedUntil != 0 && delivered > appLimitedUntil) {
            appLimitedUntil = 0; // the application-limited bubble is out of the pipe
        }
    }

    /**
     * Ends an ACK: the sample of the packets it acknowledged.
     *
     * @param minRtt the path's minimum RTT, or 0 if unknown; a sample over a shorter interval has
     *     no rate, as the draft says, since an ACK compressed in time would overstate it
     * @return the sample, or null if the ACK acknowledged nothing in flight
     */
    public RateSample sample(long minRtt) {
        if (!hasSample) {
            return null;
        }
        hasSample = false;
        long sampleDelivered = delivered - priorDelivered;
        // The longer interval: the send interval guards against ACK compression, the ACK interval
        // against send bursts
        long interval = Math.max(sendElapsed, ackElapsed);
        long rate = interval <= 0 || interval < minRtt ? -1 : bytesPerSecond(sampleDelivered, interval);
        return new RateSample(rate, sampleDelivered, interval, rtt, sampleAppLimited, priorDelivered);
    }

    /**
     * The bytes delivered on the connection so far.
     *
     * @return bytes
     */
    public long delivered() {
        return delivered;
    }

    /**
     * Whether packets sent now are marked application limited.
     *
     * @return true until the application-limited bytes are delivered
     */
    public boolean isAppLimited() {
        return appLimitedUntil != 0;
    }

    private static long bytesPerSecond(long bytes, long nanos) {
        long hi = Math.multiplyHigh(bytes, 1_000_000_000L);
        long lo = bytes * 1_000_000_000L;
        if (hi == 0 && lo >= 0) {
            return lo / nanos;
        }
        return (long) (bytes * 1e9 / nanos);
    }
}
