package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.congestion.RateSample;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class DeliveryRateTest {

    private static final long MS = 1_000_000L;

    private final DeliveryRate rate = new DeliveryRate();
    private long inFlight;

    private SentPacket send(long now) {
        SentPacket p = SentPacket.of(now, 1000, true);
        rate.onPacketSent(now, p, inFlight);
        inFlight += 1000;
        return p;
    }

    private void ack(long now, SentPacket... packets) {
        for (SentPacket p : packets) {
            inFlight -= 1000;
            rate.onPacketAcked(now, p);
        }
    }

    @Test
    void steadyFlowSamplesTheBottleneckRate() {
        // One packet a millisecond (1 MB/s), each acknowledged 40 ms later, two per ACK
        List<SentPacket> sent = new ArrayList<>();
        RateSample last = null;
        for (int t = 0; t < 300; t++) {
            if (t >= 41 && (t - 41) % 2 == 0 && t - 40 < 200) {
                ack(t * MS, sent.get(t - 41), sent.get(t - 40));
                last = rate.sample(40 * MS);
            }
            if (t < 200) {
                sent.add(send(t * MS));
            }
        }
        assertEquals(1_000_000, last.deliveryRate(), "two packets per ACK give the full rate: " + last);
        assertEquals(40 * MS, last.rtt());
        assertFalse(last.appLimited());
        assertEquals(200_000, rate.delivered());
    }

    @Test
    void ackCompressionIsBoundedByTheSendRate() {
        List<SentPacket> sent = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            sent.add(send(i * MS)); // 1 MB/s
        }
        ack(60 * MS, sent.subList(0, 10).toArray(SentPacket[]::new));
        rate.sample(40 * MS);
        // Forty acknowledged in one burst 1 ms later: the ACK interval is short, the send one not
        ack(61 * MS, sent.subList(10, 50).toArray(SentPacket[]::new));
        RateSample s = rate.sample(40 * MS);
        assertTrue(s.deliveryRate() <= 1_000_000 * 102 / 100, "sample " + s);
    }

    @Test
    void intervalsShorterThanTheMinimumRttGiveNoRate() {
        SentPacket a = send(0);
        SentPacket b = send(0);
        ack(10 * MS, a, b);
        RateSample s = rate.sample(40 * MS);
        assertEquals(-1, s.deliveryRate());
        assertFalse(s.hasRate());
        assertEquals(10 * MS, s.rtt());
        assertNull(rate.sample(40 * MS), "one sample per ACK");
    }

    @Test
    void applicationLimitedPeriodMarksPacketsUntilItsBytesAreDelivered() {
        SentPacket a = send(0);
        SentPacket b = send(MS);
        rate.onAppLimited(inFlight); // nothing more to send: 2000 bytes in flight
        assertTrue(rate.isAppLimited());
        SentPacket c = send(50 * MS);
        assertTrue(c.isAppLimited());
        assertFalse(a.isAppLimited());
        ack(40 * MS, a, b);
        assertFalse(rate.sample(0).appLimited());
        assertTrue(rate.isAppLimited(), "the 2000 bytes are delivered, but not past them yet");
        ack(90 * MS, c);
        RateSample s = rate.sample(0);
        assertTrue(s.appLimited());
        assertFalse(rate.isAppLimited());
        assertFalse(send(91 * MS).isAppLimited());
    }

    @Test
    void anIdlePeriodRestartsTheIntervals() {
        SentPacket a = send(0);
        ack(40 * MS, a);
        rate.sample(0);
        // A second later, from idle: the interval starts at the new send, not at the old ACK
        SentPacket b = send(SECOND());
        assertEquals(SECOND(), b.firstSentTime());
        assertEquals(SECOND(), b.deliveredTime());
        ack(SECOND() + 40 * MS, b);
        RateSample s = rate.sample(0);
        assertEquals(40 * MS, s.interval());
        assertEquals(1000, s.delivered());
    }

    private static long SECOND() {
        return 1_000 * MS;
    }
}
