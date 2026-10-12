package io.github.mahmoudimus.quic.congestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class RttEstimatorTest {

    private static final long MS = 1_000_000L;

    @Test
    void initialEstimates() {
        RttEstimator rtt = new RttEstimator(RttEstimator.DEFAULT_INITIAL_RTT);
        assertFalse(rtt.hasSample());
        assertEquals(333 * MS, rtt.get());
        assertEquals(166_500_000L, rtt.variance());
        // PTO = smoothed + 4 * rttvar = 333 + 666 ms (RFC 9002 section 6.2.2)
        assertEquals(999 * MS, rtt.ptoBase());
    }

    @Test
    void firstSampleResetsEverything() {
        RttEstimator rtt = new RttEstimator(333 * MS);
        rtt.update(10 * MS, 100 * MS); // ACK delay ignored on the first sample
        assertTrue(rtt.hasSample());
        assertEquals(100 * MS, rtt.get());
        assertEquals(50 * MS, rtt.variance());
        assertEquals(100 * MS, rtt.min());
        assertEquals(100 * MS, rtt.latest());
    }

    @Test
    void laterSamplesAreSmoothedAndAckDelayIsSubtracted() {
        RttEstimator rtt = new RttEstimator(333 * MS);
        rtt.update(0, 100 * MS);
        rtt.update(20 * MS, 140 * MS); // adjusted to 120 ms since min + delay <= latest
        assertEquals((7 * 100 * MS + 120 * MS) / 8, rtt.get());
        assertEquals((3 * 50 * MS + 20 * MS) / 4, rtt.variance());
        assertEquals(100 * MS, rtt.min());
        assertEquals(140 * MS, rtt.latest());
    }

    @Test
    void ackDelayIsNotSubtractedBelowMinRtt() {
        RttEstimator rtt = new RttEstimator(333 * MS);
        rtt.update(0, 100 * MS);
        rtt.update(30 * MS, 110 * MS); // 100 + 30 > 110: use the raw sample
        assertEquals((7 * 100 * MS + 110 * MS) / 8, rtt.get());
    }

    @Test
    void minRttIgnoresAckDelayAndConservativeTakesTheMax() {
        RttEstimator rtt = new RttEstimator(333 * MS);
        rtt.update(0, 100 * MS);
        rtt.update(50 * MS, 80 * MS);
        assertEquals(80 * MS, rtt.min());
        rtt.update(0, 400 * MS);
        assertEquals(400 * MS, rtt.conservative());
        assertTrue(rtt.get() < 400 * MS);
    }

    @Test
    void ptoBaseHasTimerGranularityFloor() {
        RttEstimator rtt = new RttEstimator(333 * MS);
        rtt.update(0, 10 * MS);
        for (int i = 0; i < 100; i++) {
            rtt.update(0, 10 * MS);
        }
        assertEquals(0, rtt.variance());
        assertEquals(10 * MS + RttEstimator.TIMER_GRANULARITY, rtt.ptoBase());
        RttEstimator copy = new RttEstimator(rtt);
        assertEquals(rtt.ptoBase(), copy.ptoBase());
    }
}
