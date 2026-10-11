package io.github.mahmoudimus.quic.congestion;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class BandwidthEstimationTest {

    private static final long MS = 1_000_000L;

    @Test
    void bwFromDelta() {
        assertEquals(120_000, BandwidthEstimation.bwFromDelta(1200, 10 * MS));
        assertEquals(-1, BandwidthEstimation.bwFromDelta(1200, 0));
        // Byte counts whose product with 10^9 overflows still give the rate
        assertEquals(10_000_000_000L * 1_000, BandwidthEstimation.bwFromDelta(10_000_000_000L, MS));
    }

    @Test
    void theMaximumOfTenRoundsExpires() {
        BandwidthEstimation bw = new BandwidthEstimation();
        bw.onSample(0, 5_000_000, false);
        for (long round = 1; round <= 10; round++) {
            bw.onSample(round, 1_000_000, false);
            assertEquals(5_000_000, bw.estimate(), "round " + round);
        }
        bw.onSample(11, 1_000_000, false);
        bw.onSample(12, 1_000_000, false);
        assertEquals(1_000_000, bw.estimate(), "the old maximum left the window");
        bw.onSample(13, 2_000_000, false);
        assertEquals(2_000_000, bw.estimate(), "a new maximum counts at once");
    }

    @Test
    void appLimitedSamplesCountOnlyAboveTheEstimate() {
        BandwidthEstimation bw = new BandwidthEstimation();
        bw.onSample(0, 300_000, true);
        assertEquals(300_000, bw.estimate(), "a lower bound is better than nothing");
        bw.onSample(1, 1_000_000, false);
        for (long round = 2; round < 40; round++) {
            bw.onSample(round, 100_000, true);
        }
        assertEquals(1_000_000, bw.estimate(), "application-limited samples do not age the maximum out");
        bw.onSample(40, -1, false);
        assertEquals(1_000_000, bw.estimate(), "samples without a rate are ignored");
    }

    @Test
    void bytesAckedPerWindow() {
        BandwidthEstimation bw = new BandwidthEstimation();
        bw.onAck(1000);
        bw.onAck(500);
        assertEquals(1500, bw.bytesAckedThisWindow());
        bw.endAcks();
        assertEquals(0, bw.bytesAckedThisWindow());
        bw.onAck(700);
        assertEquals(700, bw.bytesAckedThisWindow());
    }
}
