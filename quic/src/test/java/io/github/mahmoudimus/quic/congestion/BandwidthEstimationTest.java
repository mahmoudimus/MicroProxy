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
    void sampleIsTheLowerOfSendAndAckRates() {
        BandwidthEstimation bw = new BandwidthEstimation();
        long t = 1_000 * MS;
        bw.onSent(t, 1200);
        bw.onSent(t + MS, 1200); // sending at 1.2 MB/s
        bw.onAck(t + 20 * MS, t, 1200, 0, false);
        assertEquals(0, bw.estimate(), "no ack rate from a single acknowledgement");
        bw.onSent(t + 2 * MS, 1200);
        bw.onAck(t + 30 * MS, t + MS, 1200, 0, false); // acknowledged at 120 kB/s
        assertEquals(120_000, bw.estimate());
    }

    @Test
    void appLimitedSamplesAreLeftOut() {
        BandwidthEstimation bw = new BandwidthEstimation();
        long t = 1_000 * MS;
        for (int i = 0; i < 10; i++) {
            bw.onSent(t + i * MS, 1200);
        }
        for (int i = 0; i < 10; i++) {
            bw.onAck(t + 50 * MS + i * MS, t + i * MS, 1200, 0, true);
        }
        assertEquals(0, bw.estimate());
        bw.onAck(t + 60 * MS, t, 1200, 0, false);
        assertEquals(1_200_000, bw.estimate());
    }

    @Test
    void bytesAckedPerWindow() {
        BandwidthEstimation bw = new BandwidthEstimation();
        bw.onAck(1, 0, 1000, 0, false);
        bw.onAck(2, 0, 500, 0, false);
        assertEquals(1500, bw.bytesAckedThisWindow());
        bw.endAcks(0, false);
        assertEquals(0, bw.bytesAckedThisWindow());
        bw.onAck(3, 0, 700, 0, false);
        assertEquals(700, bw.bytesAckedThisWindow());
    }
}
