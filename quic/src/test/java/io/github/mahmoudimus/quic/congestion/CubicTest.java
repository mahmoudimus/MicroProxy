/*
 * The first four tests are ported from quinn-proto src/congestion/cubic.rs (tests) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.congestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CubicTest {

    private static final long MS = 1_000_000L;
    private static final long MTU = Controller.BASE_DATAGRAM_SIZE;

    private static Cubic cubic(long now) {
        return new Cubic(CubicConfig.DEFAULT, now, (int) MTU);
    }

    @Test
    void fastConvergenceReducesWMaxWithoutDoubleReducingWindow() {
        long now = 1_000 * MS;
        Cubic cubic = cubic(now);
        long window = 8 * MTU;
        cubic.state.window = window;
        cubic.state.ssthresh = window;
        cubic.state.wMax = 12.0 * MTU;

        cubic.onCongestionEvent(now, now + MS, false, false, 0);

        assertEquals(window * (1.0 + Cubic.BETA_CUBIC) / 2.0, cubic.state.wMax);
        assertEquals((long) (window * Cubic.BETA_CUBIC), cubic.state.ssthresh);
        assertEquals(cubic.state.ssthresh, cubic.state.window);
    }

    @Test
    void persistentCongestionDoesNotDoubleReduceSsthresh() {
        long now = 1_000 * MS;
        Cubic cubic = cubic(now);
        long window = 8 * MTU;
        cubic.state.window = window;
        cubic.state.ssthresh = window;
        cubic.state.wMax = window;

        cubic.onCongestionEvent(now, now + MS, true, false, 0);

        // RFC 9438 section 4.8: ssthresh is reduced by beta_cubic exactly once; only cwnd drops
        assertEquals((long) (window * Cubic.BETA_CUBIC), cubic.state.ssthresh);
        assertEquals(2 * MTU, cubic.state.window);
    }

    @Test
    void congestionAvoidancePreservesExcessCwndIncrement() {
        long now = 1_000 * MS;
        RttEstimator rtt = new RttEstimator(100 * MS);
        Cubic cubic = cubic(now);
        // Straight into congestion avoidance
        cubic.state.ssthresh = cubic.state.window;
        cubic.state.recoveryStartTime = now;
        cubic.state.inRecoveryEpoch = true;
        cubic.state.wMax = cubic.state.window;
        // Credit from earlier ACKs: one ACK grows the window by one MTU and keeps the rest
        cubic.state.cwndInc = 2 * MTU + 1;
        long window = cubic.state.window;

        cubic.onAck(now, now + MS, MTU, false, rtt);

        assertEquals(window + MTU, cubic.state.window);
        assertEquals(MTU + 1, cubic.state.cwndInc);
    }

    @Test
    void congestionAvoidanceDoesNotOverflowAfterLongLosslessPeriod() {
        long now = 1_000 * MS;
        RttEstimator rtt = new RttEstimator(100 * MS);
        Cubic cubic = cubic(now);
        cubic.state.ssthresh = cubic.state.window;
        cubic.state.recoveryStartTime = now;
        cubic.state.inRecoveryEpoch = true;
        long window = cubic.state.window;
        // Ten days without a congestion event: W_cubic exceeds 2^63
        long later = now + 10L * 24 * 60 * 60 * 1_000 * MS;
        cubic.onAck(later, later, MTU, false, rtt);
        assertEquals(window + MTU, cubic.state.window);
    }

    @Test
    void slowStartGrowsByBytesAcked() {
        long now = 1_000 * MS;
        Cubic cubic = cubic(now);
        RttEstimator rtt = new RttEstimator(50 * MS);
        long w0 = cubic.window();
        assertEquals(12000, w0);
        for (int i = 0; i < 10; i++) {
            cubic.onAck(now + 50 * MS, now + MS, MTU, false, rtt);
        }
        assertEquals(w0 + 10 * MTU, cubic.window());
        assertEquals(Long.MAX_VALUE, cubic.slowStartThreshold());
    }

    @Test
    void appLimitedAcksDoNotGrowTheWindow() {
        Cubic cubic = cubic(0);
        cubic.onAck(10 * MS, MS, MTU, true, new RttEstimator(10 * MS));
        assertEquals(12000, cubic.window());
    }

    @Test
    void lossReducesByBetaAndIgnoresPacketsSentBeforeRecovery() {
        long t0 = 1_000 * MS;
        Cubic cubic = cubic(t0);
        RttEstimator rtt = new RttEstimator(100 * MS);
        cubic.onAck(t0 + 100 * MS, t0 + 10 * MS, 8000, false, rtt); // slow start to 20000
        assertEquals(20000, cubic.window());

        cubic.onCongestionEvent(t0 + 200 * MS, t0 + 150 * MS, false, false, 1200);
        assertEquals(14000, cubic.window());
        assertEquals(14000, cubic.slowStartThreshold());

        // A second loss of a packet sent before recovery started is the same event
        cubic.onCongestionEvent(t0 + 210 * MS, t0 + 160 * MS, false, false, 1200);
        assertEquals(14000, cubic.window());
        // ACKs of packets sent before recovery do not grow the window
        cubic.onAck(t0 + 220 * MS, t0 + 190 * MS, MTU, false, rtt);
        assertEquals(14000, cubic.window());
    }

    @Test
    void windowRegrowsTowardsWMaxThenProbesBeyondIt() {
        long t0 = 1_000 * MS;
        Cubic cubic = cubic(t0);
        RttEstimator rtt = new RttEstimator(100 * MS);
        rtt.update(0, 100 * MS);
        cubic.onAck(t0, t0 + 1, 88_000, false, rtt); // slow start to 100000
        assertEquals(100_000, cubic.window());

        long lossTime = t0 + 1_000 * MS;
        cubic.onCongestionEvent(lossTime, lossTime - MS, false, false, MTU);
        assertEquals(70_000, cubic.window());
        double k = Math.cbrt(100_000.0 / MTU * (1 - Cubic.BETA_CUBIC) / Cubic.C);
        assertEquals(k, cubic.state.k, 1e-9);

        // ACK a window's worth of packets every RTT; the window climbs back towards W_max
        long now = lossTime;
        long previous = cubic.window();
        boolean passedWMax = false;
        for (int round = 0; round < 200 && !passedWMax; round++) {
            now += 100 * MS;
            long acks = cubic.window() / MTU;
            for (long i = 0; i < acks; i++) {
                cubic.onAck(now, now - 50 * MS, MTU, false, rtt);
            }
            assertTrue(cubic.window() >= previous, "the window never shrinks without loss");
            previous = cubic.window();
            passedWMax = cubic.window() > 100_000;
        }
        assertTrue(passedWMax, "CUBIC probes beyond the previous maximum");
        // Growth is cubic: near K it is slow, so the window spends time close to W_max
        long secondsAfterLoss = (now - lossTime) / 1_000_000_000L;
        assertTrue(secondsAfterLoss >= (long) k - 1, "reached W_max after " + secondsAfterLoss + " s, K = " + k);
    }

    @Test
    void spuriousCongestionEventRestoresState() {
        long t0 = 1_000 * MS;
        Cubic cubic = cubic(t0);
        cubic.onCongestionEvent(t0 + 100 * MS, t0 + 50 * MS, false, false, MTU);
        assertEquals(8400, cubic.window());
        cubic.onSpuriousCongestionEvent();
        assertEquals(12000, cubic.window());
        assertEquals(Long.MAX_VALUE, cubic.slowStartThreshold());
    }

    @Test
    void ecnEventsAreNotUndone() {
        long t0 = 1_000 * MS;
        Cubic cubic = cubic(t0);
        cubic.onCongestionEvent(t0 + 100 * MS, t0 + 50 * MS, false, true, 0);
        cubic.onSpuriousCongestionEvent();
        assertEquals(8400, cubic.window());
    }

    @Test
    void mtuIncreaseRaisesTheMinimumWindow() {
        Cubic cubic = cubic(0);
        cubic.onCongestionEvent(10 * MS, 5 * MS, true, false, MTU);
        assertEquals(2 * MTU, cubic.window());
        cubic.onMtuUpdate(1500);
        assertEquals(3000, cubic.window());
    }

    @Test
    void copyIsIndependent() {
        Cubic cubic = cubic(0);
        Controller copy = cubic.copy();
        cubic.onCongestionEvent(10 * MS, 5 * MS, false, false, MTU);
        assertEquals(12000, copy.window());
        assertEquals(12000, copy.initialWindow());
    }
}
