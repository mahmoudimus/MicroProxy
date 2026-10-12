package io.github.mahmoudimus.quic.congestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class NewRenoTest {

    private static final long MS = 1_000_000L;
    private static final long MTU = Controller.BASE_DATAGRAM_SIZE;
    private static final RttEstimator RTT = new RttEstimator(100 * MS);

    @Test
    void defaultsFollowRfc9002() {
        NewReno reno = (NewReno) NewRenoConfig.DEFAULT.build(0, (int) MTU);
        assertEquals(12000, reno.window());
        assertEquals(12000, reno.initialWindow());
        assertEquals(Long.MAX_VALUE, reno.slowStartThreshold());
        assertEquals(new ControllerMetrics(12000, Long.MAX_VALUE, -1), reno.metrics());
    }

    @Test
    void slowStartThenHalvingThenLinearGrowth() {
        long t0 = 1_000 * MS;
        NewReno reno = new NewReno(NewRenoConfig.DEFAULT, t0, (int) MTU);
        // Packets sent at or before the recovery start time (initially construction) don't count
        reno.onAck(t0 + 50 * MS, t0, MTU, false, RTT);
        assertEquals(12000, reno.window());

        // Slow start: one MTU per MTU acknowledged, doubling per round trip
        for (int i = 0; i < 10; i++) {
            reno.onAck(t0 + 100 * MS, t0 + MS, MTU, false, RTT);
        }
        assertEquals(24000, reno.window());

        // Loss: halve, and enter recovery
        long lossAt = t0 + 200 * MS;
        reno.onCongestionEvent(lossAt, t0 + 150 * MS, false, false, MTU);
        assertEquals(12000, reno.window());
        assertEquals(12000, reno.slowStartThreshold());

        // Another loss from before recovery started is ignored
        reno.onCongestionEvent(lossAt + MS, t0 + 160 * MS, false, false, MTU);
        assertEquals(12000, reno.window());
        // So are ACKs of packets sent before recovery started
        reno.onAck(lossAt + 2 * MS, t0 + 199 * MS, MTU, false, RTT);
        assertEquals(12000, reno.window());

        // Congestion avoidance: one MTU per window acknowledged
        long sent = lossAt + 10 * MS;
        for (int i = 0; i < 9; i++) {
            reno.onAck(lossAt + 100 * MS, sent, MTU, false, RTT);
        }
        assertEquals(12000, reno.window(), "nine MTUs of a 10-MTU window are not enough");
        reno.onAck(lossAt + 100 * MS, sent, MTU, false, RTT);
        assertEquals(13200, reno.window());
        // The next increase needs a full 13200-byte window, 11 MTUs
        for (int i = 0; i < 10; i++) {
            reno.onAck(lossAt + 200 * MS, sent, MTU, false, RTT);
        }
        assertEquals(13200, reno.window());
        reno.onAck(lossAt + 200 * MS, sent, MTU, false, RTT);
        assertEquals(14400, reno.window());
    }

    @Test
    void repeatedLossesHalveDownToTheMinimumWindow() {
        NewReno reno = new NewReno(NewRenoConfig.DEFAULT, 0, (int) MTU);
        reno.onCongestionEvent(10 * MS, 5 * MS, false, false, MTU); // ssthresh = window = 6000
        assertEquals(6000, reno.window());
        reno.onCongestionEvent(20 * MS, 15 * MS, false, false, MTU); // window = 3000, ssthresh 3000
        assertEquals(3000, reno.window());
        // A window that would halve below two datagrams stops there
        NewReno r2 = new NewReno(new NewRenoConfig(2400, 0.5), 0, (int) MTU);
        r2.onCongestionEvent(10 * MS, 5 * MS, false, false, MTU);
        assertEquals(2400, r2.window(), "never below the minimum window");
    }

    @Test
    void persistentCongestionCollapsesToMinimumWindow() {
        NewReno reno = new NewReno(NewRenoConfig.DEFAULT, 0, (int) MTU);
        for (int i = 0; i < 20; i++) {
            reno.onAck(50 * MS, MS, MTU, false, RTT);
        }
        assertEquals(36000, reno.window());
        reno.onCongestionEvent(100 * MS, 90 * MS, true, false, 10 * MTU);
        assertEquals(2 * MTU, reno.window());
        assertEquals(18000, reno.slowStartThreshold());
        // Back in slow start below ssthresh
        reno.onAck(200 * MS, 150 * MS, MTU, false, RTT);
        assertEquals(3 * MTU, reno.window());
    }

    @Test
    void appLimitedAcksDoNotGrowTheWindow() {
        NewReno reno = new NewReno(NewRenoConfig.DEFAULT, 0, (int) MTU);
        reno.onAck(50 * MS, MS, MTU, true, RTT);
        assertEquals(12000, reno.window());
    }

    @Test
    void customLossReductionFactor() {
        NewReno reno = new NewReno(new NewRenoConfig(12000, 0.8), 0, (int) MTU);
        reno.onCongestionEvent(10 * MS, 5 * MS, false, false, MTU);
        assertEquals(9600, reno.window());
        assertThrows(IllegalArgumentException.class, () -> new NewRenoConfig(12000, 0));
        assertThrows(IllegalArgumentException.class, () -> new NewRenoConfig(0, 0.5));
    }

    @Test
    void defaultFactoryIsCubic() {
        assertInstanceOf(Cubic.class, ControllerFactory.defaultFactory().build(0, 1200));
    }
}
