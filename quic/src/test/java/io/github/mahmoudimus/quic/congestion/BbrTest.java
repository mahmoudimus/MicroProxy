/*
 * The first test is ported from quinn-proto src/congestion/bbr/mod.rs (tests) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.congestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.connection.NanoClock;
import io.github.mahmoudimus.quic.connection.Pacer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.SplittableRandom;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

class BbrTest {

    private static final long MS = 1_000_000L;
    private static final long SECOND = 1_000 * MS;
    private static final int MTU = 1200;

    private static Bbr bbr() {
        return new Bbr(BbrConfig.DEFAULT, MTU, new SplittableRandom(1));
    }

    @Test
    void metricsReportBandwidthEstimate() {
        Bbr bbr = bbr();
        assertEquals(-1, bbr.metrics().bandwidthEstimate());

        long start = 1_000 * MS;
        long interval = 10 * MS;
        bbr.maxBandwidth.onSent(start, 1200);
        bbr.maxBandwidth.onSent(start + interval, 1200);
        bbr.maxBandwidth.onAck(start + interval * 2, start, 1200, 0, false);
        bbr.maxBandwidth.onSent(start + interval * 2, 1200);
        bbr.maxBandwidth.onAck(start + interval * 3, start + interval, 1200, 0, false);

        assertEquals(960_000, bbr.metrics().bandwidthEstimate());
    }

    @Test
    void defaults() {
        Bbr bbr = bbr();
        assertEquals(240_000, bbr.initialWindow());
        assertEquals(240_000, bbr.window());
        assertEquals(Bbr.Mode.STARTUP, bbr.mode());
        assertEquals(new ControllerMetrics(240_000, -1, 0, -1), bbr.metrics());
        assertTrue(BbrConfig.DEFAULT.build(0, MTU) instanceof Bbr);
    }

    @Test
    void mtuUpdateRaisesTheMinimumWindow() {
        Bbr bbr = new Bbr(new BbrConfig(2 * MTU), MTU, new SplittableRandom(1));
        assertEquals(2 * MTU, bbr.window());
        bbr.onMtuUpdate(1452);
        assertEquals(4 * 1452, bbr.window(), "the window is at least four datagrams");
    }

    @Test
    void copyIsIndependent() {
        Sim sim = new Sim(bbr(), 12_500_000, 40 * MS);
        sim.run(2 * SECOND);
        Bbr copy = (Bbr) sim.cc.copy();
        assertEquals(sim.cc.mode(), copy.mode());
        assertEquals(sim.cc.window(), copy.window());
        assertEquals(sim.cc.bandwidthEstimate(), copy.bandwidthEstimate());
        sim.run(4 * SECOND);
        assertTrue(copy.roundCount() < sim.cc.roundCount());
    }

    /**
     * STARTUP, DRAIN and PROBE_BW on a 100 Mbit/s path with a 100 ms RTT, then PROBE_RTT once ten
     * seconds pass without one, and back to PROBE_BW. As in quinn, the first acknowledgement that
     * is not application limited starts a PROBE_RTT, since none has started yet; on this path it
     * ends before STARTUP has found the bandwidth, so STARTUP goes on afterwards.
     */
    @Test
    void stateMachineOnALongBottleneckPath() {
        long rate = 12_500_000;
        long rtt = 100 * MS;
        Sim sim = new Sim(bbr(), rate, rtt);
        sim.run(25 * SECOND);
        System.out.println("BBR modes, 100 Mbit/s, 100 ms: " + sim.transitions + ", estimate "
                + sim.cc.bandwidthEstimate() + " B/s, utilization " + sim.deliveredSince(2 * SECOND) / (rate * 24.0));
        assertEquals(List.of(Bbr.Mode.STARTUP, Bbr.Mode.PROBE_RTT, Bbr.Mode.STARTUP, Bbr.Mode.DRAIN,
                Bbr.Mode.PROBE_BW, Bbr.Mode.PROBE_RTT, Bbr.Mode.PROBE_BW, Bbr.Mode.PROBE_RTT, Bbr.Mode.PROBE_BW),
                sim.modes(), "transitions " + sim.transitions);
        // DRAIN lasts until the queue STARTUP built is gone
        assertTrue(sim.transitions.get(4).time() - sim.transitions.get(3).time() >= rtt / 2,
                "transitions " + sim.transitions);
        // PROBE_RTT comes back ten seconds after the last one started, and lasts at least 200 ms
        long firstProbe = sim.transitions.get(1).time();
        long secondProbe = sim.transitions.get(5).time();
        long thirdProbe = sim.transitions.get(7).time();
        assertTrue(secondProbe - firstProbe > 10 * SECOND && secondProbe - firstProbe < 10 * SECOND + 2 * rtt,
                "transitions " + sim.transitions);
        assertTrue(thirdProbe - secondProbe > 10 * SECOND && thirdProbe - secondProbe < 10 * SECOND + 2 * rtt,
                "transitions " + sim.transitions);
        assertTrue(sim.transitions.get(6).time() - secondProbe >= 200 * MS);
        // The model matches the path
        assertTrue(sim.cc.isAtFullBandwidth());
        assertEquals(rtt, sim.cc.minRtt());
        long bw = sim.cc.bandwidthEstimate();
        assertTrue(Math.abs(bw - rate) <= rate / 50, "estimate " + bw + " for " + rate);
        assertEquals(bw * 8, sim.cc.metrics().bandwidthEstimate());
        assertTrue(sim.cc.pacingRate() >= bw * 3 / 4 && sim.cc.pacingRate() <= bw * 5 / 4);
        // The link was kept busy after the first two seconds
        double utilization = sim.deliveredSince(2 * SECOND) / (rate * 24.0);
        assertTrue(utilization > 0.9, "utilization " + utilization);
    }

    /**
     * On a 40 ms path the PROBE_RTT that the first acknowledgement starts lasts long enough for
     * the bandwidth estimate to stop growing, so BBR leaves it for PROBE_BW directly, as quinn's
     * does.
     */
    @Test
    void stateMachineOnAShortBottleneckPath() {
        long rate = 12_500_000;
        Sim sim = new Sim(bbr(), rate, 40 * MS);
        sim.run(25 * SECOND);
        System.out.println("BBR modes, 100 Mbit/s, 40 ms: " + sim.transitions);
        assertEquals(List.of(Bbr.Mode.STARTUP, Bbr.Mode.PROBE_RTT, Bbr.Mode.PROBE_BW, Bbr.Mode.PROBE_RTT,
                Bbr.Mode.PROBE_BW, Bbr.Mode.PROBE_RTT, Bbr.Mode.PROBE_BW), sim.modes(), "transitions " + sim.transitions);
        long bw = sim.cc.bandwidthEstimate();
        assertTrue(Math.abs(bw - rate) <= rate / 50, "estimate " + bw + " for " + rate);
        double utilization = sim.deliveredSince(2 * SECOND) / (rate * 24.0);
        assertTrue(utilization > 0.9, "utilization " + utilization);
    }

    @Test
    void drainEmptiesTheStartupQueue() {
        long rate = 12_500_000;
        long rtt = 100 * MS;
        Sim sim = new Sim(bbr(), rate, rtt);
        long bdp = rate * rtt / SECOND;
        sim.runUntil(() -> sim.cc.mode() == Bbr.Mode.DRAIN, 10 * SECOND);
        assertTrue(sim.inFlight > bdp, "STARTUP overfilled the path: " + sim.inFlight + ", BDP " + bdp);
        assertTrue(sim.cc.pacingGain() < 1.0f);
        // PROBE_BW starts once the bytes in flight are down to the BDP
        sim.runUntil(() -> sim.cc.mode() == Bbr.Mode.PROBE_BW, 10 * SECOND);
        assertTrue(sim.inFlight <= bdp + bdp / 20, "in flight " + sim.inFlight + ", BDP " + bdp);
        // In PROBE_BW the window is two BDPs plus the ack aggregation, and the queue stays below a
        // BDP
        sim.run(sim.now + SECOND);
        sim.resetQueueStats();
        sim.run(sim.now + 5 * SECOND);
        assertTrue(sim.cc.window() <= 2 * bdp + bdp / 4, "window " + sim.cc.window());
        assertTrue(sim.maxQueueDelay() <= rtt + rtt / 4, "queue delay " + sim.maxQueueDelay());
    }

    @Test
    void probeBwCyclesItsPacingGain() {
        Sim sim = new Sim(bbr(), 12_500_000, 40 * MS);
        sim.runUntil(() -> sim.cc.mode() == Bbr.Mode.PROBE_BW, 10 * SECOND);
        List<Float> gains = new ArrayList<>();
        sim.observer = s -> {
            float g = s.cc.pacingGain();
            if (gains.isEmpty() || gains.get(gains.size() - 1) != g) {
                gains.add(g);
            }
        };
        sim.run(sim.now + 3 * SECOND);
        assertTrue(gains.contains(1.25f) && gains.contains(0.75f) && gains.contains(1.0f), "gains " + gains);
        // A probe at 1.25 is always followed by a drain at 0.75
        for (int i = 0; i + 1 < gains.size(); i++) {
            if (gains.get(i) == 1.25f) {
                assertEquals(0.75f, gains.get(i + 1), "gains " + gains);
            }
        }
    }

    /**
     * As in quinn, a sample reaches the max filter only when it exceeds the current estimate, so
     * the estimate does not fall when the path slows down.
     */
    @Test
    void bandwidthEstimateDoesNotFallAsInQuinn() {
        Sim sim = new Sim(bbr(), 12_500_000, 40 * MS);
        sim.run(5 * SECOND);
        assertTrue(Math.abs(sim.cc.bandwidthEstimate() - 12_500_000) < 250_000);
        sim.rate = 5_000_000;
        sim.run(sim.now + 3 * SECOND);
        assertTrue(sim.cc.bandwidthEstimate() >= 12_250_000, "estimate " + sim.cc.bandwidthEstimate());
        // A faster path raises it
        sim.rate = 25_000_000;
        sim.run(sim.now + 3 * SECOND);
        long bw = sim.cc.bandwidthEstimate();
        assertTrue(Math.abs(bw - 25_000_000) < 500_000, "estimate " + bw);
    }

    /**
     * An application that sends a little at a time, so that acknowledgements find it with nothing
     * to send: its samples stay out of the estimate, STARTUP does not end for lack of growth, and
     * no PROBE_RTT starts while it is application limited. A bulk transfer then finds the
     * bandwidth.
     */
    @Test
    void appLimitedSamplesDoNotEndStartupOrStartProbeRtt() {
        Sim sim = new Sim(bbr(), 12_500_000, 40 * MS);
        sim.chunk = 20 * MTU; // 24 kB every 100 ms: about 2% of the path
        sim.period = 100 * MS;
        sim.run(15 * SECOND);
        assertEquals(List.of(Bbr.Mode.STARTUP), sim.modes(), "transitions " + sim.transitions);
        assertEquals(0, sim.cc.bandwidthEstimate());
        assertEquals(sim.delivered / MTU, sim.appLimitedAcks, "every acknowledgement was application limited");
        // STARTUP never lowers the window; as in quinn, it grows by the bytes acknowledged
        assertEquals(BbrConfig.DEFAULT.initialWindow() + sim.delivered, sim.cc.window());

        sim.chunk = -1;
        sim.run(sim.now + 5 * SECOND);
        long bw = sim.cc.bandwidthEstimate();
        assertTrue(Math.abs(bw - 12_500_000) < 250_000, "estimate " + bw);
        assertTrue(sim.modes().contains(Bbr.Mode.PROBE_BW), "transitions " + sim.transitions);
    }

    @Test
    void appLimitedInProbeBwStartsNoProbeRtt() {
        Sim sim = new Sim(bbr(), 12_500_000, 40 * MS);
        sim.run(5 * SECOND);
        assertEquals(Bbr.Mode.PROBE_BW, sim.cc.mode());
        long bw = sim.cc.bandwidthEstimate();
        long minRtt = sim.cc.minRtt();
        int before = sim.transitions.size();
        sim.chunk = 20 * MTU;
        sim.period = 100 * MS;
        sim.run(sim.now + 15 * SECOND);
        assertEquals(before, sim.transitions.size(), "no PROBE_RTT while application limited: " + sim.transitions);
        assertEquals(bw, sim.cc.bandwidthEstimate());
        assertEquals(minRtt, sim.cc.minRtt());
        // Back to bulk: the minimum RTT has expired, so the first acknowledgement probes it
        sim.chunk = -1;
        sim.run(sim.now + 2 * SECOND);
        assertEquals(Bbr.Mode.PROBE_RTT, sim.transitions.get(before).mode(), "transitions " + sim.transitions);
        assertEquals(Bbr.Mode.PROBE_BW, sim.cc.mode());
    }

    @Test
    void lossEntersAndLeavesRecovery() {
        Sim sim = new Sim(bbr(), 12_500_000, 40 * MS);
        sim.runUntil(() -> sim.cc.mode() == Bbr.Mode.PROBE_BW, 10 * SECOND);
        sim.run(sim.now + SECOND);
        long before = sim.cc.window();
        sim.cc.onCongestionEvent(sim.now, sim.now - 10 * MS, false, false, 3 * MTU);
        sim.stepOneAck();
        assertEquals(Bbr.RecoveryState.CONSERVATION, sim.cc.recoveryState());
        assertTrue(sim.cc.window() <= before);
        sim.run(sim.now + 500 * MS);
        assertEquals(Bbr.RecoveryState.NOT_IN_RECOVERY, sim.cc.recoveryState());
    }

    @Test
    void lossInStartupEndsItAtTheNextRoundWithoutGrowth() {
        Sim sim = new Sim(bbr(), 12_500_000, 100 * MS);
        // Back in STARTUP after the first PROBE_RTT
        sim.runUntil(() -> sim.transitions.size() >= 3, 5 * SECOND);
        assertEquals(Bbr.Mode.STARTUP, sim.cc.mode());
        long rounds = sim.cc.roundCount();
        sim.cc.onCongestionEvent(sim.now, sim.now, false, false, MTU);
        sim.runUntil(() -> sim.cc.isAtFullBandwidth(), 5 * SECOND);
        assertTrue(sim.cc.roundCount() - rounds <= 2, "rounds " + (sim.cc.roundCount() - rounds));
        assertEquals(Bbr.Mode.DRAIN, sim.cc.mode());
    }

    record Transition(long time, Bbr.Mode mode) {
        @Override
        public String toString() {
            return mode + "@" + time / MS + "ms";
        }
    }

    /**
     * A deterministic fake-clock simulation of one sender behind a bottleneck link: packets queue
     * at the link, leave at its rate, and are acknowledged one propagation RTT later. The sender
     * sends what the window and the connection's {@link Pacer} allow, the pacer limited by BBR's
     * pacing rate; the RTT estimator and the application limited flag are kept as {@code Recovery}
     * and {@code Connection} keep them.
     */
    static final class Sim {
        final Bbr cc;
        final RttEstimator rtt;
        /** The link's rate in bytes per second. */
        long rate;
        final long propagationRtt;
        long now = SECOND;
        long linkFree;
        long nextPn;
        long inFlight;
        long largestAcked = -1;
        boolean appLimited;
        /** Bytes the application writes every {@link #period}, or -1 for a bulk transfer. */
        long chunk = -1;
        long period;
        long appCredit;
        long nextChunk = now;
        long delivered;
        /** Bytes delivered by time, at each acknowledgement. */
        private final TreeMap<Long, Long> deliveredAt = new TreeMap<>();
        long appLimitedAcks;
        long maxQueueDelay;
        final Pacer pacer;
        /** When the pacer allows the next packet, or {@link NanoClock#NONE}. */
        long pacedUntil = NanoClock.NONE;
        final List<Transition> transitions = new ArrayList<>();
        java.util.function.Consumer<Sim> observer = s -> {};
        /** Pending acknowledgements: arrival time, packet number, send time. */
        private final PriorityQueue<long[]> acks = new PriorityQueue<>((a, b) -> Long.compare(a[0], b[0]) != 0
                ? Long.compare(a[0], b[0])
                : Long.compare(a[1], b[1]));

        Sim(Bbr cc, long rate, long propagationRtt) {
            this.cc = cc;
            this.rate = rate;
            this.propagationRtt = propagationRtt;
            // The handshake gave a first RTT sample
            this.rtt = new RttEstimator(RttEstimator.DEFAULT_INITIAL_RTT);
            rtt.update(0, propagationRtt);
            pacer = new Pacer(rtt.get(), cc.window(), MTU, -1, now);
            transitions.add(new Transition(now, cc.mode()));
        }

        List<Bbr.Mode> modes() {
            return transitions.stream().map(Transition::mode).toList();
        }

        /** Bytes delivered since a time. */
        double deliveredSince(long time) {
            Map.Entry<Long, Long> e = deliveredAt.floorEntry(time);
            return delivered - (e == null ? 0 : e.getValue());
        }

        long maxQueueDelay() {
            return maxQueueDelay;
        }

        void resetQueueStats() {
            maxQueueDelay = 0;
        }

        void run(long until) {
            runUntil(() -> false, until);
        }

        void runUntil(java.util.function.BooleanSupplier done, long until) {
            while (now < until && !done.getAsBoolean()) {
                send();
                advance();
            }
        }

        void stepOneAck() {
            send();
            advance();
        }

        private void send() {
            if (chunk >= 0 && now >= nextChunk) {
                appCredit += chunk;
                nextChunk = Math.max(nextChunk + period, now);
            }
            pacedUntil = NanoClock.NONE;
            // One packet per poll, as quinn polls; the last poll, which sends nothing, sets the flag
            while (true) {
                if (inFlight + MTU > cc.window()) {
                    appLimited = false;
                    break;
                }
                if (chunk >= 0 && appCredit < MTU) {
                    appLimited = true;
                    break;
                }
                long window = cc.window();
                if (cc.pacingRate() > 0) {
                    // As Recovery.pacingDelay: the pacer refills 1.25 windows per RTT
                    window = Math.min(window, Math.max(1, Math.round(cc.pacingRate() * (rtt.get() / 1e9) / 1.25)));
                }
                long t = pacer.delay(rtt.get(), MTU, MTU, window, now);
                if (t != NanoClock.NONE) {
                    pacedUntil = Math.max(t, now + 1);
                    appLimited = false;
                    break;
                }
                pacer.onTransmit(MTU);
                if (chunk >= 0) {
                    appCredit -= MTU;
                }
                long pn = nextPn++;
                cc.onSent(now, MTU, pn);
                inFlight += MTU;
                long start = Math.max(now, linkFree);
                maxQueueDelay = Math.max(maxQueueDelay, start - now);
                linkFree = start + MTU * SECOND / rate;
                acks.add(new long[] {linkFree + propagationRtt, pn, now});
            }
        }

        private void advance() {
            long next = acks.isEmpty() ? Long.MAX_VALUE : acks.peek()[0];
            if (chunk >= 0) {
                next = Math.min(next, Math.max(nextChunk, now + 1)); // the application's next write
            }
            if (pacedUntil != NanoClock.NONE) {
                next = Math.min(next, pacedUntil);
            }
            now = next;
            if (acks.isEmpty() || acks.peek()[0] > now) {
                return;
            }
            long largestSent = -1;
            while (!acks.isEmpty() && acks.peek()[0] == now) {
                long[] a = acks.poll();
                inFlight -= MTU;
                delivered += MTU;
                if (appLimited) {
                    appLimitedAcks++;
                }
                cc.onAck(now, a[2], MTU, appLimited, rtt);
                if (a[1] > largestAcked) {
                    largestAcked = a[1];
                    largestSent = a[2];
                }
            }
            cc.onEndAcks(now, inFlight, appLimited, largestAcked);
            deliveredAt.put(now, delivered);
            if (largestSent >= 0) {
                rtt.update(0, now - largestSent);
            }
            if (cc.mode() != transitions.get(transitions.size() - 1).mode()) {
                transitions.add(new Transition(now, cc.mode()));
            }
            observer.accept(this);
        }
    }
}
