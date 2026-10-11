/*
 * The first test adapts quinn-proto src/congestion/bbr/mod.rs (tests) (Apache-2.0) to rate samples.
 */
package io.github.mahmoudimus.quic.congestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.connection.DeliveryRate;
import io.github.mahmoudimus.quic.connection.NanoClock;
import io.github.mahmoudimus.quic.connection.Pacer;
import io.github.mahmoudimus.quic.connection.SentPacket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.SplittableRandom;
import java.util.TreeMap;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

/**
 * BBR on a fake clock: unit checks, then deterministic simulations of one sender behind a
 * bottleneck link, driving the controller as {@code Recovery} does, with the connection's
 * delivery rate sampler and pacer, and a receiver that acknowledges every second packet.
 */
class BbrTest {

    private static final long MS = 1_000_000L;
    private static final long SECOND = 1_000 * MS;
    private static final int MTU = 1200;
    private static final long START = SECOND;

    private static Bbr bbr() {
        return bbr(1);
    }

    private static Bbr bbr(long seed) {
        return new Bbr(BbrConfig.DEFAULT, START, MTU, new SplittableRandom(seed));
    }

    @Test
    void metricsReportBandwidthEstimate() {
        // quinn's test of the same name fed its per-packet estimator; this feeds a rate sample
        Bbr bbr = bbr();
        assertEquals(-1, bbr.metrics().bandwidthEstimate());
        long now = START + 30 * MS;
        bbr.onAck(now, START, 1200, false, new RttEstimator(30 * MS));
        bbr.onRateSample(now, new RateSample(120_000, 1200, 10 * MS, 30 * MS, false, 0));
        bbr.onEndAcks(now, 0, false, 0);
        assertEquals(960_000, bbr.metrics().bandwidthEstimate());
        assertEquals(30 * MS, bbr.minRtt());
    }

    @Test
    void defaults() {
        Bbr bbr = bbr();
        assertEquals(240_000, bbr.initialWindow());
        assertEquals(240_000, bbr.window());
        assertEquals(Bbr.Mode.STARTUP, bbr.mode());
        assertEquals(0, bbr.minRtt());
        assertEquals(-1, bbr.pacingRate());
        assertEquals(new ControllerMetrics(240_000, -1, 0, -1), bbr.metrics());
        assertTrue(BbrConfig.DEFAULT.build(0, MTU) instanceof Bbr);
    }

    @Test
    void mtuUpdateRaisesTheMinimumWindow() {
        Bbr bbr = new Bbr(new BbrConfig(2 * MTU), START, MTU, new SplittableRandom(1));
        assertEquals(2 * MTU, bbr.window());
        bbr.onMtuUpdate(1452);
        assertEquals(4 * 1452, bbr.window(), "the window is at least four datagrams");
    }

    @Test
    void applicationLimitedSamplesOnlyRaiseTheEstimate() {
        Bbr bbr = bbr();
        long now = START;
        bbr.onRateSample(now, new RateSample(1_000_000, 0, 0, 40 * MS, false, 0));
        bbr.onEndAcks(now, 0, false, 0);
        bbr.onRateSample(now, new RateSample(400_000, 0, 0, 40 * MS, true, 0));
        bbr.onEndAcks(now, 0, true, 1);
        assertEquals(1_000_000, bbr.bandwidthEstimate(), "a lower application-limited sample is left out");
        bbr.onRateSample(now, new RateSample(1_500_000, 0, 0, 40 * MS, true, 0));
        bbr.onEndAcks(now, 0, true, 2);
        assertEquals(1_500_000, bbr.bandwidthEstimate(), "a higher one counts");
        bbr.onRateSample(now, new RateSample(-1, 0, 0, 40 * MS, false, 0));
        bbr.onEndAcks(now, 0, false, 3);
        assertEquals(1_500_000, bbr.bandwidthEstimate(), "a sample without a rate is left out");
    }

    @Test
    void copyIsIndependent() {
        Sim sim = new Sim(bbr(), 12_500_000, 40 * MS);
        sim.run(START + 2 * SECOND);
        Bbr copy = (Bbr) sim.cc.copy();
        assertEquals(sim.cc.mode(), copy.mode());
        assertEquals(sim.cc.window(), copy.window());
        assertEquals(sim.cc.bandwidthEstimate(), copy.bandwidthEstimate());
        sim.run(sim.now + 2 * SECOND);
        assertTrue(copy.roundCount() < sim.cc.roundCount());
    }

    /**
     * STARTUP, DRAIN and PROBE_BW on a 100 Mbit/s path with a 40 ms RTT, then PROBE_RTT each time
     * ten seconds pass without an RTT sample at or below the minimum: here the minimum was taken
     * with the queue empty, and the pacer's bursts keep later samples a little above it.
     */
    @Test
    void stateMachineOnABottleneckLink() {
        long rate = 12_500_000;
        long rtt = 40 * MS;
        Sim sim = new Sim(bbr(), rate, rtt);
        List<Long> expiredAfter = new ArrayList<>();
        long[] stamp = {START};
        sim.observer = s -> {
            if (s.cc.mode() == Bbr.Mode.PROBE_RTT && s.transitions.get(s.transitions.size() - 1).time() == s.now) {
                expiredAfter.add(s.now - stamp[0]);
            }
            stamp[0] = s.cc.minRttStamp();
        };
        sim.run(START + 25 * SECOND);
        System.out.println("BBR modes, 100 Mbit/s, 40 ms: " + sim.transitions + ", estimate "
                + sim.cc.bandwidthEstimate() + " B/s, utilization " + sim.utilization(START + 2 * SECOND)
                + ", PROBE_RTT after minimum RTT ages of " + expiredAfter.stream().map(t -> t / MS + " ms").toList());
        assertEquals(List.of(Bbr.Mode.STARTUP, Bbr.Mode.DRAIN, Bbr.Mode.PROBE_BW, Bbr.Mode.PROBE_RTT, Bbr.Mode.PROBE_BW,
                Bbr.Mode.PROBE_RTT, Bbr.Mode.PROBE_BW), sim.modes(), "transitions " + sim.transitions);
        assertTrue(sim.transitions.get(1).time() - START < 20 * rtt, "STARTUP took " + sim.transitions);
        // PROBE_RTT starts only once the minimum RTT is ten seconds old, and lasts at least 200 ms
        assertEquals(2, expiredAfter.size());
        for (long age : expiredAfter) {
            assertTrue(age > 10 * SECOND && age < 10 * SECOND + 5 * MS, "minimum RTT age " + age);
        }
        assertTrue(sim.transitions.get(4).time() - sim.transitions.get(3).time() >= 200 * MS);
        assertTrue(sim.cc.isAtFullBandwidth());
        assertTrue(sim.cc.minRtt() >= rtt && sim.cc.minRtt() < rtt + MS, "min RTT " + sim.cc.minRtt());
        long bw = sim.cc.bandwidthEstimate();
        assertTrue(Math.abs(bw - rate) <= rate / 100, "estimate " + bw + " for " + rate);
        assertEquals(bw * 8, sim.cc.metrics().bandwidthEstimate());
        assertTrue(sim.cc.pacingRate() >= bw * 3 / 4 && sim.cc.pacingRate() <= bw * 5 / 4);
        assertTrue(sim.utilization(START + 2 * SECOND) > 0.95, "utilization " + sim.utilization(START + 2 * SECOND));
    }

    /**
     * When the path's RTT rises (a route change from 40 to 60 ms), no sample reaches the old
     * minimum: it expires ten seconds after it was last measured, PROBE_RTT starts, and the new
     * minimum is taken.
     */
    @Test
    void probeRttTakesTheNewMinimumWhenTheOldExpires() {
        Sim sim = new Sim(bbr(), 12_500_000, 40 * MS);
        sim.run(START + 5 * SECOND);
        assertEquals(Bbr.Mode.PROBE_BW, sim.cc.mode());
        long lastMinimum = sim.cc.minRttStamp();
        sim.propagationRtt = 60 * MS;
        sim.run(sim.now + 7 * SECOND);
        System.out.println("BBR modes, RTT 40 then 60 ms: " + sim.transitions);
        assertEquals(List.of(Bbr.Mode.STARTUP, Bbr.Mode.DRAIN, Bbr.Mode.PROBE_BW, Bbr.Mode.PROBE_RTT, Bbr.Mode.PROBE_BW),
                sim.modes(), "transitions " + sim.transitions);
        long probe = sim.transitions.get(3).time();
        assertTrue(probe - lastMinimum > 10 * SECOND && probe - lastMinimum < 10 * SECOND + 5 * MS,
                "PROBE_RTT at " + probe + ", minimum last seen at " + lastMinimum);
        assertTrue(sim.transitions.get(4).time() - probe >= 200 * MS);
        assertTrue(sim.cc.minRtt() >= 60 * MS && sim.cc.minRtt() < 61 * MS, "min RTT " + sim.cc.minRtt());
    }

    @Test
    void drainEmptiesTheStartupQueue() {
        long rate = 12_500_000;
        long rtt = 100 * MS;
        Sim sim = new Sim(bbr(), rate, rtt);
        long bdp = rate * rtt / SECOND;
        sim.runUntil(() -> sim.cc.mode() == Bbr.Mode.DRAIN, START + 10 * SECOND);
        assertTrue(sim.inFlight > bdp, "STARTUP overfilled the path: " + sim.inFlight + ", BDP " + bdp);
        assertTrue(sim.cc.pacingGain() < 1.0f);
        // PROBE_BW starts once the bytes in flight are down to the BDP
        sim.runUntil(() -> sim.cc.mode() == Bbr.Mode.PROBE_BW, START + 10 * SECOND);
        assertTrue(sim.inFlight <= bdp + bdp / 20, "in flight " + sim.inFlight + ", BDP " + bdp);
        // In PROBE_BW the window is two BDPs plus the ack aggregation, and the queue stays below a
        // BDP
        sim.run(sim.now + SECOND);
        sim.maxQueueDelay = 0;
        sim.run(sim.now + 5 * SECOND);
        assertTrue(sim.cc.window() <= 2 * bdp + bdp / 4, "window " + sim.cc.window());
        assertTrue(sim.maxQueueDelay <= rtt / 2, "queue delay " + sim.maxQueueDelay);
    }

    @Test
    void probeBwCyclesItsPacingGain() {
        Sim sim = new Sim(bbr(), 12_500_000, 40 * MS);
        sim.runUntil(() -> sim.cc.mode() == Bbr.Mode.PROBE_BW, START + 10 * SECOND);
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
     * The bottleneck drops from 50 to 10 Mbit/s mid-transfer: the old maximum leaves the ten-round
     * filter and the estimate and pacing rate come down to the new rate; a faster path raises them
     * again at once.
     */
    @Test
    void bandwidthEstimateFollowsARateDrop() {
        Sim sim = new Sim(bbr(), 6_250_000, 40 * MS);
        sim.run(START + 5 * SECOND);
        assertTrue(Math.abs(sim.cc.bandwidthEstimate() - 6_250_000) < 6_250_000 / 100);
        sim.rate = 1_250_000;
        long dropAt = sim.now;
        long dropRound = sim.cc.roundCount();
        long[] followed = {-1, -1};
        sim.observer = s -> {
            if (followed[0] < 0 && s.cc.bandwidthEstimate() <= 1_250_000 * 105 / 100
                    && s.cc.pacingRate() <= 1_250_000 * 125 / 100) {
                followed[0] = s.cc.roundCount() - dropRound;
                followed[1] = s.now - dropAt;
            }
        };
        sim.run(sim.now + 10 * SECOND);
        System.out.printf("BBR, 50 then 10 Mbit/s: estimate and pacing rate down after %d rounds (%d ms), "
                + "estimate %d B/s%n", followed[0], followed[1] / MS, sim.cc.bandwidthEstimate());
        assertTrue(followed[0] > 0 && followed[0] <= 12, "followed after " + followed[0] + " rounds");
        long bw = sim.cc.bandwidthEstimate();
        assertTrue(Math.abs(bw - 1_250_000) <= 1_250_000 / 50, "estimate " + bw);
        sim.observer = s -> {};
        sim.rate = 25_000_000;
        long upRound = sim.cc.roundCount();
        sim.runUntil(() -> sim.cc.bandwidthEstimate() >= 24_500_000, sim.now + 10 * SECOND);
        assertTrue(sim.cc.bandwidthEstimate() >= 24_500_000, "estimate " + sim.cc.bandwidthEstimate());
        System.out.printf("BBR, then 200 Mbit/s: estimate up after %d rounds%n", sim.cc.roundCount() - upRound);
    }

    /**
     * An application that sends a little at a time: its samples are application limited, so
     * STARTUP does not end for lack of growth and the window stays near its start; the estimate
     * is only a lower bound. A bulk transfer then finds the bandwidth.
     */
    @Test
    void appLimitedSamplesDoNotEndStartup() {
        Sim sim = new Sim(bbr(), 12_500_000, 40 * MS);
        sim.chunk = 20 * MTU; // 24 kB every 100 ms: about 2% of the path
        sim.period = 100 * MS;
        sim.run(START + 15 * SECOND);
        assertEquals(List.of(Bbr.Mode.STARTUP), sim.modes(), "transitions " + sim.transitions);
        assertTrue(sim.appLimitedSamples > 100, "application-limited samples " + sim.appLimitedSamples);
        assertTrue(sim.cc.bandwidthEstimate() < 12_500_000 / 4, "estimate " + sim.cc.bandwidthEstimate());
        assertTrue(sim.cc.window() <= 2 * BbrConfig.DEFAULT.initialWindow(), "window " + sim.cc.window());
        assertTrue(sim.cc.minRtt() >= 40 * MS && sim.cc.minRtt() < 41 * MS, "min RTT " + sim.cc.minRtt());

        sim.chunk = -1;
        sim.run(sim.now + 5 * SECOND);
        long bw = sim.cc.bandwidthEstimate();
        assertTrue(Math.abs(bw - 12_500_000) <= 12_500_000 / 100, "estimate " + bw);
        assertEquals(List.of(Bbr.Mode.STARTUP, Bbr.Mode.DRAIN, Bbr.Mode.PROBE_BW), sim.modes(),
                "transitions " + sim.transitions);
    }

    @Test
    void appLimitedInProbeBwKeepsTheEstimate() {
        Sim sim = new Sim(bbr(), 12_500_000, 40 * MS);
        sim.run(START + 5 * SECOND);
        assertEquals(Bbr.Mode.PROBE_BW, sim.cc.mode());
        long bw = sim.cc.bandwidthEstimate();
        sim.chunk = 20 * MTU;
        sim.period = 100 * MS;
        sim.run(sim.now + 15 * SECOND);
        // Lower application-limited samples are left out, so the maximum does not expire
        assertEquals(bw, sim.cc.bandwidthEstimate());
        assertTrue(sim.appLimitedSamples > 100);
        assertEquals(Bbr.Mode.PROBE_BW, sim.cc.mode(), "transitions " + sim.transitions);
        // and a bulk transfer goes on at the rate
        sim.chunk = -1;
        long from = sim.now;
        sim.run(sim.now + 3 * SECOND);
        assertTrue(sim.utilization(from + SECOND / 2) > 0.9, "utilization " + sim.utilization(from + SECOND / 2));
    }

    @Test
    void lossEntersAndLeavesRecovery() {
        Sim sim = new Sim(bbr(), 12_500_000, 40 * MS);
        sim.runUntil(() -> sim.cc.mode() == Bbr.Mode.PROBE_BW, START + 10 * SECOND);
        sim.run(sim.now + SECOND);
        long before = sim.cc.window();
        sim.cc.onCongestionEvent(sim.now, sim.now - 10 * MS, false, false, 3 * MTU);
        sim.stepOneAck();
        assertEquals(Bbr.RecoveryState.CONSERVATION, sim.cc.recoveryState());
        assertTrue(sim.cc.window() <= before);
        sim.run(sim.now + 500 * MS);
        assertEquals(Bbr.RecoveryState.NOT_IN_RECOVERY, sim.cc.recoveryState());
    }

    /** Every seed of the gain cycle, one RTT and rate after another, converges the same way. */
    @Test
    void convergesForEverySeedAndPath() {
        long[][] paths = {{1_250_000, 10 * MS}, {12_500_000, 40 * MS}, {6_250_000, 150 * MS}};
        for (long[] path : paths) {
            for (long seed = 1; seed <= 10; seed++) {
                Sim sim = new Sim(bbr(seed), path[0], path[1]);
                sim.run(START + 6 * SECOND + 20 * path[1]);
                long bw = sim.cc.bandwidthEstimate();
                String what = path[0] + " B/s, " + path[1] / MS + " ms, seed " + seed + ": " + sim.transitions;
                assertTrue(Math.abs(bw - path[0]) <= path[0] / 50, "estimate " + bw + ", " + what);
                assertFalse(sim.modes().contains(Bbr.Mode.PROBE_RTT), what);
                assertEquals(Bbr.Mode.PROBE_BW, sim.cc.mode(), what);
            }
        }
    }

    record Transition(long time, Bbr.Mode mode) {
        @Override
        public String toString() {
            return mode + "@" + (time - START) / MS + "ms";
        }
    }

    /** One acknowledgement: when it reaches the sender, and the packets it covers. */
    record Ack(long time, long sequence, List<Flight> packets) {}

    /** A packet in flight and its number. */
    record Flight(long number, SentPacket packet) {}

    /**
     * A deterministic fake-clock simulation of one sender behind a bottleneck link: packets queue
     * at the link, leave at its rate, reach the receiver half a propagation RTT later, and are
     * acknowledged by it every second packet, or 25 ms after an odd one. The sender sends what the
     * window and the connection's {@link Pacer} allow, the pacer limited by BBR's pacing rate; it
     * samples the delivery rate with the connection's {@link DeliveryRate}, and keeps the RTT
     * estimator and the application-limited flag as {@code Recovery} and {@code Connection} do.
     */
    static final class Sim {
        static final long MAX_ACK_DELAY = 25 * MS;

        final Bbr cc;
        final RttEstimator rtt;
        final DeliveryRate deliveryRate = new DeliveryRate();
        /** The link's rate in bytes per second. */
        long rate;
        long propagationRtt;
        long now = START;
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
        long appLimitedSamples;
        long maxQueueDelay;
        final Pacer pacer;
        long pacedUntil = NanoClock.NONE;
        final List<Transition> transitions = new ArrayList<>();
        Consumer<Sim> observer = s -> {};
        private final TreeMap<Long, Long> deliveredAt = new TreeMap<>();
        private final PriorityQueue<Ack> acks = new PriorityQueue<>((a, b) -> a.time() != b.time()
                ? Long.compare(a.time(), b.time())
                : Long.compare(a.sequence(), b.sequence()));
        private long ackSequence;
        /** An acknowledgement waiting for a second packet, and when the receiver got its first. */
        private Ack pendingAck;
        private long pendingArrival;

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

        /** The share of the link's capacity delivered since a time. */
        double utilization(long since) {
            Map.Entry<Long, Long> e = deliveredAt.floorEntry(since);
            return (delivered - (e == null ? 0 : e.getValue())) / (rate * ((now - since) / 1e9));
        }

        void run(long until) {
            runUntil(() -> false, until);
        }

        void runUntil(BooleanSupplier done, long until) {
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
                    deliveryRate.onAppLimited(inFlight);
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
                SentPacket packet = SentPacket.of(now, MTU, true);
                deliveryRate.onPacketSent(now, packet, inFlight);
                cc.onSent(now, MTU, pn);
                inFlight += MTU;
                long start = Math.max(now, linkFree);
                maxQueueDelay = Math.max(maxQueueDelay, start - now);
                linkFree = start + MTU * SECOND / rate;
                receive(new Flight(pn, packet), linkFree + propagationRtt / 2);
            }
        }

        /** The receiver gets a packet: it acknowledges every second one, or an odd one 25 ms late. */
        private void receive(Flight flight, long arrival) {
            if (pendingAck != null && arrival <= pendingArrival + MAX_ACK_DELAY) {
                acks.remove(pendingAck);
                acks.add(new Ack(arrival + propagationRtt / 2, ackSequence++,
                        List.of(pendingAck.packets().get(0), flight)));
                pendingAck = null;
            } else {
                pendingAck = new Ack(arrival + MAX_ACK_DELAY + propagationRtt / 2, ackSequence++, List.of(flight));
                pendingArrival = arrival;
                acks.add(pendingAck);
            }
        }

        private void advance() {
            long next = acks.isEmpty() ? Long.MAX_VALUE : acks.peek().time();
            if (chunk >= 0) {
                next = Math.min(next, Math.max(nextChunk, now + 1)); // the application's next write
            }
            if (pacedUntil != NanoClock.NONE) {
                next = Math.min(next, pacedUntil);
            }
            now = next;
            while (!acks.isEmpty() && acks.peek().time() <= now) {
                Ack ack = acks.poll();
                if (ack == pendingAck) {
                    pendingAck = null;
                }
                process(ack);
            }
        }

        private void process(Ack ack) {
            long largestSent = -1;
            for (Flight f : ack.packets()) {
                inFlight -= MTU;
                delivered += MTU;
                deliveryRate.onPacketAcked(now, f.packet());
                cc.onAck(now, f.packet().timeSent(), MTU, appLimited, rtt);
                if (f.number() > largestAcked) {
                    largestAcked = f.number();
                    largestSent = f.packet().timeSent();
                }
            }
            RateSample sample = deliveryRate.sample(rtt.hasSample() ? rtt.min() : 0);
            if (sample != null) {
                if (sample.appLimited()) {
                    appLimitedSamples++;
                }
                cc.onRateSample(now, sample);
            }
            cc.onEndAcks(now, inFlight, appLimited, largestAcked);
            deliveredAt.put(now, delivered);
            if (largestSent >= 0) {
                long delay = ack.packets().size() == 1 ? MAX_ACK_DELAY : 0;
                rtt.update(delay, now - largestSent);
            }
            if (cc.mode() != transitions.get(transitions.size() - 1).mode()) {
                transitions.add(new Transition(now, cc.mode()));
            }
            observer.accept(this);
        }
    }
}
