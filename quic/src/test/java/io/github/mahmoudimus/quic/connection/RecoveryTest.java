package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.congestion.NewRenoConfig;
import io.github.mahmoudimus.quic.crypto.Keys;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.params.TransportParameters;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/** Loss detection (RFC 9002) driven by a fake clock. */
class RecoveryTest {

    private static final long MS = 1_000_000L;
    private static final int MTU = 1200;

    /** A deterministic clock. */
    static final class FakeClock implements NanoClock {
        long now = 1_000_000 * MS;

        @Override
        public long nanoTime() {
            return now;
        }

        void advance(long nanos) {
            now += nanos;
        }
    }

    /** Records acknowledged and lost packet numbers. */
    static final class Recorder implements Recovery.Listener {
        final List<Long> acked = new ArrayList<>();
        final List<Long> lost = new ArrayList<>();

        @Override
        public void onPacketAcked(SpaceId space, long packetNumber, SentPacket packet) {
            acked.add(packetNumber);
        }

        @Override
        public void onPacketLost(SpaceId space, long packetNumber, SentPacket packet) {
            lost.add(packetNumber);
        }
    }

    private final FakeClock clock = new FakeClock();
    private final TimerTable timers = new TimerTable();
    private final Recorder recorder = new Recorder();

    private Recovery server(RecoveryConfig config) {
        Recovery r = new Recovery(Side.SERVER, config, timers, new Random(1), clock.now);
        r.packetNumberFilter = PacketNumberFilter.disabled();
        r.setAddressValidated();
        r.setHandshakeConfirmed(true);
        return r;
    }

    private Recovery server() {
        return server(RecoveryConfig.DEFAULT);
    }

    private long send(Recovery r, SpaceId space) {
        return send(r, space, MTU);
    }

    private long send(Recovery r, SpaceId space, int size) {
        long pn = r.nextPacketNumber(space);
        r.onPacketSent(clock.now, space, pn, SentPacket.of(clock.now, size, true));
        return pn;
    }

    private void ack(Recovery r, SpaceId space, long ackDelay, long... pns) throws QuicException {
        r.onAckReceived(clock.now, space, Frame.Ack.of(ackDelay, null, pns), recorder);
    }

    @Test
    void ackTakesRttSamples() throws Exception {
        Recovery r = server();
        long pn = send(r, SpaceId.DATA);
        clock.advance(100 * MS);
        ack(r, SpaceId.DATA, 0, pn);
        assertEquals(List.of(pn), recorder.acked);
        assertEquals(100 * MS, r.rtt().get());
        assertEquals(0, r.bytesInFlight());

        // 10 ms of ACK delay (10000 us >> 3) is subtracted in the application data space
        pn = send(r, SpaceId.DATA);
        clock.advance(120 * MS);
        ack(r, SpaceId.DATA, 10_000 >> 3, pn);
        assertEquals(120 * MS, r.rtt().latest());
        assertEquals((7 * 100 * MS + 110 * MS) / 8, r.rtt().get());

        // ACK delay is limited to the peer's max_ack_delay (25 ms by default)
        long before = r.rtt().get();
        pn = send(r, SpaceId.DATA);
        clock.advance(200 * MS);
        ack(r, SpaceId.DATA, 100_000 >> 3, pn);
        assertEquals((7 * before + 175 * MS) / 8, r.rtt().get());
    }

    @Test
    void ackDelayIsIgnoredDuringTheHandshake() throws Exception {
        Recovery r = server();
        send(r, SpaceId.DATA); // an earlier sample, so the next is smoothed
        clock.advance(100 * MS);
        ack(r, SpaceId.DATA, 0, 0);
        long pn = send(r, SpaceId.HANDSHAKE);
        clock.advance(140 * MS);
        ack(r, SpaceId.HANDSHAKE, 20_000 >> 3, pn);
        assertEquals((7 * 100 * MS + 140 * MS) / 8, r.rtt().get(), "Initial and Handshake ACK delay is 0");
    }

    @Test
    void packetThresholdThenTimeThresholdLoss() throws Exception {
        Recovery r = server();
        long t0 = clock.now;
        for (int i = 0; i < 5; i++) {
            send(r, SpaceId.DATA);
        }
        assertEquals(5 * MTU, r.bytesInFlight());
        clock.advance(50 * MS);
        ack(r, SpaceId.DATA, 0, 4);

        // Packets 0 and 1 are three behind the acknowledged 4; 2 and 3 are not, yet
        assertEquals(List.of(0L, 1L), recorder.lost);
        assertEquals(2 * MTU, r.bytesInFlight());
        assertEquals(1, r.congestionEvents());
        assertEquals(2, r.lostPackets());
        long lossDelay = 50 * MS * 9 / 8;
        assertEquals(t0 + lossDelay, r.space(SpaceId.DATA).lossTime());
        assertEquals(t0 + lossDelay, timers.get(Timer.LOSS_DETECTION));

        // The time threshold catches the rest
        long window = r.congestion().window();
        clock.now = timers.get(Timer.LOSS_DETECTION);
        assertEquals(Timer.LOSS_DETECTION, timers.pollExpired(clock.now));
        r.onLossDetectionTimeout(clock.now, recorder);
        assertEquals(List.of(0L, 1L, 2L, 3L), recorder.lost);
        assertEquals(0, r.bytesInFlight());
        assertEquals(2, r.congestionEvents());
        assertEquals(window, r.congestion().window(), "packets sent before recovery started reduce nothing more");
        assertEquals(NanoClock.NONE, r.space(SpaceId.DATA).lossTime());
        assertFalse(timers.isSet(Timer.LOSS_DETECTION), "nothing in flight on a server");
    }

    @Test
    void lostPacketControlFramesAreQueuedAgain() throws Exception {
        Recovery r = server();
        Retransmits frames = new Retransmits();
        frames.maxData = true;
        frames.newCids.add(new IssuedCid(1, ConnectionId.of(new byte[] {1, 2, 3, 4}),
                io.github.mahmoudimus.quic.StatelessResetToken.of(new byte[16])));
        long pn = r.nextPacketNumber(SpaceId.DATA);
        r.onPacketSent(clock.now, SpaceId.DATA, pn, new SentPacket(clock.now, 100, true, -1, frames, List.of()));
        for (int i = 0; i < 3; i++) {
            send(r, SpaceId.DATA);
        }
        clock.advance(10 * MS);
        ack(r, SpaceId.DATA, 0, 3);
        assertTrue(r.space(SpaceId.DATA).pending().maxData);
        assertEquals(1, r.space(SpaceId.DATA).pending().newCids.size());
    }

    @Test
    void ptoBacksOffExponentially() throws Exception {
        Recovery r = server();
        long t0 = clock.now;
        send(r, SpaceId.DATA);
        // PTO = 333 + 4 * 166.5 ms, plus max_ack_delay in the application data space
        long pto = 999 * MS + 25 * MS;
        assertEquals(pto, r.pto(SpaceId.DATA));
        assertEquals(t0 + pto, timers.get(Timer.LOSS_DETECTION));

        clock.now = t0 + pto;
        r.onLossDetectionTimeout(clock.now, recorder);
        assertEquals(1, r.ptoCount());
        assertEquals(2, r.space(SpaceId.DATA).lossProbes(), "two probes when ack-eliciting packets are in flight");
        assertEquals(t0 + 2 * pto, timers.get(Timer.LOSS_DETECTION), "the backoff doubles the timeout");
        assertTrue(recorder.lost.isEmpty(), "a PTO declares nothing lost");

        clock.now = t0 + 2 * pto;
        r.onLossDetectionTimeout(clock.now, recorder);
        assertEquals(2, r.ptoCount());
        assertEquals(4, r.space(SpaceId.DATA).lossProbes());
        assertEquals(t0 + 4 * pto, timers.get(Timer.LOSS_DETECTION));

        // A probe sent now restarts the timer from its send time, still backed off
        long probe = send(r, SpaceId.DATA);
        r.space(SpaceId.DATA).probeSent();
        assertEquals(clock.now + 4 * pto, timers.get(Timer.LOSS_DETECTION));

        // An ACK resets the backoff
        clock.advance(80 * MS);
        ack(r, SpaceId.DATA, 0, probe);
        assertEquals(0, r.ptoCount());
    }

    @Test
    void backoffIsCapped() {
        Recovery r = server();
        long t0 = clock.now;
        send(r, SpaceId.INITIAL);
        for (int i = 0; i < 40; i++) {
            clock.now = timers.get(Timer.LOSS_DETECTION);
            r.onLossDetectionTimeout(clock.now, recorder);
        }
        assertEquals(40, r.ptoCount());
        long expected = t0 + 999 * MS * (1L << Recovery.MAX_BACKOFF_EXPONENT);
        assertEquals(expected, timers.get(Timer.LOSS_DETECTION));
    }

    private Recovery withRttSample(RecoveryConfig config) throws Exception {
        Recovery r = server(config);
        long pn = send(r, SpaceId.DATA);
        clock.advance(100 * MS);
        ack(r, SpaceId.DATA, 0, pn);
        recorder.acked.clear();
        return r;
    }

    @Test
    void persistentCongestionCollapsesTheWindow() throws Exception {
        Recovery r = withRttSample(RecoveryConfig.DEFAULT);
        // PTO = 100 + 4 * 50 + 25 = 325 ms, so persistent congestion spans 975 ms
        assertEquals(325 * MS, r.pto(SpaceId.DATA));
        send(r, SpaceId.DATA); // 1: the first packet after the sample, which cannot start a period
        clock.advance(100 * MS);
        send(r, SpaceId.DATA); // 2: starts the period
        clock.advance(1000 * MS);
        send(r, SpaceId.DATA); // 3: 1000 ms after 2
        clock.advance(100 * MS);
        send(r, SpaceId.DATA);
        send(r, SpaceId.DATA);
        long last = send(r, SpaceId.DATA);
        clock.advance(100 * MS);
        ack(r, SpaceId.DATA, 0, last);

        assertEquals(List.of(1L, 2L, 3L), recorder.lost);
        assertEquals(2 * MTU, r.congestion().window(), "persistent congestion: the minimum window");
    }

    @Test
    void lossesWithinThePeriodAreOrdinaryCongestion() throws Exception {
        Recovery r = withRttSample(RecoveryConfig.DEFAULT);
        long window = r.congestion().window();
        send(r, SpaceId.DATA);
        clock.advance(100 * MS);
        send(r, SpaceId.DATA);
        clock.advance(500 * MS);
        send(r, SpaceId.DATA); // only 500 ms after 2
        clock.advance(100 * MS);
        send(r, SpaceId.DATA);
        send(r, SpaceId.DATA);
        long last = send(r, SpaceId.DATA);
        clock.advance(100 * MS);
        ack(r, SpaceId.DATA, 0, last);
        assertEquals(List.of(1L, 2L, 3L), recorder.lost);
        assertTrue(r.congestion().window() > 2 * MTU);
        assertTrue(r.congestion().window() < window + MTU, "a multiplicative decrease");
    }

    @Test
    void anAcknowledgedPacketInBetweenPreventsPersistentCongestion() throws Exception {
        Recovery r = withRttSample(NewRenoConfigured());
        send(r, SpaceId.DATA); // 1
        clock.advance(100 * MS);
        send(r, SpaceId.DATA); // 2
        clock.advance(500 * MS);
        long middle = send(r, SpaceId.DATA); // 3, acknowledged
        clock.advance(500 * MS);
        send(r, SpaceId.DATA); // 4, 1000 ms after 2
        clock.advance(100 * MS);
        send(r, SpaceId.DATA);
        send(r, SpaceId.DATA);
        long last = send(r, SpaceId.DATA);
        clock.advance(100 * MS);
        r.onAckReceived(clock.now, SpaceId.DATA, Frame.Ack.of(0, null, middle, last), recorder);
        assertEquals(List.of(1L, 2L, 4L), recorder.lost);
        assertTrue(r.congestion().window() > 2 * MTU, "no collapse");
        assertEquals(r.congestion().window(), r.congestion().metrics().slowStartThreshold(), "NewReno halves");
    }

    private static RecoveryConfig NewRenoConfigured() {
        return RecoveryConfig.builder().congestionControllerFactory(NewRenoConfig.DEFAULT).build();
    }

    @Test
    void spuriousLossRestoresTheCubicWindow() throws Exception {
        Recovery r = server();
        for (int i = 0; i < 5; i++) {
            send(r, SpaceId.DATA);
        }
        clock.advance(50 * MS);
        ack(r, SpaceId.DATA, 0, 4);
        long reduced = r.congestion().window();
        assertEquals(List.of(0L, 1L), recorder.lost);
        // The "lost" packets were only reordered
        clock.advance(MS);
        r.onAckReceived(clock.now, SpaceId.DATA, Frame.Ack.of(0, null, 0, 1, 4), recorder);
        assertEquals(1, r.spuriousCongestionEvents());
        assertTrue(r.congestion().window() > reduced);
    }

    @Test
    void discardingInitialKeysDropsItsPackets() {
        Recovery r = server();
        r.space(SpaceId.INITIAL).setKeys(Keys.initial(QuicVersion.V1, ConnectionId.of(new byte[8]), true));
        send(r, SpaceId.INITIAL);
        send(r, SpaceId.INITIAL);
        clock.now = timers.get(Timer.LOSS_DETECTION);
        r.onLossDetectionTimeout(clock.now, recorder);
        assertEquals(1, r.ptoCount());
        assertEquals(2 * MTU, r.bytesInFlight());

        r.discardSpace(clock.now, SpaceId.INITIAL);
        assertNull(r.space(SpaceId.INITIAL).keys());
        assertEquals(0, r.bytesInFlight());
        assertEquals(0, r.ackElicitingInFlight());
        assertEquals(0, r.ptoCount(), "the backoff restarts");
        assertEquals(0, r.space(SpaceId.INITIAL).sentPackets().size());
        assertFalse(timers.isSet(Timer.LOSS_DETECTION));
        assertThrows(IllegalArgumentException.class, () -> r.discardSpace(clock.now, SpaceId.DATA));
    }

    @Test
    void clientArmsAnAntiDeadlockProbe() throws Exception {
        Recovery r = new Recovery(Side.CLIENT, RecoveryConfig.DEFAULT, timers, new Random(1), clock.now);
        r.space(SpaceId.INITIAL).setKeys(Keys.initial(QuicVersion.V1, ConnectionId.of(new byte[8]), false));
        assertFalse(r.peerCompletedAddressValidation());
        r.setLossDetectionTimer(clock.now);
        assertEquals(clock.now + 999 * MS, timers.get(Timer.LOSS_DETECTION), "nothing in flight, yet a PTO");
        clock.now = timers.get(Timer.LOSS_DETECTION);
        r.onLossDetectionTimeout(clock.now, recorder);
        assertEquals(1, r.space(SpaceId.INITIAL).lossProbes(), "one probe when nothing is in flight");

        // With Handshake keys, the probe goes in the Handshake space
        r.space(SpaceId.HANDSHAKE).setKeys(Keys.initial(QuicVersion.V1, ConnectionId.of(new byte[8]), false));
        clock.now = timers.get(Timer.LOSS_DETECTION);
        r.onLossDetectionTimeout(clock.now, recorder);
        assertEquals(1, r.space(SpaceId.HANDSHAKE).lossProbes());

        // Once the server acknowledges a Handshake packet, it has validated the client
        long pn = send(r, SpaceId.HANDSHAKE);
        clock.advance(30 * MS);
        r.onAckReceived(clock.now, SpaceId.HANDSHAKE, Frame.Ack.of(0, null, pn), recorder);
        assertTrue(r.peerCompletedAddressValidation());
        assertFalse(timers.isSet(Timer.LOSS_DETECTION));
    }

    @Test
    void serverIsBlockedByTheAmplificationLimit() {
        Recovery r = new Recovery(Side.SERVER, RecoveryConfig.DEFAULT, timers, new Random(1), clock.now);
        r.packetNumberFilter = PacketNumberFilter.disabled();
        assertTrue(r.antiAmplificationBlocked(1));
        send(r, SpaceId.INITIAL);
        assertFalse(timers.isSet(Timer.LOSS_DETECTION), "no timer when nothing could be sent");
        r.onDatagramReceived(1200);
        r.onDatagramSent(clock.now, 1200, 0);
        assertFalse(r.antiAmplificationBlocked(2400));
        assertTrue(r.antiAmplificationBlocked(2401));
        r.setLossDetectionTimer(clock.now);
        assertTrue(timers.isSet(Timer.LOSS_DETECTION));
    }

    @Test
    void applicationDataPtoWaitsForHandshakeConfirmation() {
        Recovery r = server();
        r.setHandshakeConfirmed(false);
        send(r, SpaceId.DATA);
        assertFalse(timers.isSet(Timer.LOSS_DETECTION));
        r.setHandshakeConfirmed(true);
        r.setLossDetectionTimer(clock.now);
        assertEquals(clock.now + r.pto(SpaceId.DATA), timers.get(Timer.LOSS_DETECTION));
    }

    @Test
    void ackOfUnsentPacketIsAProtocolViolation() {
        Recovery r = server();
        send(r, SpaceId.DATA);
        QuicException e = assertThrows(QuicException.class, () -> ack(r, SpaceId.DATA, 0, 1));
        assertEquals(QuicException.PROTOCOL_VIOLATION, e.code());
    }

    @Test
    void ackOfSkippedPacketNumberIsAProtocolViolation() {
        Recovery r = new Recovery(Side.SERVER, RecoveryConfig.DEFAULT, timers, new Random(7), clock.now);
        r.setAddressValidated();
        r.setHandshakeConfirmed(true);
        long expected = 0;
        long skipped = -1;
        while (skipped < 0) {
            long pn = send(r, SpaceId.DATA);
            if (pn != expected) {
                skipped = expected;
            }
            expected = pn + 1;
        }
        long s = skipped;
        QuicException e = assertThrows(QuicException.class,
                () -> r.onAckReceived(clock.now, SpaceId.DATA,
                        new Frame.Ack(List.of(new Frame.AckRange(0, s + 1)), 0, null), recorder));
        assertEquals(QuicException.PROTOCOL_VIOLATION, e.code());
    }

    @Test
    void ecnCongestionAndValidation() throws Exception {
        Recovery r = server();
        long pn = send(r, SpaceId.DATA);
        clock.advance(10 * MS);
        r.onAckReceived(clock.now, SpaceId.DATA, Frame.Ack.of(0, new Frame.EcnCounts(1, 0, 0), pn), recorder);
        assertEquals(0, r.congestionEvents());
        assertTrue(r.sendingEcn());
        long window = r.congestion().window();

        pn = send(r, SpaceId.DATA);
        clock.advance(10 * MS);
        r.onAckReceived(clock.now, SpaceId.DATA, Frame.Ack.of(0, new Frame.EcnCounts(1, 0, 1), pn), recorder);
        assertEquals(1, r.congestionEvents(), "CE is a congestion signal");
        assertTrue(r.congestion().window() < window);
        assertTrue(recorder.lost.isEmpty());

        pn = send(r, SpaceId.DATA);
        clock.advance(10 * MS);
        ack(r, SpaceId.DATA, 0, pn);
        assertFalse(r.sendingEcn(), "an ACK without ECN counts turns ECN off");
    }

    @Test
    void ecnBleachingTurnsEcnOff() throws Exception {
        Recovery r = server();
        long pn = send(r, SpaceId.DATA);
        clock.advance(10 * MS);
        r.onAckReceived(clock.now, SpaceId.DATA, Frame.Ack.of(0, new Frame.EcnCounts(0, 0, 0), pn), recorder);
        assertFalse(r.sendingEcn());
    }

    @Test
    void lostMtuProbeIsNotCongestion() throws Exception {
        Recovery r = server();
        r.setPeerParams(TransportParameters.defaults());
        long window = r.congestion().window();
        int probeSize = r.mtud().pollTransmit(clock.now, r.peekPacketNumber(SpaceId.DATA));
        assertEquals(1326, probeSize);
        long probe = send(r, SpaceId.DATA, probeSize);
        for (int i = 0; i < 3; i++) {
            send(r, SpaceId.DATA);
        }
        clock.advance(20 * MS);
        ack(r, SpaceId.DATA, 0, probe + 1, probe + 2, probe + 3);
        assertEquals(1, r.lostMtuProbes());
        assertEquals(0, r.congestionEvents());
        assertTrue(recorder.lost.isEmpty());
        assertTrue(r.congestion().window() >= window);
        assertEquals(0, r.bytesInFlight());

        // The retransmitted probe is acknowledged: the MTU rises
        probeSize = r.mtud().pollTransmit(clock.now, r.peekPacketNumber(SpaceId.DATA));
        assertEquals(1326, probeSize);
        probe = send(r, SpaceId.DATA, probeSize);
        clock.advance(20 * MS);
        ack(r, SpaceId.DATA, 0, probe);
        assertEquals(1326, r.mtud().currentMtu());
    }

    @Test
    void streamListenerRetransmitsAndFinishes() throws Exception {
        Recovery r = server();
        StreamsState streams = new StreamsState(Side.SERVER, 4, 4, 1 << 20, 1 << 20, 1 << 16);
        streams.setParams(TransportParameters.builder().initialMaxStreamsUni(1).initialMaxData(1000)
                .initialMaxStreamDataUni(1000).build());
        Retransmits pending = new Retransmits();
        StreamId id = streams.open(Dir.UNI);
        streams.write(id, ByteBuffer.wrap(new byte[100]), pending);
        streams.finish(id);
        List<StreamMeta> frames = streams.writeStreamFrames(ByteBuffer.allocate(1200), 1200, true);
        Recovery.Listener listener = Recovery.Listener.forStreams(streams);

        long pn = r.nextPacketNumber(SpaceId.DATA);
        r.onPacketSent(clock.now, SpaceId.DATA, pn, new SentPacket(clock.now, 150, true, -1, null, frames));
        for (int i = 0; i < 3; i++) {
            send(r, SpaceId.DATA);
        }
        clock.advance(10 * MS);
        r.onAckReceived(clock.now, SpaceId.DATA, Frame.Ack.of(0, null, pn + 3), listener);
        assertTrue(streams.canSendStreamData(), "the lost STREAM frame is queued again");

        List<StreamMeta> again = streams.writeStreamFrames(ByteBuffer.allocate(1200), 1200, true);
        assertEquals(frames, again);
        long retransmission = r.nextPacketNumber(SpaceId.DATA);
        r.onPacketSent(clock.now, SpaceId.DATA, retransmission, new SentPacket(clock.now, 150, true, -1, null, again));
        clock.advance(10 * MS);
        r.onAckReceived(clock.now, SpaceId.DATA, Frame.Ack.of(0, null, retransmission), listener);
        assertEquals(new StreamEvent.Finished(id), streams.poll());
    }

    @Test
    void receivingArmsTheMaxAckDelayTimer() {
        Recovery r = server();
        assertFalse(r.onPacketReceived(clock.now, SpaceId.DATA, 0, true));
        assertEquals(clock.now + 25 * MS, timers.get(Timer.MAX_ACK_DELAY));
        assertTrue(r.onPacketReceived(clock.now, SpaceId.DATA, 0, true), "a duplicate");
        clock.advance(25 * MS);
        assertEquals(Timer.MAX_ACK_DELAY, timers.pollExpired(clock.now));
        r.onMaxAckDelayTimeout();
        assertTrue(r.space(SpaceId.DATA).pendingAcks().canSend());
        r.onAcksSent(SpaceId.DATA);
        assertFalse(r.space(SpaceId.DATA).pendingAcks().canSend());
        assertFalse(timers.isSet(Timer.MAX_ACK_DELAY));
    }

    @Test
    void idleAndKeyDiscardTimers() {
        Recovery r = server();
        r.resetIdleTimer(clock.now, SpaceId.DATA, 30_000 * MS);
        assertEquals(clock.now + 30_000 * MS, timers.get(Timer.IDLE));
        r.resetIdleTimer(clock.now, SpaceId.DATA, 10 * MS);
        assertEquals(clock.now + 3 * r.pto(SpaceId.DATA), timers.get(Timer.IDLE), "at least three PTOs");
        r.setKeyDiscardTimer(clock.now, SpaceId.DATA);
        assertEquals(clock.now + 3 * r.pto(SpaceId.DATA), timers.get(Timer.KEY_DISCARD));
        r.close();
        r.resetIdleTimer(clock.now, SpaceId.DATA, 10 * MS);
        assertFalse(timers.isSet(Timer.IDLE));
        send(r, SpaceId.DATA);
        assertFalse(timers.isSet(Timer.LOSS_DETECTION), "closed connections detect no loss");
    }

    @Test
    void pacingDelaysBurstsAndSetsTheTimer() throws Exception {
        Recovery r = server();
        // At the initial 333 ms RTT a burst is at most 10 ms of traffic: one datagram
        assertEquals(NanoClock.NONE, r.pacingDelay(clock.now, MTU));
        long pn = send(r, SpaceId.DATA);
        long next = r.pacingDelay(clock.now, MTU);
        assertTrue(next > clock.now);
        assertEquals(next, timers.get(Timer.PACING));

        // A 20 ms RTT allows bursts of several datagrams
        clock.advance(20 * MS);
        ack(r, SpaceId.DATA, 0, pn);
        int sent = 0;
        while (r.pacingDelay(clock.now, MTU) == NanoClock.NONE && sent < 1000) {
            send(r, SpaceId.DATA);
            sent++;
        }
        assertTrue(sent >= 2 && sent < 20, "sent " + sent);
        assertTrue(timers.isSet(Timer.PACING));
        clock.now = timers.get(Timer.PACING);
        assertEquals(NanoClock.NONE, r.pacingDelay(clock.now, MTU));
        assertFalse(timers.isSet(Timer.PACING));
    }

    @Test
    void congestionWindowLimitsSending() {
        Recovery r = server();
        for (int i = 0; i < 10; i++) {
            assertFalse(r.isCongestionBlocked(MTU));
            send(r, SpaceId.DATA);
        }
        assertTrue(r.isCongestionBlocked(MTU), "the initial window is ten datagrams");
        assertEquals(10, r.sentPackets());
    }
}
