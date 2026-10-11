/*
 * Mostly ported from quinn-proto src/connection/spaces.rs (tests) and
 * src/connection/sent_packets.rs (tests) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.frame.Frame;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;

class PacketSpaceTest {

    private static final long MS = 1_000_000L;

    private static BigInteger w(long bits) {
        return BigInteger.valueOf(bits);
    }

    @Test
    void dedupSanity() {
        Dedup dedup = new Dedup();
        assertFalse(dedup.insert(0));
        assertEquals(1, dedup.next());
        assertEquals(w(0b1), dedup.window());
        assertTrue(dedup.insert(0));
        assertEquals(1, dedup.next());
        assertEquals(w(0b1), dedup.window());
        assertFalse(dedup.insert(1));
        assertEquals(2, dedup.next());
        assertEquals(w(0b11), dedup.window());
        assertFalse(dedup.insert(2));
        assertEquals(3, dedup.next());
        assertEquals(w(0b111), dedup.window());
        assertFalse(dedup.insert(4));
        assertEquals(5, dedup.next());
        assertEquals(w(0b11110), dedup.window());
        assertFalse(dedup.insert(7));
        assertEquals(8, dedup.next());
        assertEquals(w(0b1111_0100), dedup.window());
        assertTrue(dedup.insert(4));
        assertFalse(dedup.insert(3));
        assertEquals(8, dedup.next());
        assertEquals(w(0b1111_1100), dedup.window());
        assertFalse(dedup.insert(6));
        assertEquals(8, dedup.next());
        assertEquals(w(0b1111_1101), dedup.window());
        assertFalse(dedup.insert(5));
        assertEquals(8, dedup.next());
        assertEquals(w(0b1111_1111), dedup.window());
    }

    @Test
    void dedupHappyPath() {
        Dedup dedup = new Dedup();
        for (long i = 0; i < 2 * Dedup.WINDOW_SIZE; i++) {
            assertFalse(dedup.insert(i));
            for (long j = 0; j <= i; j++) {
                assertTrue(dedup.insert(j));
            }
        }
    }

    @Test
    void dedupJump() {
        Dedup dedup = new Dedup();
        dedup.insert(2 * Dedup.WINDOW_SIZE);
        assertTrue(dedup.insert(Dedup.WINDOW_SIZE));
        assertEquals(2 * Dedup.WINDOW_SIZE + 1, dedup.next());
        assertEquals(BigInteger.ZERO, dedup.window());
        assertFalse(dedup.insert(Dedup.WINDOW_SIZE + 1));
        assertEquals(2 * Dedup.WINDOW_SIZE + 1, dedup.next());
        assertEquals(BigInteger.ONE.shiftLeft((int) (Dedup.WINDOW_SIZE - 2)), dedup.window());
    }

    @Test
    void dedupHasMissing() {
        Dedup dedup = new Dedup();
        dedup.insert(0);
        assertFalse(dedup.missingInInterval(0, 0));
        dedup.insert(1);
        assertFalse(dedup.missingInInterval(0, 1));
        dedup.insert(3);
        assertTrue(dedup.missingInInterval(1, 3));
        dedup.insert(4);
        assertFalse(dedup.missingInInterval(3, 4));
        assertTrue(dedup.missingInInterval(0, 4));
        dedup.insert(2);
        assertFalse(dedup.missingInInterval(0, 4));
    }

    @Test
    void dedupOutsideOfWindowHasMissing() {
        Dedup dedup = new Dedup();
        for (long i = 0; i < 140; i++) {
            dedup.insert(i);
        }
        // 0 and 4 are outside the window
        assertFalse(dedup.missingInInterval(0, 4));
        dedup.insert(160);
        assertFalse(dedup.missingInInterval(0, 4));
        assertFalse(dedup.missingInInterval(0, 140));
        assertTrue(dedup.missingInInterval(0, 160));
    }

    @Test
    void dedupSmallestMissing() {
        Dedup dedup = new Dedup();
        dedup.insert(0);
        assertEquals(-1, dedup.smallestMissingInInterval(0, 0));
        dedup.insert(1);
        assertEquals(-1, dedup.smallestMissingInInterval(0, 1));
        dedup.insert(5);
        dedup.insert(7);
        assertEquals(2, dedup.smallestMissingInInterval(0, 7));
        assertEquals(6, dedup.smallestMissingInInterval(5, 7));
        dedup.insert(2);
        assertEquals(3, dedup.smallestMissingInInterval(1, 7));
        dedup.insert(170);
        dedup.insert(172);
        dedup.insert(300);
        assertEquals(-1, dedup.smallestMissingInInterval(170, 172));
        dedup.insert(500);
        assertEquals(372, dedup.smallestMissingInInterval(0, 500));
        assertEquals(372, dedup.smallestMissingInInterval(0, 373));
        assertEquals(-1, dedup.smallestMissingInInterval(0, 372));
    }

    @Test
    void pendingAcksFirstPacketIsNotConsideredReordered() {
        PendingAcks acks = new PendingAcks();
        Dedup dedup = new Dedup();
        dedup.insert(0);
        acks.packetReceived(0, 0, true, dedup);
        assertFalse(acks.immediateAckRequired);
    }

    @Test
    void pendingAcksAfterImmediateAckSet() {
        PendingAcks acks = new PendingAcks();
        Dedup dedup = new Dedup();
        dedup.insert(0);
        long now = 5 * MS;
        acks.insertOne(0, now);
        acks.packetReceived(now, 0, true, dedup);
        assertFalse(acks.ranges().isEmpty());
        assertFalse(acks.canSend());
        acks.setImmediateAckRequired(); // as after max_ack_delay
        assertTrue(acks.canSend());
    }

    @Test
    void pendingAcksAckDelay() {
        PendingAcks acks = new PendingAcks();
        Dedup dedup = new Dedup();
        long t1 = 100 * MS;
        long t2 = t1 + 2 * MS;
        long t3 = t2 + 5 * MS;
        assertEquals(0, acks.ackDelay(t1));
        assertEquals(0, acks.ackDelay(t3));
        // In order
        dedup.insert(0);
        acks.insertOne(0, t1);
        acks.packetReceived(t1, 0, true, dedup);
        assertEquals(0, acks.ackDelay(t1));
        assertEquals(2 * MS, acks.ackDelay(t2));
        assertEquals(7 * MS, acks.ackDelay(t3));
        // Out of order, higher than expected
        dedup.insert(3);
        acks.insertOne(3, t2);
        acks.packetReceived(t2, 3, true, dedup);
        assertEquals(0, acks.ackDelay(t2));
        assertEquals(5 * MS, acks.ackDelay(t3));
        // Lower than expected: the previous time is kept
        dedup.insert(2);
        acks.insertOne(2, t3);
        acks.packetReceived(t3, 2, true, dedup);
        assertEquals(5 * MS, acks.ackDelay(t3));
    }

    @Test
    void everySecondAckElicitingPacketIsAcknowledgedAtOnce() {
        PacketSpace space = new PacketSpace(SpaceId.DATA, 0);
        assertFalse(space.onPacketReceived(MS, 0, true));
        assertFalse(space.pendingAcks().canSend(), "one packet waits for max_ack_delay");
        assertEquals(MS + 25 * MS, space.pendingAcks().maxAckDelayTimeout(25 * MS));
        assertFalse(space.onPacketReceived(2 * MS, 1, true));
        assertTrue(space.pendingAcks().canSend(), "the threshold is one ack-eliciting packet");
        space.pendingAcks().acksSent();
        assertFalse(space.pendingAcks().canSend());
        assertEquals(NanoClock.NONE, space.pendingAcks().maxAckDelayTimeout(25 * MS));
        assertTrue(space.onPacketReceived(3 * MS, 1, true), "a duplicate");
    }

    @Test
    void reorderingTriggersAnImmediateAck() {
        PacketSpace space = new PacketSpace(SpaceId.DATA, 0);
        space.onPacketReceived(MS, 0, true);
        space.pendingAcks().acksSent();
        space.onPacketReceived(2 * MS, 2, true); // 1 is missing
        assertTrue(space.pendingAcks().canSend());
    }

    @Test
    void maxAckDelayTimeoutRequiresAnAck() {
        PendingAcks acks = new PendingAcks();
        Dedup dedup = new Dedup();
        dedup.insert(0);
        acks.insertOne(0, MS);
        acks.packetReceived(MS, 0, true, dedup);
        acks.onMaxAckDelayTimeout();
        assertTrue(acks.canSend());
    }

    @Test
    void nonAckElicitingPacketsGetALazyAck() {
        PacketSpace space = new PacketSpace(SpaceId.DATA, 0);
        for (long pn = 0; pn < PendingAcks.LAZY_ACK_THRESHOLD; pn++) {
            space.onPacketReceived(MS, pn, false);
        }
        space.pendingAcks().maybeAckNonEliciting();
        assertFalse(space.pendingAcks().canSend());
        space.onPacketReceived(MS, 99, false);
        space.pendingAcks().maybeAckNonEliciting();
        assertTrue(space.pendingAcks().canSend());
    }

    @Test
    void ackFrameHasDescendingRangesAndScaledDelay() {
        PacketSpace space = new PacketSpace(SpaceId.DATA, 0);
        for (long pn : new long[] {0, 1, 2, 5, 6, 9}) {
            space.onPacketReceived(10 * MS, pn, true);
        }
        Frame.Ack ack = space.pendingAcks().ackFrame(10 * MS + 800_000, 3, null);
        assertEquals(List.of(new Frame.AckRange(9, 9), new Frame.AckRange(5, 6), new Frame.AckRange(0, 2)), ack.ranges());
        assertEquals(800 >> 3, ack.ackDelay(), "800 us at exponent 3");
        assertNull(ack.ecn());
        // Once the peer acknowledged our ACK of up to 5, those ranges go
        space.pendingAcks().subtractBelow(5);
        ack = space.pendingAcks().ackFrame(10 * MS, 3, space.ecnCounters());
        assertEquals(List.of(new Frame.AckRange(9, 9), new Frame.AckRange(6, 6)), ack.ranges());
        assertEquals(new Frame.EcnCounts(0, 0, 0), ack.ecn());
    }

    @Test
    void ackRangesAreBounded() {
        PendingAcks acks = new PendingAcks();
        for (long pn = 0; pn < 2 * PendingAcks.MAX_ACK_BLOCKS; pn++) {
            acks.insertOne(pn * 2, MS);
        }
        assertEquals(PendingAcks.MAX_ACK_BLOCKS, acks.ranges().size());
        assertEquals(2 * PendingAcks.MAX_ACK_BLOCKS, acks.ranges().min(), "the oldest ranges were dropped");
    }

    @Test
    void ackFrequencyThresholds() {
        PendingAcks acks = new PendingAcks();
        acks.setAckFrequencyParams(new Frame.AckFrequency(0, 3, 50_000, 0));
        Dedup dedup = new Dedup();
        for (long pn : new long[] {0, 1, 2, 5}) {
            dedup.insert(pn);
            acks.insertOne(pn, MS);
            acks.packetReceived(MS, pn, true, dedup);
            if (pn < 5) {
                assertFalse(acks.canSend(), "reordering threshold 0 ignores gaps");
            }
        }
        assertTrue(acks.canSend(), "four packets exceed the threshold of three");
    }

    @Test
    void ecnCountsAreValidated() {
        PacketSpace space = new PacketSpace(SpaceId.DATA, 0);
        assertFalse(space.detectEcn(2, new Frame.EcnCounts(2, 0, 0)));
        assertTrue(space.detectEcn(1, new Frame.EcnCounts(2, 0, 1)), "CE increased");
        assertThrows(IllegalArgumentException.class, () -> space.detectEcn(1, new Frame.EcnCounts(1, 0, 1)),
                "regression");
        assertThrows(IllegalArgumentException.class, () -> space.detectEcn(3, new Frame.EcnCounts(3, 0, 1)),
                "bleaching");
        assertThrows(IllegalArgumentException.class, () -> space.detectEcn(1, new Frame.EcnCounts(2, 1, 1)),
                "ECT(1) was never sent");
        space.onEcnReceived(3);
        assertEquals(new Frame.EcnCounts(0, 0, 1), space.ecnCounters());
        assertFalse(space.pendingAcks().canSend(), "nothing to acknowledge yet");
    }

    @Test
    void nonAckElicitingTailIsBounded() {
        PacketSpace space = new PacketSpace(SpaceId.DATA, 0);
        space.sent(0, SentPacket.of(0, 1200, true));
        SentPacket forgotten = null;
        long pn = 1;
        for (; pn <= PacketSpace.MAX_UNACKED_NON_ACK_ELICITING_TAIL + 1; pn++) {
            assertNull(space.sent(pn, SentPacket.of(0, 0, false)));
        }
        forgotten = space.sent(pn, SentPacket.of(0, 0, false));
        assertEquals(0, forgotten.size());
        assertTrue(space.sentPackets().get(0) != null, "the ack-eliciting packet stays");
        assertNull(space.sentPackets().get(1), "the oldest of the tail goes");
    }

    @Test
    void probeResendsTheOldestPacketsFrames() {
        PacketSpace space = new PacketSpace(SpaceId.HANDSHAKE, 0);
        StreamsState streams = StreamsStateTest.make(Side.CLIENT);
        Retransmits frames = new Retransmits();
        frames.handshakeDone = true;
        space.sent(0, new SentPacket(0, 100, true, -1, frames, List.of()));
        space.lossProbes = 1;
        space.maybeQueueProbe(false, false, streams);
        assertTrue(space.pending().handshakeDone);
        assertNull(space.sentPackets().get(0).retransmits(), "taken so it is not resent twice");
        assertFalse(space.pingPending());

        // With nothing to resend, a PING
        PacketSpace empty = new PacketSpace(SpaceId.INITIAL, 0);
        empty.lossProbes = 1;
        empty.maybeQueueProbe(false, false, streams);
        assertTrue(empty.pingPending());
        assertTrue(empty.canSend(streams).other());
    }

    @Test
    void packetNumberFilterSkipsAndRejectsAcksOfSkippedNumbers() throws Exception {
        Random random = new Random(42);
        PacketNumberFilter filter = new PacketNumberFilter(random);
        PacketSpace space = new PacketSpace(SpaceId.DATA, 0);
        long expected = 0;
        long skipped = -1;
        while (skipped < 0) {
            long peek = filter.peek(space);
            long pn = filter.allocate(random, space);
            assertEquals(peek, pn);
            if (pn != expected) {
                skipped = expected;
            }
            expected = pn + 1;
        }
        assertTrue(skipped < 64, "the first skip is below 64");
        if (skipped > 0) {
            filter.checkAck(SpaceId.DATA, 0, skipped - 1);
        }
        final long s = skipped;
        QuicException e = assertThrows(QuicException.class, () -> filter.checkAck(SpaceId.DATA, s, s));
        assertEquals(QuicException.PROTOCOL_VIOLATION, e.code());
        filter.checkAck(SpaceId.HANDSHAKE, s, s); // other spaces never skip
    }

    // ---- SentPackets, ported from sent_packets.rs ----

    private static SentPacket packet(int size) {
        return SentPacket.of(0, size, false);
    }

    @Test
    void storageIsBoundedByLivePackets() {
        SentPackets packets = new SentPackets();
        packets.insert(0, packet(1200));
        for (long pn = 1; pn < 4096; pn++) {
            packets.insert(pn, packet(0));
            packets.remove(pn);
        }
        assertEquals(1, packets.size());
        assertTrue(packets.hasInFlight());
        assertEquals(1200, packets.get(0).size());
    }

    @Test
    void insertGetAndOrder() {
        SentPackets m = new SentPackets();
        for (long pn = 3; pn <= 6; pn++) {
            m.insert(pn, packet((int) pn * 10));
        }
        assertEquals(30, m.get(3).size());
        assertEquals(60, m.get(6).size());
        assertNull(m.get(2));
        assertNull(m.get(7));
        assertEquals(List.of(30, 40, 50, 60), m.values().stream().map(SentPacket::size).toList());
    }

    @Test
    void rangeBounds() {
        SentPackets m = new SentPackets();
        for (long pn = 10; pn < 20; pn++) {
            m.insert(pn, packet((int) pn));
        }
        assertEquals(List.of(12L, 13L, 14L), new ArrayList<>(m.range(12, 15).keySet()));
        Map.Entry<Long, SentPacket> after = m.higher(15);
        assertEquals(16, after.getKey());
        assertTrue(m.range(0, 5).isEmpty());
        assertTrue(m.range(100, 200).isEmpty());
        assertTrue(m.range(5, 0).isEmpty());
    }

    @Test
    void removeMiddleLeavesHole() {
        SentPackets m = new SentPackets();
        for (long pn = 0; pn < 5; pn++) {
            m.insert(pn, packet((int) pn));
        }
        assertEquals(2, m.remove(2).size());
        assertNull(m.remove(2));
        assertEquals(List.of(0L, 1L, 3L, 4L), new ArrayList<>(m.range(0, 100).keySet()));
        assertThrows(IllegalArgumentException.class, () -> m.insert(4, packet(1)), "numbers only increase");
    }

    @Test
    void tracksInFlight() {
        SentPackets m = new SentPackets();
        assertFalse(m.hasInFlight());
        m.insert(0, packet(0));
        assertFalse(m.hasInFlight());
        m.insert(1, packet(1200));
        m.insert(2, packet(1200));
        assertTrue(m.hasInFlight());
        m.remove(1);
        assertTrue(m.hasInFlight());
        m.remove(2);
        assertFalse(m.hasInFlight());
        m.insert(3, packet(1200));
        assertEquals(2, m.clear().size());
        assertFalse(m.hasInFlight());
    }
}
