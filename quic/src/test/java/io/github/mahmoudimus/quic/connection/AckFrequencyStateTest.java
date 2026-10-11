/*
 * The first two tests are ported from quinn-proto src/connection/ack_frequency.rs (tests)
 * (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.frame.Frame;
import org.junit.jupiter.api.Test;

class AckFrequencyStateTest {

    private static final long MS = 1_000_000L;

    @Test
    void peerMinAckDelayCanExceedRtt() {
        AckFrequencyState state = new AckFrequencyState(100 * MS);
        // min_ack_delay 100000 us, max_ack_delay 100 ms
        assertEquals(100 * MS, state.candidateMaxAckDelay(5 * MS, -1, 100_000));
    }

    @Test
    void peerMinAckDelayCanExceedRttWithLargeMax() {
        AckFrequencyState state = new AckFrequencyState(100 * MS);
        state.setPeerMaxAckDelay(200 * MS);
        assertEquals(100 * MS, state.candidateMaxAckDelay(5 * MS, -1, 100_000));
    }

    @Test
    void candidateIsBoundedByRttButNotBelow25Ms() {
        AckFrequencyState state = new AckFrequencyState(25 * MS);
        state.setPeerMaxAckDelay(200 * MS);
        assertEquals(80 * MS, state.candidateMaxAckDelay(80 * MS, -1, -1));
        assertEquals(25 * MS, state.candidateMaxAckDelay(5 * MS, -1, -1));
        assertEquals(10 * MS, state.candidateMaxAckDelay(80 * MS, 10 * MS, -1), "a configured delay");
    }

    @Test
    void requestedDelayCountsForPtoUntilAcknowledged() {
        AckFrequencyState state = new AckFrequencyState(25 * MS);
        assertTrue(state.shouldSendAckFrequency(100 * MS, -1, -1), "always at first");
        assertEquals(0, state.nextSequenceNumber());
        state.ackFrequencySent(7, 60 * MS);
        assertEquals(60 * MS, state.maxAckDelayForPto());
        assertFalse(state.shouldSendAckFrequency(60 * MS, 60 * MS, -1));
        assertTrue(state.shouldSendAckFrequency(100 * MS, 100 * MS, -1), "a 67% change");
        state.onAcked(6);
        assertEquals(25 * MS, state.peerMaxAckDelay());
        state.onAcked(7);
        assertEquals(60 * MS, state.peerMaxAckDelay());
        assertEquals(60 * MS, state.maxAckDelayForPto());
    }

    @Test
    void receivedFramesUpdateThresholdsAndIgnoreStaleOnes() throws Exception {
        AckFrequencyState state = new AckFrequencyState(25 * MS);
        PendingAcks acks = new PendingAcks();
        assertTrue(state.ackFrequencyReceived(new Frame.AckFrequency(3, 5, 40_000, 0), acks));
        assertEquals(40 * MS, state.maxAckDelay());
        assertFalse(state.ackFrequencyReceived(new Frame.AckFrequency(3, 1, 10_000, 1), acks), "stale");
        assertEquals(40 * MS, state.maxAckDelay());
        QuicException e = assertThrows(QuicException.class,
                () -> state.ackFrequencyReceived(new Frame.AckFrequency(4, 1, 500, 1), acks));
        assertEquals(QuicException.PROTOCOL_VIOLATION, e.code());
    }
}
