/*
 * Ported from quinn-proto src/connection/mtud.rs (tests) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class MtuDiscoveryTest {

    private static final long SECOND = 1_000_000_000L;
    private static final long NOW = 1_000 * SECOND;
    private static final int THRESHOLD = MtuDiscovery.BLACK_HOLE_THRESHOLD;

    private static MtuDiscovery defaultMtud() {
        return MtuDiscovery.enabled(1200, 1200, -1, MtuDiscoveryConfig.DEFAULT);
    }

    /** Drives discovery to completion over a link with a payload size limit. */
    private static List<Integer> driveToCompletion(MtuDiscovery mtud, long now, int linkLimit) {
        List<Integer> probed = new ArrayList<>();
        for (long probePn = 1; probePn < 100; probePn++) {
            int result = mtud.pollTransmit(now, probePn);
            if (mtud.isComplete()) {
                break;
            }
            assertTrue(result >= 0, "a probe is sent");
            probed.add(result);
            if (result <= linkLimit) {
                mtud.onAcked(SpaceId.DATA, probePn, result);
            } else {
                mtud.onProbeLost();
            }
        }
        return probed;
    }

    @Test
    void blackHoleDetectorIgnoresBurstContainingNonSuspiciousPacket() {
        MtuDiscovery mtud = defaultMtud();
        mtud.onNonProbeLost(2, 1300);
        mtud.onNonProbeLost(3, 1300);
        assertEquals(3, mtud.blackHoleDetector.largestNonProbeLost());
        assertEquals(0, mtud.blackHoleDetector.suspiciousLossBurstCount());
        mtud.onNonProbeLost(4, 800);
        assertFalse(mtud.blackHoleDetected(NOW));
        assertEquals(-1, mtud.blackHoleDetector.largestNonProbeLost());
        assertEquals(0, mtud.blackHoleDetector.suspiciousLossBurstCount());
    }

    @Test
    void blackHoleDetectorCountsBurstContainingOnlySuspiciousPackets() {
        MtuDiscovery mtud = defaultMtud();
        mtud.onNonProbeLost(2, 1300);
        mtud.onNonProbeLost(3, 1300);
        assertFalse(mtud.blackHoleDetected(NOW));
        assertEquals(-1, mtud.blackHoleDetector.largestNonProbeLost());
        assertEquals(1, mtud.blackHoleDetector.suspiciousLossBurstCount());
    }

    @Test
    void blackHoleDetectorIgnoresEmptyBurst() {
        MtuDiscovery mtud = defaultMtud();
        assertFalse(mtud.blackHoleDetected(NOW));
        assertEquals(0, mtud.blackHoleDetector.suspiciousLossBurstCount());
    }

    @Test
    void mtuDiscoveryDisabledDoesNothing() {
        MtuDiscovery mtud = MtuDiscovery.disabled(1200, 1200);
        assertEquals(-1, mtud.pollTransmit(NOW, 0));
    }

    @Test
    void mtuDiscoveryDisabledLostFourPacketBurstsTriggersBlackHoleDetection() {
        MtuDiscovery mtud = MtuDiscovery.disabled(1400, 1250);
        for (int i = 0; i < 4; i++) {
            mtud.onNonProbeLost(i * 2L, 1300); // never contiguous: one burst each
        }
        assertTrue(mtud.blackHoleDetected(NOW));
        assertEquals(1250, mtud.currentMtu());
        assertNull(mtud.state);
    }

    @Test
    void mtuDiscoveryLostTwoPacketBurstsDoesNotTriggerBlackHoleDetection() {
        MtuDiscovery mtud = defaultMtud();
        for (int i = 0; i < 2; i++) {
            mtud.onNonProbeLost(i, 1300);
            assertFalse(mtud.blackHoleDetected(NOW));
        }
    }

    @Test
    void mtuDiscoveryLostFourPacketBurstsTriggersBlackHoleDetectionAndResetsTimer() {
        MtuDiscovery mtud = defaultMtud();
        for (int i = 0; i < 4; i++) {
            mtud.onNonProbeLost(i * 2L, 1300);
        }
        assertTrue(mtud.blackHoleDetected(NOW));
        assertEquals(1200, mtud.currentMtu());
        assertEquals(MtuDiscovery.Phase.COMPLETE, mtud.state.phase);
        assertEquals(NOW + 60 * SECOND, mtud.state.nextActivation);
    }

    @Test
    void mtuDiscoveryAfterCompleteReactivatesWhenIntervalElapsed() {
        MtuDiscovery mtud = MtuDiscovery.enabled(1200, 1200, -1, MtuDiscoveryConfig.DEFAULT.withUpperBound(9000));
        driveToCompletion(mtud, NOW, 1500);
        // Polling right after completion sends nothing
        assertEquals(-1, mtud.pollTransmit(NOW, 42));
        assertTrue(mtud.isComplete());
        assertEquals(1471, mtud.currentMtu());
        // After the interval, a new search starts from the current MTU
        assertEquals(5235, mtud.pollTransmit(NOW + 600 * SECOND, 43));
        assertEquals(MtuDiscovery.Phase.SEARCHING, mtud.state.phase);
        assertEquals(1471, mtud.state.search.lowerBound);
        assertEquals(9000, mtud.state.search.upperBound);
    }

    @Test
    void mtuDiscoveryLostThreeProbesLowersProbeSize() {
        MtuDiscovery mtud = defaultMtud();
        int[] sizes = new int[4];
        for (int i = 0; i < 4; i++) {
            sizes[i] = mtud.pollTransmit(NOW, i);
            assertTrue(sizes[i] >= 0, "no probe returned for packet " + i);
            mtud.onProbeLost();
        }
        // The first probe is retransmitted twice, then the size drops
        assertEquals(sizes[0], sizes[1]);
        assertEquals(sizes[0], sizes[2]);
        assertTrue(sizes[3] < sizes[0]);
        assertEquals(sizes[0] - (sizes[0] - 1200) / 2 - 1, sizes[3]);
    }

    @Test
    void mtuDiscoveryWithPeerMaxUdpPayloadSizeClampsUpperBound() {
        MtuDiscovery mtud = defaultMtud();
        mtud.onPeerMaxUdpPayloadSizeReceived(1300);
        List<Integer> probed = driveToCompletion(mtud, NOW, 1500);
        assertEquals(1300, mtud.state.peerMaxUdpPayloadSize);
        assertEquals(1300, mtud.currentMtu());
        assertEquals(List.of(1250, 1275, 1300), probed);
        assertTrue(mtud.isComplete());
    }

    @Test
    void mtuDiscoveryWithPreviousPeerMaxUdpPayloadSizeClampsUpperBound() {
        MtuDiscovery mtud = MtuDiscovery.enabled(1500, 1200, 1400, MtuDiscoveryConfig.DEFAULT);
        assertEquals(1400, mtud.currentMtu());
        assertEquals(1400, mtud.state.peerMaxUdpPayloadSize);
        List<Integer> probed = driveToCompletion(mtud, NOW, 1500);
        assertEquals(1400, mtud.currentMtu());
        assertTrue(probed.isEmpty());
        assertTrue(mtud.isComplete());
    }

    @Test
    void mtuDiscoveryWithPeerMaxUdpPayloadSizeDuringSearchFails() {
        MtuDiscovery mtud = defaultMtud();
        assertTrue(mtud.pollTransmit(NOW, 0) >= 0);
        assertEquals(MtuDiscovery.Phase.SEARCHING, mtud.state.phase);
        assertThrows(IllegalStateException.class, () -> mtud.onPeerMaxUdpPayloadSizeReceived(1300));
    }

    @Test
    void mtuDiscoveryWith1500Limit() {
        MtuDiscovery mtud = defaultMtud();
        List<Integer> probed = driveToCompletion(mtud, NOW, 1500);
        assertEquals(List.of(1326, 1389, 1420, 1452), probed);
        assertEquals(1452, mtud.currentMtu());
        assertTrue(mtud.isComplete());
    }

    @Test
    void mtuDiscoveryWith1500LimitAnd10000UpperBound() {
        MtuDiscovery mtud = MtuDiscovery.enabled(1200, 1200, -1, MtuDiscoveryConfig.DEFAULT.withUpperBound(10_000));
        List<Integer> probed = driveToCompletion(mtud, NOW, 1500);
        assertEquals(List.of(5600, 5600, 5600, 3399, 3399, 3399, 2299, 2299, 2299, 1749, 1749, 1749, 1474, 1611, 1611,
                1611, 1542, 1542, 1542, 1507, 1507, 1507), probed);
        assertEquals(1474, mtud.currentMtu());
        assertTrue(mtud.isComplete());
    }

    @Test
    void mtuDiscoveryNoLostProbesFindsMaximumUdpPayload() {
        MtuDiscovery mtud = MtuDiscovery.enabled(1200, 1200, -1,
                MtuDiscoveryConfig.DEFAULT.withUpperBound(MtuDiscoveryConfig.MAX_UDP_PAYLOAD));
        driveToCompletion(mtud, NOW, 65535);
        assertEquals(65527, mtud.currentMtu());
        assertTrue(mtud.isComplete());
    }

    @Test
    void mtuDiscoveryLostHalfOfProbesFindsMaximumUdpPayload() {
        MtuDiscovery mtud = MtuDiscovery.enabled(1200, 1200, -1,
                MtuDiscoveryConfig.DEFAULT.withUpperBound(MtuDiscoveryConfig.MAX_UDP_PAYLOAD));
        int iterations = 0;
        for (long i = 1; i < 100; i++) {
            iterations++;
            long probePn = i * 2 - 1;
            long otherPn = i * 2;
            int result = mtud.pollTransmit(NOW, probePn);
            if (mtud.isComplete()) {
                break;
            }
            assertTrue(result >= 0);
            assertTrue(mtud.inFlightMtuProbe() >= 0);
            // Nothing else to send while the probe is in flight
            assertEquals(-1, mtud.pollTransmit(NOW, otherPn));
            if (i % 2 == 0) {
                mtud.onAcked(SpaceId.DATA, probePn, result);
            } else {
                mtud.onProbeLost();
            }
        }
        assertEquals(25, iterations);
        assertEquals(65527, mtud.currentMtu());
        assertTrue(mtud.isComplete());
    }

    @Test
    void searchStateLowerBoundHigherThanUpperBoundClampsUpperBound() {
        MtuDiscovery.SearchState state = new MtuDiscovery.SearchState(1500, 65535, MtuDiscoveryConfig.DEFAULT.withUpperBound(1400));
        assertEquals(1500, state.lowerBound);
        assertEquals(1500, state.upperBound);
    }

    @Test
    void searchStateLowerBoundHigherThanPeerMaxUdpPayloadSizeClampsLowerBound() {
        MtuDiscovery.SearchState state = new MtuDiscovery.SearchState(1500, 1300, MtuDiscoveryConfig.DEFAULT.withUpperBound(9000));
        assertEquals(1300, state.lowerBound);
        assertEquals(1300, state.upperBound);
    }

    @Test
    void searchStateUpperBoundHigherThanPeerMaxUdpPayloadSizeClampsUpperBound() {
        MtuDiscovery.SearchState state = new MtuDiscovery.SearchState(1200, 1450, MtuDiscoveryConfig.DEFAULT.withUpperBound(9000));
        assertEquals(1200, state.lowerBound);
        assertEquals(1450, state.upperBound);
    }

    @Test
    void simpleBlackHoleDetection() {
        MtuDiscovery.BlackHoleDetector bhd = new MtuDiscovery.BlackHoleDetector(1200);
        bhd.onNonProbeAcked((THRESHOLD + 1) * 2L, 1300);
        for (int i = 0; i < THRESHOLD; i++) {
            bhd.onNonProbeLost(i * 2L, 1400);
        }
        assertFalse(bhd.blackHoleDetected(), "not before THRESHOLD + 1 bursts");
        bhd.onNonProbeLost(THRESHOLD * 2L, 1400);
        assertTrue(bhd.blackHoleDetected());
    }

    @Test
    void nonSuspiciousBursts() {
        MtuDiscovery.BlackHoleDetector bhd = new MtuDiscovery.BlackHoleDetector(1200);
        bhd.onNonProbeAcked((THRESHOLD + 1) * 2L, 1500);
        for (int i = 0; i < THRESHOLD + 1; i++) {
            bhd.onNonProbeLost(i * 2L, 1400);
        }
        assertFalse(bhd.blackHoleDetected());
    }

    @Test
    void dynamicMtuReduction() {
        MtuDiscovery.BlackHoleDetector bhd = new MtuDiscovery.BlackHoleDetector(1200);
        bhd.onNonProbeAcked(0, 1500);
        for (int i = 0; i < THRESHOLD + 1; i++) {
            bhd.onNonProbeLost(i * 2L, 1400);
        }
        assertTrue(bhd.blackHoleDetected());
    }

    @Test
    void mixedNonSuspiciousBursts() {
        MtuDiscovery.BlackHoleDetector bhd = new MtuDiscovery.BlackHoleDetector(1200);
        bhd.onNonProbeAcked((THRESHOLD + 1) * 3L, 1400);
        for (int i = 0; i < THRESHOLD + 1; i++) {
            bhd.onNonProbeLost(i * 3L, 1500);
            bhd.onNonProbeLost(i * 3L + 1, 1300);
        }
        assertFalse(bhd.blackHoleDetected());
    }

    @Test
    void burstsCountOnce() {
        MtuDiscovery.BlackHoleDetector bhd = new MtuDiscovery.BlackHoleDetector(1200);
        bhd.onNonProbeAcked((THRESHOLD + 1) * 3L, 1400);
        for (int i = 0; i < THRESHOLD; i++) {
            bhd.onNonProbeLost(i * 3L, 1500);
            bhd.onNonProbeLost(i * 3L + 1, 1500);
        }
        assertFalse(bhd.blackHoleDetected());
        bhd.onNonProbeLost(THRESHOLD * 3L, 1500);
        assertTrue(bhd.blackHoleDetected());
    }

    @Test
    void interleavedBursts() {
        MtuDiscovery.BlackHoleDetector bhd = new MtuDiscovery.BlackHoleDetector(1200);
        bhd.onNonProbeAcked((THRESHOLD + 1) * 4L, 1400);
        for (int i = 0; i < THRESHOLD + 1; i++) {
            bhd.onNonProbeLost(i * 4L, 1500);
            bhd.onNonProbeLost(i * 4L + 2, 1300);
        }
        assertTrue(bhd.blackHoleDetected());
    }

    @Test
    void suspiciousAfterAcked() {
        MtuDiscovery.BlackHoleDetector bhd = new MtuDiscovery.BlackHoleDetector(1200);
        bhd.onNonProbeAcked((THRESHOLD + 1) * 2L, 1400);
        for (int i = 0; i < THRESHOLD + 1; i++) {
            bhd.onNonProbeLost(i * 2L, 1300);
        }
        assertFalse(bhd.blackHoleDetected(), "1300 byte losses before a 1400 byte delivery are not suspicious");
        for (int i = 0; i < THRESHOLD + 1; i++) {
            bhd.onNonProbeLost((THRESHOLD + 1L + i) * 2, 1300);
        }
        assertTrue(bhd.blackHoleDetected(), "1300 byte losses after a 1400 byte delivery are suspicious");
    }

    @Test
    void equalSizeDeliveryClearsPrecedingBursts() {
        MtuDiscovery.BlackHoleDetector bhd = new MtuDiscovery.BlackHoleDetector(1200);
        bhd.onNonProbeAcked(0, 1400);
        bhd.onNonProbeAcked((THRESHOLD + 1) * 2L, 1400);
        for (int i = 0; i < THRESHOLD + 1; i++) {
            bhd.onNonProbeLost(i * 2L + 1, 1400);
        }
        assertFalse(bhd.blackHoleDetected(), "full-size losses before a full-size delivery are not suspicious");
        for (int i = 0; i < THRESHOLD + 1; i++) {
            bhd.onNonProbeLost((THRESHOLD + 1L + i) * 2 + 1, 1400);
        }
        assertTrue(bhd.blackHoleDetected(), "full-size losses after the last full-size delivery are suspicious");
    }

    @Test
    void retroactivelyNonSuspicious() {
        MtuDiscovery.BlackHoleDetector bhd = new MtuDiscovery.BlackHoleDetector(1200);
        for (int i = 0; i < THRESHOLD; i++) {
            bhd.onNonProbeLost(i * 2L, 1400);
        }
        bhd.onNonProbeAcked(THRESHOLD * 2L, 1400);
        bhd.onNonProbeLost(THRESHOLD * 2L + 1, 1400);
        assertFalse(bhd.blackHoleDetected());
    }
}
