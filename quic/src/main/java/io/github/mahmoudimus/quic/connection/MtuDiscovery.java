/*
 * Ported from quinn-proto src/connection/mtud.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.util.ArrayList;
import java.util.List;

/**
 * Datagram packetization layer path MTU discovery (DPLPMTUD, RFC 8899): probes larger packets in
 * the application data space by binary search, and detects MTU black holes from the pattern of
 * lost packets. Times are nanoseconds.
 *
 * <p>Probes are padded PING packets of the size {@link #pollTransmit} returns; an acknowledged
 * probe raises the MTU, and a probe lost three times lowers the next size tried. Lost probes do not
 * count as congestion.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class MtuDiscovery {

    /** Retransmissions of a lost probe before its size is deemed too big (RFC 8899 MAX_PROBES). */
    static final int MAX_PROBE_RETRANSMITS = 3;
    /** Suspicious loss bursts tolerated before declaring a black hole. */
    static final int BLACK_HOLE_THRESHOLD = 3;

    /** The current MTU: the largest UDP payload known to get through. */
    int currentMtu;
    /** The search state, or null if discovery is disabled. */
    final Enabled state;
    final BlackHoleDetector blackHoleDetector;

    private MtuDiscovery(int currentMtu, int minMtu, Enabled state) {
        this.currentMtu = currentMtu;
        this.state = state;
        this.blackHoleDetector = new BlackHoleDetector(minMtu);
    }

    /**
     * Enabled discovery.
     *
     * @param initialMtu the MTU to start from, at least {@code minMtu}
     * @param minMtu the MTU the path is assumed to support, 1200 for QUIC
     * @param peerMaxUdpPayloadSize the peer's {@code max_udp_payload_size} if already known (after
     *     a migration), or -1
     * @param config the configuration
     * @return the discovery state
     */
    public static MtuDiscovery enabled(int initialMtu, int minMtu, int peerMaxUdpPayloadSize,
            MtuDiscoveryConfig config) {
        if (initialMtu < minMtu) {
            throw new IllegalArgumentException("initial MTU " + initialMtu + " below minimum " + minMtu);
        }
        MtuDiscovery mtud = new MtuDiscovery(initialMtu, minMtu, new Enabled(config));
        if (peerMaxUdpPayloadSize >= 0) {
            mtud.onPeerMaxUdpPayloadSizeReceived(peerMaxUdpPayloadSize);
        }
        return mtud;
    }

    /**
     * Disabled discovery: the MTU stays fixed, except that a black hole still lowers it to the
     * minimum.
     *
     * @param mtu the fixed MTU
     * @param minMtu the minimum MTU
     * @return the discovery state
     */
    public static MtuDiscovery disabled(int mtu, int minMtu) {
        return new MtuDiscovery(mtu, minMtu, null);
    }

    /**
     * The current MTU.
     *
     * @return the largest UDP payload to send
     */
    public int currentMtu() {
        return currentMtu;
    }

    /**
     * The size of the next probe to send, if one is due.
     *
     * @param now the current time
     * @param nextPacketNumber the number the probe packet will have
     * @return the probe's UDP payload size, or -1 if no probe should be sent now
     */
    public int pollTransmit(long now, long nextPacketNumber) {
        return state == null ? -1 : state.pollTransmit(now, currentMtu, nextPacketNumber);
    }

    /**
     * Applies the peer's {@code max_udp_payload_size}, which caps the MTU and the search. It must
     * arrive before probing starts.
     *
     * @param peerMaxUdpPayloadSize the transport parameter
     */
    public void onPeerMaxUdpPayloadSizeReceived(int peerMaxUdpPayloadSize) {
        currentMtu = Math.min(currentMtu, peerMaxUdpPayloadSize);
        if (state != null) {
            if (state.phase == Phase.SEARCHING) {
                throw new IllegalStateException("Transport parameters received after MTU probing started");
            }
            state.peerMaxUdpPayloadSize = peerMaxUdpPayloadSize;
        }
    }

    /**
     * Records an acknowledged packet.
     *
     * @param space the packet's space; probes are only sent in the application data space
     * @param pn the packet number
     * @param length the packet's size
     * @return true if it was the in-flight probe, which raised the MTU
     */
    public boolean onAcked(SpaceId space, long pn, int length) {
        if (space != SpaceId.DATA) {
            return false;
        }
        int newMtu = state == null ? -1 : state.onProbeAcked(pn);
        if (newMtu >= 0) {
            currentMtu = newMtu;
            blackHoleDetector.onProbeAcked(pn, length);
            return true;
        }
        blackHoleDetector.onNonProbeAcked(pn, length);
        return false;
    }

    /**
     * The packet number of the probe in flight.
     *
     * @return the packet number, or -1 if none
     */
    public long inFlightMtuProbe() {
        return state != null && state.phase == Phase.SEARCHING ? state.search.inFlightProbe : -1;
    }

    /** Records that the in-flight probe was lost. */
    public void onProbeLost() {
        if (state != null) {
            state.onProbeLost();
        }
    }

    /**
     * Records a lost packet that was not a probe. Call {@link #blackHoleDetected} once the losses of
     * a batch are recorded.
     *
     * @param pn the packet number
     * @param length the packet's size
     */
    public void onNonProbeLost(long pn, int length) {
        blackHoleDetector.onNonProbeLost(pn, length);
    }

    /**
     * Ends the current loss burst and checks for a black hole. On a black hole the MTU drops to the
     * minimum and discovery pauses for the cooldown.
     *
     * @param now the current time
     * @return true if a black hole was detected
     */
    public boolean blackHoleDetected(long now) {
        if (!blackHoleDetector.blackHoleDetected()) {
            return false;
        }
        currentMtu = blackHoleDetector.minMtu;
        if (state != null) {
            state.onBlackHoleDetected(now);
        }
        return true;
    }

    /** Whether discovery finished and waits for its next run, for tests. */
    boolean isComplete() {
        return state != null && state.phase == Phase.COMPLETE;
    }

    enum Phase {
        /** Not started. */
        INITIAL,
        /** Searching for a larger MTU. */
        SEARCHING,
        /** Done until {@link Enabled#nextActivation}. */
        COMPLETE
    }

    /** The state of enabled discovery. */
    static final class Enabled {
        final MtuDiscoveryConfig config;
        Phase phase = Phase.INITIAL;
        long nextActivation;
        SearchState search;
        int peerMaxUdpPayloadSize = MtuDiscoveryConfig.MAX_UDP_PAYLOAD;

        Enabled(MtuDiscoveryConfig config) {
            this.config = config;
        }

        int pollTransmit(long now, int currentMtu, long nextPn) {
            if (phase == Phase.INITIAL) {
                startSearch(currentMtu);
            } else if (phase == Phase.COMPLETE) {
                if (now < nextActivation) {
                    return -1;
                }
                startSearch(currentMtu); // the next run is due
            }
            if (phase != Phase.SEARCHING) {
                return -1;
            }
            SearchState s = search;
            if (s.inFlightProbe >= 0) {
                return -1; // one probe at a time
            }
            // Retransmit a lost probe
            if (0 < s.lostProbeCount && s.lostProbeCount < MAX_PROBE_RETRANSMITS) {
                s.inFlightProbe = nextPn;
                return s.lastProbedMtu;
            }
            boolean lastProbeSucceeded = s.lostProbeCount == 0;
            if (!lastProbeSucceeded) {
                // Lost too often: the size is too big
                s.lostProbeCount = 0;
                s.inFlightProbe = -1;
            }
            int probe = s.nextMtuToProbe(lastProbeSucceeded);
            if (probe >= 0) {
                s.inFlightProbe = nextPn;
                s.lastProbedMtu = probe;
                return probe;
            }
            phase = Phase.COMPLETE;
            nextActivation = now + config.interval();
            return -1;
        }

        private void startSearch(int currentMtu) {
            search = new SearchState(currentMtu, peerMaxUdpPayloadSize, config);
            phase = Phase.SEARCHING;
        }

        int onProbeAcked(long pn) {
            if (phase == Phase.SEARCHING && search.inFlightProbe >= 0 && search.inFlightProbe == pn) {
                search.inFlightProbe = -1;
                search.lostProbeCount = 0;
                return search.lastProbedMtu;
            }
            return -1;
        }

        void onProbeLost() {
            // No longer searching, perhaps, after a black hole
            if (phase == Phase.SEARCHING) {
                search.inFlightProbe = -1;
                search.lostProbeCount++;
            }
        }

        void onBlackHoleDetected(long now) {
            phase = Phase.COMPLETE; // stop any search and reset the timer
            nextActivation = now + config.blackHoleCooldown();
        }
    }

    /** A binary search between a lower bound known to work and an upper bound. */
    static final class SearchState {
        int lowerBound;
        int upperBound;
        final int minimumChange;
        /** The size probed last; the lower bound counts as probed at the start. */
        int lastProbedMtu;
        /** The in-flight probe's packet number, or -1. */
        long inFlightProbe = -1;
        /** Lost probes at the current size. */
        int lostProbeCount;

        SearchState(int lowerBound, int peerMaxUdpPayloadSize, MtuDiscoveryConfig config) {
            lowerBound = Math.min(lowerBound, peerMaxUdpPayloadSize);
            this.lowerBound = lowerBound;
            this.upperBound = Math.clamp(config.upperBound(), lowerBound, peerMaxUdpPayloadSize);
            this.minimumChange = config.minimumChange();
            this.lastProbedMtu = lowerBound;
        }

        /** The next size to probe, or -1 when the search is done. */
        int nextMtuToProbe(boolean lastProbeSucceeded) {
            if (lastProbeSucceeded) {
                lowerBound = lastProbedMtu;
            } else {
                upperBound = lastProbedMtu - 1;
            }
            int nextMtu = (lowerBound + upperBound) / 2;
            if (Math.abs(nextMtu - lastProbedMtu) < minimumChange) {
                // Probe the upper bound last if it is far enough, or it would never be reached
                if (upperBound - lastProbedMtu >= minimumChange) {
                    return upperBound;
                }
                return -1;
            }
            return nextMtu;
        }
    }

    /**
     * Judges whether losses suggest the MTU dropped. Contiguous lost packets form a burst; a burst is
     * suspicious unless it holds a packet no bigger than the minimum MTU, or one no bigger than a
     * packet acknowledged after it was sent, since such losses are not explained by a smaller MTU.
     * More than {@value MtuDiscovery#BLACK_HOLE_THRESHOLD} suspicious bursts make a black hole.
     */
    static final class BlackHoleDetector {
        /** The smallest packet size of each suspicious burst. */
        private final List<Integer> suspiciousLossBursts = new ArrayList<>(BLACK_HOLE_THRESHOLD + 1);
        /** The burst being aggregated: its last packet number (or -1) and smallest size. */
        private long currentLatestNonProbe = -1;
        private int currentSmallestPacketSize;
        /** The biggest packet acknowledged more recently than any suspicious burst. */
        private long largestPostLossPacket;
        /** The larger of the minimum MTU and that packet's size. */
        private int ackedMtu;
        final int minMtu;

        BlackHoleDetector(int minMtu) {
            this.minMtu = minMtu;
            this.ackedMtu = minMtu;
        }

        void onProbeAcked(long pn, int len) {
            // Probes are bigger than the old MTU, so no earlier burst is suspicious
            suspiciousLossBursts.clear();
            ackedMtu = len;
            largestPostLossPacket = pn;
        }

        void onNonProbeAcked(long pn, int len) {
            if (len < ackedMtu) {
                return;
            }
            if (len == ackedMtu) {
                // Bursts before this delivery cannot be explained by a smaller MTU either
                largestPostLossPacket = Math.max(largestPostLossPacket, pn);
                return;
            }
            ackedMtu = len;
            largestPostLossPacket = pn;
            // Bursts of smaller packets are retroactively not suspicious
            suspiciousLossBursts.removeIf(smallest -> smallest <= len);
        }

        void onNonProbeLost(long pn, int len) {
            // A gap in packet numbers starts a new burst
            if (currentLatestNonProbe >= 0 && pn - currentLatestNonProbe != 1) {
                finishLossBurst();
            }
            currentSmallestPacketSize = currentLatestNonProbe >= 0 ? Math.min(currentSmallestPacketSize, len) : len;
            currentLatestNonProbe = pn;
        }

        boolean blackHoleDetected() {
            finishLossBurst();
            if (suspiciousLossBursts.size() <= BLACK_HOLE_THRESHOLD) {
                return false;
            }
            suspiciousLossBursts.clear();
            return true;
        }

        private void finishLossBurst() {
            if (currentLatestNonProbe < 0) {
                return;
            }
            long latest = currentLatestNonProbe;
            int smallest = currentSmallestPacketSize;
            currentLatestNonProbe = -1;
            if (smallest <= minMtu || (latest < largestPostLossPacket && smallest <= ackedMtu)) {
                return; // not suspicious
            }
            // A suspicious burst after the largest acknowledged packet invalidates it
            if (latest > largestPostLossPacket) {
                ackedMtu = minMtu;
            }
            if (suspiciousLossBursts.size() <= BLACK_HOLE_THRESHOLD) {
                suspiciousLossBursts.add(smallest);
                return;
            }
            // Keep only the most suspicious bursts
            int minIndex = 0;
            for (int i = 1; i < suspiciousLossBursts.size(); i++) {
                if (suspiciousLossBursts.get(i) < suspiciousLossBursts.get(minIndex)) {
                    minIndex = i;
                }
            }
            if (suspiciousLossBursts.get(minIndex) < smallest) {
                suspiciousLossBursts.set(minIndex, smallest);
            }
        }

        int suspiciousLossBurstCount() {
            return suspiciousLossBursts.size();
        }

        long largestNonProbeLost() {
            return currentLatestNonProbe;
        }
    }
}
