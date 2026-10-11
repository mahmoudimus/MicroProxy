/*
 * Ported from quinn-proto src/congestion/bbr/mod.rs (Apache-2.0), changed to follow
 * draft-cardwell-iccrg-bbr-congestion-control where quinn's port does not: see the class comment.
 */
package io.github.mahmoudimus.quic.congestion;

import java.util.Objects;
import java.util.SplittableRandom;
import java.util.random.RandomGenerator;

/**
 * A BBR congestion controller, experimental as in quinn: it models the path's bottleneck bandwidth
 * and minimum RTT instead of reacting to loss, aiming at less buffer bloat and better throughput on
 * paths with a high bandwidth-delay product. quinn's port, which this follows, is based on a BBRv1
 * sender ({@code bbr_sender.cc}) and draft-cardwell-iccrg-bbr-congestion-control.
 *
 * <p>The controller moves through four {@linkplain Mode modes}: {@link Mode#STARTUP} doubles the
 * sending rate each round trip until the bandwidth estimate stops growing by 25% for three rounds
 * (or a loss happens in that round), {@link Mode#DRAIN} empties the queue built up doing so, and
 * {@link Mode#PROBE_BW} cycles its pacing gain through 1.25, 0.75 and six rounds of 1.0 around the
 * estimate. When no PROBE_RTT has started for ten seconds, {@link Mode#PROBE_RTT} cuts the window
 * to three quarters of the bandwidth-delay product for at least 200 ms to measure the minimum RTT
 * again. Losses put it in conservation, then growth, recovery until a round passes without any.
 *
 * <p>Where quinn's port departs from BBRv1, this one follows the draft: the bandwidth comes from
 * the connection's delivery rate samples ({@link #onRateSample}) through a max filter that expires
 * after ten round trips, the minimum RTT expires ten seconds after it was last measured or
 * refreshed and only then starts a PROBE_RTT, and STARTUP grows the window only below its target.
 * {@link #pacingRate()} reaches the connection's pacer, which quinn's ignores, so DRAIN drains.
 * The README of this module lists what still differs from the draft.
 *
 * <p>Rates are bytes per second; times are nanoseconds.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class Bbr implements Controller {

    /** BBR's modes. */
    public enum Mode {
        /** The start of the connection: the sending rate doubles each round trip. */
        STARTUP,
        /** After STARTUP found the bandwidth, a lower pacing rate drains the queue it built. */
        DRAIN,
        /** Cruising: the pacing gain cycles around the bandwidth estimate. */
        PROBE_BW,
        /** Sending slows for a while to empty the queue and measure the real minimum RTT. */
        PROBE_RTT
    }

    /** How losses limit the bytes in flight. */
    enum RecoveryState {
        /** No limit. */
        NOT_IN_RECOVERY,
        /** One more outstanding byte for each byte acknowledged. */
        CONSERVATION,
        /** Two more outstanding bytes for each byte acknowledged (slow start). */
        GROWTH;

        boolean inRecovery() {
            return this != NOT_IN_RECOVERY;
        }
    }

    /** The gain used in STARTUP, 2/ln(2). */
    static final float DEFAULT_HIGH_GAIN = 2.885f;
    /** The window gain after STARTUP. */
    static final float DERIVED_HIGH_CWND_GAIN = 2.0f;
    /** The cycle of pacing gains in PROBE_BW. */
    static final float[] PACING_GAIN = {1.25f, 0.75f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    /** The growth of the bandwidth estimate per round that keeps STARTUP going. */
    static final float STARTUP_GROWTH_TARGET = 1.25f;
    /** Rounds without that growth that end STARTUP. */
    static final int ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP = 3;
    /** How long a PROBE_RTT lasts once the bytes in flight are low enough. */
    static final long PROBE_RTT_TIME = 200_000_000L;
    /** How long a minimum RTT measurement stays valid without a PROBE_RTT. */
    static final long MIN_RTT_EXPIRY = 10_000_000_000L;
    /** The PROBE_RTT window, as a fraction of the bandwidth-delay product. */
    static final float MODERATE_PROBE_RTT_MULTIPLIER = 0.75f;
    /** Whether the PROBE_RTT window is a fraction of the BDP rather than the minimum window. */
    static final boolean PROBE_RTT_BASED_ON_BDP = true;
    /** Whether the 0.75 gain phase of PROBE_BW lasts until the bytes in flight reach the BDP. */
    static final boolean DRAIN_TO_TARGET = true;

    /** An unset time. */
    private static final long NONE = Long.MIN_VALUE;
    /** An unknown minimum RTT. */
    private static final long UNKNOWN = Long.MAX_VALUE;

    private final BbrConfig config;
    private long currentMtu;
    final BandwidthEstimation maxBandwidth;
    private long ackedBytes;
    private Mode mode = Mode.STARTUP;
    /** Bytes lost since the last batch of acknowledgements. */
    private long lostBytes;
    private RecoveryState recoveryState = RecoveryState.NOT_IN_RECOVERY;
    private long recoveryWindow;
    private boolean isAtFullBandwidth;
    private float pacingGain = DEFAULT_HIGH_GAIN;
    private final float highGain = DEFAULT_HIGH_GAIN;
    private final float drainGain = 1.0f / DEFAULT_HIGH_GAIN;
    private float cwndGain = DEFAULT_HIGH_GAIN;
    private final float highCwndGain = DEFAULT_HIGH_GAIN;
    private long lastCycleStart = NONE;
    private int currentCycleOffset;
    private long initCwnd;
    private long minCwnd;
    private long prevInFlightCount;
    private long exitProbeRttAt = NONE;
    /** The minimum RTT ({@code RTprop}), nanoseconds; {@link #UNKNOWN} before the first measurement. */
    private long minRtt = UNKNOWN;
    /** When the minimum RTT was last measured or refreshed ({@code rtprop_stamp}). */
    private long minRttStamp;
    /** Whether the minimum RTT had expired at the latest acknowledgements ({@code rtprop_expired}). */
    private boolean minRttExpired;
    /** The delivery rate sample of the acknowledgements being processed, or null. */
    private RateSample pendingSample;
    private boolean exitingQuiescence;
    private long pacingRate;
    private long maxAckedPacketNumber;
    private long maxSentPacketNumber;
    private long endRecoveryAtPacketNumber;
    private long cwnd;
    private long currentRoundTripEndPacketNumber;
    private long roundCount;
    private long bwAtLastRound;
    private long roundWithoutBwGain;
    // Ack aggregation state
    private final MinMax maxAckHeight;
    private long aggregationEpochStartTime = NONE;
    private long aggregationEpochBytes;
    private final RandomGenerator.SplittableGenerator random;

    /**
     * A controller in STARTUP.
     *
     * @param config the configuration
     * @param now the current time
     * @param currentMtu the path's maximum UDP payload size
     */
    public Bbr(BbrConfig config, long now, int currentMtu) {
        this(config, now, currentMtu, new SplittableRandom());
    }

    /**
     * A controller in STARTUP with a chosen source of randomness, for reproducible runs.
     *
     * @param config the configuration
     * @param now the current time
     * @param currentMtu the path's maximum UDP payload size
     * @param random picks where in the PROBE_BW gain cycle each PROBE_BW starts
     */
    public Bbr(BbrConfig config, long now, int currentMtu, RandomGenerator.SplittableGenerator random) {
        this.config = Objects.requireNonNull(config, "config");
        this.random = Objects.requireNonNull(random, "random");
        this.currentMtu = currentMtu;
        this.minRttStamp = now;
        this.maxBandwidth = new BandwidthEstimation();
        this.initCwnd = config.initialWindow();
        this.minCwnd = minWindow(currentMtu);
        this.cwnd = config.initialWindow();
        this.maxAckHeight = new MinMax();
    }

    private Bbr(Bbr o) {
        config = o.config;
        currentMtu = o.currentMtu;
        maxBandwidth = new BandwidthEstimation(o.maxBandwidth);
        ackedBytes = o.ackedBytes;
        mode = o.mode;
        lostBytes = o.lostBytes;
        recoveryState = o.recoveryState;
        recoveryWindow = o.recoveryWindow;
        isAtFullBandwidth = o.isAtFullBandwidth;
        pacingGain = o.pacingGain;
        cwndGain = o.cwndGain;
        lastCycleStart = o.lastCycleStart;
        currentCycleOffset = o.currentCycleOffset;
        initCwnd = o.initCwnd;
        minCwnd = o.minCwnd;
        prevInFlightCount = o.prevInFlightCount;
        exitProbeRttAt = o.exitProbeRttAt;
        minRtt = o.minRtt;
        minRttStamp = o.minRttStamp;
        minRttExpired = o.minRttExpired;
        pendingSample = o.pendingSample;
        exitingQuiescence = o.exitingQuiescence;
        pacingRate = o.pacingRate;
        maxAckedPacketNumber = o.maxAckedPacketNumber;
        maxSentPacketNumber = o.maxSentPacketNumber;
        endRecoveryAtPacketNumber = o.endRecoveryAtPacketNumber;
        cwnd = o.cwnd;
        currentRoundTripEndPacketNumber = o.currentRoundTripEndPacketNumber;
        roundCount = o.roundCount;
        bwAtLastRound = o.bwAtLastRound;
        roundWithoutBwGain = o.roundWithoutBwGain;
        maxAckHeight = new MinMax(o.maxAckHeight);
        aggregationEpochStartTime = o.aggregationEpochStartTime;
        aggregationEpochBytes = o.aggregationEpochBytes;
        random = o.random.split();
    }

    private static long minWindow(long currentMtu) {
        return 4 * currentMtu;
    }

    private void enterStartupMode() {
        mode = Mode.STARTUP;
        pacingGain = highGain;
        cwndGain = highCwndGain;
    }

    private void enterProbeBandwidthMode(long now) {
        mode = Mode.PROBE_BW;
        cwndGain = DERIVED_HIGH_CWND_GAIN;
        lastCycleStart = now;
        // A random offset into the gain cycle out of {0, 2..7}. 1 is excluded because then the
        // increased and decreased gains would not follow each other.
        int index = random.nextInt(PACING_GAIN.length - 1);
        if (index >= 1) {
            index++;
        }
        currentCycleOffset = index;
        pacingGain = PACING_GAIN[index];
    }

    private void updateRecoveryState(boolean isRoundStart) {
        // Exit recovery when there are no losses for a round
        if (hasLosses()) {
            endRecoveryAtPacketNumber = maxSentPacketNumber;
        }
        switch (recoveryState) {
            case NOT_IN_RECOVERY -> {
                // Enter conservation on the first loss
                if (hasLosses()) {
                    recoveryState = RecoveryState.CONSERVATION;
                    // calculateRecoveryWindow sets the recovery window from this
                    recoveryWindow = 0;
                    // Conservation is meant to last a whole round, so extend the current round as
                    // if it started now
                    currentRoundTripEndPacketNumber = maxSentPacketNumber;
                }
            }
            case GROWTH, CONSERVATION -> {
                if (recoveryState == RecoveryState.CONSERVATION && isRoundStart) {
                    recoveryState = RecoveryState.GROWTH;
                }
                // Exit recovery if appropriate
                if (!hasLosses() && maxAckedPacketNumber > endRecoveryAtPacketNumber) {
                    recoveryState = RecoveryState.NOT_IN_RECOVERY;
                }
            }
        }
    }

    private void updateGainCyclePhase(long now, long inFlight) {
        // In most cases the cycle advances after an RTT
        boolean shouldAdvanceGainCycling = lastCycleStart != NONE && now - lastCycleStart > minRtt;
        // With a pacing gain above 1 the connection probes for bandwidth by raising the bytes in
        // flight to at least pacing_gain * BDP. Make sure it reaches the target, as long as no
        // losses suggest the buffers cannot hold that much.
        if (pacingGain > 1.0f && !hasLosses() && prevInFlightCount < targetCwnd(pacingGain)) {
            shouldAdvanceGainCycling = false;
        }
        // With a pacing gain below 1 the connection drains the queue its probing may have built.
        // If the bytes in flight fall to the BDP early, the queue is drained: end this phase early.
        if (pacingGain < 1.0f && inFlight <= targetCwnd(1.0f)) {
            shouldAdvanceGainCycling = true;
        }
        if (shouldAdvanceGainCycling) {
            currentCycleOffset = (currentCycleOffset + 1) % PACING_GAIN.length;
            lastCycleStart = now;
            // Stay in low gain mode until the target BDP is hit; low gain mode is left as soon as
            // it is
            if (DRAIN_TO_TARGET
                    && pacingGain < 1.0f
                    && Math.abs(PACING_GAIN[currentCycleOffset] - 1.0f) < Math.ulp(1.0f)
                    && inFlight > targetCwnd(1.0f)) {
                return;
            }
            pacingGain = PACING_GAIN[currentCycleOffset];
        }
    }

    private void maybeExitStartupOrDrain(long now, long inFlight) {
        if (mode == Mode.STARTUP && isAtFullBandwidth) {
            mode = Mode.DRAIN;
            pacingGain = drainGain;
            cwndGain = highCwndGain;
        }
        if (mode == Mode.DRAIN && inFlight <= targetCwnd(1.0f)) {
            enterProbeBandwidthMode(now);
        }
    }

    /**
     * {@code BBRUpdateRTprop}: whether the minimum RTT has expired, ten seconds after it was last
     * measured or refreshed, and a new minimum from the sample, or any sample once it expired.
     */
    private void updateMinRtt(long now, RateSample sample) {
        minRttExpired = now - minRttStamp > MIN_RTT_EXPIRY;
        if (sample != null && sample.rtt() > 0 && (sample.rtt() <= minRtt || minRttExpired)) {
            minRtt = sample.rtt();
            minRttStamp = now;
        }
    }

    private void maybeEnterOrExitProbeRtt(long now, boolean isRoundStart, long bytesInFlight) {
        // BBRCheckProbeRTT: only an expired minimum RTT starts a PROBE_RTT
        if (minRttExpired && !exitingQuiescence && mode != Mode.PROBE_RTT) {
            mode = Mode.PROBE_RTT;
            pacingGain = 1.0f;
            // Do not decide when to exit PROBE_RTT until the bytes in flight are at the target
            // small value
            exitProbeRttAt = NONE;
        }
        if (mode == Mode.PROBE_RTT) {
            if (exitProbeRttAt == NONE) {
                // Once the window has reached the right size, schedule the exit. The window in
                // PROBE_RTT is the probe window, but allow an extra packet, since QUIC checks the
                // window before sending a packet.
                if (bytesInFlight < probeRttCwnd() + currentMtu) {
                    exitProbeRttAt = now + PROBE_RTT_TIME;
                }
            } else if (isRoundStart && now >= exitProbeRttAt) {
                // The minimum RTT was just measured at the lowest bytes in flight: it is fresh
                minRttStamp = now;
                minRttExpired = false;
                if (!isAtFullBandwidth) {
                    enterStartupMode();
                } else {
                    enterProbeBandwidthMode(now);
                }
            }
        }
        exitingQuiescence = false;
    }

    private long targetCwnd(float gain) {
        long bw = maxBandwidth.estimate();
        if (minRtt == UNKNOWN) {
            return initCwnd;
        }
        long bdp = saturatingMul(minRtt / 1_000, bw);
        long cwnd = (long) (((double) gain * (double) bdp) / 1_000_000.0);
        // The BDP estimate is zero until there are bandwidth samples
        if (cwnd == 0) {
            return initCwnd;
        }
        return Math.max(cwnd, minCwnd);
    }

    private long probeRttCwnd() {
        if (PROBE_RTT_BASED_ON_BDP) {
            return targetCwnd(MODERATE_PROBE_RTT_MULTIPLIER);
        }
        return minCwnd;
    }

    private void calculatePacingRate() {
        long bw = maxBandwidth.estimate();
        if (bw == 0) {
            return;
        }
        long targetRate = (long) (bw * (double) pacingGain);
        if (isAtFullBandwidth) {
            pacingRate = targetRate;
            return;
        }
        // Pace at the initial window per RTT as soon as there is an RTT measurement
        if (pacingRate == 0 && minRtt != UNKNOWN) {
            pacingRate = BandwidthEstimation.bwFromDelta(initCwnd, minRtt);
            return;
        }
        // Do not lower the pacing rate during STARTUP
        if (pacingRate < targetRate) {
            pacingRate = targetRate;
        }
    }

    private void calculateCwnd(long bytesAcked, long excessAcked) {
        if (mode == Mode.PROBE_RTT) {
            return;
        }
        long targetWindow = targetCwnd(cwndGain);
        if (isAtFullBandwidth) {
            // Add the largest recently measured ack aggregation
            targetWindow += maxAckHeight.get();
        } else {
            // Add the latest excess acknowledged. The window never falls in STARTUP, so this
            // makes a very local max filter.
            targetWindow += excessAcked;
        }
        // Rather than jumping to the target, grow the window towards it by the bytes acknowledged
        if (isAtFullBandwidth) {
            cwnd = Math.min(targetWindow, cwnd + bytesAcked);
        } else if (cwnd < targetWindow || ackedBytes < initCwnd) {
            // Before leaving STARTUP, grow towards the target and never lower the window. (quinn
            // compares the gain, not the window, with the target, so its window grows without
            // bound, even while application limited.)
            cwnd += bytesAcked;
        }
        // Enforce the lower limit
        if (cwnd < minCwnd) {
            cwnd = minCwnd;
        }
    }

    private void calculateRecoveryWindow(long bytesAcked, long bytesLost, long inFlight) {
        if (!recoveryState.inRecovery()) {
            return;
        }
        // Set up the initial recovery window
        if (recoveryWindow == 0) {
            recoveryWindow = Math.max(minCwnd, inFlight + bytesAcked);
            return;
        }
        // Remove losses from the recovery window, without going below zero
        if (recoveryWindow >= bytesLost) {
            recoveryWindow -= bytesLost;
        } else {
            recoveryWindow = currentMtu; // one maximum segment
        }
        // In CONSERVATION subtracting losses is enough; in GROWTH release the bytes acknowledged
        // too, for slow-start-like growth
        if (recoveryState == RecoveryState.GROWTH) {
            recoveryWindow += bytesAcked;
        }
        // Always allow sending at least the bytes acknowledged, and the minimum window
        recoveryWindow = Math.max(Math.max(recoveryWindow, inFlight + bytesAcked), minCwnd);
    }

    /** draft-cardwell-iccrg-bbr-congestion-control section 4.3.2.2. */
    private void checkIfFullBwReached(boolean appLimited) {
        if (appLimited) {
            return;
        }
        long target = (long) (bwAtLastRound * (double) STARTUP_GROWTH_TARGET);
        long bw = maxBandwidth.estimate();
        if (bw >= target) {
            bwAtLastRound = bw;
            roundWithoutBwGain = 0;
            maxAckHeight.reset();
            return;
        }
        roundWithoutBwGain++;
        if (roundWithoutBwGain >= ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP || recoveryState.inRecovery()) {
            isAtFullBandwidth = true;
        }
    }

    /**
     * Updates the ack aggregation state; returns the bytes acknowledged beyond what the bandwidth
     * estimate explains since the aggregation epoch started.
     */
    private long updateAckAggregationBytes(long newlyAckedBytes, long now, long round, long maxBw) {
        // The bytes expected to be delivered, if the bandwidth estimate is right
        long since = aggregationEpochStartTime == NONE ? 0 : Math.max(0, now - aggregationEpochStartTime);
        long expectedBytesAcked = saturatingMul(maxBw, since / 1_000) / 1_000_000;
        // Start a new aggregation epoch as soon as the ack rate is at most the bandwidth
        if (aggregationEpochBytes <= expectedBytesAcked) {
            aggregationEpochBytes = newlyAckedBytes;
            aggregationEpochStartTime = now;
            return 0;
        }
        // The extra bytes delivered beyond the bandwidth, counting the bytes just acknowledged
        // for stretch acks
        aggregationEpochBytes += newlyAckedBytes;
        long diff = aggregationEpochBytes - expectedBytesAcked;
        maxAckHeight.updateMax(round, diff);
        return diff;
    }

    private boolean hasLosses() {
        return lostBytes != 0;
    }

    @Override
    public void onSent(long now, long bytes, long lastPacketNumber) {
        maxSentPacketNumber = lastPacketNumber;
    }

    @Override
    public void onAck(long now, long sent, long bytes, boolean appLimited, RttEstimator rtt) {
        maxBandwidth.onAck(bytes);
        ackedBytes += bytes;
    }

    @Override
    public void onRateSample(long now, RateSample sample) {
        pendingSample = sample;
    }

    @Override
    public void onEndAcks(long now, long inFlight, boolean appLimited, long largestPacketNumberAcked) {
        RateSample sample = pendingSample;
        pendingSample = null;
        long bytesAcked = maxBandwidth.bytesAckedThisWindow();
        long excessAcked = updateAckAggregationBytes(bytesAcked, now, roundCount, maxBandwidth.estimate());
        maxBandwidth.endAcks();
        if (largestPacketNumberAcked >= 0) {
            maxAckedPacketNumber = largestPacketNumberAcked;
        }

        boolean isRoundStart = false;
        if (bytesAcked > 0) {
            isRoundStart = maxAckedPacketNumber > currentRoundTripEndPacketNumber;
            if (isRoundStart) {
                currentRoundTripEndPacketNumber = maxSentPacketNumber;
                roundCount++;
            }
        }
        // BBRUpdateBtlBw and BBRUpdateRTprop, after the round count as in the draft
        boolean sampleAppLimited = appLimited;
        if (sample != null) {
            maxBandwidth.onSample(roundCount, sample.deliveryRate(), sample.appLimited());
            sampleAppLimited = sample.appLimited();
        }
        updateMinRtt(now, sample);

        updateRecoveryState(isRoundStart);
        if (mode == Mode.PROBE_BW) {
            updateGainCyclePhase(now, inFlight);
        }
        if (isRoundStart && !isAtFullBandwidth) {
            checkIfFullBwReached(sampleAppLimited);
        }
        maybeExitStartupOrDrain(now, inFlight);
        maybeEnterOrExitProbeRtt(now, isRoundStart, inFlight);

        // With the model updated, compute the pacing rate and the congestion window
        calculatePacingRate();
        calculateCwnd(bytesAcked, excessAcked);
        calculateRecoveryWindow(bytesAcked, lostBytes, inFlight);

        prevInFlightCount = inFlight;
        lostBytes = 0;
    }

    @Override
    public void onCongestionEvent(long now, long sent, boolean persistentCongestion, boolean ecn, long lostBytes) {
        this.lostBytes += lostBytes;
    }

    @Override
    public void onMtuUpdate(int newMtu) {
        currentMtu = newMtu;
        minCwnd = minWindow(currentMtu);
        initCwnd = Math.max(config.initialWindow(), minCwnd);
        cwnd = Math.max(cwnd, minCwnd);
    }

    @Override
    public long window() {
        if (mode == Mode.PROBE_RTT) {
            return probeRttCwnd();
        } else if (recoveryState.inRecovery() && mode != Mode.STARTUP) {
            return Math.min(cwnd, recoveryWindow);
        }
        return cwnd;
    }

    @Override
    public ControllerMetrics metrics() {
        long bw = maxBandwidth.estimate();
        return new ControllerMetrics(window(), -1, saturatingMul(pacingRate, 8), bw != 0 ? saturatingMul(bw, 8) : -1);
    }

    @Override
    public Controller copy() {
        return new Bbr(this);
    }

    @Override
    public long initialWindow() {
        return config.initialWindow();
    }

    /**
     * The current mode.
     *
     * @return the mode
     */
    public Mode mode() {
        return mode;
    }

    /**
     * The bottleneck bandwidth estimate: the largest delivery rate sampled, not application
     * limited, over the last ten round trips.
     *
     * @return bytes per second, 0 before the first sample
     */
    public long bandwidthEstimate() {
        return maxBandwidth.estimate();
    }

    /**
     * The pacing rate: the bandwidth estimate times the pacing gain, or in STARTUP never less than
     * the initial window per minimum RTT.
     *
     * @return bytes per second, or -1 before the first bandwidth sample
     */
    @Override
    public long pacingRate() {
        return pacingRate > 0 ? pacingRate : -1;
    }

    /**
     * The minimum RTT the model uses.
     *
     * @return nanoseconds, 0 before the first measurement
     */
    public long minRtt() {
        return minRtt == UNKNOWN ? 0 : minRtt;
    }

    /**
     * Whether STARTUP found the bottleneck bandwidth.
     *
     * @return true once the bandwidth estimate stopped growing
     */
    public boolean isAtFullBandwidth() {
        return isAtFullBandwidth;
    }

    /**
     * The round trips counted so far.
     *
     * @return the round count
     */
    public long roundCount() {
        return roundCount;
    }

    /** When the minimum RTT was last measured or refreshed. */
    long minRttStamp() {
        return minRttStamp;
    }

    /** The current pacing gain. */
    float pacingGain() {
        return pacingGain;
    }

    /** The current loss recovery state. */
    RecoveryState recoveryState() {
        return recoveryState;
    }

    private static long saturatingMul(long a, long b) {
        long hi = Math.multiplyHigh(a, b);
        long lo = a * b;
        return hi == 0 && lo >= 0 ? lo : Long.MAX_VALUE;
    }
}
