/*
 * Ported from quinn-proto src/congestion/cubic.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.congestion;

/**
 * The CUBIC congestion controller (RFC 9438), counting the window in bytes: slow start, then the
 * cubic window function {@code W_cubic(t) = C * (t - K)^3 + W_max} with the Reno-friendly
 * estimate {@code W_est}, fast convergence, and a multiplicative decrease of {@code beta_cubic =
 * 0.7}. A congestion event later found spurious restores the state from before it.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class Cubic implements Controller {

    /** The multiplicative decrease factor (RFC 9438 section 4.6). */
    static final double BETA_CUBIC = 0.7;
    /** The cubic scaling constant (RFC 9438 section 4.2). */
    static final double C = 0.4;

    /** The state CUBIC keeps across the connection; copied to undo a spurious event. */
    static final class State {
        /** Seconds the cubic function takes to grow the window back to {@code wMax}. */
        double k;
        /** The window when the last congestion event happened, in bytes. */
        double wMax;
        /** Window growth credit accumulated in congestion avoidance. */
        long cwndInc;
        /** The bytes in flight allowed. */
        long window;
        /** Below this the controller is in slow start. */
        long ssthresh;
        /** When the current recovery period started. */
        long recoveryStartTime;
        /** Whether {@code recoveryStartTime} is set. */
        boolean inRecoveryEpoch;

        State copy() {
            State s = new State();
            s.k = k;
            s.wMax = wMax;
            s.cwndInc = cwndInc;
            s.window = window;
            s.ssthresh = ssthresh;
            s.recoveryStartTime = recoveryStartTime;
            s.inRecoveryEpoch = inRecoveryEpoch;
            return s;
        }

        /** {@code K = cbrt(W_max * (1 - beta_cubic) / C)}, in datagrams (RFC 9438 equation 2). */
        double cubicK(long maxDatagramSize) {
            double w = wMax / maxDatagramSize;
            return Math.cbrt(w * (1.0 - BETA_CUBIC) / C);
        }

        /** {@code W_cubic(t) = C * (t - K)^3 + W_max}, in bytes (RFC 9438 equation 1). */
        double wCubic(long tNanos, long maxDatagramSize) {
            double w = wMax / maxDatagramSize;
            double d = seconds(tNanos) - k;
            return (C * d * d * d + w) * maxDatagramSize;
        }

        /** {@code W_est(t)}, the Reno-friendly window in bytes (RFC 9438 equation 4). */
        double wEst(long tNanos, long rttNanos, long maxDatagramSize) {
            double w = wMax / maxDatagramSize;
            return (w * BETA_CUBIC + 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC) * seconds(tNanos) / seconds(rttNanos))
                    * maxDatagramSize;
        }
    }

    private final CubicConfig config;
    private long currentMtu;
    State state;
    /** The state before the last loss event, to restore if it proves spurious; null if none. */
    private State preCongestionState;

    /**
     * A controller in slow start.
     *
     * @param config the configuration
     * @param now the current time, in nanoseconds
     * @param currentMtu the path's maximum UDP payload size
     */
    public Cubic(CubicConfig config, long now, int currentMtu) {
        this.config = config;
        this.currentMtu = currentMtu;
        this.state = new State();
        state.window = config.initialWindow();
        state.ssthresh = Long.MAX_VALUE;
    }

    private Cubic(Cubic o) {
        config = o.config;
        currentMtu = o.currentMtu;
        state = o.state.copy();
        preCongestionState = o.preCongestionState == null ? null : o.preCongestionState.copy();
    }

    private long minimumWindow() {
        return 2 * currentMtu;
    }

    @Override
    public void onAck(long now, long sent, long bytes, boolean appLimited, RttEstimator rtt) {
        if (appLimited || (state.inRecoveryEpoch && sent <= state.recoveryStartTime)) {
            return;
        }
        if (state.window < state.ssthresh) {
            state.window += bytes; // slow start
            return;
        }
        // Congestion avoidance
        long caStartTime;
        if (state.inRecoveryEpoch) {
            caStartTime = state.recoveryStartTime;
        } else {
            // Reached without a congestion event: start the epoch here
            caStartTime = now;
            state.recoveryStartTime = now;
            state.inRecoveryEpoch = true;
            state.wMax = state.window;
            state.k = 0.0;
        }
        long t = now - caStartTime;
        double wCubic = state.wCubic(t + rtt.get(), currentMtu);
        double wEst = state.wEst(t, rtt.get(), currentMtu);
        long cubicCwnd = state.window;
        if (wCubic < wEst) {
            // Reno-friendly region
            cubicCwnd = Math.max(cubicCwnd, (long) wEst);
        } else if (cubicCwnd < (long) wCubic) {
            // Concave and convex regions grow alike; W_cubic can exceed 2^63 after a long
            // lossless period, so saturate
            double cubicInc = (wCubic - cubicCwnd) / cubicCwnd * currentMtu;
            cubicCwnd = saturatingAdd(cubicCwnd, (long) cubicInc);
        }
        state.cwndInc = saturatingAdd(state.cwndInc, cubicCwnd - state.window);
        // RFC 9002 section 7.3.3 limits growth to one datagram per acknowledgement; keep the
        // excess credit for later ACKs
        if (state.cwndInc >= currentMtu) {
            state.window += currentMtu;
            state.cwndInc -= currentMtu;
        }
    }

    @Override
    public void onCongestionEvent(long now, long sent, boolean persistentCongestion, boolean ecn, long lostBytes) {
        if (state.inRecoveryEpoch && sent <= state.recoveryStartTime) {
            return;
        }
        if (!ecn) {
            preCongestionState = state.copy(); // in case the loss proves spurious
        }
        state.recoveryStartTime = now;
        state.inRecoveryEpoch = true;
        double window = state.window;
        // Fast convergence lowers W_max; the reduction still applies to the old window
        // (RFC 9438 sections 4.6 and 4.7)
        if (window < state.wMax) {
            state.wMax = window * (1.0 + BETA_CUBIC) / 2.0;
        } else {
            state.wMax = window;
        }
        state.ssthresh = Math.max((long) (window * BETA_CUBIC), minimumWindow());
        state.window = state.ssthresh;
        state.k = state.cubicK(currentMtu);
        state.cwndInc = (long) (state.cwndInc * BETA_CUBIC);
        if (persistentCongestion) {
            // RFC 9438 section 4.8: ssthresh keeps its single reduction; only cwnd drops to the
            // minimum window
            state.inRecoveryEpoch = false;
            state.wMax = state.window;
            state.cwndInc = 0;
            state.window = minimumWindow();
        }
    }

    @Override
    public void onSpuriousCongestionEvent() {
        State prior = preCongestionState;
        preCongestionState = null;
        if (prior != null && state.window < prior.window) {
            state = prior;
        }
    }

    @Override
    public void onMtuUpdate(int newMtu) {
        currentMtu = newMtu;
        state.window = Math.max(state.window, minimumWindow());
    }

    @Override
    public long window() {
        return state.window;
    }

    /**
     * The slow start threshold.
     *
     * @return bytes, {@link Long#MAX_VALUE} before the first congestion event
     */
    public long slowStartThreshold() {
        return state.ssthresh;
    }

    @Override
    public ControllerMetrics metrics() {
        return new ControllerMetrics(state.window, state.ssthresh, -1);
    }

    @Override
    public Controller copy() {
        return new Cubic(this);
    }

    @Override
    public long initialWindow() {
        return config.initialWindow();
    }

    private static double seconds(long nanos) {
        return nanos / 1e9;
    }

    private static long saturatingAdd(long a, long b) {
        long r = a + b;
        return ((a ^ r) & (b ^ r)) < 0 ? (a < 0 ? Long.MIN_VALUE : Long.MAX_VALUE) : r;
    }
}
