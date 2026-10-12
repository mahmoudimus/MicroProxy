/*
 * Ported from quinn-proto src/congestion/new_reno.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.congestion;

/**
 * The NewReno congestion controller of RFC 9002 section 7: slow start, then congestion avoidance
 * growing the window by one datagram per window acknowledged (Appropriate Byte Counting, RFC
 * 3465), and a multiplicative decrease once per recovery period.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class NewReno implements Controller {

    private final NewRenoConfig config;
    private long currentMtu;
    /** The bytes in flight allowed. */
    private long window;
    /** Below this the controller is in slow start. */
    private long ssthresh;
    /** When the current recovery period started; packets sent before it do not count. */
    private long recoveryStartTime;
    /** Bytes acknowledged since leaving slow start. */
    private long bytesAcked;

    /**
     * A controller in slow start.
     *
     * @param config the configuration
     * @param now the current time, in nanoseconds
     * @param currentMtu the path's maximum UDP payload size
     */
    public NewReno(NewRenoConfig config, long now, int currentMtu) {
        this.config = config;
        this.window = config.initialWindow();
        this.ssthresh = Long.MAX_VALUE;
        this.recoveryStartTime = now;
        this.currentMtu = currentMtu;
    }

    private NewReno(NewReno o) {
        config = o.config;
        currentMtu = o.currentMtu;
        window = o.window;
        ssthresh = o.ssthresh;
        recoveryStartTime = o.recoveryStartTime;
        bytesAcked = o.bytesAcked;
    }

    private long minimumWindow() {
        return 2 * currentMtu;
    }

    @Override
    public void onAck(long now, long sent, long bytes, boolean appLimited, RttEstimator rtt) {
        if (appLimited || sent <= recoveryStartTime) {
            return;
        }
        if (window < ssthresh) {
            // Slow start
            window += bytes;
            if (window >= ssthresh) {
                // Leaving slow start: bytes past ssthresh already count towards avoidance
                bytesAcked = window - ssthresh;
            }
        } else {
            // Congestion avoidance: one datagram per window acknowledged
            bytesAcked += bytes;
            if (bytesAcked >= window) {
                bytesAcked -= window;
                window += currentMtu;
            }
        }
    }

    @Override
    public void onCongestionEvent(long now, long sent, boolean persistentCongestion, boolean ecn, long lostBytes) {
        if (sent <= recoveryStartTime) {
            return;
        }
        recoveryStartTime = now;
        window = (long) (window * config.lossReductionFactor());
        window = Math.max(window, minimumWindow());
        ssthresh = window;
        if (persistentCongestion) {
            window = minimumWindow();
        }
    }

    @Override
    public void onMtuUpdate(int newMtu) {
        currentMtu = newMtu;
        window = Math.max(window, minimumWindow());
    }

    @Override
    public long window() {
        return window;
    }

    /**
     * The slow start threshold.
     *
     * @return bytes, {@link Long#MAX_VALUE} before the first congestion event
     */
    public long slowStartThreshold() {
        return ssthresh;
    }

    @Override
    public ControllerMetrics metrics() {
        return new ControllerMetrics(window, ssthresh, -1);
    }

    @Override
    public Controller copy() {
        return new NewReno(this);
    }

    @Override
    public long initialWindow() {
        return config.initialWindow();
    }
}
