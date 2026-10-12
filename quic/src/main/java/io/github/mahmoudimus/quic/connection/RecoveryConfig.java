/*
 * Ported from quinn-proto src/config/transport.rs (the recovery fields of TransportConfig)
 * (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.congestion.ControllerFactory;
import io.github.mahmoudimus.quic.congestion.RttEstimator;
import java.util.Objects;

/**
 * Configuration of loss detection, congestion control, pacing and MTU discovery. Durations are
 * nanoseconds. Immutable; build one with {@link #builder()}.
 *
 * @param packetThreshold packets acknowledged after a packet before it is deemed lost, 3 (RFC 9002
 *     kPacketThreshold)
 * @param timeThreshold the RTT multiple after which an unacknowledged packet is deemed lost, 9/8
 *     (RFC 9002 kTimeThreshold)
 * @param initialRtt the RTT assumed before a sample, 333 ms (RFC 9002 kInitialRtt)
 * @param persistentCongestionThreshold PTOs of loss that make persistent congestion, 3 (RFC 9002
 *     kPersistentCongestionThreshold)
 * @param initialMtu the UDP payload size to start with, at least 1200
 * @param minMtu the UDP payload size the path is assumed to support, at least 1200
 * @param mtuDiscovery MTU discovery settings, or null to keep the MTU fixed at {@code initialMtu}
 * @param congestionControllerFactory the congestion controller, CUBIC by default
 * @param maxOutgoingBytesPerSecond a pacing rate limit, or -1 for none
 * @param maxAckDelay this endpoint's {@code max_ack_delay}, 25 ms by default; also the peer's until
 *     its transport parameters arrive
 * @param ackDelayExponent this endpoint's {@code ack_delay_exponent}, 3 by default
 */
public record RecoveryConfig(int packetThreshold, double timeThreshold, long initialRtt,
        int persistentCongestionThreshold, int initialMtu, int minMtu, MtuDiscoveryConfig mtuDiscovery,
        ControllerFactory congestionControllerFactory, long maxOutgoingBytesPerSecond, long maxAckDelay,
        int ackDelayExponent) {

    /** The smallest MTU QUIC allows, 1200 bytes (RFC 9000 section 14). */
    public static final int MIN_MTU = 1200;

    /** The defaults. */
    public static final RecoveryConfig DEFAULT = builder().build();

    /**
     * A configuration.
     *
     * @param packetThreshold the packet reordering threshold, at least 1
     * @param timeThreshold the time reordering threshold, above 1
     * @param initialRtt the initial RTT, positive
     * @param persistentCongestionThreshold the persistent congestion threshold, at least 1
     * @param initialMtu the initial MTU, at least {@code minMtu}
     * @param minMtu the minimum MTU, at least 1200
     * @param mtuDiscovery MTU discovery settings, or null
     * @param congestionControllerFactory the congestion controller factory
     * @param maxOutgoingBytesPerSecond the rate limit, or -1
     * @param maxAckDelay our {@code max_ack_delay}
     * @param ackDelayExponent our {@code ack_delay_exponent}, 0 to 20
     */
    public RecoveryConfig {
        if (packetThreshold < 1 || !(timeThreshold > 1) || initialRtt <= 0 || persistentCongestionThreshold < 1) {
            throw new IllegalArgumentException("invalid loss detection thresholds");
        }
        if (minMtu < MIN_MTU || initialMtu < minMtu) {
            throw new IllegalArgumentException("MTU " + initialMtu + " / minimum " + minMtu);
        }
        if (ackDelayExponent < 0 || ackDelayExponent > 20) {
            throw new IllegalArgumentException("ackDelayExponent " + ackDelayExponent);
        }
        Objects.requireNonNull(congestionControllerFactory, "congestionControllerFactory");
    }

    /**
     * A builder with the defaults.
     *
     * @return the builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /** Builds a {@link RecoveryConfig}. Not thread-safe. */
    public static final class Builder {
        private int packetThreshold = 3;
        private double timeThreshold = 9.0 / 8.0;
        private long initialRtt = RttEstimator.DEFAULT_INITIAL_RTT;
        private int persistentCongestionThreshold = 3;
        private int initialMtu = MIN_MTU;
        private int minMtu = MIN_MTU;
        private MtuDiscoveryConfig mtuDiscovery = MtuDiscoveryConfig.DEFAULT;
        private ControllerFactory congestionControllerFactory = ControllerFactory.defaultFactory();
        private long maxOutgoingBytesPerSecond = -1;
        private long maxAckDelay = 25_000_000L;
        private int ackDelayExponent = 3;

        private Builder() {}

        /**
         * Sets the packet reordering threshold.
         *
         * @param v the threshold
         * @return this builder
         */
        public Builder packetThreshold(int v) {
            packetThreshold = v;
            return this;
        }

        /**
         * Sets the time reordering threshold.
         *
         * @param v the RTT multiple
         * @return this builder
         */
        public Builder timeThreshold(double v) {
            timeThreshold = v;
            return this;
        }

        /**
         * Sets the initial RTT.
         *
         * @param v nanoseconds
         * @return this builder
         */
        public Builder initialRtt(long v) {
            initialRtt = v;
            return this;
        }

        /**
         * Sets the persistent congestion threshold.
         *
         * @param v PTOs
         * @return this builder
         */
        public Builder persistentCongestionThreshold(int v) {
            persistentCongestionThreshold = v;
            return this;
        }

        /**
         * Sets the initial MTU.
         *
         * @param v bytes
         * @return this builder
         */
        public Builder initialMtu(int v) {
            initialMtu = v;
            return this;
        }

        /**
         * Sets the minimum MTU.
         *
         * @param v bytes
         * @return this builder
         */
        public Builder minMtu(int v) {
            minMtu = v;
            return this;
        }

        /**
         * Sets MTU discovery.
         *
         * @param v the settings, or null to disable discovery
         * @return this builder
         */
        public Builder mtuDiscovery(MtuDiscoveryConfig v) {
            mtuDiscovery = v;
            return this;
        }

        /**
         * Sets the congestion controller.
         *
         * @param v the factory
         * @return this builder
         */
        public Builder congestionControllerFactory(ControllerFactory v) {
            congestionControllerFactory = v;
            return this;
        }

        /**
         * Sets a pacing rate limit.
         *
         * @param v bytes per second, or -1 for none
         * @return this builder
         */
        public Builder maxOutgoingBytesPerSecond(long v) {
            maxOutgoingBytesPerSecond = v;
            return this;
        }

        /**
         * Sets our {@code max_ack_delay}.
         *
         * @param v nanoseconds
         * @return this builder
         */
        public Builder maxAckDelay(long v) {
            maxAckDelay = v;
            return this;
        }

        /**
         * Sets our {@code ack_delay_exponent}.
         *
         * @param v 0 to 20
         * @return this builder
         */
        public Builder ackDelayExponent(int v) {
            ackDelayExponent = v;
            return this;
        }

        /**
         * Builds the configuration.
         *
         * @return the configuration
         * @throws IllegalArgumentException if a value is out of range
         */
        public RecoveryConfig build() {
            return new RecoveryConfig(packetThreshold, timeThreshold, initialRtt, persistentCongestionThreshold,
                    initialMtu, minMtu, mtuDiscovery, congestionControllerFactory, maxOutgoingBytesPerSecond,
                    maxAckDelay, ackDelayExponent);
        }
    }
}
