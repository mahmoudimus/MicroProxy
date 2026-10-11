/*
 * Ported from quinn-proto src/config/transport.rs (TransportConfig and its defaults) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.congestion.ControllerFactory;
import io.github.mahmoudimus.quic.congestion.CubicConfig;
import io.github.mahmoudimus.quic.congestion.NewRenoConfig;
import io.github.mahmoudimus.quic.congestion.RttEstimator;
import java.time.Duration;
import java.util.Objects;

/**
 * The transport settings of a connection, the same for both sides: flow-control windows, stream
 * limits, timeouts, loss detection, congestion control, MTU discovery, DATAGRAM support and the
 * debugging aids. Immutable and shareable; start from {@link #defaults()} or {@link #builder()}.
 *
 * <p>The defaults follow quinn's: 100 concurrent streams of each directionality, a 30 second idle
 * timeout, a 1.25 MB stream window, CUBIC, MTU discovery on. The connection receive window is
 * bounded (10 MB by default) rather than unlimited, so memory a peer can make a connection hold is
 * bounded too.
 */
public final class TransportConfig {

    /** The congestion controllers this module provides. */
    public enum CongestionControl {
        /** CUBIC (RFC 9438), the default. */
        CUBIC,
        /** NewReno (RFC 9002). */
        NEW_RENO
    }

    private static final TransportConfig DEFAULTS = builder().build();

    final long maxConcurrentBidiStreams;
    final long maxConcurrentUniStreams;
    final Duration maxIdleTimeout;
    final long streamReceiveWindow;
    final long receiveWindow;
    final long sendWindow;
    final boolean sendFairness;
    final int packetThreshold;
    final double timeThreshold;
    final Duration initialRtt;
    final int initialMtu;
    final int minMtu;
    final MtuDiscoveryConfig mtuDiscovery;
    final int persistentCongestionThreshold;
    final Duration keepAliveInterval;
    final int cryptoBufferSize;
    final boolean allowSpin;
    final int datagramReceiveBufferSize;
    final int datagramSendBufferSize;
    final ControllerFactory congestionControllerFactory;
    final long maxOutgoingBytesPerSecond;
    final Duration maxAckDelay;
    final int ackDelayExponent;
    final int activeConnectionIdLimit;
    final int maxUdpPayloadSize;
    final KeyLog keyLog;
    final QlogSink qlog;

    private TransportConfig(Builder b) {
        this.maxConcurrentBidiStreams = b.maxConcurrentBidiStreams;
        this.maxConcurrentUniStreams = b.maxConcurrentUniStreams;
        this.maxIdleTimeout = b.maxIdleTimeout;
        this.streamReceiveWindow = b.streamReceiveWindow;
        this.receiveWindow = b.receiveWindow;
        this.sendWindow = b.sendWindow;
        this.sendFairness = b.sendFairness;
        this.packetThreshold = b.packetThreshold;
        this.timeThreshold = b.timeThreshold;
        this.initialRtt = b.initialRtt;
        this.initialMtu = b.initialMtu;
        this.minMtu = b.minMtu;
        this.mtuDiscovery = b.mtuDiscovery;
        this.persistentCongestionThreshold = b.persistentCongestionThreshold;
        this.keepAliveInterval = b.keepAliveInterval;
        this.cryptoBufferSize = b.cryptoBufferSize;
        this.allowSpin = b.allowSpin;
        this.datagramReceiveBufferSize = b.datagramReceiveBufferSize;
        this.datagramSendBufferSize = b.datagramSendBufferSize;
        this.congestionControllerFactory = b.congestionControllerFactory;
        this.maxOutgoingBytesPerSecond = b.maxOutgoingBytesPerSecond;
        this.maxAckDelay = b.maxAckDelay;
        this.ackDelayExponent = b.ackDelayExponent;
        this.activeConnectionIdLimit = b.activeConnectionIdLimit;
        this.maxUdpPayloadSize = b.maxUdpPayloadSize;
        this.keyLog = b.keyLog;
        this.qlog = b.qlog;
    }

    /**
     * The default settings.
     *
     * @return the shared default configuration
     */
    public static TransportConfig defaults() {
        return DEFAULTS;
    }

    /**
     * A builder starting from the defaults.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder starting from this configuration.
     *
     * @return a new builder with these settings
     */
    public Builder toBuilder() {
        Builder b = new Builder();
        b.maxConcurrentBidiStreams = maxConcurrentBidiStreams;
        b.maxConcurrentUniStreams = maxConcurrentUniStreams;
        b.maxIdleTimeout = maxIdleTimeout;
        b.streamReceiveWindow = streamReceiveWindow;
        b.receiveWindow = receiveWindow;
        b.sendWindow = sendWindow;
        b.sendFairness = sendFairness;
        b.packetThreshold = packetThreshold;
        b.timeThreshold = timeThreshold;
        b.initialRtt = initialRtt;
        b.initialMtu = initialMtu;
        b.minMtu = minMtu;
        b.mtuDiscovery = mtuDiscovery;
        b.persistentCongestionThreshold = persistentCongestionThreshold;
        b.keepAliveInterval = keepAliveInterval;
        b.cryptoBufferSize = cryptoBufferSize;
        b.allowSpin = allowSpin;
        b.datagramReceiveBufferSize = datagramReceiveBufferSize;
        b.datagramSendBufferSize = datagramSendBufferSize;
        b.congestionControllerFactory = congestionControllerFactory;
        b.maxOutgoingBytesPerSecond = maxOutgoingBytesPerSecond;
        b.maxAckDelay = maxAckDelay;
        b.ackDelayExponent = ackDelayExponent;
        b.activeConnectionIdLimit = activeConnectionIdLimit;
        b.maxUdpPayloadSize = maxUdpPayloadSize;
        b.keyLog = keyLog;
        b.qlog = qlog;
        return b;
    }

    /**
     * The idle timeout this endpoint offers; the connection uses the smaller of both sides'.
     *
     * @return the timeout, or {@link Duration#ZERO} for none
     */
    public Duration maxIdleTimeout() {
        return maxIdleTimeout;
    }

    /**
     * The per-stream receive window.
     *
     * @return bytes
     */
    public long streamReceiveWindow() {
        return streamReceiveWindow;
    }

    /**
     * The connection receive window.
     *
     * @return bytes
     */
    public long receiveWindow() {
        return receiveWindow;
    }

    /**
     * The most outgoing stream data buffered, unacknowledged, per connection.
     *
     * @return bytes
     */
    public long sendWindow() {
        return sendWindow;
    }

    /**
     * Whether MTU discovery is on.
     *
     * @return true if it is
     */
    public boolean mtuDiscoveryEnabled() {
        return mtuDiscovery != null;
    }

    /**
     * The largest DATAGRAM payload buffered for the application, or 0 when DATAGRAM frames are
     * refused.
     *
     * @return bytes
     */
    public int datagramReceiveBufferSize() {
        return datagramReceiveBufferSize;
    }

    /**
     * The receiver of TLS secrets for packet analyzers, if any.
     *
     * @return the key log, or null
     */
    public KeyLog keyLog() {
        return keyLog;
    }

    /**
     * The receiver of qlog-style events, if any.
     *
     * @return the sink, or null
     */
    public QlogSink qlog() {
        return qlog;
    }

    RecoveryConfig recoveryConfig(boolean allowMtud) {
        return RecoveryConfig.builder()
                .packetThreshold(packetThreshold)
                .timeThreshold(timeThreshold)
                .initialRtt(initialRtt.toNanos())
                .persistentCongestionThreshold(persistentCongestionThreshold)
                .initialMtu(initialMtu)
                .minMtu(minMtu)
                .mtuDiscovery(allowMtud ? mtuDiscovery : null)
                .congestionControllerFactory(congestionControllerFactory)
                .maxOutgoingBytesPerSecond(maxOutgoingBytesPerSecond)
                .maxAckDelay(maxAckDelay.toNanos())
                .ackDelayExponent(ackDelayExponent)
                .build();
    }

    /** Builds a {@link TransportConfig}. Not thread-safe. */
    public static final class Builder {
        private long maxConcurrentBidiStreams = 100;
        private long maxConcurrentUniStreams = 100;
        private Duration maxIdleTimeout = Duration.ofSeconds(30);
        private long streamReceiveWindow = 1_250_000;
        private long receiveWindow = 10_000_000;
        private long sendWindow = 10_000_000;
        private boolean sendFairness = true;
        private int packetThreshold = 3;
        private double timeThreshold = 9.0 / 8.0;
        private Duration initialRtt = Duration.ofNanos(RttEstimator.DEFAULT_INITIAL_RTT);
        private int initialMtu = RecoveryConfig.MIN_MTU;
        private int minMtu = RecoveryConfig.MIN_MTU;
        private MtuDiscoveryConfig mtuDiscovery = MtuDiscoveryConfig.DEFAULT;
        private int persistentCongestionThreshold = 3;
        private Duration keepAliveInterval;
        private int cryptoBufferSize = 16 * 1024;
        private boolean allowSpin = true;
        private int datagramReceiveBufferSize = 1_250_000;
        private int datagramSendBufferSize = 1 << 20;
        private ControllerFactory congestionControllerFactory = ControllerFactory.defaultFactory();
        private long maxOutgoingBytesPerSecond = -1;
        private Duration maxAckDelay = Duration.ofMillis(25);
        private int ackDelayExponent = 3;
        private int activeConnectionIdLimit = RemoteCidQueue.DEFAULT_LIMIT;
        private int maxUdpPayloadSize = 1472;
        private KeyLog keyLog;
        private QlogSink qlog;

        private Builder() {}

        /**
         * How many bidirectional streams the peer may have open at once.
         *
         * @param count 0 to 2<sup>60</sup>
         * @return this builder
         */
        public Builder maxConcurrentBidiStreams(long count) {
            this.maxConcurrentBidiStreams = checkCount(count);
            return this;
        }

        /**
         * How many unidirectional streams the peer may have open at once.
         *
         * @param count 0 to 2<sup>60</sup>
         * @return this builder
         */
        public Builder maxConcurrentUniStreams(long count) {
            this.maxConcurrentUniStreams = checkCount(count);
            return this;
        }

        /**
         * The idle timeout to offer (RFC 9000 section 10.1); the smaller of both sides' applies.
         *
         * @param timeout the timeout, or {@link Duration#ZERO} for none
         * @return this builder
         */
        public Builder maxIdleTimeout(Duration timeout) {
            if (timeout.isNegative()) {
                throw new IllegalArgumentException("negative idle timeout");
            }
            this.maxIdleTimeout = timeout;
            return this;
        }

        /**
         * The receive window of each stream: how much the peer may send ahead of what the
         * application read.
         *
         * @param bytes at least 1
         * @return this builder
         */
        public Builder streamReceiveWindow(long bytes) {
            this.streamReceiveWindow = checkPositive(bytes);
            return this;
        }

        /**
         * The receive window of the connection, across streams.
         *
         * @param bytes at least 1
         * @return this builder
         */
        public Builder receiveWindow(long bytes) {
            this.receiveWindow = checkPositive(bytes);
            return this;
        }

        /**
         * The most outgoing stream data to buffer until it is acknowledged. Writers block beyond it.
         *
         * @param bytes at least 1
         * @return this builder
         */
        public Builder sendWindow(long bytes) {
            this.sendWindow = checkPositive(bytes);
            return this;
        }

        /**
         * Whether streams of equal priority share packets round-robin (true, the default) or
         * one finishes before the next starts.
         *
         * @param fair the fairness
         * @return this builder
         */
        public Builder sendFairness(boolean fair) {
            this.sendFairness = fair;
            return this;
        }

        /**
         * The packet reordering threshold of loss detection (RFC 9002 section 6.1.1).
         *
         * @param packets at least 1
         * @return this builder
         */
        public Builder packetThreshold(int packets) {
            this.packetThreshold = (int) checkPositive(packets);
            return this;
        }

        /**
         * The time reordering threshold of loss detection, in RTTs (RFC 9002 section 6.1.2).
         *
         * @param rtts more than 1
         * @return this builder
         */
        public Builder timeThreshold(double rtts) {
            if (!(rtts > 1)) {
                throw new IllegalArgumentException("time threshold " + rtts);
            }
            this.timeThreshold = rtts;
            return this;
        }

        /**
         * The RTT assumed before the first sample.
         *
         * @param rtt positive
         * @return this builder
         */
        public Builder initialRtt(Duration rtt) {
            if (rtt.isNegative() || rtt.isZero()) {
                throw new IllegalArgumentException("initial RTT " + rtt);
            }
            this.initialRtt = rtt;
            return this;
        }

        /**
         * The UDP payload size to start with, at least {@link #minMtu(int)}.
         *
         * @param bytes the size
         * @return this builder
         */
        public Builder initialMtu(int bytes) {
            this.initialMtu = bytes;
            return this;
        }

        /**
         * The UDP payload size the path is assumed to carry, at least 1200.
         *
         * @param bytes the size
         * @return this builder
         */
        public Builder minMtu(int bytes) {
            this.minMtu = bytes;
            return this;
        }

        /**
         * Turns path MTU discovery (RFC 8899) on with its default settings, or off.
         *
         * @param enabled whether to probe for a larger MTU
         * @return this builder
         */
        public Builder mtuDiscovery(boolean enabled) {
            this.mtuDiscovery = enabled ? MtuDiscoveryConfig.DEFAULT : null;
            return this;
        }

        /**
         * Path MTU discovery settings, or null to turn it off.
         *
         * @param config the settings
         * @return this builder
         */
        public Builder mtuDiscoveryConfig(MtuDiscoveryConfig config) {
            this.mtuDiscovery = config;
            return this;
        }

        /**
         * How many PTOs of loss make persistent congestion (RFC 9002 section 7.6).
         *
         * @param ptos at least 1
         * @return this builder
         */
        public Builder persistentCongestionThreshold(int ptos) {
            this.persistentCongestionThreshold = (int) checkPositive(ptos);
            return this;
        }

        /**
         * Sends a PING after this much time without sending, to keep an idle connection open.
         *
         * @param interval the interval, or null for none (the default)
         * @return this builder
         */
        public Builder keepAliveInterval(Duration interval) {
            if (interval != null && (interval.isNegative() || interval.isZero())) {
                throw new IllegalArgumentException("keep-alive interval " + interval);
            }
            this.keepAliveInterval = interval;
            return this;
        }

        /**
         * The most out-of-order CRYPTO data to buffer per encryption level; more is {@code
         * CRYPTO_BUFFER_EXCEEDED}.
         *
         * @param bytes at least 1
         * @return this builder
         */
        public Builder cryptoBufferSize(int bytes) {
            this.cryptoBufferSize = (int) checkPositive(bytes);
            return this;
        }

        /**
         * Whether to take part in the latency spin bit (RFC 9000 section 17.4); when on, a
         * connection still opts out one time in eight.
         *
         * @param allow whether to spin
         * @return this builder
         */
        public Builder allowSpin(boolean allow) {
            this.allowSpin = allow;
            return this;
        }

        /**
         * The DATAGRAM (RFC 9221) receive buffer; the oldest unread datagrams are dropped beyond it.
         * 0 refuses DATAGRAM frames altogether.
         *
         * @param bytes 0 or more
         * @return this builder
         */
        public Builder datagramReceiveBufferSize(int bytes) {
            if (bytes < 0) {
                throw new IllegalArgumentException("datagram receive buffer " + bytes);
            }
            this.datagramReceiveBufferSize = bytes;
            return this;
        }

        /**
         * The DATAGRAM send buffer; the oldest unsent datagrams are dropped beyond it.
         *
         * @param bytes at least 1
         * @return this builder
         */
        public Builder datagramSendBufferSize(int bytes) {
            this.datagramSendBufferSize = (int) checkPositive(bytes);
            return this;
        }

        /**
         * Chooses one of the provided congestion controllers with its default settings.
         *
         * @param control the controller
         * @return this builder
         */
        public Builder congestionControl(CongestionControl control) {
            this.congestionControllerFactory = switch (control) {
                case CUBIC -> CubicConfig.DEFAULT;
                case NEW_RENO -> NewRenoConfig.DEFAULT;
            };
            return this;
        }

        /**
         * A custom congestion controller.
         *
         * @param factory builds one controller per connection
         * @return this builder
         */
        public Builder congestionControllerFactory(ControllerFactory factory) {
            this.congestionControllerFactory = Objects.requireNonNull(factory, "factory");
            return this;
        }

        /**
         * Caps the sending rate through the pacer.
         *
         * @param bytesPerSecond the cap, or -1 for none (the default)
         * @return this builder
         */
        public Builder maxOutgoingBytesPerSecond(long bytesPerSecond) {
            this.maxOutgoingBytesPerSecond = bytesPerSecond;
            return this;
        }

        /**
         * The {@code max_ack_delay} transport parameter: how long this endpoint may delay ACKs.
         *
         * @param delay below 2<sup>14</sup> ms
         * @return this builder
         */
        public Builder maxAckDelay(Duration delay) {
            if (delay.isNegative() || delay.toMillis() >= (1 << 14)) {
                throw new IllegalArgumentException("max_ack_delay " + delay);
            }
            this.maxAckDelay = delay;
            return this;
        }

        /**
         * The {@code active_connection_id_limit} transport parameter: how many of the peer's
         * connection IDs to keep.
         *
         * @param limit at least 2
         * @return this builder
         */
        public Builder activeConnectionIdLimit(int limit) {
            if (limit < 2) {
                throw new IllegalArgumentException("active_connection_id_limit " + limit);
            }
            this.activeConnectionIdLimit = limit;
            return this;
        }

        /**
         * The {@code max_udp_payload_size} transport parameter: the largest datagram this endpoint
         * receives.
         *
         * @param bytes 1200 to 65527
         * @return this builder
         */
        public Builder maxUdpPayloadSize(int bytes) {
            if (bytes < 1200 || bytes > MtuDiscoveryConfig.MAX_UDP_PAYLOAD) {
                throw new IllegalArgumentException("max_udp_payload_size " + bytes);
            }
            this.maxUdpPayloadSize = bytes;
            return this;
        }

        /**
         * Writes each connection's TLS secrets in the {@code SSLKEYLOGFILE} format, for Wireshark.
         * For debugging only: anyone with the log can decrypt the traffic.
         *
         * @param keyLog the destination, or null for none (the default)
         * @return this builder
         */
        public Builder keyLog(KeyLog keyLog) {
            this.keyLog = keyLog;
            return this;
        }

        /**
         * Reports qlog-style events (packets sent, received and lost, metrics, state changes).
         *
         * @param sink the destination, or null for none (the default)
         * @return this builder
         */
        public Builder qlog(QlogSink sink) {
            this.qlog = sink;
            return this;
        }

        /**
         * Builds the configuration.
         *
         * @return the configuration
         * @throws IllegalArgumentException if the MTU settings are inconsistent
         */
        public TransportConfig build() {
            if (minMtu < RecoveryConfig.MIN_MTU || initialMtu < minMtu) {
                throw new IllegalArgumentException("initial MTU " + initialMtu + " / minimum MTU " + minMtu);
            }
            return new TransportConfig(this);
        }

        private static long checkCount(long count) {
            if (count < 0 || count > StreamsState.MAX_STREAM_COUNT) {
                throw new IllegalArgumentException("stream count " + count);
            }
            return count;
        }

        private static long checkPositive(long v) {
            if (v <= 0) {
                throw new IllegalArgumentException("must be positive: " + v);
            }
            return v;
        }
    }
}
