/*
 * Ported from quinn-proto src/config/transport.rs (MtuDiscoveryConfig) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

/**
 * Configuration of DPLPMTUD, packetization layer path MTU discovery (RFC 8899, RFC 9000 section
 * 14.3). Discovery runs right after the handshake and again every {@code interval}; it binary
 * searches between the current MTU and the smaller of {@code upperBound} and the peer's {@code
 * max_udp_payload_size}. A black hole (lost packets above the minimum MTU) drops the MTU to the
 * minimum and restarts discovery after {@code blackHoleCooldown}.
 *
 * @param interval the time between discovery runs, in nanoseconds; 600 s by default (RFC 8899)
 * @param upperBound the largest UDP payload to search for, at most 65527; 1452 by default, which
 *     fits Ethernet with IPv4 or IPv6
 * @param minimumChange the step below which the search stops; 20 by default
 * @param blackHoleCooldown the wait after a black hole before searching again, in nanoseconds; 60
 *     s by default
 */
public record MtuDiscoveryConfig(long interval, int upperBound, int minimumChange, long blackHoleCooldown) {

    /** The largest UDP payload over IPv6, 65527 bytes. */
    public static final int MAX_UDP_PAYLOAD = 65527;

    /** The defaults. */
    public static final MtuDiscoveryConfig DEFAULT = new MtuDiscoveryConfig(600_000_000_000L, 1452, 20,
            60_000_000_000L);

    /**
     * A configuration; {@code upperBound} is clamped to {@link #MAX_UDP_PAYLOAD}.
     *
     * @param interval the time between runs, in nanoseconds
     * @param upperBound the largest payload to search for
     * @param minimumChange the step that stops the search, positive
     * @param blackHoleCooldown the wait after a black hole, in nanoseconds
     */
    public MtuDiscoveryConfig {
        upperBound = Math.min(upperBound, MAX_UDP_PAYLOAD);
        if (minimumChange <= 0) {
            throw new IllegalArgumentException("minimumChange " + minimumChange);
        }
    }

    /**
     * This configuration with another upper bound.
     *
     * @param value the largest payload to search for
     * @return the new configuration
     */
    public MtuDiscoveryConfig withUpperBound(int value) {
        return new MtuDiscoveryConfig(interval, value, minimumChange, blackHoleCooldown);
    }
}
