/*
 * Ported from quinn-proto src/congestion/cubic.rs (CubicConfig) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.congestion;

/**
 * Configuration of the {@link Cubic} controller.
 *
 * @param initialWindow the initial congestion window in bytes; RFC 9002 recommends {@code min(10 *
 *     max_datagram_size, max(2 * max_datagram_size, 14720))}
 */
public record CubicConfig(long initialWindow) implements ControllerFactory {

    /** The default: a 12000-byte initial window. */
    public static final CubicConfig DEFAULT = new CubicConfig(
            Math.clamp(14720, 2 * Controller.BASE_DATAGRAM_SIZE, 10 * Controller.BASE_DATAGRAM_SIZE));

    /**
     * A configuration.
     *
     * @param initialWindow the initial window, positive
     */
    public CubicConfig {
        if (initialWindow <= 0) {
            throw new IllegalArgumentException("initialWindow " + initialWindow);
        }
    }

    @Override
    public Controller build(long now, int currentMtu) {
        return new Cubic(this, now, currentMtu);
    }
}
