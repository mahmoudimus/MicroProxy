/*
 * Ported from quinn-proto src/congestion/bbr/mod.rs (BbrConfig) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.congestion;

/**
 * Configuration of the {@link Bbr} controller.
 *
 * @param initialWindow the initial congestion window in bytes; quinn's default is 200 datagrams
 *     of {@link Controller#BASE_DATAGRAM_SIZE}, 240000 bytes
 */
public record BbrConfig(long initialWindow) implements ControllerFactory {

    /** The most datagrams the initial window holds by default. */
    static final long MAX_INITIAL_CONGESTION_WINDOW = 200;

    /** The default: a 240000-byte initial window, as in quinn. */
    public static final BbrConfig DEFAULT = new BbrConfig(MAX_INITIAL_CONGESTION_WINDOW * Controller.BASE_DATAGRAM_SIZE);

    /**
     * A configuration.
     *
     * @param initialWindow the initial window, positive
     */
    public BbrConfig {
        if (initialWindow <= 0) {
            throw new IllegalArgumentException("initialWindow " + initialWindow);
        }
    }

    @Override
    public Controller build(long now, int currentMtu) {
        return new Bbr(this, currentMtu);
    }
}
