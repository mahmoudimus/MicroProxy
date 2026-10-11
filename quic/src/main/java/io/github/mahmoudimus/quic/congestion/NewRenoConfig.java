/*
 * Ported from quinn-proto src/congestion/new_reno.rs (NewRenoConfig) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.congestion;

/**
 * Configuration of the {@link NewReno} controller.
 *
 * @param initialWindow the initial congestion window in bytes; RFC 9002 recommends {@code min(10 *
 *     max_datagram_size, max(2 * max_datagram_size, 14720))}
 * @param lossReductionFactor the factor the window is multiplied by on a congestion event, 0.5 in
 *     RFC 9002
 */
public record NewRenoConfig(long initialWindow, double lossReductionFactor) implements ControllerFactory {

    /** The RFC 9002 defaults: a 12000-byte initial window and a loss reduction factor of 0.5. */
    public static final NewRenoConfig DEFAULT = new NewRenoConfig(
            Math.clamp(14720, 2 * Controller.BASE_DATAGRAM_SIZE, 10 * Controller.BASE_DATAGRAM_SIZE), 0.5);

    /**
     * A configuration.
     *
     * @param initialWindow the initial window, positive
     * @param lossReductionFactor the reduction factor, in (0, 1]
     */
    public NewRenoConfig {
        if (initialWindow <= 0) {
            throw new IllegalArgumentException("initialWindow " + initialWindow);
        }
        if (!(lossReductionFactor > 0 && lossReductionFactor <= 1)) {
            throw new IllegalArgumentException("lossReductionFactor " + lossReductionFactor);
        }
    }

    @Override
    public Controller build(long now, int currentMtu) {
        return new NewReno(this, now, currentMtu);
    }
}
