/*
 * Ported from quinn-proto src/congestion.rs (ControllerFactory) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.congestion;

/**
 * Builds congestion controllers, one per path. Factories are immutable and may be shared.
 */
@FunctionalInterface
public interface ControllerFactory {

    /**
     * A new controller.
     *
     * @param now the current time, in nanoseconds
     * @param currentMtu the path's current maximum UDP payload size
     * @return the controller
     */
    Controller build(long now, int currentMtu);

    /**
     * The default, CUBIC with its default configuration, as quinn uses.
     *
     * @return {@link CubicConfig#DEFAULT}
     */
    static ControllerFactory defaultFactory() {
        return CubicConfig.DEFAULT;
    }
}
