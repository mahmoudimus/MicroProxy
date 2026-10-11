package org.microproxy;

import java.util.Locale;

/**
 * How a draining proxy ({@link HttpProxyServer#drain}) tells its clients to go elsewhere, as
 * Envoy's {@code --drain-strategy}: each new request may be answered with {@code Connection:
 * close} (HTTP/1) or make the proxy send GOAWAY (HTTP/2, HTTP/3) on its connection.
 */
public enum DrainStrategy {
    /**
     * The chance that a request drains its connection grows from 0 at the start of the drain to 1
     * at its end, so clients move away gradually rather than all at once (the default).
     */
    GRADUAL,
    /** Every connection is told at once: idle ones are closed, busy ones close after their request in progress. */
    IMMEDIATE;

    /**
     * The strategy named {@code name}, in any case.
     *
     * @param name {@code gradual} or {@code immediate}
     * @return the strategy
     * @throws IllegalArgumentException for another name
     */
    public static DrainStrategy parse(String name) {
        return switch (name.strip().toLowerCase(Locale.ROOT)) {
            case "gradual" -> GRADUAL;
            case "immediate" -> IMMEDIATE;
            default -> throw new IllegalArgumentException("unknown drain strategy: " + name + "; expected gradual or immediate");
        };
    }
}
