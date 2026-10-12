package org.microproxy.otel;

import java.util.Locale;

/**
 * Decides whether a new trace, or the proxy's part of a trace that came with the request, is
 * sampled: recorded and exported. The samplers are OpenTelemetry's, by the names {@code
 * OTEL_TRACES_SAMPLER} gives them: {@code always_on}, {@code always_off}, {@code traceidratio}
 * and the {@code parentbased_*} ones, which follow a sampled flag that came with the request and
 * ask their root sampler only for new traces.
 */
public interface Sampler {

    /**
     * Decides.
     *
     * @param parent the context that came with the request, or {@code null} for a new trace
     * @param traceIdHigh the trace id's first 8 bytes
     * @param traceIdLow the trace id's last 8 bytes, which {@link #traceIdRatio} decides by
     * @return whether to sample
     */
    boolean shouldSample(SpanContext parent, long traceIdHigh, long traceIdLow);

    /** {@return a description, such as {@code ParentBased{root:TraceIdRatioBased{0.25}}}} */
    String description();

    /** {@return a sampler that samples everything} */
    static Sampler alwaysOn() {
        return Samplers.ALWAYS_ON;
    }

    /** {@return a sampler that samples nothing} */
    static Sampler alwaysOff() {
        return Samplers.ALWAYS_OFF;
    }

    /**
     * A sampler that samples a fraction of traces, decided by the trace id alone, so every process
     * of a trace decides the same: the last 8 bytes of the id, as a signed number, are compared with
     * {@code ratio} times {@link Long#MAX_VALUE}, as OpenTelemetry's Java SDK does.
     *
     * @param ratio the fraction, from 0 to 1
     * @return the sampler
     * @throws IllegalArgumentException if {@code ratio} is not in [0, 1]
     */
    static Sampler traceIdRatio(double ratio) {
        return new Samplers.TraceIdRatio(ratio);
    }

    /**
     * A sampler that follows the request's sampled flag when it came with a trace context, and
     * asks {@code root} otherwise.
     *
     * @param root the sampler of new traces
     * @return the sampler
     */
    static Sampler parentBased(Sampler root) {
        return new Samplers.ParentBased(root);
    }

    /**
     * The sampler {@code OTEL_TRACES_SAMPLER} and {@code OTEL_TRACES_SAMPLER_ARG} name: {@code
     * always_on}, {@code always_off}, {@code traceidratio}, {@code parentbased_always_on} (the
     * default), {@code parentbased_always_off} or {@code parentbased_traceidratio}; the ratio is
     * the argument, 1 when there is none.
     *
     * @param name the sampler's name, or {@code null} for the default
     * @param arg the argument, or {@code null}
     * @return the sampler
     * @throws IllegalArgumentException for an unknown name or a bad ratio
     */
    static Sampler of(String name, String arg) {
        String n = name == null || name.isBlank() ? "parentbased_always_on" : name.strip().toLowerCase(Locale.ROOT);
        double ratio = 1.0;
        if (arg != null && !arg.isBlank()) {
            try {
                ratio = Double.parseDouble(arg.strip());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("bad sampler ratio: " + arg);
            }
        }
        return switch (n) {
            case "always_on" -> alwaysOn();
            case "always_off" -> alwaysOff();
            case "traceidratio" -> traceIdRatio(ratio);
            case "parentbased_always_on" -> parentBased(alwaysOn());
            case "parentbased_always_off" -> parentBased(alwaysOff());
            case "parentbased_traceidratio" -> parentBased(traceIdRatio(ratio));
            default -> throw new IllegalArgumentException("unknown sampler: " + name + " (known: always_on, always_off,"
                    + " traceidratio, parentbased_always_on, parentbased_always_off, parentbased_traceidratio)");
        };
    }
}
