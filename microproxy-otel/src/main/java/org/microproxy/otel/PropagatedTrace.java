package org.microproxy.otel;

import org.microproxy.FlowTrace;
import org.microproxy.http.HttpHeaders;

/**
 * The trace of an exchange that is not recorded (not sampled, or no traces are exported): ids and
 * propagation only. It records nothing, so it is all an unsampled exchange costs besides the
 * headers it writes.
 */
class PropagatedTrace implements FlowTrace {

    final Telemetry telemetry;
    final long traceIdHigh;
    final long traceIdLow;
    /** The proxy's span for the exchange. */
    final long spanId;
    final boolean sampled;
    /** The client's {@code tracestate}, sent on when the tracing headers are not stripped. */
    final String traceState;
    private final String requestId;

    PropagatedTrace(Telemetry telemetry, long traceIdHigh, long traceIdLow, long spanId, boolean sampled,
            String traceState, String requestId) {
        this.telemetry = telemetry;
        this.traceIdHigh = traceIdHigh;
        this.traceIdLow = traceIdLow;
        this.spanId = spanId;
        this.sampled = sampled;
        this.traceState = traceState == null ? "" : traceState;
        this.requestId = requestId;
    }

    @Override
    public String traceId() {
        return SpanContext.traceIdHex(traceIdHigh, traceIdLow);
    }

    @Override
    public String spanId() {
        return SpanContext.spanIdHex(spanId);
    }

    @Override
    public boolean isSampled() {
        return sampled;
    }

    @Override
    public String requestId() {
        return requestId;
    }

    @Override
    public void injectUpstream(HttpHeaders headers, boolean tracingHeadersStripped) {
        inject(headers, tracingHeadersStripped, spanId);
    }

    /** Writes the context with {@code parentSpanId} as the parent the server sees. */
    final void inject(HttpHeaders headers, boolean stripped, long parentSpanId) {
        if (stripped && telemetry.whenStripped == Telemetry.WhenStripped.NONE) return;
        SpanContext context = new SpanContext(traceIdHigh, traceIdLow, parentSpanId, sampled ? SpanContext.SAMPLED : 0,
                stripped ? "" : traceState, false);
        for (Propagator p : telemetry.propagators) p.inject(context, headers);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + traceId() + "-" + spanId() + (sampled ? " sampled" : "") + "]";
    }
}
