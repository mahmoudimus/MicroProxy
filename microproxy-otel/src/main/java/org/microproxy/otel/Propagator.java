package org.microproxy.otel;

import java.util.List;
import org.microproxy.http.HttpHeaders;

/**
 * Reads a trace context from request headers and writes one onto them, in one format: W3C Trace
 * Context ({@link Propagators#TRACE_CONTEXT}), B3 in its single-header and multi-header forms
 * ({@link Propagators#B3}, {@link Propagators#B3_MULTI}) or Jaeger's {@code uber-trace-id} ({@link
 * Propagators#JAEGER}). The configured propagators form OpenTelemetry's composite propagator:
 * they extract in order, each over what the previous ones found, so the last that finds a valid
 * context gives the parent; and every one of them injects the proxy's context.
 */
public interface Propagator {

    /** {@return the name {@code OTEL_PROPAGATORS} gives this propagator, such as {@code tracecontext}} */
    String name();

    /** {@return the headers this propagator reads and writes, lower-case} */
    List<String> fields();

    /**
     * Reads the trace context in {@code headers}.
     *
     * @param headers the request's headers
     * @return the remote context, or {@code null} when there is none or it is not valid
     */
    SpanContext extract(HttpHeaders headers);

    /**
     * Writes {@code context} onto {@code headers}, replacing this propagator's {@linkplain #fields()
     * headers} that were there.
     *
     * @param context the context to send on
     * @param headers the request's headers, changed in place
     */
    void inject(SpanContext context, HttpHeaders headers);
}
