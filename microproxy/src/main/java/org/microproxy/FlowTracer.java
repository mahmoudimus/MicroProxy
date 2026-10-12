package org.microproxy;

import org.microproxy.http.HttpRequest;

/**
 * Traces the proxy's exchanges and flows: given with {@link HttpProxyServerBootstrap#withTracer},
 * it is asked for a {@link FlowTrace} when each request head arrives, and handed each exchange's
 * and flow's {@link FlowRecord} when it is over. The optional {@code microproxy-otel} module
 * implements it with OpenTelemetry's W3C Trace Context, B3 and Jaeger propagation and OTLP
 * export; the core only calls it.
 *
 * <p>Calls run on the exchange's thread and should be quick. {@link #NOOP}, the default, costs
 * nothing: the proxy checks for it before calling.
 */
public interface FlowTracer extends AutoCloseable {

    /** Traces nothing. */
    FlowTracer NOOP = new FlowTracer() {
        @Override
        public FlowTrace startExchange(FlowContext flow, HttpRequest request) {
            return FlowTrace.NONE;
        }

        @Override
        public String toString() {
            return "FlowTracer.NOOP";
        }
    };

    /**
     * Called when a request head arrives from the client, before trackers, authentication and
     * filters see it, so that headers the tracer adds (an {@code X-Request-Id}) are seen by all of
     * them and the access log. The request may also be a {@code CONNECT} (real, or made up for a
     * SOCKS client or a transparent connection), which opens a tunnel or a flow.
     *
     * @param flow the exchange's context
     * @param request the request head, which may be changed in place
     * @return the exchange's trace, or {@link FlowTrace#NONE} to trace nothing
     */
    FlowTrace startExchange(FlowContext flow, HttpRequest request);

    /**
     * Called once per finished exchange or flow, with the record {@link
     * ActivityTracker#flowEnded} gets: {@link FlowRecord#trace()} is the trace {@link
     * #startExchange} made, or {@link FlowTrace#NONE} for a flow that had no request of its own (a
     * relayed transparent QUIC flow, a request a transport answered itself).
     *
     * @param record the finished exchange or flow
     */
    default void flowEnded(FlowRecord record) {}

    /**
     * Called once a proxy that uses this tracer has started, for instance to read its {@link
     * HttpProxyServer#getStats() stats}.
     *
     * @param server the running proxy
     */
    default void proxyStarted(HttpProxyServer server) {}

    /** Called once the proxy has stopped, after its exchanges ended: a last chance to flush. */
    @Override
    default void close() {}
}
