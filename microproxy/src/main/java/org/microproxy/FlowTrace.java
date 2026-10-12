package org.microproxy;

import java.util.Map;
import org.microproxy.http.HttpHeaders;

/**
 * The distributed trace of one exchange, made by a {@link FlowTracer} when the request head
 * arrives: its trace and span ids, which {@link FlowContext#trace()}, access logs ({@code
 * %TRACE_ID%}, {@code %SPAN_ID%}) and scripts ({@code ctx.trace_id}) show, and the calls through
 * which the proxy reports each attempt to reach the server and asks for the headers that carry the
 * trace to it.
 *
 * <p>The proxy calls the attempt methods on the exchange's thread, in this order for each attempt:
 * {@link #attemptStarted} when it begins to connect to the server or a chained proxy (or to send
 * the request on a connection at hand), {@link #injectUpstream} right before a request head (the
 * exchange's, or a {@code CONNECT} to a chained proxy) is written, and {@link #attemptEnded}. A
 * failed connection to one chained proxy, the next one tried, and a request sent again after a
 * stale keep-alive connection are attempts of their own. Every method has a no-op default; {@link
 * #NONE} is the trace of an exchange nobody traces.
 */
public interface FlowTrace {

    /** No trace: ids are {@code null} and every call does nothing. */
    FlowTrace NONE = new FlowTrace() {
        @Override
        public String toString() {
            return "FlowTrace.NONE";
        }
    };

    /** {@return the trace id, 32 lower-case hex digits, or {@code null} for no trace} */
    default String traceId() {
        return null;
    }

    /** {@return the id of the proxy's span for the exchange, 16 lower-case hex digits, or {@code null}} */
    default String spanId() {
        return null;
    }

    /** {@return whether the trace is sampled: its spans are recorded and exported} */
    default boolean isSampled() {
        return false;
    }

    /**
     * The exchange's request id ({@code X-Request-Id}), which access logs show as {@code
     * %UNIQUE_ID%} too, or {@code null} to leave {@link FlowRecord#uniqueId()} random.
     *
     * @return the request id, or {@code null}
     */
    default String requestId() {
        return null;
    }

    /**
     * Adds an attribute to the exchange's span; ignored when it is not sampled.
     *
     * @param key the attribute's name
     * @param value a {@code String}, {@code Boolean}, integer, floating-point number, or a list of
     *     those; other values are recorded as their {@code toString()}
     */
    default void setAttribute(String key, Object value) {}

    /**
     * Adds an event, at the current time, to the exchange's span; ignored when it is not sampled.
     *
     * @param name the event's name
     * @param attributes the event's attributes (values as for {@link #setAttribute}), possibly empty
     */
    default void addEvent(String name, Map<String, ?> attributes) {}

    /**
     * An attempt to reach the server begins: a connection to it or to a chained proxy, or a request
     * on a connection at hand.
     *
     * @param hostAndPort the server's {@code host:port}
     * @param chainedProxy the chained proxy the attempt goes through, or {@code null} for a direct
     *     connection
     */
    default void attemptStarted(String hostAndPort, ChainedProxy chainedProxy) {}

    /**
     * A request head is about to be written upstream for the current attempt, after the proxy
     * removed the headers it strips ({@link HttpProxyServerBootstrap#withStrippedRequestHeaders}):
     * the trace may put its propagation headers on it.
     *
     * @param headers the request's headers, to change in place
     * @param tracingHeadersStripped whether the proxy strips the tracing headers ({@code
     *     traceparent} among them) from requests sent upstream
     */
    default void injectUpstream(HttpHeaders headers, boolean tracingHeadersStripped) {}

    /**
     * The current attempt is over.
     *
     * @param status the status of the server's response, or 0 when none came
     * @param errorType why the attempt failed, as a short low-cardinality name ({@code
     *     connect_failed}, {@code server_timeout}, {@code stale_connection}, ...), or {@code null}
     *     when it did not
     */
    default void attemptEnded(int status, String errorType) {}
}
