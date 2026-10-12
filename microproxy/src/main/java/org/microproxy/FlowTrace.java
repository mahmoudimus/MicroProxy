package org.microproxy;

import java.util.Map;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpVersion;

/**
 * The distributed trace of one exchange, made by a {@link FlowTracer} when the request head
 * arrives: its trace and span ids, which {@link FlowContext#trace()}, access logs ({@code
 * %TRACE_ID%}, {@code %SPAN_ID%}) and scripts ({@code ctx.trace_id}) show, and the calls through
 * which the proxy reports each attempt to reach the server and asks for the headers that carry the
 * trace to it.
 *
 * <p>The proxy calls the attempt methods on the exchange's thread, in this order for each attempt:
 * {@link #attemptStarted} when it begins to connect to the server or a chained proxy (or to send
 * the request on a connection at hand), {@link #upstreamRequest} once the exchange's request is
 * about to go on the connection, {@link #injectUpstream} right before a request head (the
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
     * Starts a span of the proxy's own work for the exchange, such as a script's hook call: an
     * INTERNAL span, a child of the exchange's span (of the tunnel's or flow's, for the hooks of a
     * tunnel or a flow), which ends when {@link Span#end} is called. A trace that is not sampled
     * returns {@link Span#NONE}, so callers that only start spans when {@link #isSampled()} pay
     * nothing otherwise.
     *
     * @param name the span's name, such as {@code starlark on_request}
     * @return the span, or {@link Span#NONE}
     */
    default Span startSpan(String name) {
        return Span.NONE;
    }

    /**
     * A span {@link #startSpan} started, used by one thread at a time. Every method has a no-op
     * default.
     */
    interface Span {

        /** No span: every call does nothing. */
        Span NONE = new Span() {
            @Override
            public String toString() {
                return "FlowTrace.Span.NONE";
            }
        };

        /**
         * Adds an attribute to the span.
         *
         * @param key the attribute's name
         * @param value a value as for {@link FlowTrace#setAttribute}
         */
        default void setAttribute(String key, Object value) {}

        /**
         * Ends the span, now; later calls do nothing.
         *
         * @param error why the work failed, which gives the span an error status with this message,
         *     or {@code null} when it did not
         */
        default void end(String error) {}
    }

    /**
     * An attempt to reach the server begins: a connection to it or to a chained proxy, or a request
     * on a connection at hand.
     *
     * @param hostAndPort the server's {@code host:port}
     * @param chainedProxy the chained proxy the attempt goes through, or {@code null} for a direct
     *     connection
     * @param tls whether the proxy speaks TLS to the server itself (to an {@code https} origin, an
     *     intercepted session's server or a reverse proxy's {@code https://} upstream), whatever
     *     the connection to a chained proxy is
     */
    default void attemptStarted(String hostAndPort, ChainedProxy chainedProxy, boolean tls) {}

    /**
     * The exchange's request is about to go to the server on the current attempt's connection, as
     * that connection really is.
     *
     * @param tls whether the proxy speaks TLS to the server on it (HTTP/2 and HTTP/3 always do)
     * @param version the protocol of the connection: {@link HttpVersion#HTTP_1_1}, {@link
     *     HttpVersion#HTTP_2_0} (a stream of a shared HTTP/2 connection) or {@link
     *     HttpVersion#HTTP_3_0}
     */
    default void upstreamRequest(boolean tls, HttpVersion version) {}

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
