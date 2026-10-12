package org.microproxy;

/**
 * Sees every call into a script's hooks (with the optional Starlark module): when it starts, and
 * how it ended, with the interpreter steps it ran, about how many bytes of values it created, how
 * long it took and why it failed. It is the place for tracing to make a span of each call, as a
 * child of its exchange's. Register one with {@link HttpProxyServerBootstrap#withScriptCallObserver}
 * (the {@code --script} option passes it on to the script) or the script's builder.
 *
 * <p>Calls come from the proxy's threads, at the same time for different exchanges (and for the two
 * directions of a tunnel), so implementations must be thread-safe; they run inside the hook call,
 * so they must be quick and must not throw. Without an observer the proxy calls nothing.
 */
public interface ScriptCallObserver {

    /** Sees nothing. */
    ScriptCallObserver NOOP = new ScriptCallObserver() {};

    /**
     * A call is starting.
     *
     * @param hook the function called: {@code on_request}, {@code on_response}, {@code on_frame},
     *     {@code on_tcp_message}, ...
     * @param script the script's name, as its stats are tagged
     * @param flow the exchange the call is for (the tunnel's or flow's, for TCP, UDP and QUIC hooks),
     *     or null when the hook has none ({@code upstream}, a QUIC framer)
     * @return a value handed back to {@link #onCallEnd} (a span, say), or null
     */
    default Object onCallStart(String hook, String script, FlowContext flow) {
        return null;
    }

    /**
     * A call has ended.
     *
     * @param token what {@link #onCallStart} returned for the call
     * @param hook the function called
     * @param script the script's name
     * @param flow the exchange the call was for, or null
     * @param steps the interpreter steps the call ran
     * @param allocBytes about how many bytes of values the call created (an estimate)
     * @param nanos how long the call took
     * @param budgetExceeded the budget the call ran out of, {@code "steps"}, {@code "memory"} or
     *     {@code "time"}, or null
     * @param error why the call failed, or null when it returned
     */
    default void onCallEnd(Object token, String hook, String script, FlowContext flow, long steps, long allocBytes,
            long nanos, String budgetExceeded, Throwable error) {}
}
