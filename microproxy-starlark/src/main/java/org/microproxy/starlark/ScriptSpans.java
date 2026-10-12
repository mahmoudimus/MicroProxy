package org.microproxy.starlark;

import org.microproxy.FlowContext;
import org.microproxy.FlowTrace;
import org.microproxy.ScriptCallObserver;

/**
 * Traces hook calls: the {@link ScriptCallObserver} that gives each call made for a sampled
 * exchange a span of its own ({@link FlowTrace#startSpan}), named {@code starlark <hook>}, a child
 * of the exchange's span (of the tunnel's or flow's, for the TCP, UDP and QUIC hooks), with the
 * attributes {@code starlark.hook}, {@code starlark.script}, {@code starlark.steps}, {@code
 * starlark.alloc_bytes} and, for a call stopped by a budget, {@code starlark.budget_exceeded}
 * ({@code steps}, {@code memory} or {@code time}); a call that fails has an error status with its
 * message. {@link StarlarkScript} uses it only for exchanges whose trace is sampled, so without a
 * tracer it costs nothing.
 */
final class ScriptSpans implements ScriptCallObserver {

    static final ScriptSpans INSTANCE = new ScriptSpans();

    private ScriptSpans() {}

    @Override
    public Object onCallStart(String hook, String script, FlowContext flow) {
        FlowTrace trace = flow == null ? FlowTrace.NONE : flow.trace();
        if (!trace.isSampled()) return null;
        FlowTrace.Span span = trace.startSpan("starlark " + hook);
        if (span == FlowTrace.Span.NONE) return null;
        span.setAttribute("starlark.hook", hook);
        span.setAttribute("starlark.script", script);
        return span;
    }

    @Override
    public void onCallEnd(Object token, String hook, String script, FlowContext flow, long steps, long allocBytes,
            long nanos, String budgetExceeded, Throwable error) {
        if (!(token instanceof FlowTrace.Span span)) return;
        span.setAttribute("starlark.steps", steps);
        span.setAttribute("starlark.alloc_bytes", allocBytes);
        if (budgetExceeded != null) span.setAttribute("starlark.budget_exceeded", budgetExceeded);
        span.end(error == null ? null : message(error));
    }

    /** The error's message (its first line: an EvalException's, without the Starlark stack). */
    private static String message(Throwable error) {
        String m = error.getMessage();
        if (m == null || m.isEmpty()) return error.getClass().getSimpleName();
        int nl = m.indexOf('\n');
        return nl < 0 ? m : m.substring(0, nl);
    }
}
