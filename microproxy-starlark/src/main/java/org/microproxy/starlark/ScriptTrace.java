package org.microproxy.starlark;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.microproxy.FlowTrace;
import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Sequence;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkFloat;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;

/**
 * The {@code trace} module: the distributed trace of the exchange a hook runs for (see {@code
 * microproxy-otel}), whose span a script can add attributes and events to: {@code
 * trace.set_attribute("tenant", "acme")}, {@code trace.add_event("rule.matched", {"rule": "r1"})}.
 * {@code ctx.trace_id} and {@code ctx.span_id} read its ids. The calls add to the exchange's span
 * (the tunnel's or flow's, in the TCP, UDP and QUIC hooks), not to the span of the hook call itself
 * ({@link ScriptSpans}): what a script notes describes the exchange, and stays on its span however
 * many hooks see it. In a hook without an exchange ({@code upstream}, a QUIC framer), or without a
 * tracer, or when the exchange is not sampled, the calls do nothing. Values are strings, booleans, ints, floats, or lists of those; others are recorded as
 * their {@code str()}.
 */
@StarlarkBuiltin(name = "trace", doc = "The exchange's distributed trace: attributes and events on its span.")
public final class ScriptTrace implements StarlarkValue {

    /** The module. */
    static final ScriptTrace MODULE = new ScriptTrace();

    private ScriptTrace() {}

    /** The trace of the exchange the calling hook runs for, which {@link StarlarkScript#call} keeps on the thread. */
    private static FlowTrace current(StarlarkThread thread) {
        FlowTrace trace = thread.getThreadLocal(FlowTrace.class);
        return trace == null ? FlowTrace.NONE : trace;
    }

    /**
     * {@code trace.set_attribute(key, value)}: sets an attribute of the exchange's span.
     *
     * @param key the attribute's name
     * @param value its value
     * @param thread the calling thread
     * @throws EvalException if the key is empty
     */
    @StarlarkMethod(name = "set_attribute", doc = "Sets an attribute of the exchange's span.", useStarlarkThread = true,
            parameters = {@Param(name = "key", doc = "the attribute's name"), @Param(name = "value", doc = "its value")})
    public void setAttribute(String key, Object value, StarlarkThread thread) throws EvalException {
        if (key.isEmpty()) throw Starlark.errorf("an attribute needs a name");
        current(thread).setAttribute(key, java(value));
    }

    /**
     * {@code trace.add_event(name, attributes={})}: adds an event, now, to the exchange's span.
     *
     * @param name the event's name
     * @param attributes the event's attributes
     * @param thread the calling thread
     * @throws EvalException if an attribute's name is not a string
     */
    @StarlarkMethod(name = "add_event", doc = "Adds an event, now, to the exchange's span.", useStarlarkThread = true,
            parameters = {
                @Param(name = "name", doc = "the event's name"),
                @Param(name = "attributes", doc = "a dict of attributes", defaultValue = "{}")
            })
    public void addEvent(String name, Dict<?, ?> attributes, StarlarkThread thread) throws EvalException {
        Map<String, Object> converted = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : attributes.entrySet()) {
            if (!(e.getKey() instanceof String key)) throw Starlark.errorf("attribute names are strings");
            converted.put(key, java(e.getValue()));
        }
        current(thread).addEvent(name, converted);
    }

    /**
     * {@code trace.is_recording()}: whether the exchange's span is recorded (sampled), so a script
     * can skip computing attributes nobody will see.
     *
     * @param thread the calling thread
     * @return whether the span is recorded
     */
    @StarlarkMethod(name = "is_recording", doc = "Whether the exchange's span is sampled and recorded.",
            useStarlarkThread = true)
    public boolean isRecording(StarlarkThread thread) {
        return current(thread).isSampled();
    }

    /** A Starlark value as a span attribute's value. */
    private static Object java(Object value) {
        return switch (value) {
            case String s -> s;
            case Boolean b -> b;
            case StarlarkInt i -> {
                try {
                    yield i.toLong("value");
                } catch (EvalException e) {
                    yield i.toString();
                }
            }
            case StarlarkFloat f -> f.toDouble();
            case Sequence<?> seq -> {
                List<Object> list = new ArrayList<>(seq.size());
                for (Object o : seq) list.add(o instanceof Sequence<?> ? Starlark.str(o, StarlarkSemantics.DEFAULT) : java(o));
                yield list;
            }
            default -> Starlark.str(value, StarlarkSemantics.DEFAULT);
        };
    }
}
