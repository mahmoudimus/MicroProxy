package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import org.microproxy.FlowContext;
import org.microproxy.ScriptUsage;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.StarlarkFloat;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * {@code ctx.script_stats}: what the calls into scripts for the exchange added up to before the
 * call reading it ({@link FlowContext#scriptStats()}), read when it is: {@code calls}, {@code
 * time_ms} (a float), {@code steps} and {@code alloc_bytes} (an estimate of the bytes of values the
 * calls created, not of what stayed in memory).
 */
@StarlarkBuiltin(name = "script_stats", doc = "What the calls into scripts for the exchange added up to.")
public final class ScriptUsageValue implements Structure {

    private static final ImmutableList<String> FIELDS = ImmutableList.of("calls", "time_ms", "steps", "alloc_bytes");

    private final ScriptUsage usage;

    ScriptUsageValue(ScriptUsage usage) {
        this.usage = usage;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for script totals
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.SCRIPT_STATS_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.SCRIPT_STATS;
    }

    @Override
    public Object getValue(String name) {
        return switch (name) {
            case "calls" -> StarlarkInt.of(usage.calls());
            case "time_ms" -> StarlarkFloat.of(usage.nanos() / 1e6);
            case "steps" -> StarlarkInt.of(usage.steps());
            case "alloc_bytes" -> StarlarkInt.of(usage.allocBytes());
            default -> null;
        };
    }

    @Override
    public ImmutableList<String> getFieldNames() {
        return FIELDS;
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "script_stats has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<script_stats");
        for (String field : FIELDS) {
            printer.append(' ').append(field).append('=');
            printer.repr(getValue(field), semantics);
        }
        printer.append('>');
    }
}
