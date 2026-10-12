package org.microproxy;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

/**
 * What the calls into scripts for one exchange added up to, as {@link FlowContext#scriptStats()}
 * gives it: how many calls, how long they took, how many interpreter steps they ran and about how
 * many bytes of values they created (an estimate of what was made, not of what stayed in memory).
 * The calls of an exchange may come from several threads (a tunnel's two directions), so the
 * totals are added to without a lock; read together they may be a call apart.
 */
public final class ScriptUsage {

    /** The totals of an exchange no script was called for: all zero, and never added to. */
    public static final ScriptUsage NONE = new ScriptUsage();

    private static final VarHandle CALLS;
    private static final VarHandle NANOS;
    private static final VarHandle STEPS;
    private static final VarHandle ALLOC_BYTES;

    static {
        try {
            MethodHandles.Lookup lookup = MethodHandles.lookup();
            CALLS = lookup.findVarHandle(ScriptUsage.class, "calls", long.class);
            NANOS = lookup.findVarHandle(ScriptUsage.class, "nanos", long.class);
            STEPS = lookup.findVarHandle(ScriptUsage.class, "steps", long.class);
            ALLOC_BYTES = lookup.findVarHandle(ScriptUsage.class, "allocBytes", long.class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @SuppressWarnings("unused") // through CALLS
    private volatile long calls;
    @SuppressWarnings("unused") // through NANOS
    private volatile long nanos;
    @SuppressWarnings("unused") // through STEPS
    private volatile long steps;
    @SuppressWarnings("unused") // through ALLOC_BYTES
    private volatile long allocBytes;

    ScriptUsage() {}

    /** Adds one call. */
    void add(long nanos, long steps, long allocBytes) {
        CALLS.getAndAdd(this, 1L);
        NANOS.getAndAdd(this, nanos);
        STEPS.getAndAdd(this, steps);
        ALLOC_BYTES.getAndAdd(this, allocBytes);
    }

    /** {@return the number of calls into scripts} */
    public long calls() {
        return calls;
    }

    /** {@return the nanoseconds the calls took, together} */
    public long nanos() {
        return nanos;
    }

    /** {@return the interpreter steps the calls ran, together} */
    public long steps() {
        return steps;
    }

    /** {@return about how many bytes of values the calls created, together} */
    public long allocBytes() {
        return allocBytes;
    }

    @Override
    public String toString() {
        return "ScriptUsage[calls=" + calls + ", nanos=" + nanos + ", steps=" + steps + ", allocBytes=" + allocBytes
                + "]";
    }
}
