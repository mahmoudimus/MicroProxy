package org.microproxy.starlark;

/** A Starlark script failed to parse, compile or run its top-level statements. */
public final class ScriptException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Describes a script failure without an underlying exception.
     *
     * @param message the diagnostic, including script location when available
     */
    public ScriptException(String message) {
        super(message);
    }

    /**
     * Describes a script failure and preserves its underlying exception.
     *
     * @param message the diagnostic, including script location when available
     * @param cause the parse, evaluation or interruption failure
     */
    public ScriptException(String message, Throwable cause) {
        super(message, cause);
    }
}
