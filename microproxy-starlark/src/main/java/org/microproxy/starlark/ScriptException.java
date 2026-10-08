package org.microproxy.starlark;

/** A Starlark script failed to parse, compile or run its top-level statements. */
public final class ScriptException extends Exception {

    private static final long serialVersionUID = 1L;

    public ScriptException(String message) {
        super(message);
    }

    public ScriptException(String message, Throwable cause) {
        super(message, cause);
    }
}
