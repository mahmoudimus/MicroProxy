package org.microproxy.starlark.stdlib;

import java.util.Map;
import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.ParamType;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.NoneType;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkIterable;
import org.microproxy.thirdparty.starlark.eval.StarlarkSet;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;
import org.microproxy.thirdparty.starlark.lib.json.Json;

/**
 * {@code @stdlib//json}: the interpreter's {@code json} module ({@link Json}, the same one scripts
 * have predeclared), with Python's names {@code dumps} and {@code loads}, and Python's refusal to
 * encode bytes and sets. As in Starlark, object keys are written in sorted order.
 */
@StarlarkBuiltin(name = "json", doc = "JSON encoding and decoding (Python's dumps/loads, Starlark's encode/decode).")
public final class JsonModule implements StarlarkValue {

    static final JsonModule INSTANCE = new JsonModule();

    private JsonModule() {}

    /**
     * Encodes a value as compact JSON with sorted object keys.
     *
     * @param x the Starlark value to encode
     * @param thread the calling interpreter thread
     * @return the JSON text
     * @throws EvalException if the value cannot be represented as JSON
     * @throws InterruptedException if encoding is interrupted
     */
    @StarlarkMethod(name = "encode", doc = "Encodes x as JSON (keys sorted, no spaces).",
            parameters = {@Param(name = "x")}, useStarlarkThread = true)
    public String encode(Object x, StarlarkThread thread) throws EvalException, InterruptedException {
        checkSerializable(x, 0);
        return Json.INSTANCE.encode(x, thread);
    }

    /**
     * Encodes a value using Python-style optional indentation.
     *
     * @param x the Starlark value to encode
     * @param indent the number of spaces, an indentation string or {@code None} for compact output
     * @param thread the calling interpreter thread
     * @return the JSON text
     * @throws EvalException if the value or indentation cannot be encoded
     * @throws InterruptedException if encoding is interrupted
     */
    @StarlarkMethod(name = "dumps", doc = "Python's json.dumps: encode(x), or encode_indent with indent spaces.",
            parameters = {
                @Param(name = "x"),
                @Param(name = "indent", named = true, defaultValue = "None",
                        allowedTypes = {@ParamType(type = StarlarkInt.class), @ParamType(type = String.class),
                            @ParamType(type = NoneType.class)}),
            },
            useStarlarkThread = true)
    public String dumps(Object x, Object indent, StarlarkThread thread) throws EvalException, InterruptedException {
        if (indent == Starlark.NONE) {
            return encode(x, thread);
        }
        String unit = indent instanceof StarlarkInt n ? " ".repeat(Math.max(0, n.toInt("indent"))) : (String) indent;
        checkSerializable(x, 0);
        return Json.INSTANCE.encodeIndent(x, "", unit, thread);
    }

    /**
     * Parses JSON, optionally returning a fallback for malformed input.
     *
     * @param x the JSON text
     * @param defaultValue the fallback, or {@code Starlark.UNBOUND} to report invalid JSON
     * @param thread the calling thread that owns decoded containers
     * @return the decoded Starlark value or the supplied fallback
     * @throws EvalException if JSON is invalid and no fallback was supplied
     */
    @StarlarkMethod(name = "decode", doc = "Decodes a JSON string; returns default (if given) for invalid JSON.",
            parameters = {@Param(name = "x"), @Param(name = "default", named = true, defaultValue = "unbound")},
            useStarlarkThread = true)
    public Object decode(String x, Object defaultValue, StarlarkThread thread) throws EvalException {
        return Json.INSTANCE.decode(x, defaultValue, thread);
    }

    /**
     * Parses JSON from text or strictly decoded UTF-8 bytes.
     *
     * @param s the JSON string or bytes
     * @param thread the calling thread that owns decoded containers
     * @return the decoded Starlark value
     * @throws EvalException if UTF-8 decoding or JSON parsing fails
     */
    @StarlarkMethod(name = "loads", doc = "Python's json.loads: decodes a JSON string (or UTF-8 bytes).",
            parameters = {
                @Param(name = "s", allowedTypes = {@ParamType(type = String.class), @ParamType(type = StarlarkBytes.class)})
            },
            useStarlarkThread = true)
    public Object loads(Object s, StarlarkThread thread) throws EvalException {
        String text = s instanceof StarlarkBytes b ? b.decodeWithCharset("utf-8", "strict") : (String) s;
        return Json.INSTANCE.decode(text, Starlark.UNBOUND, thread);
    }

    /**
     * Reformats JSON with a line prefix and indentation unit.
     *
     * @param s the JSON text to reformat
     * @param prefix the prefix for output lines
     * @param indent the indentation added per nesting level
     * @return the reformatted JSON text
     * @throws EvalException if the input is invalid JSON
     */
    @StarlarkMethod(name = "indent", doc = "Reformats a valid JSON string with indentation.",
            parameters = {
                @Param(name = "s"),
                @Param(name = "prefix", positional = false, named = true, defaultValue = "''"),
                @Param(name = "indent", positional = false, named = true, defaultValue = "'\\t'"),
            })
    public String indent(String s, String prefix, String indent) throws EvalException {
        return Json.INSTANCE.indent(s, prefix, indent);
    }

    /**
     * Encodes a value as JSON and formats it with indentation.
     *
     * @param x the Starlark value to encode
     * @param prefix the prefix for output lines
     * @param indent the indentation added per nesting level
     * @param thread the calling interpreter thread
     * @return the formatted JSON text
     * @throws EvalException if the value cannot be represented as JSON
     * @throws InterruptedException if encoding is interrupted
     */
    @StarlarkMethod(name = "encode_indent", doc = "encode(x), then indent.",
            parameters = {
                @Param(name = "x"),
                @Param(name = "prefix", positional = false, named = true, defaultValue = "''"),
                @Param(name = "indent", positional = false, named = true, defaultValue = "'\\t'"),
            },
            useStarlarkThread = true)
    public String encodeIndent(Object x, String prefix, String indent, StarlarkThread thread)
            throws EvalException, InterruptedException {
        checkSerializable(x, 0);
        return Json.INSTANCE.encodeIndent(x, prefix, indent, thread);
    }

    /** Bytes, bytearrays and sets are iterable, but not JSON types (as in Python's json). */
    private static void checkSerializable(Object x, int depth) throws EvalException {
        if (depth > 1000) {
            return; // the encoder reports cycles and excessive nesting itself
        }
        if (x instanceof StarlarkBytes || x instanceof StarlarkSet) {
            throw Starlark.errorf("Object of type %s is not JSON serializable", Starlark.type(x));
        }
        if (x instanceof Map<?, ?> m) {
            for (Object v : m.values()) {
                checkSerializable(v, depth + 1);
            }
        } else if (x instanceof StarlarkIterable<?> it && !(x instanceof String)) {
            for (Object v : it) {
                checkSerializable(v, depth + 1);
            }
        }
    }
}
