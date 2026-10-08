package org.microproxy.starlark;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.HttpBodies;
import org.microproxy.http.HttpMessage;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.Structure;

/**
 * Body and header access shared by {@link ScriptRequest} and {@link ScriptResponse}. {@code body}
 * and {@code text} are the content-decoded body (bytes and text in the declared charset) and are
 * {@code None} when the body was streamed rather than buffered. Assigning either re-encodes with
 * the message's content coding.
 */
abstract class ScriptMessage implements Structure {

    final HttpMessage message;
    final boolean readOnly;
    private final ScriptHeaders headers;
    private byte[] decoded;

    ScriptMessage(HttpMessage message, boolean readOnly) {
        this.message = message;
        this.readOnly = readOnly;
        this.headers = new ScriptHeaders(message.headers(), readOnly);
    }

    ScriptHeaders headers() {
        return headers;
    }

    /** Whether the whole body is available. */
    boolean buffered() {
        return message instanceof FullHttpMessage;
    }

    Object body() throws EvalException {
        if (!buffered()) return Starlark.NONE;
        return StarlarkBytes.of(null, decoded());
    }

    Object text() throws EvalException {
        if (!buffered()) return Starlark.NONE;
        return new String(decoded(), HttpBodies.charset(message, StandardCharsets.UTF_8));
    }

    void setBody(Object value) throws EvalException {
        FullHttpMessage full = writableBody("body");
        byte[] bytes;
        if (value instanceof StarlarkBytes b) {
            bytes = b.toByteArray();
        } else if (value instanceof String s) {
            bytes = s.getBytes(HttpBodies.charset(message, StandardCharsets.UTF_8));
        } else {
            throw Starlark.errorf("body must be bytes or string, not %s", Starlark.type(value));
        }
        try {
            HttpBodies.setDecoded(full, bytes);
        } catch (IOException e) {
            throw Starlark.errorf("cannot encode body: %s", e.getMessage());
        }
        decoded = bytes;
    }

    void setText(Object value) throws EvalException {
        if (!(value instanceof String)) {
            throw Starlark.errorf("text must be a string, not %s", Starlark.type(value));
        }
        writableBody("text");
        setBody(value);
    }

    private byte[] decoded() throws EvalException {
        if (decoded == null) {
            try {
                decoded = HttpBodies.decoded((FullHttpMessage) message);
            } catch (IOException e) {
                throw Starlark.errorf("cannot decode body: %s", e.getMessage());
            }
        }
        return decoded;
    }

    private FullHttpMessage writableBody(String field) throws EvalException {
        checkWritable(field);
        if (!(message instanceof FullHttpMessage full)) {
            throw Starlark.errorf("%s is not available: the body was streamed, not buffered", field);
        }
        return full;
    }

    void checkWritable(String field) throws EvalException {
        if (readOnly) {
            throw Starlark.errorf("%s is read-only here", field);
        }
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return Starlark.type(this) + " has no field '" + field + "'";
    }
}
