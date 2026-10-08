package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * A response as scripts see it: from the server in {@code on_response}, or made by {@code
 * response()}. {@code status}, {@code reason}, {@code body} and {@code text} can be assigned.
 */
@StarlarkBuiltin(name = "response", doc = "An HTTP response.")
public final class ScriptResponse extends ScriptMessage {

    private static final ImmutableList<String> FIELDS = ImmutableList.of("status", "reason", "headers", "body", "text");

    private final HttpResponse response;

    ScriptResponse(HttpResponse response, boolean readOnly) {
        super(response, readOnly);
        this.response = response;
    }

    HttpResponse response() {
        return response;
    }

    /** Types the builtins that return this class (see {@link ScriptType}). */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.RESPONSE_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.RESPONSE;
    }

    @Override
    public Object getValue(String name) throws EvalException {
        return switch (name) {
            case "status" -> StarlarkInt.of(response.status().code());
            case "reason" -> response.status().reasonPhrase();
            case "headers" -> headers();
            case "body" -> body();
            case "text" -> text();
            default -> null;
        };
    }

    @Override
    public ImmutableList<String> getFieldNames() {
        return FIELDS;
    }

    @Override
    public void setField(String field, Object value) throws EvalException {
        switch (field) {
            case "status" -> {
                checkWritable(field);
                if (!(value instanceof StarlarkInt code)) {
                    throw Starlark.errorf("status must be an int, not %s", Starlark.type(value));
                }
                response.setStatus(status(code.toInt("status")));
            }
            case "reason" -> {
                checkWritable(field);
                if (!(value instanceof String reason)) {
                    throw Starlark.errorf("reason must be a string, not %s", Starlark.type(value));
                }
                if (reason.indexOf('\r') >= 0 || reason.indexOf('\n') >= 0) {
                    throw Starlark.errorf("reason must not contain line breaks");
                }
                response.setStatus(HttpResponseStatus.valueOf(response.status().code(), reason));
            }
            case "body" -> setBody(value);
            case "text" -> setText(value);
            default -> throw Starlark.errorf(FIELDS.contains(field)
                    ? "response." + field + " is read-only"
                    : getErrorMessageForUnknownField(field));
        }
    }

    static HttpResponseStatus status(int code) throws EvalException {
        if (code < 200 || code > 599) {
            throw Starlark.errorf("invalid status code %d", code);
        }
        return HttpResponseStatus.valueOf(code);
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<response ").append(response.status().code()).append('>');
    }
}
