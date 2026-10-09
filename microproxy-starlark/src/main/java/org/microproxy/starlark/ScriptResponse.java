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
 * {@code source} says where it came from and {@code upstream_status} what the server sent; both
 * describe the response as the hook received it, not the script's own changes.
 */
@StarlarkBuiltin(name = "response", doc = "An HTTP response.")
public final class ScriptResponse extends ScriptMessage {

    private static final ImmutableList<String> FIELDS =
            ImmutableList.of("status", "reason", "headers", "body", "text", "source", "upstream_status");

    private final HttpResponse response;
    private final String source;
    private final int upstreamStatus;

    /** A response the script made ({@code response(...)}): its source is {@code "filter"}. */
    ScriptResponse(HttpResponse response, boolean readOnly) {
        this(response, readOnly, "filter", -1);
    }

    /**
     * @param source where the response came from ({@code "server"}, {@code "proxy"}, {@code
     *     "filter"}, {@code "cache"}), or null when that is not known
     * @param upstreamStatus the status the server sent, or -1 for none
     */
    ScriptResponse(HttpResponse response, boolean readOnly, String source, int upstreamStatus) {
        super(response, readOnly);
        this.response = response;
        this.source = source;
        this.upstreamStatus = upstreamStatus;
    }

    HttpResponse response() {
        return response;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for a response value
     */
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
            case "source" -> source == null ? Starlark.NONE : source;
            case "upstream_status" -> upstreamStatus < 0 ? Starlark.NONE : StarlarkInt.of(upstreamStatus);
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
