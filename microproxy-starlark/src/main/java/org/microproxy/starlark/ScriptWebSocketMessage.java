package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.nio.charset.StandardCharsets;
import org.microproxy.http.WebSocketMessage;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * A whole WebSocket message as {@code on_websocket_message} sees it, or one a script made with
 * {@code websocket_message(...)}. {@code text} and {@code payload} can be assigned to change what
 * is sent; {@code text} is {@code None} for a payload that is not valid UTF-8.
 */
@StarlarkBuiltin(name = "websocket_message", doc = "A whole WebSocket message.")
public final class ScriptWebSocketMessage implements Structure {

    private static final ImmutableList<String> FIELDS =
            ImmutableList.of("type", "from_client", "length", "text", "payload");

    private WebSocketMessage message;

    ScriptWebSocketMessage(WebSocketMessage message) {
        this.message = message;
    }

    /** The message to send: the original, or one rebuilt from assigned fields. */
    WebSocketMessage message() {
        return message;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for a WebSocket message value
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.WEBSOCKET_MESSAGE_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.WEBSOCKET_MESSAGE;
    }

    @Override
    public Object getValue(String name) {
        return switch (name) {
            case "type" -> message.isText() ? "text" : "binary";
            case "from_client" -> message.fromClient();
            case "length" -> StarlarkInt.of(message.length());
            case "text" -> {
                String text = message.textOrNull();
                yield text == null ? Starlark.NONE : text;
            }
            case "payload" -> StarlarkBytes.of(null, message.payload());
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
            case "text" -> {
                if (!(value instanceof String text)) {
                    throw Starlark.errorf("text must be a string, not %s", Starlark.type(value));
                }
                message = message.withPayload(text.getBytes(StandardCharsets.UTF_8));
            }
            case "payload" -> message = message.withPayload(Builtins.bytes(value, "payload"));
            default -> throw Starlark.errorf(FIELDS.contains(field)
                    ? "websocket_message." + field + " is read-only"
                    : getErrorMessageForUnknownField(field));
        }
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "websocket_message has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<websocket_message ").append((String) getValue("type"))
                .append(message.fromClient() ? " from client, " : " from server, ")
                .append(message.length()).append(" bytes>");
    }
}
