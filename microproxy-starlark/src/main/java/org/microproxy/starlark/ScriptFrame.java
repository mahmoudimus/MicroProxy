package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import org.microproxy.http.WebSocketFrame;
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
 * A WebSocket frame as {@code on_websocket_frame} sees it. {@code text} and {@code payload} can
 * be assigned to change what is forwarded. {@code text} is {@code None} for a frame whose payload
 * is not valid UTF-8 or was too large to buffer ({@code truncated}).
 */
@StarlarkBuiltin(name = "websocket_frame", doc = "A WebSocket frame.")
public final class ScriptFrame implements Structure {

    private static final ImmutableList<String> FIELDS = ImmutableList.of(
            "type", "opcode", "fin", "from_client", "truncated", "length", "text", "payload");

    private final boolean fromClient;
    private WebSocketFrame frame;

    ScriptFrame(WebSocketFrame frame, boolean fromClient) {
        this.frame = frame;
        this.fromClient = fromClient;
    }

    /** The frame to forward: the original, or one rebuilt from assigned fields. */
    WebSocketFrame frame() {
        return frame;
    }

    /** Types the builtins that return this class (see {@link ScriptType}). */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.FRAME_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.FRAME;
    }

    @Override
    public Object getValue(String name) {
        return switch (name) {
            case "type" -> switch (frame.opcode()) {
                case WebSocketFrame.OPCODE_TEXT -> "text";
                case WebSocketFrame.OPCODE_BINARY -> "binary";
                case WebSocketFrame.OPCODE_CONTINUATION -> "continuation";
                case WebSocketFrame.OPCODE_CLOSE -> "close";
                case WebSocketFrame.OPCODE_PING -> "ping";
                case WebSocketFrame.OPCODE_PONG -> "pong";
                default -> "other";
            };
            case "opcode" -> StarlarkInt.of(frame.opcode());
            case "fin" -> frame.isFinal();
            case "from_client" -> fromClient;
            case "truncated" -> frame.isTruncated();
            case "length" -> StarlarkInt.of(frame.payloadLength());
            case "text" -> text();
            case "payload" -> frame.isTruncated() ? Starlark.NONE : StarlarkBytes.of(null, frame.payload());
            default -> null;
        };
    }

    private Object text() {
        byte[] payload = frame.payload();
        if (payload == null) return Starlark.NONE;
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(payload)).toString();
        } catch (CharacterCodingException e) {
            return Starlark.NONE;
        }
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
                frame = rebuild(text.getBytes(StandardCharsets.UTF_8));
            }
            case "payload" -> frame = rebuild(Builtins.bytes(value, "payload"));
            default -> throw Starlark.errorf(FIELDS.contains(field)
                    ? "websocket_frame." + field + " is read-only"
                    : getErrorMessageForUnknownField(field));
        }
    }

    private WebSocketFrame rebuild(byte[] payload) throws EvalException {
        if (frame.isTruncated()) {
            throw Starlark.errorf("a truncated frame cannot be rewritten; return False to drop it");
        }
        try {
            return frame.withPayload(payload);
        } catch (IllegalArgumentException e) {
            throw Starlark.errorf("%s", e.getMessage());
        }
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "websocket_frame has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<websocket_frame ").append((String) getValue("type"))
                .append(fromClient ? " from client, " : " from server, ")
                .append(frame.payloadLength()).append(" bytes>");
    }
}
