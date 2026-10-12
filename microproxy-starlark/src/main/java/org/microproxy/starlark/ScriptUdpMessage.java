package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkFloat;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * One datagram of a UDP flow (CONNECT-UDP), as {@code on_udp_message} sees it: {@code data},
 * {@code text} ({@code None} when the payload is not valid UTF-8), {@code from_client} and {@code
 * timestamp} (seconds since the epoch). Assign {@code data} or {@code text} to change what is
 * sent on, or make a changed copy with {@code with_data} and {@code with_text} and return it. UDP
 * keeps message boundaries: a message is one datagram.
 */
@StarlarkBuiltin(name = "udp_message", doc = "One datagram of a UDP flow.")
public final class ScriptUdpMessage implements Structure {

    private static final ImmutableList<String> FIELDS = ImmutableList.of("data", "text", "from_client", "timestamp");

    private final boolean fromClient;
    private final Instant timestamp;
    private byte[] data;

    ScriptUdpMessage(byte[] data, boolean fromClient, Instant timestamp) {
        this.data = data;
        this.fromClient = fromClient;
        this.timestamp = timestamp;
    }

    /** The payload to send on: the one received, or the one assigned. */
    byte[] data() {
        return data;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for a UDP message value
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.UDP_MESSAGE_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.UDP_MESSAGE;
    }

    @Override
    public Object getValue(String name) {
        return switch (name) {
            case "data" -> StarlarkBytes.of(null, data);
            case "text" -> text();
            case "from_client" -> fromClient;
            case "timestamp" -> StarlarkFloat.of(timestamp.getEpochSecond() + timestamp.getNano() / 1e9);
            default -> null;
        };
    }

    private Object text() {
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(data)).toString();
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
            case "data" -> data = Builtins.bytes(value, "data");
            case "text" -> {
                if (!(value instanceof String text)) {
                    throw Starlark.errorf("text must be a string, not %s", Starlark.type(value));
                }
                data = text.getBytes(StandardCharsets.UTF_8);
            }
            default -> throw Starlark.errorf(FIELDS.contains(field)
                    ? "udp_message." + field + " is read-only"
                    : getErrorMessageForUnknownField(field));
        }
    }

    /**
     * A copy of this message with another payload.
     *
     * @param data the payload of the copy, as bytes or a string (UTF-8)
     * @return the copy, with the same direction and timestamp
     * @throws EvalException if {@code data} is neither bytes nor a string
     */
    @StarlarkMethod(
            name = "with_data",
            doc = "A copy of this message with another payload (bytes, or a string as UTF-8).",
            parameters = {@Param(name = "data")})
    public ScriptUdpMessage withData(Object data) throws EvalException {
        return new ScriptUdpMessage(Builtins.bytes(data, "data"), fromClient, timestamp);
    }

    /**
     * A copy of this message with the UTF-8 encoding of {@code text}.
     *
     * @param text the text of the copy
     * @return the copy, with the same direction and timestamp
     */
    @StarlarkMethod(
            name = "with_text",
            doc = "A copy of this message with the UTF-8 encoding of text.",
            parameters = {@Param(name = "text")})
    public ScriptUdpMessage withText(String text) {
        return new ScriptUdpMessage(text.getBytes(StandardCharsets.UTF_8), fromClient, timestamp);
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "udp_message has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<udp_message ").append(fromClient ? "from client, " : "from target, ")
                .append(data.length).append(" bytes>");
    }
}
