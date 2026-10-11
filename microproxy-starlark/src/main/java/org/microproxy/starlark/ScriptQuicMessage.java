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
 * Bytes of an intercepted QUIC connection, as {@code on_quic_stream_data} (bytes read from one side
 * of a stream) and {@code on_quic_datagram} (one datagram) see them: {@code data}, {@code text}
 * ({@code None} when the bytes are not valid UTF-8, as a character split between two reads is not),
 * {@code from_client} and {@code timestamp} (seconds since the epoch). Assign {@code data} or
 * {@code text} to change what is passed on, or make a changed copy with {@code with_data} and
 * {@code with_text} and return it. A stream has no message boundaries, as TCP has none: a message
 * is whatever one read returned.
 */
@StarlarkBuiltin(name = "quic_message", doc = "Bytes of an intercepted QUIC connection: of one stream read, or one datagram.")
public final class ScriptQuicMessage implements Structure {

    private static final ImmutableList<String> FIELDS = ImmutableList.of("data", "text", "from_client", "timestamp");

    private final boolean fromClient;
    private final Instant timestamp;
    private byte[] data;

    ScriptQuicMessage(byte[] data, boolean fromClient, Instant timestamp) {
        this.data = data;
        this.fromClient = fromClient;
        this.timestamp = timestamp;
    }

    /** The bytes to pass on: those read, or those assigned. */
    byte[] data() {
        return data;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for a QUIC message value
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.QUIC_MESSAGE_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.QUIC_MESSAGE;
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
                    ? "quic_message." + field + " is read-only"
                    : getErrorMessageForUnknownField(field));
        }
    }

    /**
     * A copy of this message with other bytes.
     *
     * @param data the bytes of the copy, as bytes or a string (UTF-8)
     * @return the copy, with the same direction and timestamp
     * @throws EvalException if {@code data} is neither bytes nor a string
     */
    @StarlarkMethod(
            name = "with_data",
            doc = "A copy of this message with other bytes (bytes, or a string as UTF-8).",
            parameters = {@Param(name = "data")})
    public ScriptQuicMessage withData(Object data) throws EvalException {
        return new ScriptQuicMessage(Builtins.bytes(data, "data"), fromClient, timestamp);
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
    public ScriptQuicMessage withText(String text) {
        return new ScriptQuicMessage(text.getBytes(StandardCharsets.UTF_8), fromClient, timestamp);
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "quic_message has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<quic_message ").append(fromClient ? "from client, " : "from server, ")
                .append(data.length).append(" bytes>");
    }
}
