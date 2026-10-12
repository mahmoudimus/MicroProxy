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
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * Bytes of an intercepted QUIC connection, as {@code on_quic_stream_data} (bytes read from one side
 * of a stream), {@code on_quic_message} (one whole message of a framed stream, without its length
 * prefix or delimiter) and {@code on_quic_datagram} (one datagram) see them: {@code data}, {@code
 * text} ({@code None} when the bytes are not valid UTF-8, as a character split between two reads is
 * not), {@code from_client}, {@code stream_id} (on the client's connection; {@code None} for a
 * datagram) and {@code timestamp} (seconds since the epoch). Assign {@code data} or {@code text} to
 * change what is passed on, or make a changed copy with {@code with_data}, {@code with_text} and
 * {@code with_from_client} and return it. Without framing, a stream has no message boundaries, as
 * TCP has none: a message is whatever one read returned.
 */
@StarlarkBuiltin(name = "quic_message",
        doc = "Bytes of an intercepted QUIC connection: of one stream read, one framed message, or one datagram.")
public final class ScriptQuicMessage implements Structure {

    private static final ImmutableList<String> FIELDS = ImmutableList.of("data", "text", "from_client", "stream_id",
            "timestamp");

    private final boolean fromClient;
    /** The stream's ID on the client's connection; null for a datagram. */
    private final Long streamId;
    private final Instant timestamp;
    private byte[] data;

    ScriptQuicMessage(byte[] data, boolean fromClient, Long streamId, Instant timestamp) {
        this.data = data;
        this.fromClient = fromClient;
        this.streamId = streamId;
        this.timestamp = timestamp;
    }

    /** Whether the message goes to the server. */
    boolean fromClient() {
        return fromClient;
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
            case "stream_id" -> streamId == null ? Starlark.NONE : StarlarkInt.of(streamId);
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
        return new ScriptQuicMessage(Builtins.bytes(data, "data"), fromClient, streamId, timestamp);
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
        return new ScriptQuicMessage(text.getBytes(StandardCharsets.UTF_8), fromClient, streamId, timestamp);
    }

    /**
     * A copy of this message going the other way, or the same: {@code on_quic_message} returns one
     * with {@code from_client=False} to answer the client itself, on the same stream.
     *
     * @param fromClient whether the copy goes to the server
     * @return the copy, with the same bytes, stream and timestamp
     */
    @StarlarkMethod(
            name = "with_from_client",
            doc = "A copy of this message that goes to the server (from_client True) or to the client (False).",
            parameters = {@Param(name = "from_client")})
    public ScriptQuicMessage withFromClient(Boolean fromClient) {
        return new ScriptQuicMessage(data, fromClient, streamId, timestamp);
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "quic_message has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<quic_message ").append(fromClient ? "from client, " : "from server, ");
        if (streamId != null) printer.append("stream ").append(streamId).append(", ");
        printer.append(data.length).append(" bytes>");
    }
}
