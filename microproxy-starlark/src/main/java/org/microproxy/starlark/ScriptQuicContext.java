package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.net.InetSocketAddress;
import org.microproxy.quic.QuicContext;
import org.microproxy.quic.QuicStreamContext;
import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * An intercepted QUIC connection, or one of its streams, as {@code on_quic_start}, {@code
 * on_quic_stream_data}, {@code on_quic_datagram} and {@code on_quic_end} see it: the client, the
 * server ({@code host}, {@code port}, {@code server}, and {@code address}, where the proxy connected
 * to), the {@code sni} and {@code alpn} both sides use, whether the QUIC came inside a CONNECT-UDP
 * flow ({@code masque}), {@code vars}, a dict that lives as long as the connection (its streams
 * share it), and {@code error}, why the connection failed ({@code None} until then, and for one that
 * ended normally). For {@code on_quic_stream_data}, {@code stream_id} (on the client's connection),
 * {@code bidirectional} and {@code client_initiated} name the stream, and {@code send(from_client,
 * data)} adds bytes to it, as {@link QuicStreamContext#send} does; they are {@code None} for the
 * connection's own hooks. {@code send_datagram(from_client, data)} adds a datagram.
 */
@StarlarkBuiltin(name = "quic_context", doc = "An intercepted QUIC connection or stream, and per-connection scratch space.")
public final class ScriptQuicContext implements Structure {

    private static final ImmutableList<String> FIELDS = ImmutableList.of("connection_id", "client_ip", "client_port",
            "host", "port", "server", "address", "sni", "alpn", "masque", "stream_id", "bidirectional",
            "client_initiated", "vars", "error");

    private final QuicContext context;
    /** The stream, for {@code on_quic_stream_data}; null for the connection's hooks. */
    private final QuicStreamContext stream;
    private final Dict<Object, Object> vars;
    private final String error;

    ScriptQuicContext(QuicContext context, QuicStreamContext stream, Dict<Object, Object> vars, String error) {
        this.context = context;
        this.stream = stream;
        this.vars = vars;
        this.error = error;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for a QUIC context value
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.QUIC_CONTEXT_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.QUIC_CONTEXT;
    }

    @Override
    public Object getValue(String name) {
        InetSocketAddress client = context.clientAddress();
        InetSocketAddress server = context.serverAddress();
        return switch (name) {
            case "connection_id" -> StarlarkInt.of(context.connectionId());
            case "client_ip" -> client == null ? "" : client.getAddress() != null
                    ? client.getAddress().getHostAddress() : client.getHostString();
            case "client_port" -> StarlarkInt.of(client == null ? 0 : client.getPort());
            case "host" -> context.host();
            case "port" -> StarlarkInt.of(context.port());
            case "server" -> (context.host().indexOf(':') >= 0 ? "[" + context.host() + "]" : context.host())
                    + ":" + context.port();
            case "address" -> server == null || server.getAddress() == null ? "" : server.getAddress().getHostAddress();
            case "sni" -> context.sni() == null ? Starlark.NONE : context.sni();
            case "alpn" -> context.alpn() == null ? Starlark.NONE : context.alpn();
            case "masque" -> context.masque();
            case "stream_id" -> stream == null ? Starlark.NONE : StarlarkInt.of(stream.streamId());
            case "bidirectional" -> stream == null ? Starlark.NONE : (Object) stream.bidirectional();
            case "client_initiated" -> stream == null ? Starlark.NONE : (Object) stream.clientInitiated();
            case "vars" -> vars;
            case "error" -> error == null ? Starlark.NONE : error;
            default -> null;
        };
    }

    /**
     * Adds bytes to the stream as if one side had sent them (see {@link QuicStreamContext#send}).
     *
     * @param fromClient true to send to the server, false to send to the client
     * @param data the bytes, or a string sent as UTF-8
     * @throws EvalException if {@code data} is neither bytes nor a string, there is no stream (the
     *     connection's own hooks), or that direction has ended
     */
    @StarlarkMethod(
            name = "send",
            doc = "Adds bytes to the stream as if one side sent them: to the server with from_client True, else to"
                    + " the client.",
            parameters = {@Param(name = "from_client"), @Param(name = "data")})
    public void send(Boolean fromClient, Object data) throws EvalException {
        byte[] bytes = Builtins.bytes(data, "data");
        if (stream == null) throw Starlark.errorf("send needs a stream: use send_datagram outside on_quic_stream_data");
        try {
            stream.send(fromClient, bytes);
        } catch (IllegalStateException e) {
            throw Starlark.errorf("%s", e.getMessage());
        }
    }

    /**
     * Sends a datagram as if one side had sent it (see {@link QuicContext#sendDatagram}).
     *
     * @param fromClient true to send to the server, false to send to the client
     * @param data the payload, or a string sent as UTF-8
     * @throws EvalException if {@code data} is neither bytes nor a string, or the connection has ended
     */
    @StarlarkMethod(
            name = "send_datagram",
            doc = "Sends a datagram as if one side sent it: to the server with from_client True, else to the client.",
            parameters = {@Param(name = "from_client"), @Param(name = "data")})
    public void sendDatagram(Boolean fromClient, Object data) throws EvalException {
        byte[] bytes = Builtins.bytes(data, "data");
        try {
            context.sendDatagram(fromClient, bytes);
        } catch (IllegalStateException e) {
            throw Starlark.errorf("%s", e.getMessage());
        }
    }

    @Override
    public ImmutableList<String> getFieldNames() {
        return FIELDS;
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "quic_context has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<quic_context connection ").append(context.connectionId()).append(" to ")
                .append((String) getValue("server"));
        if (stream != null) printer.append(" stream ").append(stream.streamId());
        printer.append('>');
    }
}
