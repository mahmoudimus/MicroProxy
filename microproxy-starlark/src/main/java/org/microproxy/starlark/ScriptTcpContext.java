package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.net.InetSocketAddress;
import org.microproxy.tcp.TcpContext;
import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * A raw TCP tunnel, as {@code on_tcp_start}, {@code on_tcp_message} and {@code on_tcp_end} see
 * it: the client, the target, whether the proxy decrypted the client's TLS ({@code tls}) with its
 * {@code sni} and {@code alpn}, {@code vars}, a dict that lives as long as the tunnel, and {@code
 * error}, why the tunnel failed ({@code None} until then, and for one that ended normally). {@code
 * send(from_client, data)} adds bytes, as {@link TcpContext#send} does.
 */
@StarlarkBuiltin(name = "tcp_context", doc = "A raw TCP tunnel and per-tunnel scratch space.")
public final class ScriptTcpContext implements Structure {

    private static final ImmutableList<String> FIELDS = ImmutableList.of("connection_id", "client_ip", "client_port",
            "host", "port", "server", "tls", "sni", "alpn", "vars", "error");

    private final TcpContext context;
    private final Dict<Object, Object> vars;
    private volatile String error;

    ScriptTcpContext(TcpContext context, Mutability mu) {
        this.context = context;
        this.vars = Dict.of(mu);
    }

    /** Records why the tunnel failed, for {@code on_tcp_end}. */
    void error(Throwable failure) {
        String message = failure.getMessage();
        error = message == null || message.isEmpty() ? failure.getClass().getSimpleName() : message;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for a TCP context value
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.TCP_CONTEXT_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.TCP_CONTEXT;
    }

    @Override
    public Object getValue(String name) {
        InetSocketAddress client = context.clientAddress();
        return switch (name) {
            case "connection_id" -> StarlarkInt.of(context.connectionId());
            case "client_ip" -> client == null ? "" : client.getAddress() != null
                    ? client.getAddress().getHostAddress() : client.getHostString();
            case "client_port" -> StarlarkInt.of(client == null ? 0 : client.getPort());
            case "host" -> context.host();
            case "port" -> StarlarkInt.of(context.port());
            case "server" -> (context.host().indexOf(':') >= 0 ? "[" + context.host() + "]" : context.host())
                    + ":" + context.port();
            case "tls" -> context.tlsIntercepted();
            case "sni" -> context.sni() == null ? Starlark.NONE : context.sni();
            case "alpn" -> context.alpn() == null ? Starlark.NONE : context.alpn();
            case "vars" -> vars;
            case "error" -> error == null ? Starlark.NONE : error;
            default -> null;
        };
    }

    /**
     * Adds bytes to the tunnel as if one side had sent them (see {@link TcpContext#send}).
     *
     * @param fromClient true to send to the server, false to send to the client
     * @param data the bytes, or a string sent as UTF-8
     * @throws EvalException if {@code data} is neither bytes nor a string, or that direction has
     *     ended
     */
    @StarlarkMethod(
            name = "send",
            doc = "Adds bytes as if one side sent them: to the server with from_client True, else to the client.",
            parameters = {@Param(name = "from_client"), @Param(name = "data")})
    public void send(Boolean fromClient, Object data) throws EvalException {
        byte[] bytes = Builtins.bytes(data, "data");
        try {
            context.send(fromClient, bytes);
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
        return "tcp_context has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<tcp_context connection ").append(context.connectionId()).append(" to ")
                .append((String) getValue("server")).append('>');
    }
}
