package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.net.InetSocketAddress;
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
import org.microproxy.udp.UdpContext;

/**
 * A UDP flow (CONNECT-UDP), as {@code on_udp_start}, {@code on_udp_message} and {@code on_udp_end}
 * see it: the client, the target ({@code host}, {@code port}, {@code server}, and {@code address},
 * what its name resolved to), and {@code vars}, a dict that lives as long as the flow. {@code
 * send(from_client, data)} adds a datagram, as {@link UdpContext#send} does.
 */
@StarlarkBuiltin(name = "udp_context", doc = "A UDP flow and per-flow scratch space.")
public final class ScriptUdpContext implements Structure {

    private static final ImmutableList<String> FIELDS = ImmutableList.of("connection_id", "client_ip", "client_port",
            "host", "port", "server", "address", "vars");

    private final UdpContext context;
    private final Dict<Object, Object> vars;

    ScriptUdpContext(UdpContext context, Mutability mu) {
        this.context = context;
        this.vars = Dict.of(mu);
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for a UDP context value
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.UDP_CONTEXT_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.UDP_CONTEXT;
    }

    @Override
    public Object getValue(String name) {
        InetSocketAddress client = context.clientAddress();
        InetSocketAddress target = context.targetAddress();
        return switch (name) {
            case "connection_id" -> StarlarkInt.of(context.connectionId());
            case "client_ip" -> client == null ? "" : client.getAddress() != null
                    ? client.getAddress().getHostAddress() : client.getHostString();
            case "client_port" -> StarlarkInt.of(client == null ? 0 : client.getPort());
            case "host" -> context.host();
            case "port" -> StarlarkInt.of(context.port());
            case "server" -> (context.host().indexOf(':') >= 0 ? "[" + context.host() + "]" : context.host())
                    + ":" + context.port();
            case "address" -> target == null || target.getAddress() == null ? "" : target.getAddress().getHostAddress();
            case "vars" -> vars;
            default -> null;
        };
    }

    /**
     * Adds a datagram to the flow as if one side had sent it (see {@link UdpContext#send}).
     *
     * @param fromClient true to send to the target, false to send to the client
     * @param data the payload, or a string sent as UTF-8
     * @throws EvalException if {@code data} is neither bytes nor a string, or the flow has ended
     */
    @StarlarkMethod(
            name = "send",
            doc = "Adds a datagram as if one side sent it: to the target with from_client True, else to the client.",
            parameters = {@Param(name = "from_client"), @Param(name = "data")})
    public void send(Boolean fromClient, Object data) throws EvalException {
        byte[] bytes = Builtins.bytes(data, "data");
        try {
            context.send(fromClient, bytes);
        } catch (IllegalStateException | IllegalArgumentException e) {
            throw Starlark.errorf("%s", e.getMessage());
        }
    }

    @Override
    public ImmutableList<String> getFieldNames() {
        return FIELDS;
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "udp_context has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<udp_context connection ").append(context.connectionId()).append(" to ")
                .append((String) getValue("server")).append('>');
    }
}
