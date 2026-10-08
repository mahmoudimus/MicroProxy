package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.net.InetSocketAddress;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;

/**
 * Per-request context: who the client is, and {@code vars}, a dict that lives as long as the
 * request so {@code on_request} can leave notes for {@code on_response}.
 */
@StarlarkBuiltin(name = "context", doc = "The client and per-request scratch space.")
public final class ScriptContext implements Structure {

    private static final ImmutableList<String> FIELDS =
            ImmutableList.of("client_ip", "client_port", "user", "connection_id", "tls", "vars");

    private final InetSocketAddress client;
    private final String user;
    private final long connectionId;
    private final boolean tls;
    private final Dict<Object, Object> vars;

    ScriptContext(InetSocketAddress client, String user, long connectionId, boolean tls, Mutability mu) {
        this.client = client;
        this.user = user;
        this.connectionId = connectionId;
        this.tls = tls;
        this.vars = Dict.of(mu);
    }

    @Override
    public Object getValue(String name) {
        return switch (name) {
            case "client_ip" -> client == null ? "" : client.getAddress() != null
                    ? client.getAddress().getHostAddress() : client.getHostString();
            case "client_port" -> StarlarkInt.of(client == null ? 0 : client.getPort());
            case "user" -> user == null ? Starlark.NONE : user;
            case "connection_id" -> StarlarkInt.of(connectionId);
            case "tls" -> tls;
            case "vars" -> vars;
            default -> null;
        };
    }

    @Override
    public ImmutableList<String> getFieldNames() {
        return FIELDS;
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "context has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<context ").append(String.valueOf(getValue("client_ip"))).append('>');
    }
}
