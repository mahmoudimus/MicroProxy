package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.net.InetSocketAddress;
import org.microproxy.FlowContext;
import org.microproxy.FlowTimings;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * Per-request context: who the client is, {@code vars}, a dict that lives as long as the request
 * so {@code on_request} can leave notes for {@code on_response}, and {@code timings}, a snapshot
 * of the exchange's timings taken when it is read.
 */
@StarlarkBuiltin(name = "context", doc = "The client and per-request scratch space.")
public final class ScriptContext implements Structure {

    private static final ImmutableList<String> FIELDS =
            ImmutableList.of("client_ip", "client_port", "user", "connection_id", "tls", "vars", "timings");

    private final InetSocketAddress client;
    private final String user;
    private final long connectionId;
    private final boolean tls;
    private final Dict<Object, Object> vars;
    /** The client connection, for timings; null where the hook gets no flow ({@code upstream}). */
    private final FlowContext flow;

    ScriptContext(InetSocketAddress client, String user, long connectionId, boolean tls, Mutability mu) {
        this(client, user, connectionId, tls, mu, null);
    }

    /** The context of a request on the client connection {@code flow}. */
    ScriptContext(FlowContext flow, Mutability mu) {
        this(flow.getClientAddress(), flow.getClientDetails().getUserName(), flow.getConnectionId(),
                flow.getClientSslSession() != null, mu, flow);
    }

    private ScriptContext(InetSocketAddress client, String user, long connectionId, boolean tls, Mutability mu,
            FlowContext flow) {
        this.client = client;
        this.user = user;
        this.connectionId = connectionId;
        this.tls = tls;
        this.vars = Dict.of(mu);
        this.flow = flow;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for a context value
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.CONTEXT_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.CONTEXT;
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
            case "timings" -> new ScriptTimings(flow == null ? FlowTimings.NONE : flow.timings());
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
