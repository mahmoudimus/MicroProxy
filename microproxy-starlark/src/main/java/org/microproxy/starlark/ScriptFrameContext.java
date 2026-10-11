package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.net.InetSocketAddress;
import org.microproxy.frames.FrameContext;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * Where a frame {@code on_frame} sees travels: the protocol, the client connection and stream,
 * the client and the server. Values as {@link ScriptContext} has them, where both have one.
 */
@StarlarkBuiltin(name = "frame_context", doc = "The connection and stream of a frame.")
public final class ScriptFrameContext implements Structure {

    private static final ImmutableList<String> FIELDS =
            ImmutableList.of("protocol", "connection_id", "stream_id", "client_ip", "client_port", "server");

    private final FrameContext context;

    ScriptFrameContext(FrameContext context) {
        this.context = context;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for a frame context value
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.FRAME_CONTEXT_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.FRAME_CONTEXT;
    }

    @Override
    public Object getValue(String name) {
        InetSocketAddress client = context.clientAddress();
        return switch (name) {
            case "protocol" -> context.protocol().alpn();
            case "connection_id" -> StarlarkInt.of(context.connectionId());
            case "stream_id" -> StarlarkInt.of(context.streamId());
            case "client_ip" -> client == null ? "" : client.getAddress() != null
                    ? client.getAddress().getHostAddress() : client.getHostString();
            case "client_port" -> StarlarkInt.of(client == null ? 0 : client.getPort());
            case "server" -> context.server() == null ? Starlark.NONE : context.server();
            default -> null;
        };
    }

    @Override
    public ImmutableList<String> getFieldNames() {
        return FIELDS;
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "frame_context has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<frame_context ").append(context.protocol().alpn()).append(" connection ")
                .append(context.connectionId()).append(" stream ").append(context.streamId()).append('>');
    }
}
