package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.time.Duration;
import java.util.Optional;
import org.microproxy.FlowTimings;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkFloat;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * {@code ctx.timings}: a read-only snapshot of the exchange's {@link FlowTimings}, in milliseconds
 * as floats, each {@code None} when that phase has not happened (yet) or did not happen at all.
 *
 * <ul>
 *   <li>{@code dns_ms}, {@code connect_ms}, {@code tls_ms}: resolving the server's name,
 *       connecting and the TLS handshakes towards the server; {@code None} on a reused
 *       connection, and for requests inside an intercepted session (they belong to its {@code
 *       CONNECT});
 *   <li>{@code client_tls_ms}: the TLS handshake with the client (TLS listener or interception);
 *   <li>{@code ttfb_ms}: from the start of the request to the first byte of the server's response;
 *   <li>{@code total_ms}: from the start of the request to the last byte sent to the client.
 * </ul>
 */
@StarlarkBuiltin(name = "timings", doc = "When the phases of the exchange happened, in milliseconds.")
public final class ScriptTimings implements Structure {

    private static final ImmutableList<String> FIELDS =
            ImmutableList.of("dns_ms", "connect_ms", "tls_ms", "client_tls_ms", "ttfb_ms", "total_ms");

    private final FlowTimings timings;

    ScriptTimings(FlowTimings timings) {
        this.timings = timings;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for a timing snapshot
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.TIMINGS_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.TIMINGS;
    }

    private static Object millis(Optional<Duration> d) {
        return d.isPresent() ? StarlarkFloat.of(d.get().toNanos() / 1e6) : Starlark.NONE;
    }

    @Override
    public Object getValue(String name) {
        return switch (name) {
            case "dns_ms" -> millis(timings.dnsLookup());
            case "connect_ms" -> millis(timings.connect());
            case "tls_ms" -> millis(timings.tlsHandshake());
            case "client_tls_ms" -> millis(timings.clientTlsHandshake());
            case "ttfb_ms" -> millis(timings.timeToFirstByte());
            case "total_ms" -> millis(timings.total());
            default -> null;
        };
    }

    @Override
    public ImmutableList<String> getFieldNames() {
        return FIELDS;
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "timings has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<timings");
        for (String field : FIELDS) {
            printer.append(' ').append(field).append('=');
            printer.repr(getValue(field), semantics);
        }
        printer.append('>');
    }
}
