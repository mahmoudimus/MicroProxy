package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.util.ArrayList;
import java.util.List;
import org.microproxy.ClientHello;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkList;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * A client's TLS {@code ClientHello}, as {@code on_client_hello} and {@code ctx.client_hello} see
 * it: a read-only view of a {@link ClientHello}.
 *
 * <ul>
 *   <li>{@code sni}: the host name the client asked for, or {@code None};
 *   <li>{@code alpn}: the application protocols it offered, in its order ({@code ["h2",
 *       "http/1.1"]}), empty without ALPN;
 *   <li>{@code versions}: the TLS versions it offered by name ({@code ["TLSv1.3", "TLSv1.2"]});
 *   <li>{@code cipher_suites}: the cipher suites it offered, as numbers, GREASE values included.
 * </ul>
 */
@StarlarkBuiltin(name = "client_hello", doc = "The TLS ClientHello a client sent.")
public final class ScriptClientHello implements Structure {

    private static final ImmutableList<String> FIELDS = ImmutableList.of("sni", "alpn", "versions", "cipher_suites");

    private final ClientHello hello;

    ScriptClientHello(ClientHello hello) {
        this.hello = hello;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for a ClientHello value
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.CLIENT_HELLO_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.CLIENT_HELLO;
    }

    @Override
    public Object getValue(String name) {
        return switch (name) {
            case "sni" -> hello.sni() == null ? Starlark.NONE : hello.sni();
            case "alpn" -> StarlarkList.immutableCopyOf(hello.alpnProtocols());
            case "versions" -> StarlarkList.immutableCopyOf(hello.versionNames());
            case "cipher_suites" -> {
                List<StarlarkInt> suites = new ArrayList<>(hello.cipherSuites().size());
                for (int suite : hello.cipherSuites()) suites.add(StarlarkInt.of(suite));
                yield StarlarkList.immutableCopyOf(suites);
            }
            default -> null;
        };
    }

    @Override
    public ImmutableList<String> getFieldNames() {
        return FIELDS;
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "client_hello has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<client_hello ").append(hello.sni() == null ? "(no sni)" : hello.sni()).append('>');
    }
}
