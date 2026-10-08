package org.microproxy.starlark;

import com.google.common.collect.ImmutableMap;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;
import org.microproxy.thirdparty.starlark.syntax.TypeContext;
import org.microproxy.thirdparty.starlark.syntax.Types;

/**
 * The Starlark types of the values scripts receive, named so that scripts can annotate with them
 * ({@code def on_request(req: Request, ctx: Context) -> Response | None}). The checker learns
 * the type of every field, so a misspelt field or a wrong-typed use fails when the script loads.
 *
 * <p>The values are {@code Structure}s, whose default type is an anonymous struct; they return
 * these named types instead, and name them as the types of builtins that return them (through
 * {@code getAssociatedTypeConstructor}), so {@code response(...)} is a {@code Response}.
 */
final class ScriptType extends StarlarkType {

    /** Bodies (and frame payloads) are {@code None} when they were streamed rather than buffered. */
    private static final StarlarkType BODY = Types.union(
            Starlark.getStarlarkType(StarlarkBytes.of(null, new byte[0]), StarlarkSemantics.DEFAULT), Types.NONE);

    private static final StarlarkType TEXT = Types.union(Types.STR, Types.NONE);

    /** A mapping from names to values, as {@code headers[name]} reads and assigns. */
    static final StarlarkType HEADERS = new HeadersType();

    static final ScriptType REQUEST = new ScriptType("Request", ScriptRequest.class, ImmutableMap.<String, StarlarkType>builder()
            .put("method", Types.STR)
            .put("uri", Types.STR)
            .put("url", Types.STR)
            .put("scheme", Types.STR)
            .put("host", Types.STR)
            .put("port", Types.INT)
            .put("path", Types.STR)
            .put("query", Types.STR)
            .put("headers", HEADERS)
            .put("body", BODY)
            .put("text", TEXT)
            .buildOrThrow(), true);

    static final ScriptType RESPONSE = new ScriptType("Response", ScriptResponse.class, ImmutableMap.of(
            "status", Types.INT,
            "reason", Types.STR,
            "headers", HEADERS,
            "body", BODY,
            "text", TEXT), true);

    static final ScriptType CONTEXT = new ScriptType("Context", ScriptContext.class, ImmutableMap.of(
            "client_ip", Types.STR,
            "client_port", Types.INT,
            "user", Types.union(Types.STR, Types.NONE),
            "connection_id", Types.INT,
            "tls", Types.BOOL,
            "vars", Types.dict(Types.ANY, Types.ANY)), false);

    static final ScriptType FRAME = new ScriptType("WebSocketFrame", ScriptFrame.class, ImmutableMap.<String, StarlarkType>builder()
            .put("type", Types.STR)
            .put("opcode", Types.INT)
            .put("fin", Types.BOOL)
            .put("from_client", Types.BOOL)
            .put("truncated", Types.BOOL)
            .put("length", Types.INT)
            .put("text", TEXT)
            .put("payload", BODY)
            .buildOrThrow(), true);

    static final TypeConstructor REQUEST_CONSTRUCTOR = Types.wrapType("Request", REQUEST);
    static final TypeConstructor RESPONSE_CONSTRUCTOR = Types.wrapType("Response", RESPONSE);
    static final TypeConstructor HEADERS_CONSTRUCTOR = Types.wrapType("Headers", HEADERS);
    static final TypeConstructor CONTEXT_CONSTRUCTOR = Types.wrapType("Context", CONTEXT);
    static final TypeConstructor FRAME_CONSTRUCTOR = Types.wrapType("WebSocketFrame", FRAME);

    private final String name;
    private final Class<?> javaClass;
    private final ImmutableMap<String, StarlarkType> fields;
    private final boolean assignable;

    private ScriptType(String name, Class<?> javaClass, ImmutableMap<String, StarlarkType> fields, boolean assignable) {
        this.name = name;
        this.javaClass = javaClass;
        this.fields = fields;
        this.assignable = assignable;
    }

    @Override
    public StarlarkType getField(String field, TypeContext context) {
        StarlarkType type = fields.get(field);
        // Methods (headers.get(), ...) are typed from their annotations.
        return type != null ? type : context.getStarlarkBuiltinFieldType(javaClass, field);
    }

    /** Some fields are read-only; assigning one fails when the script runs. */
    @Override
    public boolean hasSetField() {
        return assignable;
    }

    @Override
    public String typeRepr() {
        return name;
    }

    private static final class HeadersType extends Types.AbstractMappingType {
        @Override
        public StarlarkType getKeyType() {
            return Types.STR;
        }

        @Override
        public StarlarkType getValueType() {
            return Types.STR;
        }

        @Override
        public boolean hasSetIndex() {
            return true;
        }

        @Override
        public StarlarkType getField(String field, TypeContext context) {
            return context.getStarlarkBuiltinFieldType(ScriptHeaders.class, field);
        }

        @Override
        public String typeRepr() {
            return "Headers";
        }
    }
}
