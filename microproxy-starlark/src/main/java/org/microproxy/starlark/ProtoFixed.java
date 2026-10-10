package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import org.microproxy.contentviews.ProtoValue;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.StarlarkFloat;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * A fixed-width protobuf value in a script: what {@code protobuf.decode} gives for a field with
 * wire type fixed32 or fixed64 (without a schema it could be an integer or a float), and what
 * {@code protobuf.fixed32(x)} and {@code protobuf.fixed64(x)} make. It encodes back with its wire
 * type. Fields: {@code bits} (32 or 64), {@code value} (unsigned), {@code signed} and {@code
 * float}. Two are equal when their bits and widths are.
 */
@StarlarkBuiltin(name = "ProtoFixed", doc = "A protobuf fixed32 or fixed64 value.")
public final class ProtoFixed implements Structure {

    private static final ImmutableList<String> FIELDS = ImmutableList.of("bits", "value", "signed", "float");

    private final ProtoValue value;

    ProtoFixed(ProtoValue value) {
        if (!(value instanceof ProtoValue.Fixed32 || value instanceof ProtoValue.Fixed64)) {
            throw new IllegalArgumentException("not a fixed-width value: " + value);
        }
        this.value = value;
    }

    /** The wire value. */
    ProtoValue value() {
        return value;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for fixed-width values
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.PROTO_FIXED_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.PROTO_FIXED;
    }

    @Override
    public Object getValue(String name) {
        return switch (value) {
            case ProtoValue.Fixed32 f -> switch (name) {
                case "bits" -> StarlarkInt.of(32);
                case "value" -> StarlarkInt.of(f.unsigned());
                case "signed" -> StarlarkInt.of(f.bits());
                case "float" -> StarlarkFloat.of(f.asFloat());
                default -> null;
            };
            case ProtoValue.Fixed64 f -> switch (name) {
                case "bits" -> StarlarkInt.of(64);
                case "value" -> StarlarkInt.of(new java.math.BigInteger(f.unsigned()));
                case "signed" -> StarlarkInt.of(f.bits());
                case "float" -> StarlarkFloat.of(f.asDouble());
                default -> null;
            };
            default -> null;
        };
    }

    @Override
    public ImmutableList<String> getFieldNames() {
        return FIELDS;
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "ProtoFixed has no field '" + field + "'";
    }

    @Override
    public boolean isImmutable() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ProtoFixed f && f.value.equals(value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append(value instanceof ProtoValue.Fixed32 ? "protobuf.fixed32(" : "protobuf.fixed64(");
        printer.repr(getValue("value"), semantics);
        printer.append(')');
    }
}
