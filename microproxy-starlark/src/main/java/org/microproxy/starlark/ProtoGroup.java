package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * A protobuf group (proto2's deprecated wire types 3 and 4) in a script: what {@code
 * protobuf.decode} gives for one, and what {@code protobuf.group(fields)} makes. {@code fields}
 * is its dict of fields, as for a nested message; it encodes back as a group.
 */
@StarlarkBuiltin(name = "ProtoGroup", doc = "A protobuf group: fields delimited by start and end tags.")
public final class ProtoGroup implements Structure {

    private static final ImmutableList<String> FIELDS = ImmutableList.of("fields");

    private final Dict<Object, Object> fields;

    ProtoGroup(Dict<Object, Object> fields) {
        this.fields = fields;
    }

    /** The group's fields. */
    Dict<Object, Object> fields() {
        return fields;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for groups
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.PROTO_GROUP_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.PROTO_GROUP;
    }

    @Override
    public Object getValue(String name) {
        return name.equals("fields") ? fields : null;
    }

    @Override
    public ImmutableList<String> getFieldNames() {
        return FIELDS;
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "ProtoGroup has no field '" + field + "'";
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ProtoGroup g && g.fields.equals(fields);
    }

    @Override
    public int hashCode() {
        return fields.hashCode();
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("protobuf.group(");
        printer.repr(fields, semantics);
        printer.append(')');
    }
}
