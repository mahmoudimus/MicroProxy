package org.microproxy.starlark;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkList;
import org.microproxy.thirdparty.starlark.syntax.Types;

/**
 * Values injected into a script as read-only globals ({@link ScriptedProxy.Builder#constants}).
 * They become predeclared names, frozen, so the type checker knows their types and no call can
 * change them.
 */
final class ScriptConstants {

    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");

    /** Keywords and reserved words of the Starlark lexer. */
    private static final ImmutableSet<String> KEYWORDS = ImmutableSet.of(
            "and", "as", "assert", "break", "class", "continue", "def", "del", "elif", "else", "except", "finally",
            "for", "from", "global", "if", "import", "in", "is", "lambda", "load", "nonlocal", "not", "or", "pass",
            "raise", "return", "try", "while", "with", "yield", "cast", "isinstance");

    private ScriptConstants() {}

    /**
     * Checks the names and converts the values: strings, ints, bools, and lists and dicts of them
     * (dict keys: strings, ints or bools) become frozen Starlark values.
     *
     * @throws IllegalArgumentException for an invalid name, one that would hide a built-in, or a
     *     value of another type
     */
    static ImmutableMap<String, Object> convert(Map<String, ?> constants) {
        ImmutableMap.Builder<String, Object> out = ImmutableMap.builder();
        for (Map.Entry<String, ?> e : constants.entrySet()) {
            String name = e.getKey();
            checkName(name);
            out.put(name, value(e.getValue(), name));
        }
        return out.buildOrThrow();
    }

    static void checkName(String name) {
        if (name == null || !IDENTIFIER.matcher(name).matches() || KEYWORDS.contains(name)) {
            throw new IllegalArgumentException("script constant name " + (name == null ? "null" : "'" + name + "'")
                    + " is not a valid identifier");
        }
        if (Builtins.PREDECLARED.containsKey(name) || Starlark.UNIVERSE.containsKey(name)
                || Types.TYPE_UNIVERSE.containsKey(name)) {
            throw new IllegalArgumentException("script constant " + name + " would hide the built-in of that name");
        }
    }

    private static Object value(Object v, String where) {
        switch (v) {
            case String s -> {
                return s;
            }
            case Boolean b -> {
                return b;
            }
            case Integer i -> {
                return StarlarkInt.of(i);
            }
            case Long l -> {
                return StarlarkInt.of(l);
            }
            case Short s -> {
                return StarlarkInt.of(s);
            }
            case Byte b -> {
                return StarlarkInt.of(b);
            }
            case BigInteger b -> {
                return StarlarkInt.of(b);
            }
            case StarlarkInt i -> {
                return i; // converted already (lists and dicts are copied again, frozen)
            }
            case List<?> list -> {
                List<Object> elements = new ArrayList<>(list.size());
                for (int i = 0; i < list.size(); i++) {
                    elements.add(value(list.get(i), where + "[" + i + "]"));
                }
                return StarlarkList.immutableCopyOf(elements);
            }
            case Map<?, ?> map -> {
                Map<Object, Object> entries = new LinkedHashMap<>();
                for (Map.Entry<?, ?> e : map.entrySet()) {
                    Object key = e.getKey();
                    if (!(key instanceof String || key instanceof Boolean || key instanceof Number || key instanceof StarlarkInt)) {
                        throw unsupported(where + " key", key);
                    }
                    Object k = value(key, where + " key");
                    entries.put(k, value(e.getValue(), where + "[" + Starlark.reprForErrors(k) + "]"));
                }
                return Dict.immutableCopyOf(entries);
            }
            case null -> throw unsupported(where, null);
            default -> throw unsupported(where, v);
        }
    }

    private static IllegalArgumentException unsupported(String where, Object v) {
        return new IllegalArgumentException("script constant " + where + " is a "
                + (v == null ? "null" : v.getClass().getName())
                + "; constants are strings, ints, bools, and lists or dicts of them");
    }
}
