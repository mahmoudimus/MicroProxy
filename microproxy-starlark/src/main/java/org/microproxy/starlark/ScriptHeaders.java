package org.microproxy.starlark;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.microproxy.http.HttpHeaders;
import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkIterable;
import org.microproxy.thirdparty.starlark.eval.StarlarkList;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.StarlarkSetIndexable;
import org.microproxy.thirdparty.starlark.eval.Tuple;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * The headers of a request or response, or the header block of an HTTP/2 or HTTP/3 frame. Names
 * are case-insensitive; {@code h[name]} is the first value (an error if absent), {@code h[name] =
 * v} replaces all values, {@code name in h} tests presence and iterating yields the distinct names.
 * A frame's header block includes its pseudo-headers ({@code :method}, {@code :status}, ...).
 */
@StarlarkBuiltin(name = "headers", doc = "HTTP headers, case-insensitive.")
public final class ScriptHeaders implements StarlarkSetIndexable, StarlarkIterable<String> {

    /** Where the fields live: {@link HttpHeaders}, or a frame's field list ({@link FrameFields}). */
    interface Store {
        String get(String name);

        List<String> getAll(String name);

        boolean contains(String name);

        Collection<String> names();

        List<Map.Entry<String, String>> entries();

        void set(String name, Iterable<?> values);

        void add(String name, Iterable<?> values);

        boolean remove(String name);
    }

    private final Store headers;
    private final boolean readOnly;

    ScriptHeaders(HttpHeaders headers, boolean readOnly) {
        this(new Store() {
            @Override
            public String get(String name) {
                return headers.get(name);
            }

            @Override
            public List<String> getAll(String name) {
                return headers.getAll(name);
            }

            @Override
            public boolean contains(String name) {
                return headers.contains(name);
            }

            @Override
            public Collection<String> names() {
                return headers.names();
            }

            @Override
            public List<Map.Entry<String, String>> entries() {
                return headers.entries();
            }

            @Override
            public void set(String name, Iterable<?> values) {
                headers.set(name, values);
            }

            @Override
            public void add(String name, Iterable<?> values) {
                headers.add(name, values);
            }

            @Override
            public boolean remove(String name) {
                return headers.remove(name);
            }

            @Override
            public String toString() {
                return headers.toString();
            }
        }, readOnly);
    }

    ScriptHeaders(Store headers, boolean readOnly) {
        this.headers = headers;
        this.readOnly = readOnly;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for HTTP headers
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.HEADERS_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.HEADERS;
    }

    @Override
    public Object getIndex(StarlarkSemantics semantics, Object key) throws EvalException {
        String value = headers.get(name(key));
        if (value == null) {
            throw Starlark.errorf("no header %s", Starlark.repr(key, semantics));
        }
        return value;
    }

    @Override
    public boolean containsKey(StarlarkSemantics semantics, Object key) throws EvalException {
        return headers.contains(name(key));
    }

    @Override
    public void setIndex(StarlarkSemantics semantics, Object key, Object value) throws EvalException {
        set(name(key), value);
    }

    @Override
    public Iterator<String> iterator() {
        return List.copyOf(headers.names()).iterator();
    }

    /**
     * Returns the first value of a header, with a caller-supplied fallback.
     *
     * @param name the case-insensitive header name
     * @param defaultValue the result when the header is absent
     * @return the first header value, or {@code defaultValue}
     */
    @StarlarkMethod(
            name = "get",
            doc = "The first value of a header, or default.",
            allowReturnNones = true,
            parameters = {@Param(name = "name"), @Param(name = "default", defaultValue = "None")})
    public Object get(String name, Object defaultValue) {
        String value = headers.get(name);
        return value != null ? value : defaultValue;
    }

    /**
     * Returns every value of a header.
     *
     * @param name the case-insensitive header name
     * @return an immutable list of values, empty when absent
     */
    @StarlarkMethod(name = "get_all", doc = "All values of a header, as a list.", parameters = {@Param(name = "name")})
    public StarlarkList<String> getAll(String name) {
        return StarlarkList.immutableCopyOf(headers.getAll(name));
    }

    /**
     * Replaces all values of a header.
     *
     * @param name the header name
     * @param value a string or a list or tuple of strings
     * @throws EvalException if headers are read-only or the name or values are invalid
     */
    @StarlarkMethod(
            name = "set",
            doc = "Replaces a header's values with value (a string or list of strings).",
            parameters = {@Param(name = "name"), @Param(name = "value")})
    public void set(String name, Object value) throws EvalException {
        checkWritable();
        List<String> values = values(value);
        try {
            headers.set(name, values);
        } catch (IllegalArgumentException e) {
            throw Starlark.errorf("%s", e.getMessage());
        }
    }

    /**
     * Appends values to a header without removing existing values.
     *
     * @param name the header name
     * @param value a string or a list or tuple of strings
     * @throws EvalException if headers are read-only or the name or values are invalid
     */
    @StarlarkMethod(name = "add", doc = "Adds a value to a header.", parameters = {@Param(name = "name"), @Param(name = "value")})
    public void add(String name, Object value) throws EvalException {
        checkWritable();
        List<String> values = values(value);
        try {
            headers.add(name, values);
        } catch (IllegalArgumentException e) {
            throw Starlark.errorf("%s", e.getMessage());
        }
    }

    /**
     * Removes all values of a header.
     *
     * @param name the case-insensitive header name
     * @return whether any values were removed
     * @throws EvalException if headers are read-only
     */
    @StarlarkMethod(name = "remove", doc = "Removes a header; returns whether it was present.", parameters = {@Param(name = "name")})
    public boolean remove(String name) throws EvalException {
        checkWritable();
        return headers.remove(name);
    }

    /**
     * Returns the distinct header names.
     *
     * @return an immutable list of header names
     */
    @StarlarkMethod(name = "keys", doc = "The distinct header names.")
    public StarlarkList<String> keys() {
        return StarlarkList.immutableCopyOf(headers.names());
    }

    /**
     * Returns each header value with its name in header order.
     *
     * @return an immutable list of name/value tuples, including repeated names
     */
    @StarlarkMethod(name = "items", doc = "(name, value) pairs in order, one per value.")
    public StarlarkList<Tuple> items() {
        List<Tuple> items = new ArrayList<>();
        for (Map.Entry<String, String> e : headers.entries()) {
            items.add(Tuple.of(e.getKey(), e.getValue()));
        }
        return StarlarkList.immutableCopyOf(items);
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<headers ").append(headers.toString()).append(">");
    }

    @Override
    public boolean isImmutable() {
        return readOnly;
    }

    private void checkWritable() throws EvalException {
        if (readOnly) {
            throw Starlark.errorf("headers are read-only here");
        }
    }

    private static String name(Object key) throws EvalException {
        if (key instanceof String s) return s;
        throw Starlark.errorf("header names are strings, not %s", Starlark.type(key));
    }

    private static List<String> values(Object value) throws EvalException {
        if (value instanceof String s) return List.of(s);
        if (value instanceof StarlarkList<?> || value instanceof Tuple) {
            List<String> out = new ArrayList<>();
            for (Object v : Starlark.toIterable(value)) {
                if (!(v instanceof String s)) throw Starlark.errorf("header values are strings, not %s", Starlark.type(v));
                out.add(s);
            }
            return out;
        }
        throw Starlark.errorf("header values are strings, not %s", Starlark.type(value));
    }
}
