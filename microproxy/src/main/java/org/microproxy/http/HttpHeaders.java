package org.microproxy.http;

import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * An ordered, case-insensitive multimap of header fields. The original spelling and order of
 * header names is preserved when a message is forwarded.
 *
 * <p>Names must be RFC 9110 tokens and values must not contain CR, LF or NUL; violations throw
 * {@link IllegalArgumentException}, which prevents header injection through filters.
 */
public final class HttpHeaders implements Iterable<Map.Entry<String, String>> {

    private final ArrayList<String> names = new ArrayList<>();
    private final ArrayList<String> values = new ArrayList<>();

    public HttpHeaders() {}

    /** Returns a deep copy of these headers. */
    public HttpHeaders copy() {
        HttpHeaders copy = new HttpHeaders();
        copy.names.addAll(names);
        copy.values.addAll(values);
        return copy;
    }

    public int size() {
        return names.size();
    }

    public boolean isEmpty() {
        return names.isEmpty();
    }

    public HttpHeaders add(String name, Object value) {
        names.add(validateName(name));
        values.add(validateValue(String.valueOf(value)));
        return this;
    }

    public HttpHeaders add(String name, Iterable<?> values) {
        for (Object v : values) {
            add(name, v);
        }
        return this;
    }

    /** Appends every field of {@code other}. */
    public HttpHeaders add(HttpHeaders other) {
        for (int i = 0; i < other.names.size(); i++) {
            names.add(other.names.get(i));
            values.add(other.values.get(i));
        }
        return this;
    }

    /** Replaces all fields named {@code name} with a single field, keeping the first position. */
    public HttpHeaders set(String name, Object value) {
        validateName(name);
        String v = validateValue(String.valueOf(value));
        int first = indexOf(name);
        if (first < 0) {
            names.add(name);
            values.add(v);
            return this;
        }
        values.set(first, v);
        removeFrom(name, first + 1);
        return this;
    }

    /** Replaces all fields named {@code name} with one field per element of {@code values}. */
    public HttpHeaders set(String name, Iterable<?> values) {
        remove(name);
        return add(name, values);
    }

    /** Replaces the contents of these headers with {@code other}. */
    public HttpHeaders set(HttpHeaders other) {
        if (other != this) {
            clear();
            add(other);
        }
        return this;
    }

    /** Returns the first value for {@code name}, or {@code null}. */
    public String get(String name) {
        int i = indexOf(name);
        return i < 0 ? null : values.get(i);
    }

    public String get(String name, String defaultValue) {
        String v = get(name);
        return v == null ? defaultValue : v;
    }

    /** Returns all values for {@code name}, in order. */
    public List<String> getAll(String name) {
        List<String> all = new ArrayList<>(2);
        for (int i = 0; i < names.size(); i++) {
            if (names.get(i).equalsIgnoreCase(name)) {
                all.add(values.get(i));
            }
        }
        return all;
    }

    public boolean contains(String name) {
        return indexOf(name) >= 0;
    }

    /**
     * Returns true if any comma-separated element of any field named {@code name} equals {@code
     * value}.
     */
    public boolean containsValue(String name, String value, boolean ignoreCase) {
        for (int i = 0; i < names.size(); i++) {
            if (names.get(i).equalsIgnoreCase(name)) {
                for (String element : splitList(values.get(i))) {
                    if (ignoreCase ? element.equalsIgnoreCase(value) : element.equals(value)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /** Removes every field named {@code name}. Returns true if anything was removed. */
    public boolean remove(String name) {
        int before = names.size();
        removeFrom(name, 0);
        return names.size() != before;
    }

    public HttpHeaders clear() {
        names.clear();
        values.clear();
        return this;
    }

    /** The distinct field names, in first-seen order and original spelling. */
    public Set<String> names() {
        Map<String, String> seen = new LinkedHashMap<>();
        for (String n : names) {
            seen.putIfAbsent(n.toLowerCase(Locale.ROOT), n);
        }
        return Collections.unmodifiableSet(new java.util.LinkedHashSet<>(seen.values()));
    }

    /** All fields as (name, value) pairs in order. */
    public List<Map.Entry<String, String>> entries() {
        List<Map.Entry<String, String>> entries = new ArrayList<>(names.size());
        for (int i = 0; i < names.size(); i++) {
            entries.add(new SimpleImmutableEntry<>(names.get(i), values.get(i)));
        }
        return entries;
    }

    @Override
    public Iterator<Map.Entry<String, String>> iterator() {
        return entries().iterator();
    }

    /**
     * Splits a list-valued header ({@code a, b ,c}) into its trimmed, non-empty elements. Quoted
     * strings are not specially handled, which is fine for the connection-management headers this
     * is used for.
     */
    public static List<String> splitList(String value) {
        List<String> out = new ArrayList<>(2);
        for (String part : value.split(",")) {
            String trimmed = part.strip();
            if (!trimmed.isEmpty()) {
                out.add(trimmed);
            }
        }
        return out;
    }

    /** All comma-separated elements across every field named {@code name}. */
    public List<String> getAllElements(String name) {
        List<String> out = new ArrayList<>(2);
        for (String v : getAll(name)) {
            out.addAll(splitList(v));
        }
        return out;
    }

    static boolean isToken(String s) {
        if (s == null || s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
            if (!ok) return false;
        }
        return true;
    }

    private static String validateName(String name) {
        if (!isToken(name)) {
            throw new IllegalArgumentException("invalid header name: " + name);
        }
        return name;
    }

    private static String validateValue(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\r' || c == '\n' || c == 0) {
                throw new IllegalArgumentException("invalid character in header value");
            }
        }
        return value;
    }

    private int indexOf(String name) {
        for (int i = 0; i < names.size(); i++) {
            if (names.get(i).equalsIgnoreCase(name)) {
                return i;
            }
        }
        return -1;
    }

    private void removeFrom(String name, int start) {
        for (int i = names.size() - 1; i >= start; i--) {
            if (names.get(i).equalsIgnoreCase(name)) {
                names.remove(i);
                values.remove(i);
            }
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < names.size(); i++) {
            sb.append(names.get(i)).append(": ").append(values.get(i)).append("\r\n");
        }
        return sb.toString();
    }
}
