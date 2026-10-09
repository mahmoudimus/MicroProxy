package org.microproxy.http;

import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

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

    /**
     * Creates an empty header collection.
     */
    public HttpHeaders() {}

    /**
     * Returns a deep copy of these headers.
     *
     * @return an independent copy preserving all field names, values, and order
     */
    public HttpHeaders copy() {
        HttpHeaders copy = new HttpHeaders();
        copy.names.addAll(names);
        copy.values.addAll(values);
        return copy;
    }

    /**
     * Counts the header fields, including repeated names.
     *
     * @return the number of fields
     */
    public int size() {
        return names.size();
    }

    /**
     * Checks whether any fields are present.
     *
     * @return true if there are no fields
     */
    public boolean isEmpty() {
        return names.isEmpty();
    }

    /**
     * Appends a field after validating its name and value.
     *
     * @param name the field name, preserved as supplied
     * @param value the value, converted with String.valueOf
     * @return these headers
     */
    public HttpHeaders add(String name, Object value) {
        names.add(validateName(name));
        values.add(validateValue(String.valueOf(value)));
        return this;
    }

    /**
     * Appends one field for each supplied value.
     *
     * @param name the field name, preserved as supplied
     * @param values the values to append in iteration order, converted with String.valueOf
     * @return these headers
     */
    public HttpHeaders add(String name, Iterable<?> values) {
        for (Object v : values) {
            add(name, v);
        }
        return this;
    }

    /**
     * Appends every field of {@code other}.
     *
     * @param other the fields to append in their existing order
     * @return these headers
     */
    public HttpHeaders add(HttpHeaders other) {
        for (int i = 0; i < other.names.size(); i++) {
            names.add(other.names.get(i));
            values.add(other.values.get(i));
        }
        return this;
    }

    /**
     * Replaces all fields named {@code name} with a single field, keeping the first position.
     *
     * @param name the field name, matched without regard to case
     * @param value the replacement value, converted with String.valueOf
     * @return these headers
     */
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

    /**
     * Replaces all fields named {@code name} with one field per element of {@code values}.
     *
     * @param name the field name, matched without regard to case
     * @param values the replacement values in iteration order, converted with String.valueOf
     * @return these headers
     */
    public HttpHeaders set(String name, Iterable<?> values) {
        remove(name);
        return add(name, values);
    }

    /**
     * Replaces the contents of these headers with {@code other}.
     *
     * @param other the fields to copy, preserving their order
     * @return these headers
     */
    public HttpHeaders set(HttpHeaders other) {
        if (other != this) {
            clear();
            add(other);
        }
        return this;
    }

    /**
     * Returns the first value for {@code name}, or {@code null}.
     *
     * @param name the field name, matched without regard to case
     * @return the first matching value, or null if absent
     */
    public String get(String name) {
        int i = indexOf(name);
        return i < 0 ? null : values.get(i);
    }

    /**
     * Returns the first matching value with a fallback for absent fields.
     *
     * @param name the field name, matched without regard to case
     * @param defaultValue the value to return when no field matches
     * @return the first matching value, or defaultValue if absent
     */
    public String get(String name, String defaultValue) {
        String v = get(name);
        return v == null ? defaultValue : v;
    }

    /**
     * Returns all values for {@code name}, in order.
     *
     * @param name the field name, matched without regard to case
     * @return a new list of matching values in field order, or an empty list
     */
    public List<String> getAll(String name) {
        List<String> all = null;
        for (int i = 0; i < names.size(); i++) {
            if (names.get(i).equalsIgnoreCase(name)) {
                if (all == null) all = new ArrayList<>(2);
                all.add(values.get(i));
            }
        }
        return all != null ? all : new ArrayList<>(0);
    }

    /**
     * The number of fields named {@code name}.
     *
     * @param name the field name, matched without regard to case
     * @return the number of matching fields
     */
    public int count(String name) {
        int n = 0;
        for (int i = 0; i < names.size(); i++) {
            if (names.get(i).equalsIgnoreCase(name)) n++;
        }
        return n;
    }

    /**
     * The name of field {@code index} (0 to {@link #size()} - 1), as received.
     *
     * @param index the zero-based field index
     * @return the field name with its original spelling
     */
    public String nameAt(int index) {
        return names.get(index);
    }

    /**
     * The value of field {@code index}.
     *
     * @param index the zero-based field index
     * @return the field value at that index
     */
    public String valueAt(int index) {
        return values.get(index);
    }

    /**
     * Removes every field whose name matches {@code namePredicate}.
     *
     * @param namePredicate the predicate tested against each name in its original spelling
     */
    public void removeIf(Predicate<String> namePredicate) {
        for (int i = names.size() - 1; i >= 0; i--) {
            if (namePredicate.test(names.get(i))) {
                names.remove(i);
                values.remove(i);
            }
        }
    }

    /**
     * Checks whether a field with this name exists.
     *
     * @param name the field name, matched without regard to case
     * @return whether at least one field matches
     */
    public boolean contains(String name) {
        return indexOf(name) >= 0;
    }

    /**
     * Returns true if any comma-separated element of any field named {@code name} equals {@code
     * value}.
     *
     * @param name the field name, matched without regard to case
     * @param value the comma-separated element to find
     * @param ignoreCase whether element comparison ignores case
     * @return whether any matching field contains the element
     */
    public boolean containsValue(String name, String value, boolean ignoreCase) {
        for (int i = 0; i < names.size(); i++) {
            if (names.get(i).equalsIgnoreCase(name) && containsElement(values.get(i), value, ignoreCase)) {
                return true;
            }
        }
        return false;
    }

    /** Whether the comma-separated {@code list} has an element equal to {@code element}, without allocating. */
    static boolean containsElement(String list, String element, boolean ignoreCase) {
        int i = 0;
        int n = list.length();
        while (i <= n) {
            int comma = list.indexOf(',', i);
            int end = comma < 0 ? n : comma;
            int s = i;
            int e = end;
            while (s < e && Character.isWhitespace(list.charAt(s))) s++;
            while (e > s && Character.isWhitespace(list.charAt(e - 1))) e--;
            if (e - s == element.length() && list.regionMatches(ignoreCase, s, element, 0, element.length())) {
                return true;
            }
            if (comma < 0) break;
            i = comma + 1;
        }
        return false;
    }

    /**
     * Removes every field named {@code name}. Returns true if anything was removed.
     *
     * @param name the field name, matched without regard to case
     * @return whether any fields were removed
     */
    public boolean remove(String name) {
        int before = names.size();
        removeFrom(name, 0);
        return names.size() != before;
    }

    /**
     * Removes all fields.
     *
     * @return these headers
     */
    public HttpHeaders clear() {
        names.clear();
        values.clear();
        return this;
    }

    /**
     * The distinct field names, in first-seen order and original spelling.
     *
     * @return an unmodifiable snapshot of distinct names in first-seen order
     */
    public Set<String> names() {
        Map<String, String> seen = new LinkedHashMap<>();
        for (String n : names) {
            seen.putIfAbsent(n.toLowerCase(Locale.ROOT), n);
        }
        return Collections.unmodifiableSet(new LinkedHashSet<>(seen.values()));
    }

    /**
     * All fields as (name, value) pairs in order.
     *
     * @return a new list of immutable name/value entries in field order
     */
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
     *
     * @param value the comma-separated header value to split
     * @return the trimmed, nonempty elements in order
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

    /**
     * All comma-separated elements across every field named {@code name}.
     *
     * @param name the field name, matched without regard to case
     * @return the trimmed, nonempty elements in field and element order
     */
    public List<String> getAllElements(String name) {
        List<String> out = new ArrayList<>(2);
        for (int i = 0; i < names.size(); i++) {
            if (names.get(i).equalsIgnoreCase(name)) out.addAll(splitList(values.get(i)));
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
