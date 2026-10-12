package org.microproxy.otel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Attributes in the order they were first set, within a count and a value-length limit: values
 * are {@code String}, {@code Boolean}, {@code Long}, {@code Double} or a list of those; other
 * numbers are widened, other objects become their strings. Setting a key again replaces its value;
 * a new key past the limit is dropped and counted. Not thread-safe.
 */
final class Attrs {

    static final Attrs EMPTY = new Attrs(0, 1);

    private final int max;
    private final int maxLength;
    private String[] keys;
    private Object[] values;
    private int size;
    private int dropped;

    Attrs(int max, int maxLength) {
        this.max = max;
        this.maxLength = maxLength;
        int initial = Math.min(max, 16);
        this.keys = new String[initial];
        this.values = new Object[initial];
    }

    /** Sets {@code key} to {@code value}; {@code null} values and keys are ignored. */
    Attrs put(String key, Object value) {
        if (key == null || key.isEmpty() || value == null) return this;
        Object v = normalize(value);
        if (v == null) return this;
        for (int i = 0; i < size; i++) {
            if (keys[i].equals(key)) {
                values[i] = v;
                return this;
            }
        }
        if (size >= max) {
            dropped++;
            return this;
        }
        if (size == keys.length) {
            int n = Math.min(max, Math.max(4, keys.length * 2));
            keys = Arrays.copyOf(keys, n);
            values = Arrays.copyOf(values, n);
        }
        keys[size] = key;
        values[size] = v;
        size++;
        return this;
    }

    private Object normalize(Object value) {
        return switch (value) {
            case String s -> cut(s);
            case Boolean b -> b;
            case Long l -> l;
            case Integer i -> (long) i;
            case Short s -> (long) s;
            case Byte b -> (long) b;
            case Double d -> d;
            case Float f -> (double) f;
            case Collection<?> c -> {
                List<Object> list = new ArrayList<>(c.size());
                for (Object o : c) {
                    if (o == null) continue;
                    Object e = o instanceof Collection<?> ? cut(o.toString()) : normalize(o);
                    if (e != null) list.add(e);
                }
                yield List.copyOf(list);
            }
            default -> cut(value.toString());
        };
    }

    private String cut(String s) {
        return s.length() <= maxLength ? s : s.substring(0, maxLength);
    }

    int size() {
        return size;
    }

    int dropped() {
        return dropped;
    }

    /** Counts {@code n} more attributes as dropped (those of another set merged into this one). */
    void addDropped(int n) {
        dropped += n;
    }

    String key(int i) {
        return keys[i];
    }

    Object value(int i) {
        return values[i];
    }

    /** The value of {@code key}, or {@code null}. */
    Object get(String key) {
        for (int i = 0; i < size; i++) {
            if (keys[i].equals(key)) return values[i];
        }
        return null;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < size; i++) {
            if (i > 0) sb.append(", ");
            sb.append(keys[i]).append('=').append(values[i]);
        }
        return sb.append('}').toString();
    }
}
