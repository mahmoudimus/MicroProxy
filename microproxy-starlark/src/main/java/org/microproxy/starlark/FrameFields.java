package org.microproxy.starlark;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.microproxy.frames.Field;

/**
 * The header block of an HTTP/2 or HTTP/3 frame as {@code frame.headers} edits it: fields in order,
 * pseudo-headers included, names lower-cased as they are set (both protocols want them so).
 * {@link #fields()} puts the pseudo-headers first, keeps the {@link Field#sensitive()} mark of the
 * names that had it, and leaves the full checks to {@link Field#validate}, which the proxy runs.
 */
final class FrameFields implements ScriptHeaders.Store {

    private final List<String> names = new ArrayList<>();
    private final List<String> values = new ArrayList<>();
    private final Set<String> sensitive = new HashSet<>();

    FrameFields(List<Field> fields) {
        for (Field f : fields) {
            names.add(f.name());
            values.add(f.value());
            if (f.sensitive()) sensitive.add(f.name());
        }
    }

    /** The fields, pseudo-headers first. */
    List<Field> fields() {
        List<Field> pseudo = new ArrayList<>();
        List<Field> regular = new ArrayList<>();
        for (int i = 0; i < names.size(); i++) {
            String name = names.get(i);
            Field f = new Field(name, values.get(i), sensitive.contains(name));
            (f.isPseudo() ? pseudo : regular).add(f);
        }
        pseudo.addAll(regular);
        return pseudo;
    }

    private static String key(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        int start = n.startsWith(":") ? 1 : 0;
        if (n.length() == start) throw new IllegalArgumentException("invalid header name: " + name);
        for (int i = start; i < n.length(); i++) {
            char c = n.charAt(i);
            boolean token = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
            if (!token) throw new IllegalArgumentException("invalid header name: " + name);
        }
        return n;
    }

    private static String value(Object value) {
        String v = String.valueOf(value);
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '\r' || c == '\n' || c == 0) throw new IllegalArgumentException("invalid character in header value");
        }
        return v;
    }

    @Override
    public String get(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        int i = names.indexOf(n);
        return i < 0 ? null : values.get(i);
    }

    @Override
    public List<String> getAll(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        List<String> out = new ArrayList<>();
        for (int i = 0; i < names.size(); i++) {
            if (names.get(i).equals(n)) out.add(values.get(i));
        }
        return out;
    }

    @Override
    public boolean contains(String name) {
        return names.contains(name.toLowerCase(Locale.ROOT));
    }

    @Override
    public Collection<String> names() {
        return new LinkedHashSet<>(names);
    }

    @Override
    public List<Map.Entry<String, String>> entries() {
        List<Map.Entry<String, String>> out = new ArrayList<>(names.size());
        for (int i = 0; i < names.size(); i++) out.add(Map.entry(names.get(i), values.get(i)));
        return out;
    }

    /** Replaces the values of {@code name}, at the position of its first field (or at the end). */
    @Override
    public void set(String name, Iterable<?> newValues) {
        String n = key(name);
        List<String> vs = new ArrayList<>();
        for (Object v : newValues) vs.add(value(v));
        int at = names.indexOf(n);
        remove(n);
        if (at < 0 || at > names.size()) at = names.size();
        for (String v : vs) {
            names.add(at, n);
            values.add(at++, v);
        }
    }

    @Override
    public void add(String name, Iterable<?> newValues) {
        String n = key(name);
        for (Object v : newValues) {
            String checked = value(v);
            names.add(n);
            values.add(checked);
        }
    }

    @Override
    public boolean remove(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        boolean removed = false;
        for (int i = names.size() - 1; i >= 0; i--) {
            if (names.get(i).equals(n)) {
                names.remove(i);
                values.remove(i);
                removed = true;
            }
        }
        return removed;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < names.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(names.get(i)).append(": ").append(sensitive.contains(names.get(i)) ? "<sensitive>" : values.get(i));
        }
        return sb.append(']').toString();
    }
}
