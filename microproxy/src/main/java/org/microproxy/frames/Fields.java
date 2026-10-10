package org.microproxy.frames;

import java.util.ArrayList;
import java.util.List;

/** Field list edits shared by the frame records. */
final class Fields {

    private Fields() {}

    static String get(List<Field> fields, String name) {
        for (Field f : fields) {
            if (f.name().equals(name)) return f.value();
        }
        return null;
    }

    static List<Field> set(List<Field> fields, String name, String value) {
        List<Field> out = new ArrayList<>(fields.size() + 1);
        boolean done = false;
        int lastPseudo = -1;
        for (Field f : fields) {
            if (f.name().equals(name)) {
                if (!done) out.add(f.withValue(value));
                done = true;
                continue;
            }
            out.add(f);
            if (f.isPseudo()) lastPseudo = out.size() - 1;
        }
        if (!done) {
            Field added = new Field(name, value);
            if (added.isPseudo()) {
                out.add(lastPseudo + 1, added);
            } else {
                out.add(added);
            }
        }
        return out;
    }

    static List<Field> remove(List<Field> fields, String name) {
        List<Field> out = new ArrayList<>(fields.size());
        for (Field f : fields) {
            if (!f.name().equals(name)) out.add(f);
        }
        return out;
    }
}
