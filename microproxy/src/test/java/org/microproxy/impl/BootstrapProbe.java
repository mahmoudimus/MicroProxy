package org.microproxy.impl;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.Deque;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

/** Finds the keys {@link DefaultHttpProxyServerBootstrap} reads from a properties file. */
public final class BootstrapProbe {

    /** Values offered to keys that do not take a path, in turn: booleans, numbers, names, URLs. */
    private static final List<String> SAMPLES = List.of("true", "1", "headers", "regular", "http://127.0.0.1:1");

    private BootstrapProbe() {}

    /**
     * Every key a properties file is read for. A recording {@link Properties} answers as if only
     * one key were set; whatever keys the bootstrap asks about meanwhile are recorded, and each
     * newly found key is offered the same way, until no new key turns up. Keys read only when
     * another is set are found that way too.
     *
     * <p>Each key is first offered a path in {@code scratch}. A key that creates something there
     * takes a path (an access log, a cache directory) and is offered nothing else, so that no
     * sample value creates a file outside {@code scratch}; the others are offered every sample.
     *
     * @param scratch an empty directory for keys that take a path
     * @return the keys, sorted
     */
    public static Set<String> propertyKeys(Path scratch) {
        Path path = scratch.resolve("sample");
        Set<String> found = new TreeSet<>();
        Deque<String> todo = new ArrayDeque<>();
        record(null, "", found, todo);
        while (!todo.isEmpty()) {
            String key = todo.poll();
            delete(path);
            record(key, path.toString(), found, todo);
            if (Files.exists(path)) continue;
            for (String sample : SAMPLES) record(key, sample, found, todo);
        }
        delete(path);
        return found;
    }

    /** Applies a recording {@link Properties} with only {@code key} set, and records what it asked. */
    private static void record(String key, String value, Set<String> found, Deque<String> todo) {
        Recording props = new Recording(key, value);
        try {
            new DefaultHttpProxyServerBootstrap().applyProperties(props);
        } catch (RuntimeException e) {
            // a sample the key does not take; the keys asked about until then still count
        }
        for (String asked : props.asked) {
            if (found.add(asked)) todo.add(asked);
        }
    }

    private static void delete(Path path) {
        if (!Files.exists(path)) return;
        try (Stream<Path> files = Files.walk(path)) {
            for (Path p : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(p);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Properties that hold at most one key, and record every key asked about. */
    private static final class Recording extends Properties {
        private final String key;
        private final String value;
        final Set<String> asked = new TreeSet<>();

        Recording(String key, String value) {
            this.key = key;
            this.value = value;
        }

        private boolean has(Object k) {
            if (k instanceof String s) asked.add(s);
            return k != null && k.equals(key);
        }

        @Override
        public boolean containsKey(Object k) {
            return has(k);
        }

        @Override
        public Object get(Object k) {
            return has(k) ? value : null;
        }

        @Override
        public String getProperty(String k) {
            return has(k) ? value : null;
        }

        @Override
        public String getProperty(String k, String defaultValue) {
            return has(k) ? value : defaultValue;
        }
    }
}
