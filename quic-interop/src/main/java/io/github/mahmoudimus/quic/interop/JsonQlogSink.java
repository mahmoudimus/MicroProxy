package io.github.mahmoudimus.quic.interop;

import io.github.mahmoudimus.quic.connection.QlogSink;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;

/** qlog 0.3 JSON text sequences, flushed per event so terminating a server preserves its log. */
final class JsonQlogSink implements QlogSink {
    private final Path directory;
    private final String role;
    private final Map<String, Long> origins = new HashMap<>();

    JsonQlogSink(Path directory, String role) throws IOException {
        this.directory = directory;
        this.role = role;
        Files.createDirectories(directory);
    }

    @Override public synchronized void event(String connection, long timeNanos, String name, String data) {
        if (!connection.matches("[0-9a-fA-F]+") || !name.matches("[a-zA-Z0-9_:.-]+")) {
            throw new IllegalArgumentException("invalid qlog identifier");
        }
        Path path = directory.resolve(role + "-" + connection + ".sqlog");
        try {
            if (!origins.containsKey(connection)) {
                origins.put(connection, timeNanos);
                append(path, "\u001e{\"qlog_version\":\"0.3\",\"qlog_format\":\"JSON-SEQ\",\"trace\":{"
                        + "\"vantage_point\":{\"type\":\"" + role + "\"},\"common_fields\":{\"group_id\":\""
                        + connection + "\",\"time_format\":\"relative\"}}}\n");
            }
            double milliseconds = (timeNanos - origins.get(connection)) / 1_000_000.0;
            append(path, "\u001e{\"time\":" + milliseconds + ",\"name\":\"" + name + "\",\"data\":" + data + "}\n");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void append(Path path, String value) throws IOException {
        Files.writeString(path, value, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }
}
