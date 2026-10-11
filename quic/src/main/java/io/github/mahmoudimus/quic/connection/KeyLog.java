package io.github.mahmoudimus.quic.connection;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HexFormat;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Receives TLS traffic secrets in the NSS key log format ({@code SSLKEYLOGFILE}), which Wireshark
 * reads to decrypt QUIC packets. A debugging aid only: whoever holds the log can read the traffic.
 *
 * <p>The labels are those of TLS 1.3: {@code CLIENT_HANDSHAKE_TRAFFIC_SECRET}, {@code
 * SERVER_HANDSHAKE_TRAFFIC_SECRET}, {@code CLIENT_TRAFFIC_SECRET_0} and {@code
 * SERVER_TRAFFIC_SECRET_0}. Implementations must be thread-safe: connections log from their own
 * threads.
 */
@FunctionalInterface
public interface KeyLog {

    /**
     * Logs one secret.
     *
     * @param label the NSS key log label
     * @param clientRandom the ClientHello random that identifies the handshake
     * @param secret the secret
     */
    void log(String label, byte[] clientRandom, byte[] secret);

    /**
     * Formats one line of the key log file.
     *
     * @param label the label
     * @param clientRandom the client random
     * @param secret the secret
     * @return the line, without a line terminator
     */
    static String line(String label, byte[] clientRandom, byte[] secret) {
        HexFormat hex = HexFormat.of();
        return label + " " + hex.formatHex(clientRandom) + " " + hex.formatHex(secret);
    }

    /**
     * A key log that appends to a file, creating it if needed.
     *
     * @param file the file, such as the one named by the {@code SSLKEYLOGFILE} environment variable
     * @return the key log; each line is written and flushed under a lock
     */
    static KeyLog file(Path file) {
        Objects.requireNonNull(file, "file");
        ReentrantLock lock = new ReentrantLock();
        return (label, clientRandom, secret) -> {
            String line = line(label, clientRandom, secret) + "\n";
            lock.lock();
            try (Writer w = Files.newBufferedWriter(file, StandardCharsets.US_ASCII, StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND)) {
                w.write(line);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            } finally {
                lock.unlock();
            }
        };
    }

    /**
     * The key log named by the {@code SSLKEYLOGFILE} environment variable.
     *
     * @return a file key log, or null if the variable is not set
     */
    static KeyLog fromEnvironment() {
        String path = System.getenv("SSLKEYLOGFILE");
        return path == null || path.isEmpty() ? null : file(Path.of(path));
    }
}
