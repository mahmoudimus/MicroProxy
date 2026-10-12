package org.microproxy.extras;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.lang.System.Logger.Level;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

/**
 * Where an {@link ActivityLogger} writes its lines: a file it appends to, or standard output. Each
 * line is written whole and flushed, under a lock, so lines from concurrent exchanges never mix
 * and nothing is lost when the process stops without closing it.
 */
public final class AccessLogWriter implements Consumer<String>, AutoCloseable {

    private static final System.Logger LOG = System.getLogger(AccessLogWriter.class.getName());

    private final Writer out;
    private final boolean closeable;
    private final String name;
    private final ReentrantLock lock = new ReentrantLock();
    private boolean failed;

    private AccessLogWriter(Writer out, boolean closeable, String name) {
        this.out = out;
        this.closeable = closeable;
        this.name = name;
    }

    /**
     * Appends lines to {@code file}, creating it if needed.
     *
     * @param file the log file
     * @return the writer
     * @throws UncheckedIOException if the file cannot be opened
     */
    public static AccessLogWriter open(Path file) {
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            Writer w = Files.newBufferedWriter(file, StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND, StandardOpenOption.WRITE);
            return new AccessLogWriter(w, true, file.toString());
        } catch (IOException e) {
            throw new UncheckedIOException("cannot open the access log " + file, e);
        }
    }

    /**
     * Writes lines to {@code stream}, such as {@link System#out}, which closing the writer leaves open.
     *
     * @param stream the stream
     * @return the writer
     */
    public static AccessLogWriter to(PrintStream stream) {
        return new AccessLogWriter(new BufferedWriter(new OutputStreamWriter(stream, StandardCharsets.UTF_8)), false,
                "standard output");
    }

    /**
     * Opens {@code target}: {@code -} for standard output, else a file path.
     *
     * @param target {@code -} or a path
     * @return the writer
     */
    public static AccessLogWriter of(String target) {
        return "-".equals(target.strip()) ? to(System.out) : open(Path.of(target.strip()));
    }

    @Override
    public void accept(String line) {
        lock.lock();
        try {
            out.write(line);
            out.write('\n');
            out.flush();
            failed = false;
        } catch (IOException e) {
            if (!failed) LOG.log(Level.WARNING, "writing the access log to " + name + " failed", e);
            failed = true;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void close() throws IOException {
        lock.lock();
        try {
            if (closeable) {
                out.close();
            } else {
                out.flush();
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public String toString() {
        return name;
    }
}
