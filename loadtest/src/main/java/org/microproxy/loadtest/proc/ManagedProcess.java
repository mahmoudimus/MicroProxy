package org.microproxy.loadtest.proc;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A child process of the harness: a proxy, the origin, the load generator or an external tool. Its
 * standard output and error are copied to a log file; lines starting with {@link #PROTOCOL_PREFIX}
 * are kept apart for the caller ({@link #nextProtocolLine}).
 */
public final class ManagedProcess implements AutoCloseable {

    /** The prefix of the lines a child writes for the harness rather than for its log. */
    public static final String PROTOCOL_PREFIX = "##LT ";

    private final String name;
    private final Process process;
    private final Path log;
    private final long startNanos = System.nanoTime();
    private final BlockingQueue<String> protocol = new LinkedBlockingQueue<>();
    private final ReentrantLock writeLock = new ReentrantLock();
    private final Thread pump;

    private ManagedProcess(String name, Process process, Path log) throws IOException {
        this.name = name;
        this.process = process;
        this.log = log;
        Writer out = Files.newBufferedWriter(log, StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                StandardOpenOption.APPEND);
        this.pump = Thread.ofPlatform().daemon().name("pump-" + name).start(() -> {
            try (out; BufferedReader in = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = in.readLine()) != null) {
                    if (line.startsWith(PROTOCOL_PREFIX)) {
                        protocol.add(line.substring(PROTOCOL_PREFIX.length()));
                    } else {
                        out.write(line);
                        out.write('\n');
                        out.flush();
                    }
                }
            } catch (IOException ignored) {
                // The process ended.
            }
        });
    }

    /**
     * Starts {@code command}, with standard error merged into standard output, and without the
     * environment's {@code JAVA_TOOL_OPTIONS} (which would set the child JVMs' options behind the
     * harness's back) or proxy variables ({@code http_proxy} and the like, which some proxies under
     * test would otherwise chain through).
     */
    public static ManagedProcess start(String name, List<String> command, Path log, Map<String, String> extraEnv)
            throws IOException {
        Files.createDirectories(log.getParent());
        Files.writeString(log, "# " + String.join(" ", command) + "\n", StandardCharsets.UTF_8);
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        pb.environment().remove("JAVA_TOOL_OPTIONS");
        pb.environment().remove("JDK_JAVA_OPTIONS");
        pb.environment().remove("_JAVA_OPTIONS");
        for (String v : List.of("http_proxy", "https_proxy", "all_proxy", "no_proxy")) {
            pb.environment().remove(v);
            pb.environment().remove(v.toUpperCase(java.util.Locale.ROOT));
        }
        if (extraEnv != null) pb.environment().putAll(extraEnv);
        return new ManagedProcess(name, pb.start(), log);
    }

    /** The process's name in the harness. */
    public String name() {
        return name;
    }

    /** The process id. */
    public long pid() {
        return process.pid();
    }

    /** The log file. */
    public Path log() {
        return log;
    }

    /** Seconds since the process started. */
    public double uptimeSeconds() {
        return (System.nanoTime() - startNanos) / 1e9;
    }

    /** Whether the process is still running. */
    public boolean alive() {
        return process.isAlive();
    }

    /** The exit code, or null while it runs. */
    public Integer exitCode() {
        return process.isAlive() ? null : process.exitValue();
    }

    /** Writes a line to the process's standard input. */
    public void send(String line) throws IOException {
        writeLock.lock();
        try {
            OutputStream in = process.getOutputStream();
            in.write((line + "\n").getBytes(StandardCharsets.UTF_8));
            in.flush();
        } finally {
            writeLock.unlock();
        }
    }

    /** The next protocol line, or null after {@code timeout} or once the process has ended. */
    public String nextProtocolLine(Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            String line = protocol.poll(200, TimeUnit.MILLISECONDS);
            if (line != null) return line;
            if (!process.isAlive() && !pump.isAlive()) return protocol.poll();
            if (System.nanoTime() > deadline) return null;
        }
    }

    /** Whether the log contains {@code text}. */
    public boolean logContains(String text) {
        try {
            return Files.readString(log, StandardCharsets.UTF_8).contains(text);
        } catch (IOException | java.io.UncheckedIOException e) {
            return false;
        }
    }

    /** Waits for the process to end. */
    public boolean waitFor(Duration timeout) throws InterruptedException {
        return process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
    }

    /** Stops the process: SIGTERM, then SIGKILL after {@code grace}. */
    public void stop(Duration grace) {
        if (!process.isAlive()) return;
        process.destroy();
        try {
            if (!process.waitFor(grace.toMillis(), TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                process.waitFor(5, TimeUnit.SECONDS);
            }
            pump.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }
    }

    /** Kills the process at once. */
    @Override
    public void close() {
        if (process.isAlive()) {
            process.destroyForcibly();
            try {
                process.waitFor(5, TimeUnit.SECONDS);
                pump.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
