package org.microproxy.impl;

import io.github.mahmoudimus.quic.connection.QlogSink;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import java.lang.System.Logger.Level;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Writes one qlog file per QUIC connection of the proxy's ({@link org.microproxy.Http3Options#qlogDirectory()}),
 * from the events its connections report through {@link QlogSink}s ({@link #sink}): JSON-SEQ (RFC
 * 7464), as the qlog main schema serializes a trace into a {@code .sqlog} file. Each record starts
 * with the record separator (0x1E) and ends with a newline: first the header, with {@code
 * "qlog_version":"0.3"} and {@code "qlog_format":"JSON-SEQ"}, the vantage point ({@code server} or
 * {@code client}) and the connection's original Destination Connection ID as {@code ODCID} and
 * {@code group_id}; then one record per event, {@code {"time":...,"name":"transport:packet_sent",
 * "data":{...}}}, whose names and data are the quic module's ({@code transport:}, {@code recovery:},
 * {@code security:} and {@code connectivity:} events), its time in milliseconds since the first
 * event ({@code "time_format":"relative"}, with the wall-clock {@code reference_time}).
 *
 * <p>The file is {@code <ODCID>_<vantage>.sqlog}, closed when the connection ends ({@link
 * #closed}). Bounded: the directory keeps at most {@code qlogMaxFiles} of the files written (the
 * oldest are deleted), and a file stops at {@code qlogMaxFileBytes}. A file that cannot be written
 * is given up on, logged once. Only code that runs QUIC loads this class.
 */
final class QlogWriter {

    private static final System.Logger LOG = System.getLogger(QlogWriter.class.getName());
    private static final ReentrantLock MAKING = new ReentrantLock();
    private static final char RECORD_SEPARATOR = 0x1e;
    /** Connections ended recently, whose late events are dropped rather than starting another file. */
    private static final int RECENTLY_ENDED = 1024;

    /** One connection's file. Its events come under the connection's lock, so one at a time. */
    private static final class Trace {
        final Writer out;
        final long startNanos;
        long bytes;
        boolean full;
        boolean failed;

        Trace(Writer out, long startNanos) {
            this.out = out;
            this.startNanos = startNanos;
        }
    }

    private final Path directory;
    private final int maxFiles;
    private final long maxFileBytes;
    private final Map<String, Trace> open = new ConcurrentHashMap<>();
    private final ReentrantLock lock = new ReentrantLock();
    /** The files written, oldest first; guarded by lock. */
    private final ArrayDeque<Path> files = new ArrayDeque<>();
    /** Guarded by lock. */
    private final Map<String, Boolean> ended = new LinkedHashMap<>(64, 0.75f, false) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
            return size() > RECENTLY_ENDED;
        }
    };
    private final AtomicBoolean warned = new AtomicBoolean();

    QlogWriter(Path directory, int maxFiles, long maxFileBytes) {
        this.directory = directory;
        this.maxFiles = maxFiles;
        this.maxFileBytes = maxFileBytes;
    }

    /** The proxy's writer, made on first use; null without a qlog directory. */
    static QlogWriter of(DefaultHttpProxyServer server) {
        Path dir = server.http3Options.qlogDirectory();
        if (dir == null) return null;
        MAKING.lock();
        try {
            if (server.qlogWriter == null) {
                server.qlogWriter = new QlogWriter(dir, server.http3Options.qlogMaxFiles(),
                        server.http3Options.qlogMaxFileBytes());
            }
            return (QlogWriter) server.qlogWriter;
        } finally {
            MAKING.unlock();
        }
    }

    /** The sink of the proxy's connections as {@code server}s or as clients; null without a qlog directory. */
    static QlogSink sink(DefaultHttpProxyServer server, boolean serverSide) {
        QlogWriter writer = of(server);
        return writer == null ? null : writer.sink(serverSide ? "server" : "client");
    }

    /** The sink of connections seen from {@code vantage}, {@code server} or {@code client}. */
    QlogSink sink(String vantage) {
        return (connection, time, name, data) -> event(vantage, connection, time, name, data);
    }

    private void event(String vantage, String connection, long timeNanos, String name, String data) {
        String key = connection + "_" + vantage;
        Trace t = open.get(key);
        if (t == null) {
            t = start(key, vantage, connection, timeNanos);
            if (t == null) return;
        }
        if (t.full || t.failed) return;
        long micros = (timeNanos - t.startNanos) / 1_000;
        String record = RECORD_SEPARATOR + "{\"time\":" + micros / 1000 + "." + pad3(micros % 1000) + ",\"name\":\""
                + name + "\",\"data\":" + data + "}\n";
        if (t.bytes + record.length() > maxFileBytes) {
            t.full = true;
            return;
        }
        write(t, record);
    }

    private static String pad3(long n) {
        return n < 10 ? "00" + n : n < 100 ? "0" + n : Long.toString(n);
    }

    /** Opens the file of a connection's first event, with the trace's header; null if it is not to be written. */
    private Trace start(String key, String vantage, String connection, long timeNanos) {
        Path file = directory.resolve(key + ".sqlog");
        lock.lock();
        try {
            if (ended.containsKey(key) || open.size() >= maxFiles) return null;
            Files.createDirectories(directory);
            BufferedWriter out = Files.newBufferedWriter(file, StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            Trace t = new Trace(out, timeNanos);
            files.addLast(file);
            while (files.size() > maxFiles) {
                Path oldest = files.removeFirst();
                try {
                    Files.deleteIfExists(oldest);
                } catch (IOException e) {
                    LOG.log(Level.DEBUG, "cannot delete the qlog file " + oldest + ": " + e);
                }
            }
            open.put(key, t);
            write(t, RECORD_SEPARATOR + "{\"qlog_version\":\"0.3\",\"qlog_format\":\"JSON-SEQ\",\"title\":\"MicroProxy "
                    + vantage + " " + connection + "\",\"trace\":{\"vantage_point\":{\"type\":\"" + vantage
                    + "\"},\"common_fields\":{\"ODCID\":\"" + connection + "\",\"group_id\":\"" + connection
                    + "\",\"protocol_type\":[\"QUIC\"],\"time_format\":\"relative\",\"reference_time\":"
                    + System.currentTimeMillis() + "}}}\n");
            return t;
        } catch (IOException e) {
            warn("cannot write the qlog file " + file + ": " + e);
            return null;
        } finally {
            lock.unlock();
        }
    }

    private void write(Trace t, String record) {
        try {
            t.out.write(record);
            t.bytes += record.length();
        } catch (IOException e) {
            t.failed = true;
            warn("writing a qlog file failed: " + e);
        }
    }

    /** The connection seen from {@code vantage} ended: its file is closed, and its later events dropped. */
    void closed(String vantage, String connection) {
        String key = connection + "_" + vantage;
        lock.lock();
        try {
            ended.put(key, Boolean.TRUE);
        } finally {
            lock.unlock();
        }
        Trace t = open.remove(key);
        if (t == null) return;
        try {
            t.out.close();
        } catch (IOException e) {
            warn("closing a qlog file failed: " + e);
        }
    }

    /** The files whose connections have not ended, for tests. */
    int openFiles() {
        return open.size();
    }

    private void warn(String message) {
        if (warned.compareAndSet(false, true)) {
            LOG.log(Level.WARNING, message + " (later qlog failures are not logged)");
        } else {
            LOG.log(Level.DEBUG, message);
        }
    }
}
