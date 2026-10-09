package org.microproxy.warc;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.zip.GZIPOutputStream;

/**
 * Appends WARC 1.1 records to files in a directory, starting a new file (each opened by a {@code
 * warcinfo} record) when one reaches its size limit. A file is named {@code
 * prefix-timestamp-serial.warc.gz} and carries an extra {@code .open} suffix while it is being
 * written. Each record is its own gzip member, so readers can seek to any record. Thread-safe;
 * records passed to one {@link #write} call stay together.
 */
public final class WarcWriter implements Closeable {

    private static final DateTimeFormatter FILE_TIME =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmssSSS").withZone(ZoneOffset.UTC);

    /** One record to write: its WARC fields (beyond those the writer adds) and its block. */
    // @value-candidate: becomes a value class in the valhalla build profile
    record Record(String type, String id, Instant date, Map<String, String> fields, String contentType,
            byte[] head, Spool body) {}

    private final Path dir;
    private final String prefix;
    private final long maxFileSize;
    private final boolean gzip;
    private final String software;
    private final ReentrantLock lock = new ReentrantLock();
    private int serial;
    private Path current;
    private CountingStream out;
    private String warcinfoId;
    private boolean closed;

    /**
     * Creates a WARC writer with file rotation and optional compression.
     *
     * @param maxFileSize start a new file once the current one reaches this many bytes
     * @param gzip compress each record ({@code .warc.gz}); otherwise plain {@code .warc}
     *
     * @param dir the directory in which to create WARC files
     * @param prefix the WARC file-name prefix
     * @param software the software identification written to warcinfo records
     * @throws IOException if the output directory cannot be created
     */
    public WarcWriter(Path dir, String prefix, long maxFileSize, boolean gzip, String software) throws IOException {
        this.dir = dir;
        this.prefix = prefix;
        this.maxFileSize = maxFileSize;
        this.gzip = gzip;
        this.software = software;
        Files.createDirectories(dir);
    }

    static String newId() {
        return "<urn:uuid:" + UUID.randomUUID() + ">";
    }

    /** Writes {@code records} consecutively. */
    void write(List<Record> records) throws IOException {
        lock.lock();
        try {
            if (closed) throw new IOException("WARC writer is closed");
            if (out == null) open();
            for (Record r : records) {
                Map<String, String> fields = new LinkedHashMap<>();
                fields.put("WARC-Warcinfo-ID", warcinfoId);
                fields.putAll(r.fields());
                writeRecord(r.type(), r.id(), r.date(), fields, r.contentType(), r.head(), r.body());
            }
            out.flush();
            if (out.count >= maxFileSize) finishFile();
        } finally {
            lock.unlock();
        }
    }

    private void open() throws IOException {
        String name = prefix + "-" + FILE_TIME.format(Instant.now()) + "-" + String.format(Locale.ROOT, "%05d", serial++)
                + (gzip ? ".warc.gz" : ".warc");
        current = dir.resolve(name + ".open");
        out = new CountingStream(new BufferedOutputStream(Files.newOutputStream(current)));
        warcinfoId = newId();
        String info = "software: " + software + "\r\n"
                + "format: WARC File Format 1.1\r\n"
                + "conformsTo: http://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/\r\n";
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("WARC-Filename", name);
        writeRecord("warcinfo", warcinfoId, Instant.now(), fields, "application/warc-fields",
                info.getBytes(StandardCharsets.UTF_8), null);
    }

    private void writeRecord(String type, String id, Instant date, Map<String, String> fields, String contentType,
            byte[] head, Spool body) throws IOException {
        long length = head.length + (body == null ? 0 : body.size());
        MessageDigest block = Warc.sha1();
        block.update(head);
        if (body != null) {
            try (InputStream in = body.open()) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) block.update(buf, 0, n);
            }
        }
        StringBuilder h = new StringBuilder(512);
        h.append("WARC/1.1\r\n");
        h.append("WARC-Type: ").append(type).append("\r\n");
        h.append("WARC-Record-ID: ").append(id).append("\r\n");
        h.append("WARC-Date: ").append(DateTimeFormatter.ISO_INSTANT.format(date)).append("\r\n");
        for (Map.Entry<String, String> e : fields.entrySet()) {
            if (e.getValue() != null) h.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
        }
        h.append("WARC-Block-Digest: ").append(Warc.digestString(block.digest())).append("\r\n");
        h.append("Content-Type: ").append(contentType).append("\r\n");
        h.append("Content-Length: ").append(length).append("\r\n\r\n");

        OutputStream member = gzip ? new GZIPOutputStream(new NonClosing(out), 65536) : new NonClosing(out);
        member.write(h.toString().getBytes(StandardCharsets.UTF_8));
        member.write(head);
        if (body != null) {
            try (InputStream in = body.open()) {
                in.transferTo(member);
            }
        }
        member.write("\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        if (member instanceof GZIPOutputStream gz) gz.finish();
        member.flush();
    }

    private void finishFile() throws IOException {
        out.close();
        out = null;
        String name = current.getFileName().toString();
        Files.move(current, current.resolveSibling(name.substring(0, name.length() - ".open".length())),
                StandardCopyOption.ATOMIC_MOVE);
        current = null;
    }

    /** Finishes the current file. Later writes fail. */
    @Override
    public void close() throws IOException {
        lock.lock();
        try {
            if (closed) return;
            closed = true;
            if (out != null) finishFile();
        } finally {
            lock.unlock();
        }
    }

    /** Builds the bytes of an HTTP message head. */
    static byte[] head(String startLine, List<Map.Entry<String, String>> headers) {
        ByteArrayOutputStream b = new ByteArrayOutputStream(256);
        StringBuilder sb = new StringBuilder(startLine).append("\r\n");
        for (Map.Entry<String, String> e : headers) sb.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
        sb.append("\r\n");
        b.writeBytes(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
        return b.toByteArray();
    }

    private static final class CountingStream extends FilterOutputStream {
        long count;

        CountingStream(OutputStream out) {
            super(out);
        }

        @Override
        public void write(int b) throws IOException {
            out.write(b);
            count++;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
            count += len;
        }
    }

    private static final class NonClosing extends FilterOutputStream {
        NonClosing(OutputStream out) {
            super(out);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
        }

        @Override
        public void close() throws IOException {
            flush();
        }
    }
}
