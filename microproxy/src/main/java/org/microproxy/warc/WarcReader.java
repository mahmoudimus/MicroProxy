package org.microproxy.warc;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

/**
 * Reads WARC records (versions 1.0 and 1.1) one after another, as {@link WarcRecorder} writes them
 * and as other archiving tools do: plain {@code .warc} files, or {@code .warc.gz} files with one
 * gzip member per record (or one for the whole file). {@link org.microproxy.extras.ServerReplay}
 * uses it to answer requests from recorded responses.
 *
 * <pre>{@code
 * try (WarcReader reader = WarcReader.open(Path.of("warcs/microproxy-....warc.gz"))) {
 *     for (WarcReader.Record r; (r = reader.next()) != null; ) {
 *         if (r.type().equals("response")) System.out.println(r.field("WARC-Target-URI"));
 *     }
 * }
 * }</pre>
 *
 * <p>Each record's block is read into memory whole.
 */
public final class WarcReader implements Closeable {

    /** The largest record block read (2 GiB less a little, the most a byte array holds). */
    private static final long MAX_BLOCK = Integer.MAX_VALUE - 16;

    private final InputStream in;

    /**
     * Reads records from {@code in}, which is decompressed if it starts with the gzip magic bytes.
     *
     * @param in the WARC data
     * @throws IOException if the stream cannot be read
     */
    public WarcReader(InputStream in) throws IOException {
        BufferedInputStream buffered = new BufferedInputStream(in, 65536);
        buffered.mark(2);
        int b1 = buffered.read();
        int b2 = buffered.read();
        buffered.reset();
        this.in = b1 == 0x1f && b2 == 0x8b ? new BufferedInputStream(new GZIPInputStream(buffered, 65536), 65536) : buffered;
    }

    /**
     * Opens a WARC file.
     *
     * @param file a {@code .warc} or {@code .warc.gz} file
     * @return a reader positioned at the first record
     * @throws IOException if the file cannot be opened
     */
    public static WarcReader open(Path file) throws IOException {
        InputStream in = Files.newInputStream(file);
        try {
            return new WarcReader(in);
        } catch (IOException | RuntimeException e) {
            in.close();
            throw e;
        }
    }

    /**
     * One WARC record: its version line, named fields and block.
     *
     * @param version the version, such as {@code WARC/1.1}
     * @param fields the named fields, in order
     * @param block the record's content block
     */
    public record Record(String version, List<Map.Entry<String, String>> fields, byte[] block) {

        /** Copies the fields. */
        public Record {
            fields = List.copyOf(fields);
        }

        /**
         * The first value of a named field, compared without regard to case.
         *
         * @param name the field name, such as {@code WARC-Target-URI}
         * @return the value, or null if the record has no such field
         */
        public String field(String name) {
            for (Map.Entry<String, String> f : fields) {
                if (f.getKey().equalsIgnoreCase(name)) return f.getValue();
            }
            return null;
        }

        /** {@return the record type ({@code WARC-Type}), such as {@code response}; empty if missing} */
        public String type() {
            String type = field("WARC-Type");
            return type == null ? "" : type.strip();
        }

        /** {@return the record id ({@code WARC-Record-ID}), or null} */
        public String id() {
            String id = field("WARC-Record-ID");
            return id == null ? null : id.strip();
        }
    }

    /**
     * Reads the next record.
     *
     * @return the record, or null at the end of the input
     * @throws IOException if the input is not WARC or ends inside a record
     */
    public Record next() throws IOException {
        String version;
        do {
            version = line();
            if (version == null) return null;
        } while (version.isEmpty());
        if (!version.startsWith("WARC/")) throw new IOException("not a WARC record: " + abbreviate(version));
        List<Map.Entry<String, String>> fields = new ArrayList<>();
        for (String l = line(); ; l = line()) {
            if (l == null) throw new EOFException("WARC record header ends early");
            if (l.isEmpty()) break;
            if ((l.charAt(0) == ' ' || l.charAt(0) == '\t') && !fields.isEmpty()) {
                // A continuation line (WARC 1.0 allows folding).
                Map.Entry<String, String> last = fields.removeLast();
                fields.add(Map.entry(last.getKey(), last.getValue() + " " + l.strip()));
                continue;
            }
            int colon = l.indexOf(':');
            if (colon <= 0) throw new IOException("invalid WARC field: " + abbreviate(l));
            fields.add(Map.entry(l.substring(0, colon).strip(), l.substring(colon + 1).strip()));
        }
        Record header = new Record(version, fields, new byte[0]);
        String lengthField = header.field("Content-Length");
        long length;
        try {
            length = lengthField == null ? -1 : Long.parseLong(lengthField.strip());
        } catch (NumberFormatException e) {
            length = -1;
        }
        if (length < 0 || length > MAX_BLOCK) throw new IOException("invalid WARC Content-Length: " + lengthField);
        byte[] block = in.readNBytes((int) length);
        if (block.length < length) throw new EOFException("WARC record block ends early");
        return new Record(version, fields, block);
    }

    /** A CRLF- (or LF-) terminated line, decoded as UTF-8 (WARC 1.1 allows UTF-8 in field values). */
    private String line() throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream(128);
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') break;
            if (b.size() > 1 << 20) throw new IOException("WARC header line too long");
            b.write(c);
        }
        if (c < 0 && b.size() == 0) return null;
        byte[] bytes = b.toByteArray();
        int len = bytes.length > 0 && bytes[bytes.length - 1] == '\r' ? bytes.length - 1 : bytes.length;
        return new String(bytes, 0, len, StandardCharsets.UTF_8);
    }

    private static String abbreviate(String s) {
        return s.length() > 80 ? s.substring(0, 80) + "..." : s;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
