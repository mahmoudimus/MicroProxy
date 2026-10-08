package org.microproxy.warc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.ref.Cleaner;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;

/**
 * Collects a body as it streams past: in memory up to a threshold, then in a temporary file that
 * is deleted when the spool is closed (or garbage collected). Tracks the SHA-1 of what it holds
 * and stops (marking itself truncated) at a size limit.
 */
final class Spool implements AutoCloseable {

    private static final Cleaner CLEANER = Cleaner.create();
    private static final int MEMORY_LIMIT = 1 << 20;

    private final Path tempDir;
    private final long maxSize;
    private final MessageDigest sha1 = Warc.sha1();
    private ByteArrayOutputStream memory = new ByteArrayOutputStream();
    private FileChannel file;
    private Cleaner.Cleanable cleanable;
    private long size;
    private boolean truncated;

    Spool(Path tempDir, long maxSize) {
        this.tempDir = tempDir;
        this.maxSize = maxSize;
    }

    void add(byte[] data) {
        if (truncated || data.length == 0) return;
        int n = (int) Math.min(data.length, maxSize - size);
        if (n < data.length) truncated = true;
        if (n <= 0) return;
        sha1.update(data, 0, n);
        size += n;
        try {
            if (file == null && memory.size() + n > MEMORY_LIMIT) {
                FileChannel channel = FileChannel.open(Files.createTempFile(tempDir, "spool-", ".tmp"),
                        StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.DELETE_ON_CLOSE);
                cleanable = CLEANER.register(this, () -> closeQuietly(channel));
                file = channel;
                writeFully(ByteBuffer.wrap(memory.toByteArray()));
                memory = null;
            }
            if (file != null) {
                writeFully(ByteBuffer.wrap(data, 0, n));
            } else {
                memory.write(data, 0, n);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot spool body for WARC record", e);
        }
    }

    private void writeFully(ByteBuffer b) throws IOException {
        while (b.hasRemaining()) file.write(b);
    }

    long size() {
        return size;
    }

    boolean truncated() {
        return truncated;
    }

    /** {@code sha1:} and the base32 digest of the content. */
    String digest() {
        try {
            return Warc.digestString(((MessageDigest) sha1.clone()).digest());
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The content, from the start. */
    InputStream open() throws IOException {
        if (file == null) return new java.io.ByteArrayInputStream(memory.toByteArray());
        file.position(0);
        return new java.io.FilterInputStream(Channels.newInputStream(file)) {
            @Override
            public void close() {
                // Leave the channel open; the spool owns it.
            }
        };
    }

    @Override
    public void close() {
        if (cleanable != null) cleanable.clean();
        memory = null;
    }

    private static void closeQuietly(FileChannel channel) {
        try {
            channel.close();
        } catch (IOException ignored) {
            // The file is deleted on close; nothing else to do.
        }
    }
}
