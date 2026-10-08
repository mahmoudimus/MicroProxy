package io.github.mahmoudimus.zstd;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Decodes Zstandard data (RFC 8878). Instances are immutable and thread-safe; each stream they
 * create is not.
 *
 * <pre>{@code
 * byte[] plain = ZstdDecompressor.create().decompress(compressed);
 * try (InputStream in = ZstdDecompressor.create().inputStream(socketIn)) { ... }
 * }</pre>
 *
 * <p>Concatenated frames are decoded in order and skippable frames are ignored. Memory is bounded by
 * {@link Builder#maxWindowSize}: frames that need a larger history are rejected, and the history
 * buffer only grows as output is produced.
 */
public final class ZstdDecompressor {

    /** The default window limit, 128 MiB: what the reference decoder accepts by default. */
    public static final int DEFAULT_MAX_WINDOW_SIZE = 1 << 27;

    private static final ZstdDecompressor DEFAULT = builder().build();

    final int maxWindowSize;
    final boolean verifyChecksums;
    final Map<Integer, ZstdDictionary> dictionaries;

    private ZstdDecompressor(Builder b) {
        this.maxWindowSize = b.maxWindowSize;
        this.verifyChecksums = b.verifyChecksums;
        this.dictionaries = Map.copyOf(b.dictionaries);
    }

    /** A decompressor with default settings. */
    public static ZstdDecompressor create() {
        return DEFAULT;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Options for {@link ZstdDecompressor}. */
    public static final class Builder {
        private int maxWindowSize = DEFAULT_MAX_WINDOW_SIZE;
        private boolean verifyChecksums = true;
        private final Map<Integer, ZstdDictionary> dictionaries = new HashMap<>();

        private Builder() {}

        /** Rejects frames whose window (history) is larger than this many bytes. */
        public Builder maxWindowSize(int maxWindowSize) {
            if (maxWindowSize < 1 << 10) throw new IllegalArgumentException("maxWindowSize must be at least 1 KiB");
            this.maxWindowSize = maxWindowSize;
            return this;
        }

        /** Whether to check frames' content checksums when present (default true). */
        public Builder verifyChecksums(boolean verifyChecksums) {
            this.verifyChecksums = verifyChecksums;
            return this;
        }

        /**
         * Makes a dictionary available to frames that name its ID. A raw-content dictionary (ID 0)
         * is used for frames that name no dictionary.
         */
        public Builder dictionary(ZstdDictionary dictionary) {
            dictionaries.put(dictionary.rawId(), Objects.requireNonNull(dictionary));
            return this;
        }

        public ZstdDecompressor build() {
            return new ZstdDecompressor(this);
        }
    }

    /** A stream of the data decoded from {@code in}. */
    public ZstdInputStream inputStream(InputStream in) {
        return new ZstdInputStream(in, this);
    }

    /** Decodes all of {@code data}. */
    public byte[] decompress(byte[] data) throws ZstdException {
        return decompress(data, Integer.MAX_VALUE - 8);
    }

    /** Decodes all of {@code data}, failing if the output would exceed {@code maxOutputSize} bytes. */
    public byte[] decompress(byte[] data, int maxOutputSize) throws ZstdException {
        try (ZstdInputStream in = inputStream(new ByteArrayInputStream(data))) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] chunk = new byte[1 << 16];
            int n;
            while ((n = in.read(chunk)) > 0) {
                if (out.size() + (long) n > maxOutputSize) {
                    throw new ZstdException("decompressed size exceeds " + maxOutputSize + " bytes");
                }
                out.write(chunk, 0, n);
            }
            return out.toByteArray();
        } catch (ZstdException e) {
            throw e;
        } catch (IOException e) {
            throw new UncheckedIOException("in-memory stream failed", e);
        }
    }
}
