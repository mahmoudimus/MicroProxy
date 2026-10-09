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

    /**
     * Returns a decompressor with default settings.
     *
     * @return the shared, immutable default decompressor
     */
    public static ZstdDecompressor create() {
        return DEFAULT;
    }

    /**
     * Creates a builder initialized with the default settings.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /** Options for {@link ZstdDecompressor}. */
    public static final class Builder {
        private int maxWindowSize = DEFAULT_MAX_WINDOW_SIZE;
        private boolean verifyChecksums = true;
        private final Map<Integer, ZstdDictionary> dictionaries = new HashMap<>();

        private Builder() {}

        /**
         * Rejects frames whose window (history) is larger than this many bytes.
         *
         * @param maxWindowSize maximum history size in bytes, at least 1 KiB
         * @return this builder
         * @throws IllegalArgumentException if the limit is less than 1 KiB
         */
        public Builder maxWindowSize(int maxWindowSize) {
            if (maxWindowSize < 1 << 10) throw new IllegalArgumentException("maxWindowSize must be at least 1 KiB");
            this.maxWindowSize = maxWindowSize;
            return this;
        }

        /**
         * Sets whether to check frames' content checksums when present (default true).
         *
         * @param verifyChecksums whether to verify content checksums
         * @return this builder
         */
        public Builder verifyChecksums(boolean verifyChecksums) {
            this.verifyChecksums = verifyChecksums;
            return this;
        }

        /**
         * Makes a dictionary available to frames that name its ID. A raw-content dictionary (ID 0)
         * is used for frames that name no dictionary.
         *
         * @param dictionary dictionary to register, replacing any dictionary with the same ID
         * @return this builder
         */
        public Builder dictionary(ZstdDictionary dictionary) {
            dictionaries.put(dictionary.rawId(), Objects.requireNonNull(dictionary));
            return this;
        }

        /**
         * Creates an immutable decompressor with the current settings.
         *
         * @return a new decompressor
         */
        public ZstdDecompressor build() {
            return new ZstdDecompressor(this);
        }
    }

    /**
     * Creates a stream of the data decoded from {@code in}.
     *
     * @param in compressed input; closing the returned stream also closes this input
     * @return a new decompression stream using this decompressor's settings
     */
    public ZstdInputStream inputStream(InputStream in) {
        return new ZstdInputStream(in, this);
    }

    /**
     * Decodes all of {@code data}.
     *
     * @param data compressed frames
     * @return the concatenated decompressed contents
     * @throws ZstdException if the data is invalid or exceeds the decoder's limits
     */
    public byte[] decompress(byte[] data) throws ZstdException {
        return decompress(data, Integer.MAX_VALUE - 8);
    }

    /**
     * Decodes all of {@code data}, failing if the output would exceed {@code maxOutputSize} bytes.
     *
     * @param data compressed frames
     * @param maxOutputSize maximum decompressed output size in bytes
     * @return the concatenated decompressed contents
     * @throws ZstdException if the data is invalid or exceeds the output or decoder limits
     */
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
