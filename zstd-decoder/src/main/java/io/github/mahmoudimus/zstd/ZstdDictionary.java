package io.github.mahmoudimus.zstd;

import java.util.Arrays;

/**
 * A dictionary for frames compressed with one (RFC 8878 section 5): either a formatted dictionary,
 * as made by {@code zstd --train}, with its own ID, entropy tables and starting offsets, or raw
 * content with ID 0.
 */
public final class ZstdDictionary {

    private static final int MAGIC = 0xEC30A437;

    private final int id;
    final byte[] content;
    final HuffmanTable huffman;
    final FseTable offsets;
    final FseTable matchLengths;
    final FseTable literalLengths;
    final int[] repeatOffsets;

    private ZstdDictionary(int id, byte[] content, HuffmanTable huffman, FseTable offsets, FseTable matchLengths,
            FseTable literalLengths, int[] repeatOffsets) {
        this.id = id;
        this.content = content;
        this.huffman = huffman;
        this.offsets = offsets;
        this.matchLengths = matchLengths;
        this.literalLengths = literalLengths;
        this.repeatOffsets = repeatOffsets;
    }

    /**
     * Parses {@code data}: a formatted dictionary if it starts with the dictionary magic, else raw content.
     *
     * @param data encoded dictionary or raw dictionary content
     * @return a dictionary containing a copy of the content
     * @throws ZstdException if a formatted dictionary is malformed
     */
    public static ZstdDictionary of(byte[] data) throws ZstdException {
        if (data.length < 8 || FrameDecoder.int32(data, 0) != MAGIC) {
            return raw(data);
        }
        int id = FrameDecoder.int32(data, 4);
        int p = 8;
        int[] consumed = new int[1];
        HuffmanTable huffman = HuffmanTable.read(data, p, data.length, consumed);
        p += consumed[0];
        FseTable offsets = FseTable.read(data, p, data.length, FrameDecoder.OF_MAX_LOG, FrameDecoder.OF_MAX_SYMBOL, consumed);
        p += consumed[0];
        FseTable matchLengths = FseTable.read(data, p, data.length, FrameDecoder.ML_MAX_LOG, FrameDecoder.ML_MAX_SYMBOL, consumed);
        p += consumed[0];
        FseTable literalLengths = FseTable.read(data, p, data.length, FrameDecoder.LL_MAX_LOG, FrameDecoder.LL_MAX_SYMBOL, consumed);
        p += consumed[0];
        if (p + 12 > data.length) throw ZstdException.corrupt("truncated dictionary");
        int[] reps = {FrameDecoder.int32(data, p), FrameDecoder.int32(data, p + 4), FrameDecoder.int32(data, p + 8)};
        p += 12;
        byte[] content = Arrays.copyOfRange(data, p, data.length);
        for (int rep : reps) {
            if (rep <= 0 || rep > content.length) throw ZstdException.corrupt("bad dictionary repeat offset");
        }
        return new ZstdDictionary(id, content, huffman, offsets, matchLengths, literalLengths, reps);
    }

    /**
     * Treats all of {@code content} as a raw-content dictionary (ID 0).
     *
     * @param content bytes available as history before a frame's first output byte
     * @return a dictionary containing a copy of the supplied content
     */
    public static ZstdDictionary raw(byte[] content) {
        return new ZstdDictionary(0, content.clone(), null, null, null, null, null);
    }

    /**
     * Returns the dictionary ID frames refer to it by.
     *
     * @return the unsigned 32-bit dictionary ID, or 0 for raw content
     */
    public long id() {
        return Integer.toUnsignedLong(id);
    }

    int rawId() {
        return id;
    }

    /**
     * Returns the size of the content frames can copy from.
     *
     * @return the dictionary content size in bytes
     */
    public int contentSize() {
        return content.length;
    }
}
