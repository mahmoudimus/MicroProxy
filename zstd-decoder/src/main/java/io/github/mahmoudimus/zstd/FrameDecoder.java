package io.github.mahmoudimus.zstd;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Decodes frames block by block (RFC 8878 sections 3.1 and 4) into a history buffer that holds
 * at least the frame's window. Decoded bytes wait in {@code buf[readPos, pos)} until read.
 */
final class FrameDecoder {

    static final int MAGIC = 0xFD2FB528;
    private static final int SKIPPABLE_MAGIC = 0x184D2A50;
    private static final int MAX_BLOCK = 1 << 17;

    static final int LL_MAX_LOG = 9;
    static final int ML_MAX_LOG = 9;
    static final int OF_MAX_LOG = 8;
    static final int LL_MAX_SYMBOL = 35;
    static final int ML_MAX_SYMBOL = 52;
    static final int OF_MAX_SYMBOL = 31;

    private static final int[] LL_BASE = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
        8192, 16384, 32768, 65536};
    private static final int[] LL_BITS = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
        13, 14, 15, 16};
    private static final int[] ML_BASE = {
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
        35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
        4099, 8195, 16387, 32771, 65539};
    private static final int[] ML_BITS = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 16};

    private static final FseTable LL_DEFAULT = predefined(6, new short[] {
        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
        -1, -1, -1, -1});
    private static final FseTable ML_DEFAULT = predefined(6, new short[] {
        1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
        -1, -1, -1, -1, -1});
    private static final FseTable OF_DEFAULT = predefined(5, new short[] {
        1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1});

    private final InputStream in;
    private final ZstdDecompressor config;
    private final byte[] scratch = new byte[18];
    private final byte[] block = new byte[MAX_BLOCK];
    private final byte[] literals = new byte[MAX_BLOCK];
    private final int[] consumed = new int[1];

    byte[] buf = new byte[0];
    int pos;
    int readPos;

    private boolean inFrame;
    private boolean finished;
    private long windowSize;
    private int blockMax;
    private boolean hasChecksum;
    private long contentSize;
    private long produced;
    private int dictLength;
    private Xxh64 hash;

    private HuffmanTable huffman;
    private FseTable llTable;
    private FseTable ofTable;
    private FseTable mlTable;
    private long rep0;
    private long rep1;
    private long rep2;
    private int literalCount;

    FrameDecoder(InputStream in, ZstdDecompressor config) {
        this.in = in;
        this.config = config;
    }

    private static FseTable predefined(int log, short[] counts) {
        try {
            return FseTable.build(counts, counts.length, log);
        } catch (ZstdException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /** Decodes the next block (starting a frame if needed); returns false at the end of the input. */
    boolean decodeMore() throws IOException {
        if (finished) return false;
        if (!inFrame) {
            if (!startFrame()) {
                finished = true;
                return false;
            }
            return true;
        }
        decodeBlock();
        return true;
    }

    // ---------------------------------------------------------------------------------------
    // Frames
    // ---------------------------------------------------------------------------------------

    private boolean startFrame() throws IOException {
        while (true) {
            int first = in.read();
            if (first < 0) return false;
            scratch[0] = (byte) first;
            readFully(scratch, 1, 3);
            int magic = int32(scratch, 0);
            if (magic == MAGIC) break;
            if ((magic & 0xFFFFFFF0) != SKIPPABLE_MAGIC) {
                throw ZstdException.corrupt("unknown frame magic 0x" + Integer.toHexString(magic));
            }
            readFully(scratch, 0, 4);
            skip(Integer.toUnsignedLong(int32(scratch, 0)));
        }
        int descriptor = readByte();
        int contentSizeFlag = descriptor >>> 6;
        boolean singleSegment = (descriptor & 0x20) != 0;
        if ((descriptor & 0x08) != 0) throw ZstdException.corrupt("reserved frame header bit set");
        hasChecksum = (descriptor & 0x04) != 0;
        int dictIdSize = new int[] {0, 1, 2, 4}[descriptor & 3];

        long window = 0;
        if (!singleSegment) {
            int w = readByte();
            long base = 1L << (10 + (w >>> 3));
            window = base + (base >>> 3) * (w & 7);
        }
        int dictId = (int) readLittleEndian(dictIdSize);
        int contentSizeBytes = contentSizeFlag == 0 ? (singleSegment ? 1 : 0) : 1 << contentSizeFlag;
        contentSize = -1;
        if (contentSizeBytes > 0) {
            contentSize = readLittleEndian(contentSizeBytes);
            if (contentSizeBytes == 2) contentSize += 256;
            if (contentSize < 0) throw new ZstdException("frame content size too large");
        }
        if (singleSegment) window = contentSize;
        if (window > config.maxWindowSize) {
            throw new ZstdException("frame needs a " + window + "-byte window; the limit is " + config.maxWindowSize);
        }
        windowSize = window;
        blockMax = (int) Math.min(window, MAX_BLOCK);

        ZstdDictionary dict = config.dictionaries.get(dictId);
        if (dict == null && dictId != 0) {
            throw new ZstdException("frame needs dictionary " + Integer.toUnsignedString(dictId));
        }
        pos = 0;
        readPos = 0;
        rep0 = 1;
        rep1 = 4;
        rep2 = 8;
        huffman = null;
        llTable = ofTable = mlTable = null;
        dictLength = 0;
        if (dict != null) {
            dictLength = dict.content.length;
            ensureSpace(dictLength);
            System.arraycopy(dict.content, 0, buf, 0, dictLength);
            pos = readPos = dictLength;
            huffman = dict.huffman;
            llTable = dict.literalLengths;
            ofTable = dict.offsets;
            mlTable = dict.matchLengths;
            if (dict.repeatOffsets != null) {
                rep0 = dict.repeatOffsets[0];
                rep1 = dict.repeatOffsets[1];
                rep2 = dict.repeatOffsets[2];
            }
        }
        produced = 0;
        hash = hasChecksum ? new Xxh64() : null;
        inFrame = true;
        return true;
    }

    private void finishFrame() throws IOException {
        if (hasChecksum) {
            readFully(scratch, 0, 4);
            if (config.verifyChecksums && int32(scratch, 0) != (int) hash.digest()) {
                throw new ZstdException("zstd content checksum mismatch");
            }
        }
        if (contentSize >= 0 && produced != contentSize) {
            throw ZstdException.corrupt("frame decoded to " + produced + " bytes, header says " + contentSize);
        }
        inFrame = false;
    }

    // ---------------------------------------------------------------------------------------
    // Blocks
    // ---------------------------------------------------------------------------------------

    private void decodeBlock() throws IOException {
        readFully(scratch, 0, 3);
        int header = (scratch[0] & 0xff) | (scratch[1] & 0xff) << 8 | (scratch[2] & 0xff) << 16;
        boolean last = (header & 1) != 0;
        int type = (header >>> 1) & 3;
        int size = header >>> 3;
        ensureSpace(blockMax);
        int start = pos;
        switch (type) {
            case 0 -> {
                if (size > blockMax) throw ZstdException.corrupt("raw block larger than the maximum");
                readFully(buf, pos, size);
                pos += size;
            }
            case 1 -> {
                if (size > blockMax) throw ZstdException.corrupt("RLE block larger than the maximum");
                byte value = (byte) readByte();
                Arrays.fill(buf, pos, pos + size, value);
                pos += size;
            }
            case 2 -> {
                if (size > MAX_BLOCK) throw ZstdException.corrupt("compressed block larger than 128 KiB");
                readFully(block, 0, size);
                decodeCompressed(size);
            }
            default -> throw ZstdException.corrupt("reserved block type");
        }
        int length = pos - start;
        produced += length;
        if (hash != null) hash.update(buf, start, length);
        if (contentSize >= 0 && produced > contentSize) {
            throw ZstdException.corrupt("frame is longer than its declared content size");
        }
        if (last) finishFrame();
    }

    private void decodeCompressed(int size) throws ZstdException {
        int p = decodeLiterals(size);
        decodeSequences(p, size);
    }

    /** Decodes the literals section into {@code literals}; returns where the sequences section starts. */
    private int decodeLiterals(int size) throws ZstdException {
        if (size < 1) throw ZstdException.corrupt("empty compressed block");
        int b0 = block[0] & 0xff;
        int type = b0 & 3;
        int sizeFormat = (b0 >>> 2) & 3;
        if (type == 0 || type == 1) {
            int headerSize;
            int regenerated;
            switch (sizeFormat) {
                case 1 -> {
                    headerSize = 2;
                    need(headerSize, size);
                    regenerated = (b0 >>> 4) + ((block[1] & 0xff) << 4);
                }
                case 3 -> {
                    headerSize = 3;
                    need(headerSize, size);
                    regenerated = (b0 >>> 4) + ((block[1] & 0xff) << 4) + ((block[2] & 0xff) << 12);
                }
                default -> {
                    headerSize = 1;
                    regenerated = b0 >>> 3;
                }
            }
            if (regenerated > blockMax) throw ZstdException.corrupt("literals larger than the block maximum");
            literalCount = regenerated;
            if (type == 0) {
                need(headerSize + regenerated, size);
                System.arraycopy(block, headerSize, literals, 0, regenerated);
                return headerSize + regenerated;
            }
            need(headerSize + 1, size);
            Arrays.fill(literals, 0, regenerated, block[headerSize]);
            return headerSize + 1;
        }

        int headerSize;
        int regenerated;
        int compressed;
        switch (sizeFormat) {
            case 0, 1 -> {
                headerSize = 3;
                need(headerSize, size);
                int v = (block[0] & 0xff) | (block[1] & 0xff) << 8 | (block[2] & 0xff) << 16;
                regenerated = (v >>> 4) & 0x3FF;
                compressed = (v >>> 14) & 0x3FF;
            }
            case 2 -> {
                headerSize = 4;
                need(headerSize, size);
                int v = int32(block, 0);
                regenerated = (v >>> 4) & 0x3FFF;
                compressed = (v >>> 18) & 0x3FFF;
            }
            default -> {
                headerSize = 5;
                need(headerSize, size);
                long v = (int32(block, 0) & 0xFFFFFFFFL) | (block[4] & 0xffL) << 32;
                regenerated = (int) ((v >>> 4) & 0x3FFFF);
                compressed = (int) ((v >>> 22) & 0x3FFFF);
            }
        }
        if (regenerated > blockMax) throw ZstdException.corrupt("literals larger than the block maximum");
        int p = headerSize;
        int end = headerSize + compressed;
        need(end, size);
        if (type == 2) {
            huffman = HuffmanTable.read(block, p, end, consumed);
            p += consumed[0];
        } else if (huffman == null) {
            throw ZstdException.corrupt("treeless literals without a previous Huffman table");
        }
        if (sizeFormat == 0) {
            huffman.decodeStream(block, p, end, literals, 0, regenerated);
        } else {
            if (end - p < 6) throw ZstdException.corrupt("truncated literal jump table");
            int s1 = uint16(block, p);
            int s2 = uint16(block, p + 2);
            int s3 = uint16(block, p + 4);
            int a = p + 6;
            int b = a + s1;
            int c = b + s2;
            int d = c + s3;
            if (d > end) throw ZstdException.corrupt("literal streams exceed their section");
            int segment = (regenerated + 3) / 4;
            int lastSegment = regenerated - 3 * segment;
            if (lastSegment < 0) throw ZstdException.corrupt("too few literals for four streams");
            huffman.decodeStream(block, a, b, literals, 0, segment);
            huffman.decodeStream(block, b, c, literals, segment, segment);
            huffman.decodeStream(block, c, d, literals, 2 * segment, segment);
            huffman.decodeStream(block, d, end, literals, 3 * segment, lastSegment);
        }
        literalCount = regenerated;
        return end;
    }

    private void decodeSequences(int p, int size) throws ZstdException {
        need(p + 1, size);
        int b0 = block[p++] & 0xff;
        int blockStart = pos;
        int limit = pos + blockMax;
        if (b0 == 0) {
            if (p != size) throw ZstdException.corrupt("data after an empty sequences section");
            copyLiterals(0, literalCount, limit);
            return;
        }
        int sequences;
        if (b0 < 128) {
            sequences = b0;
        } else if (b0 < 255) {
            need(p + 1, size);
            sequences = ((b0 - 128) << 8) + (block[p++] & 0xff);
        } else {
            need(p + 2, size);
            sequences = uint16(block, p) + 0x7F00;
            p += 2;
        }
        need(p + 1, size);
        int modes = block[p++] & 0xff;
        if ((modes & 3) != 0) throw ZstdException.corrupt("reserved sequence mode bits set");
        int[] at = {p};
        FseTable ll = table(modes >>> 6, llTable, LL_DEFAULT, LL_MAX_LOG, LL_MAX_SYMBOL, at, size);
        FseTable of = table((modes >>> 4) & 3, ofTable, OF_DEFAULT, OF_MAX_LOG, OF_MAX_SYMBOL, at, size);
        FseTable ml = table((modes >>> 2) & 3, mlTable, ML_DEFAULT, ML_MAX_LOG, ML_MAX_SYMBOL, at, size);
        llTable = ll;
        ofTable = of;
        mlTable = ml;
        p = at[0];

        BackwardBitReader bits = new BackwardBitReader(block, p, size);
        int llState = (int) bits.read(ll.accuracyLog);
        int ofState = (int) bits.read(of.accuracyLog);
        int mlState = (int) bits.read(ml.accuracyLog);
        int literalPos = 0;
        long frameBefore = produced;
        for (int i = 0; i < sequences; i++) {
            int ofCode = of.symbol[ofState] & 0xff;
            int llCode = ll.symbol[llState] & 0xff;
            int mlCode = ml.symbol[mlState] & 0xff;
            long offsetValue = (1L << ofCode) + bits.read(ofCode);
            int matchLength = ML_BASE[mlCode] + (int) bits.read(ML_BITS[mlCode]);
            int literalLength = LL_BASE[llCode] + (int) bits.read(LL_BITS[llCode]);
            if (i + 1 < sequences) {
                llState = ll.baseline[llState] + (int) bits.read(ll.numBits[llState]);
                mlState = ml.baseline[mlState] + (int) bits.read(ml.numBits[mlState]);
                ofState = of.baseline[ofState] + (int) bits.read(of.numBits[ofState]);
            }

            if (literalLength > literalCount - literalPos) throw ZstdException.corrupt("sequence uses more literals than decoded");
            if ((long) pos + literalLength + matchLength > limit) throw ZstdException.corrupt("block output exceeds the maximum");
            System.arraycopy(literals, literalPos, buf, pos, literalLength);
            pos += literalLength;
            literalPos += literalLength;

            long offset;
            if (offsetValue > 3) {
                offset = offsetValue - 3;
                rep2 = rep1;
                rep1 = rep0;
                rep0 = offset;
            } else {
                int index = (int) offsetValue - 1 + (literalLength == 0 ? 1 : 0);
                if (index == 0) {
                    offset = rep0;
                } else {
                    offset = index == 1 ? rep1 : index == 2 ? rep2 : rep0 - 1;
                    if (index > 1) rep2 = rep1;
                    rep1 = rep0;
                    rep0 = offset;
                }
            }
            long frameBytes = frameBefore + (pos - blockStart);
            if (offset <= 0 || offset > pos) throw ZstdException.corrupt("match offset " + offset + " is before the history");
            if (offset > frameBytes ? offset > frameBytes + dictLength : offset > windowSize) {
                throw ZstdException.corrupt("match offset " + offset + " is outside the window");
            }
            int from = pos - (int) offset;
            if (offset >= matchLength) {
                System.arraycopy(buf, from, buf, pos, matchLength);
            } else {
                for (int k = 0; k < matchLength; k++) {
                    buf[pos + k] = buf[from + k];
                }
            }
            pos += matchLength;
        }
        if (bits.position() != 0) throw ZstdException.corrupt("sequence bitstream not fully consumed");
        copyLiterals(literalPos, literalCount - literalPos, limit);
    }

    private FseTable table(int mode, FseTable previous, FseTable predefined, int maxLog, int maxSymbol, int[] at, int size)
            throws ZstdException {
        switch (mode) {
            case 0:
                return predefined;
            case 1: {
                need(at[0] + 1, size);
                int symbol = block[at[0]++] & 0xff;
                if (symbol > maxSymbol) throw ZstdException.corrupt("RLE sequence symbol out of range");
                return FseTable.rle(symbol);
            }
            case 2: {
                FseTable t = FseTable.read(block, at[0], size, maxLog, maxSymbol, consumed);
                at[0] += consumed[0];
                return t;
            }
            default:
                if (previous == null) throw ZstdException.corrupt("repeated sequence table without a previous one");
                return previous;
        }
    }

    private void copyLiterals(int from, int count, int limit) throws ZstdException {
        if ((long) pos + count > limit) throw ZstdException.corrupt("block output exceeds the maximum");
        System.arraycopy(literals, from, buf, pos, count);
        pos += count;
    }

    // ---------------------------------------------------------------------------------------
    // History buffer
    // ---------------------------------------------------------------------------------------

    /** Makes room for {@code n} more bytes, keeping the window (and unread output) behind them. */
    private void ensureSpace(int n) {
        if (pos + n <= buf.length) return;
        long history = Math.min(pos, windowSize + dictLength);
        int keep = (int) Math.max(history, pos - readPos);
        int discard = pos - keep;
        if (discard > 0 && discard >= keep) {
            System.arraycopy(buf, discard, buf, 0, keep);
            pos -= discard;
            readPos -= discard;
        }
        if (pos + n > buf.length) {
            long bound = 2 * (windowSize + dictLength) + 2L * MAX_BLOCK;
            long capacity = Math.max((long) pos + n, Math.min(2L * buf.length, bound));
            buf = Arrays.copyOf(buf, (int) Math.min(capacity, Integer.MAX_VALUE - 8));
        }
    }

    // ---------------------------------------------------------------------------------------
    // Input
    // ---------------------------------------------------------------------------------------

    private void readFully(byte[] b, int off, int len) throws IOException {
        int n = 0;
        while (n < len) {
            int r = in.read(b, off + n, len - n);
            if (r < 0) throw ZstdException.corrupt("truncated input");
            n += r;
        }
    }

    private int readByte() throws IOException {
        int b = in.read();
        if (b < 0) throw ZstdException.corrupt("truncated input");
        return b;
    }

    private long readLittleEndian(int bytes) throws IOException {
        readFully(scratch, 0, bytes);
        long v = 0;
        for (int i = 0; i < bytes; i++) {
            v |= (scratch[i] & 0xffL) << (8 * i);
        }
        return v;
    }

    private void skip(long n) throws IOException {
        try {
            in.skipNBytes(n);
        } catch (EOFException e) {
            throw ZstdException.corrupt("truncated skippable frame");
        }
    }

    private static void need(int end, int size) throws ZstdException {
        if (end > size) throw ZstdException.corrupt("truncated block");
    }

    static int int32(byte[] b, int off) {
        return (b[off] & 0xff) | (b[off + 1] & 0xff) << 8 | (b[off + 2] & 0xff) << 16 | (b[off + 3] & 0xff) << 24;
    }

    private static int uint16(byte[] b, int off) {
        return (b[off] & 0xff) | (b[off + 1] & 0xff) << 8;
    }
}
