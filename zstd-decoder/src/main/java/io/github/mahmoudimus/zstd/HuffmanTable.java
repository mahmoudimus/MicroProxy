package io.github.mahmoudimus.zstd;

/** A Huffman decoding table for literals (RFC 8878 section 4.2.1), indexed by the next maxBits bits. */
final class HuffmanTable {

    private static final int MAX_BITS = 11;
    private static final int MAX_FSE_LOG = 6;

    final int maxBits;
    final byte[] symbol;
    final byte[] numBits;

    private HuffmanTable(int maxBits) {
        this.maxBits = maxBits;
        this.symbol = new byte[1 << maxBits];
        this.numBits = new byte[1 << maxBits];
    }

    /** Reads a Huffman tree description; stores the bytes consumed in {@code consumed[0]}. */
    static HuffmanTable read(byte[] buf, int offset, int end, int[] consumed) throws ZstdException {
        if (offset >= end) throw ZstdException.corrupt("missing Huffman tree description");
        int header = buf[offset] & 0xff;
        byte[] weights = new byte[256];
        int count;
        if (header >= 128) {
            count = header - 127;
            int bytes = (count + 1) / 2;
            if (offset + 1 + bytes > end) throw ZstdException.corrupt("truncated Huffman weights");
            for (int i = 0; i < count; i++) {
                int b = buf[offset + 1 + i / 2] & 0xff;
                weights[i] = (byte) ((i & 1) == 0 ? b >>> 4 : b & 0xf);
            }
            consumed[0] = 1 + bytes;
        } else {
            int size = header;
            if (size == 0 || offset + 1 + size > end) throw ZstdException.corrupt("bad Huffman weights size");
            int start = offset + 1;
            int stop = start + size;
            int[] tableBytes = new int[1];
            FseTable table = FseTable.read(buf, start, stop, MAX_FSE_LOG, 255, tableBytes);
            count = decodeWeights(table, buf, start + tableBytes[0], stop, weights);
            consumed[0] = 1 + size;
        }
        return build(weights, count);
    }

    /** Decodes FSE-compressed weights with two interleaved states. */
    private static int decodeWeights(FseTable t, byte[] buf, int start, int end, byte[] weights) throws ZstdException {
        BackwardBitReader in = new BackwardBitReader(buf, start, end);
        int state1 = (int) in.read(t.accuracyLog);
        int state2 = (int) in.read(t.accuracyLog);
        int n = 0;
        while (true) {
            if (n > 253) throw ZstdException.corrupt("too many Huffman weights");
            weights[n++] = t.symbol[state1];
            state1 = t.baseline[state1] + (int) in.read(t.numBits[state1]);
            if (in.position() < 0) {
                weights[n++] = t.symbol[state2];
                break;
            }
            weights[n++] = t.symbol[state2];
            state2 = t.baseline[state2] + (int) in.read(t.numBits[state2]);
            if (in.position() < 0) {
                weights[n++] = t.symbol[state1];
                break;
            }
        }
        return n;
    }

    /** Builds the table from explicit weights, deriving the last symbol's weight. */
    static HuffmanTable build(byte[] weights, int count) throws ZstdException {
        if (count < 1 || count > 255) throw ZstdException.corrupt("bad Huffman weight count");
        int sum = 0;
        for (int i = 0; i < count; i++) {
            int w = weights[i];
            if (w > MAX_BITS) throw ZstdException.corrupt("Huffman weight too large");
            if (w > 0) sum += 1 << (w - 1);
        }
        if (sum == 0) throw ZstdException.corrupt("all Huffman weights are zero");
        int maxBits = BackwardBitReader.highBit(sum) + 1;
        if (maxBits > MAX_BITS) throw ZstdException.corrupt("Huffman code too long");
        int leftOver = (1 << maxBits) - sum;
        if ((leftOver & (leftOver - 1)) != 0) throw ZstdException.corrupt("Huffman weights do not form a tree");
        weights[count] = (byte) (BackwardBitReader.highBit(leftOver) + 1);
        int symbols = count + 1;

        HuffmanTable t = new HuffmanTable(maxBits);
        int[] rankCount = new int[MAX_BITS + 2];
        int[] bits = new int[symbols];
        for (int i = 0; i < symbols; i++) {
            bits[i] = weights[i] > 0 ? maxBits + 1 - weights[i] : 0;
            rankCount[bits[i]]++;
        }
        int[] rankStart = new int[MAX_BITS + 2];
        rankStart[maxBits] = 0;
        for (int b = maxBits; b >= 1; b--) {
            rankStart[b - 1] = rankStart[b] + rankCount[b] * (1 << (maxBits - b));
            for (int i = rankStart[b]; i < rankStart[b - 1]; i++) {
                t.numBits[i] = (byte) b;
            }
        }
        if (rankStart[0] != 1 << maxBits) throw ZstdException.corrupt("Huffman table does not fill");
        for (int s = 0; s < symbols; s++) {
            if (bits[s] == 0) continue;
            int length = 1 << (maxBits - bits[s]);
            int at = rankStart[bits[s]];
            for (int i = at; i < at + length; i++) {
                t.symbol[i] = (byte) s;
            }
            rankStart[bits[s]] += length;
        }
        return t;
    }

    /** Decodes exactly {@code count} symbols from one stream into {@code out}. */
    void decodeStream(byte[] src, int start, int end, byte[] out, int outOffset, int count) throws ZstdException {
        BackwardBitReader in = new BackwardBitReader(src, start, end);
        int mask = (1 << maxBits) - 1;
        int state = (int) in.read(maxBits);
        for (int i = 0; i < count; i++) {
            out[outOffset + i] = symbol[state];
            int n = numBits[state];
            state = ((state << n) | (int) in.read(n)) & mask;
        }
        if (in.position() != -maxBits) {
            throw ZstdException.corrupt("Huffman stream length mismatch");
        }
    }
}
