package io.github.mahmoudimus.zstd;

/**
 * A finite state entropy decoding table (RFC 8878 section 4.1.1): for each state, the symbol it
 * decodes and how to compute the next state.
 */
final class FseTable {

    final int accuracyLog;
    final byte[] symbol;
    final byte[] numBits;
    final int[] baseline;

    private FseTable(int accuracyLog) {
        int size = 1 << accuracyLog;
        this.accuracyLog = accuracyLog;
        this.symbol = new byte[size];
        this.numBits = new byte[size];
        this.baseline = new int[size];
    }

    /** A one-state table that always decodes {@code value} and reads no bits ("RLE" mode). */
    static FseTable rle(int value) {
        FseTable t = new FseTable(0);
        t.symbol[0] = (byte) value;
        return t;
    }

    /** Builds a table from normalized counts, where -1 means "less than 1". */
    static FseTable build(short[] counts, int symbols, int accuracyLog) throws ZstdException {
        FseTable t = new FseTable(accuracyLog);
        int size = 1 << accuracyLog;
        int[] next = new int[symbols];
        int high = size - 1;
        for (int s = 0; s < symbols; s++) {
            if (counts[s] == -1) {
                if (high < 0) throw ZstdException.corrupt("FSE table overflow");
                t.symbol[high--] = (byte) s;
                next[s] = 1;
            }
        }
        int step = (size >>> 1) + (size >>> 3) + 3;
        int mask = size - 1;
        int position = 0;
        for (int s = 0; s < symbols; s++) {
            int count = counts[s];
            if (count <= 0) continue;
            next[s] = count;
            for (int i = 0; i < count; i++) {
                t.symbol[position] = (byte) s;
                do {
                    position = (position + step) & mask;
                } while (position > high);
            }
        }
        if (position != 0) {
            throw ZstdException.corrupt("FSE probabilities do not fill the table");
        }
        for (int state = 0; state < size; state++) {
            int s = t.symbol[state] & 0xff;
            int nextState = next[s]++;
            int bits = accuracyLog - BackwardBitReader.highBit(nextState);
            t.numBits[state] = (byte) bits;
            t.baseline[state] = (nextState << bits) - size;
        }
        return t;
    }

    /**
     * Reads a table description (RFC 8878 section 4.1.1) starting at {@code offset}; returns the
     * table and stores the bytes consumed in {@code consumed[0]}.
     */
    static FseTable read(byte[] buf, int offset, int end, int maxAccuracyLog, int maxSymbol, int[] consumed)
            throws ZstdException {
        ForwardBits in = new ForwardBits(buf, offset, end);
        int accuracyLog = in.read(4) + 5;
        if (accuracyLog > maxAccuracyLog) {
            throw ZstdException.corrupt("FSE accuracy log " + accuracyLog + " exceeds " + maxAccuracyLog);
        }
        short[] counts = new short[256];
        int remaining = 1 << accuracyLog;
        int symbols = 0;
        while (remaining > 0) {
            if (symbols > maxSymbol) {
                throw ZstdException.corrupt("FSE table has too many symbols");
            }
            int bits = BackwardBitReader.highBit(remaining + 1) + 1;
            int value = in.read(bits);
            int lowerMask = (1 << (bits - 1)) - 1;
            int threshold = (1 << bits) - 1 - (remaining + 1);
            if ((value & lowerMask) < threshold) {
                in.rewind(1);
                value &= lowerMask;
            } else if (value > lowerMask) {
                value -= threshold;
            }
            int probability = value - 1;
            remaining -= Math.abs(probability);
            counts[symbols++] = (short) probability;
            if (probability == 0) {
                while (true) {
                    int repeat = in.read(2);
                    for (int i = 0; i < repeat; i++) {
                        if (symbols > maxSymbol) {
                            throw ZstdException.corrupt("FSE table has too many symbols");
                        }
                        counts[symbols++] = 0;
                    }
                    if (repeat != 3) break;
                }
            }
        }
        if (remaining != 0) {
            throw ZstdException.corrupt("FSE probabilities do not add up");
        }
        consumed[0] = in.bytesConsumed();
        return build(counts, symbols, accuracyLog);
    }

    /** Little-endian forward bit reader for table descriptions. */
    private static final class ForwardBits {
        private final byte[] buf;
        private final int start;
        private final int end;
        private long bit;

        ForwardBits(byte[] buf, int start, int end) {
            this.buf = buf;
            this.start = start;
            this.end = end;
        }

        int read(int n) throws ZstdException {
            long last = bit + n;
            if (start + ((last + 7) >>> 3) > end) {
                throw ZstdException.corrupt("truncated FSE table description");
            }
            int value = 0;
            for (int i = 0; i < n; i++, bit++) {
                int b = buf[start + (int) (bit >>> 3)] >>> (bit & 7) & 1;
                value |= b << i;
            }
            return value;
        }

        void rewind(int n) {
            bit -= n;
        }

        int bytesConsumed() {
            return (int) ((bit + 7) >>> 3);
        }
    }
}
