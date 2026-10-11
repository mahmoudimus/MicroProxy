package io.github.mahmoudimus.http3;

import java.io.ByteArrayOutputStream;

/**
 * The Huffman code of HPACK (RFC 7541 §5.2 and Appendix B), which QPACK uses unchanged (RFC 9204
 * §4.1.2).
 *
 * <p>This is a copy of http2-codec's {@code Huffman}, not a dependency on it: that class is
 * package-private and reports errors as {@code Http2Exception} with HTTP/2 error codes, and
 * exporting it would make an implementation detail part of http2-codec's API and tie the two
 * modules' releases together for one static table. The code tables are fixed by the RFC, so the
 * copies cannot drift apart in any way that matters; {@code buildTree} checks that they form a
 * complete code.
 */
final class Huffman {

    /** The code of each symbol 0-255, and EOS (256), right-aligned. */
    private static final int[] CODES = {
        0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
        0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
        0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
        0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
        0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
        0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
        0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
        0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
        0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
        0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
        0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
        0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
        0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78,
        0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
        0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
        0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
        0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
        0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
        0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
        0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
        0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
        0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
        0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
        0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
        0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
        0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
        0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
        0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
        0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
        0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
        0x3fffffff,
    };

    /** The length in bits of each code. */
    private static final byte[] LENGTHS = {
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
        28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
        5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
        13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
        15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
        6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
        20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
        24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
        22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
        21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
        26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
        19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
        20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
        26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
        30,
    };

    static final int EOS = 256;

    /**
     * The decoding tree: node {@code n} has children {@code TREE[2n]} (bit 0) and
     * {@code TREE[2n + 1]} (bit 1); a child {@code c >= 0} is another node and {@code c < 0} is
     * the leaf for symbol {@code ~c}. Node 0 is the root.
     */
    private static final int[] TREE = buildTree();

    private Huffman() {}

    private static int[] buildTree() {
        int[] tree = new int[2 * 256]; // a complete code over 257 symbols has 256 internal nodes
        int nodes = 1;
        for (int sym = 0; sym <= EOS; sym++) {
            int code = CODES[sym];
            int len = LENGTHS[sym];
            int node = 0;
            for (int i = len - 1; i > 0; i--) {
                int slot = 2 * node + ((code >>> i) & 1);
                if (tree[slot] == 0) tree[slot] = nodes++;
                node = tree[slot];
            }
            tree[2 * node + (code & 1)] = ~sym;
        }
        if (nodes != 256) throw new AssertionError("Huffman table is not a complete code");
        return tree;
    }

    /** The length in octets of the Huffman encoding of {@code s} (one char per octet). */
    static long encodedLength(String s) {
        long bits = 0;
        for (int i = 0; i < s.length(); i++) bits += LENGTHS[s.charAt(i) & 0xff];
        return (bits + 7) >>> 3;
    }

    /** Appends the Huffman encoding of {@code s} (one char per octet), padded with the EOS prefix. */
    static void encode(String s, ByteArrayOutputStream out) {
        long acc = 0;
        int bits = 0;
        for (int i = 0; i < s.length(); i++) {
            int sym = s.charAt(i) & 0xff;
            acc = (acc << LENGTHS[sym]) | CODES[sym];
            bits += LENGTHS[sym];
            while (bits >= 8) {
                bits -= 8;
                out.write((int) (acc >>> bits));
            }
            acc &= (1L << bits) - 1; // keep at most 7 bits, so the next code (<= 30 bits) fits
        }
        if (bits > 0) {
            out.write((int) ((acc << (8 - bits)) | (0xff >>> bits)));
        }
    }

    /**
     * Decodes {@code len} octets of Huffman-coded data into a String with one char per octet.
     *
     * @param error the error code for invalid data: QPACK_DECOMPRESSION_FAILED in a field section,
     *     QPACK_ENCODER_STREAM_ERROR on the encoder stream
     * @throws Http3Exception a connection error if the data contains EOS or its padding is longer
     *     than 7 bits or not all ones (RFC 7541 §5.2), or if the result would be longer than
     *     {@code maxLength}
     */
    static String decode(byte[] src, int off, int len, long maxLength, Http3ErrorCode error) throws Http3Exception {
        // The shortest code has 5 bits, so the output is at most 8/5 of the input.
        long bound = ((long) len * 8) / 5;
        char[] out = new char[(int) Math.max(0, Math.min(bound, maxLength))];
        int n = 0;
        int node = 0;
        int depth = 0; // bits consumed since the last symbol
        boolean allOnes = true; // and whether they were all 1s
        for (int i = off, end = off + len; i < end; i++) {
            int b = src[i] & 0xff;
            for (int shift = 7; shift >= 0; shift--) {
                int bit = (b >>> shift) & 1;
                int child = TREE[2 * node + bit];
                depth++;
                allOnes &= bit == 1;
                if (child < 0) {
                    int sym = ~child;
                    if (sym == EOS) throw Http3Exception.connectionError(error, "Huffman-coded string contains EOS");
                    if (n == out.length) {
                        throw Http3Exception.connectionError(error, "Huffman-coded string longer than " + maxLength + " octets");
                    }
                    out[n++] = (char) sym;
                    node = 0;
                    depth = 0;
                    allOnes = true;
                } else {
                    node = child;
                }
            }
        }
        if (depth > 7) throw Http3Exception.connectionError(error, "Huffman padding longer than 7 bits");
        if (!allOnes) throw Http3Exception.connectionError(error, "Huffman padding is not a prefix of EOS");
        return new String(out, 0, n);
    }
}
