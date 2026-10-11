package io.github.mahmoudimus.http3;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/** QPACK's primitive types (RFC 9204 §4.1): prefixed integers and string literals. */
final class QpackWire {

    private QpackWire() {}

    /**
     * An integer with an N-bit prefix (RFC 7541 §5.1), the other bits of the first octet set to
     * {@code pattern}.
     */
    static void writeInt(ByteArrayOutputStream out, int pattern, int prefixBits, long value) {
        int max = (1 << prefixBits) - 1;
        if (value < max) {
            out.write(pattern | (int) value);
            return;
        }
        out.write(pattern | max);
        value -= max;
        while (value >= 0x80) {
            out.write((int) (value & 0x7f) | 0x80);
            value >>>= 7;
        }
        out.write((int) value);
    }

    /**
     * A string literal whose length has an N-bit prefix, with the Huffman flag just above the
     * prefix and the bits above that set to {@code pattern}. Huffman coding is used when asked
     * for and not longer than the raw octets.
     */
    static void writeString(ByteArrayOutputStream out, int pattern, int prefixBits, String s, boolean huffman) {
        if (huffman && !s.isEmpty()) {
            long encoded = Huffman.encodedLength(s);
            if (encoded <= s.length()) {
                writeInt(out, pattern | (1 << prefixBits), prefixBits, encoded);
                Huffman.encode(s, out);
                return;
            }
        }
        writeInt(out, pattern, prefixBits, s.length());
        for (int i = 0; i < s.length(); i++) out.write(s.charAt(i));
    }

    /** Thrown by a streaming {@link Input} that ran out of bytes inside an instruction. */
    static final class Incomplete extends Exception {
        private static final long serialVersionUID = 1L;
        static final Incomplete INSTANCE = new Incomplete();

        private Incomplete() {
            super("incomplete instruction", null, false, false);
        }
    }

    /**
     * A cursor over encoded bytes. Running out of bytes is an error with {@link #error} for a
     * field section, which arrives whole, and {@link Incomplete} for a stream of instructions,
     * which may arrive in pieces.
     */
    static final class Input {
        final byte[] buf;
        int pos;
        final int end;
        final Http3ErrorCode error;
        private final boolean streaming;

        Input(byte[] buf, int pos, int end, Http3ErrorCode error, boolean streaming) {
            this.buf = buf;
            this.pos = pos;
            this.end = end;
            this.error = error;
            this.streaming = streaming;
        }

        boolean hasRemaining() {
            return pos < end;
        }

        int peek() throws Http3Exception, Incomplete {
            need(1);
            return buf[pos] & 0xff;
        }

        /** An integer with an N-bit prefix; values above 2^62-1 are rejected. */
        long readInt(int prefixBits) throws Http3Exception, Incomplete {
            need(1);
            int max = (1 << prefixBits) - 1;
            long value = buf[pos++] & max;
            if (value < max) return value;
            for (int shift = 0; ; shift += 7) {
                need(1);
                if (shift > 56) throw fail("integer overflow");
                int b = buf[pos++] & 0xff;
                value += (long) (b & 0x7f) << shift;
                if (value > QuicVarInt.MAX_VALUE) throw fail("integer overflow");
                if ((b & 0x80) == 0) return value;
            }
        }

        /**
         * A string literal with an N-bit length prefix and the Huffman flag just above it.
         *
         * @param maxLength the longest string accepted, after Huffman decoding; checked against
         *     the encoded length before waiting for or decoding the octets
         */
        String readString(int prefixBits, long maxLength) throws Http3Exception, Incomplete {
            need(1);
            boolean huffman = (buf[pos] & (1 << prefixBits)) != 0;
            long length = readInt(prefixBits);
            // A Huffman code is at most 30 bits, so n octets of output take at most 4n of input.
            long maxEncoded = !huffman ? maxLength
                    : maxLength >= Long.MAX_VALUE / 8 ? Long.MAX_VALUE
                    : Math.max(0, maxLength) * 4 + 4;
            if (length > maxEncoded) throw fail("string of " + length + " octets exceeds the limit of " + maxLength);
            if (length > end - pos) {
                if (streaming) throw Incomplete.INSTANCE;
                throw fail("string of " + length + " octets runs past the end");
            }
            int n = (int) length;
            String s = huffman
                    ? Huffman.decode(buf, pos, n, maxLength, error)
                    : new String(buf, pos, n, StandardCharsets.ISO_8859_1);
            pos += n;
            return s;
        }

        private void need(int n) throws Http3Exception, Incomplete {
            if (end - pos < n) {
                if (streaming) throw Incomplete.INSTANCE;
                throw fail("truncated");
            }
        }

        Http3Exception fail(String message) {
            return Http3Exception.connectionError(error, message);
        }
    }
}
