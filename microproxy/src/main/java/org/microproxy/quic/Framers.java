package org.microproxy.quic;

import java.util.Arrays;
import java.util.Locale;

/** The built-in {@link MessageFramer}s: length prefixes and line ends. */
final class Framers {

    private Framers() {}

    static final MessageFramer U16 = new Prefix("u16", 2);
    static final MessageFramer U32 = new Prefix("u32", 4);
    static final MessageFramer VARINT = new Varint();
    static final MessageFramer LF = new Delimiter("lf", new byte[] {'\n'});
    static final MessageFramer CRLF = new Delimiter("crlf", new byte[] {'\r', '\n'});

    /** A built-in framer by name, or null. */
    static MessageFramer named(String name) {
        return switch (name.strip().toLowerCase(Locale.ROOT)) {
            case "u16" -> U16;
            case "u32" -> U32;
            case "varint" -> VARINT;
            case "lf", "line", "lines", "newline" -> LF;
            case "crlf" -> CRLF;
            default -> null;
        };
    }

    /** A big-endian unsigned length prefix of a fixed size. */
    private record Prefix(String name, int size) implements MessageFramer {

        @Override
        public long frameLength(byte[] data, int offset, int length) {
            if (length < size) return NEED_MORE;
            long n = 0;
            for (int i = 0; i < size; i++) n = (n << 8) | (data[offset + i] & 0xff);
            return size + n;
        }

        @Override
        public byte[] payload(byte[] message) {
            return Arrays.copyOfRange(message, size, message.length);
        }

        @Override
        public byte[] frame(byte[] payload) {
            long max = (1L << (8 * size)) - 1;
            if (payload.length > max) {
                throw new IllegalArgumentException("a payload of " + payload.length + " bytes does not fit a " + name
                        + " length prefix");
            }
            byte[] out = new byte[size + payload.length];
            for (int i = 0; i < size; i++) out[i] = (byte) (payload.length >>> (8 * (size - 1 - i)));
            System.arraycopy(payload, 0, out, size, payload.length);
            return out;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    /** A QUIC variable-length integer (RFC 9000 section 16) as the length prefix. */
    private static final class Varint implements MessageFramer {

        @Override
        public long frameLength(byte[] data, int offset, int length) {
            int size = 1 << ((data[offset] & 0xff) >> 6);
            if (length < size) return NEED_MORE;
            long n = data[offset] & 0x3f;
            for (int i = 1; i < size; i++) n = (n << 8) | (data[offset + i] & 0xff);
            return size + n;
        }

        @Override
        public byte[] payload(byte[] message) {
            int size = 1 << ((message[0] & 0xff) >> 6);
            return Arrays.copyOfRange(message, size, message.length);
        }

        @Override
        public byte[] frame(byte[] payload) {
            long n = payload.length;
            int size = n < 64 ? 1 : n < 16384 ? 2 : n < (1L << 30) ? 4 : 8;
            byte[] out = new byte[size + payload.length];
            for (int i = 0; i < size; i++) out[i] = (byte) (n >>> (8 * (size - 1 - i)));
            out[0] |= (byte) (Integer.numberOfTrailingZeros(size) << 6);
            System.arraycopy(payload, 0, out, size, payload.length);
            return out;
        }

        @Override
        public String toString() {
            return "varint";
        }
    }

    /** Messages that end with a delimiter, which the payload leaves out. */
    private record Delimiter(String name, byte[] delimiter) implements MessageFramer {

        @Override
        public long frameLength(byte[] data, int offset, int length) {
            int d = delimiter.length;
            outer:
            for (int i = 0; i + d <= length; i++) {
                for (int j = 0; j < d; j++) {
                    if (data[offset + i + j] != delimiter[j]) continue outer;
                }
                return i + d;
            }
            return NEED_MORE;
        }

        @Override
        public byte[] payload(byte[] message) {
            return Arrays.copyOf(message, message.length - delimiter.length);
        }

        @Override
        public byte[] frame(byte[] payload) {
            byte[] out = Arrays.copyOf(payload, payload.length + delimiter.length);
            System.arraycopy(delimiter, 0, out, payload.length, delimiter.length);
            return out;
        }

        @Override
        public String toString() {
            return name;
        }
    }
}
