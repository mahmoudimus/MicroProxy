package org.microproxy.contentviews;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Reading and writing the protobuf wire format, with no interpretation of the values. */
final class ProtoWire {

    private ProtoWire() {}

    /**
     * A field as read from the wire, before its length-delimited bytes are interpreted.
     *
     * @param number the field number
     * @param wireType the wire type (never {@link ProtoValue#WIRE_END_GROUP})
     * @param bits a varint's or fixed-width value's bits
     * @param data for a length-delimited value, the array holding it
     * @param offset where the value starts in {@code data}
     * @param length the value's length
     * @param group for a group, its fields
     */
    record Raw(int number, int wireType, long bits, byte[] data, int offset, int length, List<Raw> group) {
        byte[] bytes() {
            return Arrays.copyOfRange(data, offset, offset + length);
        }
    }

    /**
     * Reads the fields in {@code data[from, to)}. A strict read accepts only minimal varints, as
     * every encoder writes them; it tells nested messages from other bytes, and makes sure that a
     * message read as nested encodes back to the same bytes.
     */
    static List<Raw> read(byte[] data, int from, int to, boolean strict, int maxDepth) throws DecodeException {
        return new Reader(data, from, to, strict, maxDepth).fields(0, 0);
    }

    /** Reads {@code data[from, to)} as packed values of {@code wireType} (varint, fixed32 or fixed64). */
    static List<ProtoValue> unpack(byte[] data, int from, int to, int wireType) throws DecodeException {
        Reader r = new Reader(data, from, to, false, 0);
        List<ProtoValue> out = new ArrayList<>();
        while (r.pos < to) {
            out.add(switch (wireType) {
                case ProtoValue.WIRE_VARINT -> new ProtoValue.Varint(r.varint());
                case ProtoValue.WIRE_FIXED32 -> new ProtoValue.Fixed32((int) r.fixed(4));
                case ProtoValue.WIRE_FIXED64 -> new ProtoValue.Fixed64(r.fixed(8));
                default -> throw new IllegalArgumentException("not a packable wire type: " + wireType);
            });
        }
        return out;
    }

    private static final class Reader {
        private final byte[] data;
        private final int start;
        private final int end;
        private final boolean strict;
        private final int maxDepth;
        private int pos;

        Reader(byte[] data, int from, int to, boolean strict, int maxDepth) {
            this.data = data;
            this.start = from;
            this.pos = from;
            this.end = to;
            this.strict = strict;
            this.maxDepth = maxDepth;
        }

        /** The fields up to the end, or up to the end of group {@code group} (0: none). */
        List<Raw> fields(int group, int depth) throws DecodeException {
            List<Raw> out = new ArrayList<>();
            while (pos < end) {
                int at = pos;
                long tag = varint();
                long number = tag >>> 3;
                int wireType = (int) (tag & 7);
                if (number < 1 || number > Protobuf.MAX_FIELD_NUMBER) {
                    throw error("invalid field number " + Long.toUnsignedString(number), at);
                }
                int n = (int) number;
                switch (wireType) {
                    case ProtoValue.WIRE_VARINT -> out.add(new Raw(n, wireType, varint(), null, 0, 0, null));
                    case ProtoValue.WIRE_FIXED64 -> out.add(new Raw(n, wireType, fixed(8), null, 0, 0, null));
                    case ProtoValue.WIRE_FIXED32 -> out.add(new Raw(n, wireType, fixed(4), null, 0, 0, null));
                    case ProtoValue.WIRE_LEN -> {
                        int lengthAt = pos;
                        long length = varint();
                        if (length < 0 || length > end - pos) {
                            throw error("length " + Long.toUnsignedString(length) + " runs past the end", lengthAt);
                        }
                        out.add(new Raw(n, wireType, 0, data, pos, (int) length, null));
                        pos += (int) length;
                    }
                    case ProtoValue.WIRE_START_GROUP -> {
                        if (depth >= maxDepth) throw error("groups nested more than " + maxDepth + " deep", at);
                        out.add(new Raw(n, wireType, 0, null, 0, 0, fields(n, depth + 1)));
                    }
                    case ProtoValue.WIRE_END_GROUP -> {
                        if (n != group) throw error("end of group " + n + " that was not started", at);
                        return out;
                    }
                    default -> throw error("invalid wire type " + wireType, at);
                }
            }
            if (group != 0) throw error("group " + group + " is not ended", pos);
            return out;
        }

        long varint() throws DecodeException {
            int at = pos;
            long value = 0;
            for (int i = 0; i < 10; i++) {
                if (pos >= end) throw error("truncated varint", at);
                int b = data[pos++] & 0xff;
                if (i == 9 && b > 1) throw error("varint longer than 64 bits", at);
                value |= (long) (b & 0x7f) << (7 * i);
                if (b < 0x80) {
                    if (strict && i > 0 && b == 0) throw error("varint with a redundant zero byte", at);
                    return value;
                }
            }
            throw error("varint longer than 10 bytes", at);
        }

        long fixed(int size) throws DecodeException {
            if (end - pos < size) throw error("truncated " + (size * 8) + "-bit value", pos);
            long value = 0;
            for (int i = 0; i < size; i++) value |= (long) (data[pos + i] & 0xff) << (8 * i);
            pos += size;
            return size == 4 ? value & 0xffffffffL : value;
        }

        private DecodeException error(String what, int at) {
            return new DecodeException("invalid protobuf: " + what + " at byte " + (at - start));
        }
    }

    /** A growing buffer of wire-format bytes. */
    static final class Writer {
        private byte[] buf = new byte[64];
        private int size;

        void tag(int number, int wireType) {
            varint(((long) number << 3) | wireType);
        }

        void varint(long value) {
            while ((value & ~0x7fL) != 0) {
                put((int) ((value & 0x7f) | 0x80));
                value >>>= 7;
            }
            put((int) value);
        }

        void fixed32(int value) {
            for (int i = 0; i < 4; i++) put(value >>> (8 * i));
        }

        void fixed64(long value) {
            for (int i = 0; i < 8; i++) put((int) (value >>> (8 * i)));
        }

        /** A length, then the bytes. */
        void lengthDelimited(byte[] bytes) {
            varint(bytes.length);
            ensure(bytes.length);
            System.arraycopy(bytes, 0, buf, size, bytes.length);
            size += bytes.length;
        }

        byte[] toByteArray() {
            return Arrays.copyOf(buf, size);
        }

        private void put(int b) {
            ensure(1);
            buf[size++] = (byte) b;
        }

        private void ensure(int more) {
            if (size + more > buf.length) {
                buf = Arrays.copyOf(buf, Math.max(buf.length * 2, size + more));
            }
        }
    }
}
