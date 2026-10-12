package org.microproxy.otel;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Writes protobuf messages field by field into one growing buffer, nested messages in place: a
 * nested message's length is not known before its fields are written, so {@link #begin} leaves
 * room for the longest length varint and {@link #end} writes the real one and moves the fields
 * back over the room left unused. Fields with default values are written only when the caller
 * writes them.
 */
final class ProtoWriter {

    static final int VARINT = 0;
    static final int FIXED64 = 1;
    static final int LEN = 2;
    static final int FIXED32 = 5;

    /** The room {@link #begin} leaves for a length: messages up to 2^35 bytes. */
    private static final int LENGTH_ROOM = 5;

    private byte[] buf;
    private int pos;

    ProtoWriter(int initialCapacity) {
        buf = new byte[Math.max(64, initialCapacity)];
    }

    byte[] toByteArray() {
        return Arrays.copyOf(buf, pos);
    }

    int size() {
        return pos;
    }

    private void ensure(int n) {
        if (pos + n > buf.length) buf = Arrays.copyOf(buf, Math.max(buf.length * 2, pos + n));
    }

    void tag(int field, int wireType) {
        varint(((long) field << 3) | wireType);
    }

    void varint(long v) {
        ensure(10);
        while ((v & ~0x7FL) != 0) {
            buf[pos++] = (byte) ((v & 0x7F) | 0x80);
            v >>>= 7;
        }
        buf[pos++] = (byte) v;
    }

    void rawFixed64(long v) {
        ensure(8);
        for (int i = 0; i < 8; i++) {
            buf[pos++] = (byte) (v >>> (8 * i));
        }
    }

    void rawFixed32(int v) {
        ensure(4);
        for (int i = 0; i < 4; i++) {
            buf[pos++] = (byte) (v >>> (8 * i));
        }
    }

    /** An {@code int32}, {@code int64}, {@code uint32}, {@code uint64}, {@code bool} or enum field. */
    void varintField(int field, long v) {
        tag(field, VARINT);
        varint(v);
    }

    /** A {@code fixed64} or {@code sfixed64} field. */
    void fixed64Field(int field, long v) {
        tag(field, FIXED64);
        rawFixed64(v);
    }

    /** A {@code fixed32} field. */
    void fixed32Field(int field, int v) {
        tag(field, FIXED32);
        rawFixed32(v);
    }

    /** A {@code double} field. */
    void doubleField(int field, double v) {
        fixed64Field(field, Double.doubleToRawLongBits(v));
    }

    void stringField(int field, String s) {
        bytesField(field, s.getBytes(StandardCharsets.UTF_8));
    }

    void bytesField(int field, byte[] b) {
        tag(field, LEN);
        varint(b.length);
        ensure(b.length);
        System.arraycopy(b, 0, buf, pos, b.length);
        pos += b.length;
    }

    /** A 16-byte id (a trace id), big-endian, as OTLP sends ids. */
    void idField(int field, long high, long low) {
        tag(field, LEN);
        varint(16);
        rawBigEndian(high);
        rawBigEndian(low);
    }

    /** An 8-byte id (a span id), big-endian. */
    void idField(int field, long id) {
        tag(field, LEN);
        varint(8);
        rawBigEndian(id);
    }

    private void rawBigEndian(long v) {
        ensure(8);
        for (int i = 7; i >= 0; i--) {
            buf[pos++] = (byte) (v >>> (8 * i));
        }
    }

    /** Starts a nested message (or a packed field) as field {@code field}; returns the mark {@link #end} takes. */
    int begin(int field) {
        tag(field, LEN);
        ensure(LENGTH_ROOM);
        int mark = pos;
        pos += LENGTH_ROOM;
        return mark;
    }

    /** Ends the nested message {@link #begin} started at {@code mark}. */
    void end(int mark) {
        int start = mark + LENGTH_ROOM;
        int length = pos - start;
        int n = varintSize(length);
        if (n < LENGTH_ROOM) {
            System.arraycopy(buf, start, buf, mark + n, length);
            pos -= LENGTH_ROOM - n;
        }
        int p = mark;
        long v = length;
        while ((v & ~0x7FL) != 0) {
            buf[p++] = (byte) ((v & 0x7F) | 0x80);
            v >>>= 7;
        }
        buf[p] = (byte) v;
    }

    static int varintSize(long v) {
        int n = 1;
        while ((v & ~0x7FL) != 0) {
            n++;
            v >>>= 7;
        }
        return n;
    }
}
