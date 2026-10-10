package io.github.mahmoudimus.http3;

import static io.github.mahmoudimus.http3.TestBytes.hex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** QUIC variable-length integers (RFC 9000 §16). */
class QuicVarIntTest {

    @ParameterizedTest
    @ValueSource(longs = {0, 1, 37, 63, 64, 16383, 16384, (1L << 30) - 1, 1L << 30, (1L << 62) - 1})
    void edgeValuesRoundTripInTheShortestEncoding(long v) throws IOException {
        int expected = v < 64 ? 1 : v < 16384 ? 2 : v < (1L << 30) ? 4 : 8;
        byte[] b = QuicVarInt.encode(v);
        assertEquals(expected, b.length);
        assertEquals(expected, QuicVarInt.length(v));
        assertEquals(expected, QuicVarInt.lengthOf(b[0]));
        assertEquals(v, QuicVarInt.read(new ByteArrayInputStream(b)));
        assertEquals(v, QuicVarInt.read(ByteBuffer.wrap(b)));
        assertEquals(v, QuicVarInt.read(b, 0, b.length));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        QuicVarInt.write(v, out);
        assertArrayEquals(b, out.toByteArray());
        ByteBuffer buf = ByteBuffer.allocate(8);
        QuicVarInt.write(v, buf);
        assertEquals(expected, buf.position());
        byte[] dst = new byte[10];
        assertEquals(1 + expected, QuicVarInt.write(v, dst, 1));
    }

    @Test
    void examplesFromRfc9000AppendixA1() throws IOException {
        assertEquals(151_288_809_941_952_652L, QuicVarInt.read(new ByteArrayInputStream(hex("c2197c5eff14e88c"))));
        assertEquals(494_878_333L, QuicVarInt.read(new ByteArrayInputStream(hex("9d7f3e7d"))));
        assertEquals(15_293L, QuicVarInt.read(new ByteArrayInputStream(hex("7bbd"))));
        assertEquals(37L, QuicVarInt.read(new ByteArrayInputStream(hex("25"))));
        // A non-minimal encoding is accepted.
        assertEquals(37L, QuicVarInt.read(new ByteArrayInputStream(hex("4025"))));
        assertEquals("c2197c5eff14e88c", hex(QuicVarInt.encode(151_288_809_941_952_652L)));
        assertEquals("9d7f3e7d", hex(QuicVarInt.encode(494_878_333L)));
        assertEquals("7bbd", hex(QuicVarInt.encode(15_293L)));
    }

    @Test
    void outOfRangeValuesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> QuicVarInt.encode(-1));
        assertThrows(IllegalArgumentException.class, () -> QuicVarInt.encode(1L << 62));
        assertThrows(IllegalArgumentException.class, () -> QuicVarInt.length(Long.MAX_VALUE));
        assertThrows(IllegalArgumentException.class, () -> QuicVarInt.write(Long.MIN_VALUE, new byte[8], 0));
    }

    @Test
    void writesThatDoNotFitLeaveTheTargetUntouched() {
        ByteBuffer buf = ByteBuffer.allocate(3);
        assertThrows(BufferOverflowException.class, () -> QuicVarInt.write(1L << 20, buf));
        assertEquals(0, buf.position());
        assertThrows(IndexOutOfBoundsException.class, () -> QuicVarInt.write(16384, new byte[5], 3));
    }

    @Test
    void truncatedInput() throws IOException {
        assertEquals(-1, QuicVarInt.read(new ByteArrayInputStream(new byte[0])));
        assertThrows(EOFException.class, () -> QuicVarInt.read(new ByteArrayInputStream(hex("c2197c"))));
        ByteBuffer buf = ByteBuffer.wrap(hex("9d7f3e"));
        assertEquals(-1, QuicVarInt.read(buf));
        assertEquals(0, buf.position());
        assertEquals(-1, QuicVarInt.read(ByteBuffer.allocate(0)));
        assertEquals(-1, QuicVarInt.read(hex("4025"), 0, 1));
        assertEquals(-1, QuicVarInt.read(hex("25"), 1, 1));
    }

    @Test
    void randomValuesRoundTrip() throws IOException {
        Random random = new Random(9000);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        long[] values = new long[2000];
        for (int i = 0; i < values.length; i++) {
            values[i] = random.nextLong() >>> (2 + random.nextInt(62));
            QuicVarInt.write(values[i], out);
        }
        ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
        for (long v : values) assertEquals(v, QuicVarInt.read(in));
        assertEquals(-1, QuicVarInt.read(in));
    }
}
