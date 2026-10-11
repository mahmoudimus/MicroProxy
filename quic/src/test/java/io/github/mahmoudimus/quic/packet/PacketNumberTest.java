package io.github.mahmoudimus.quic.packet;

import static io.github.mahmoudimus.quic.TestVectors.hex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class PacketNumberTest {

    /** RFC 9000 appendix A.2. */
    @Test
    void rfc9000EncodingExamples() {
        assertEquals(2, PacketNumber.encodedLength(0xac5c02L, 0xabe8b3L));
        assertEquals(3, PacketNumber.encodedLength(0xace8feL, 0xabe8b3L));
    }

    /** RFC 9000 appendix A.3. */
    @Test
    void rfc9000DecodingExample() {
        assertEquals(0xa82f9b32L, PacketNumber.decode(0xa82f30eaL, 0x9b32, 2));
    }

    private static void checkPn(long full, int length, String encoded) {
        ByteBuffer out = ByteBuffer.allocate(4);
        PacketNumber.write(out, full, length);
        assertArrayEquals(hex(encoded), Arrays.copyOf(out.array(), out.position()));
        assertEquals(PacketNumber.truncate(full, length), PacketNumber.read(ByteBuffer.wrap(hex(encoded)), length));
    }

    /** quinn {@code packet::tests::roundtrip_packet_numbers}. */
    @Test
    void roundtripPacketNumbers() {
        checkPn(0x7f, 1, "7f");
        checkPn(0x80, 2, "0080");
        checkPn(0x3fff, 2, "3fff");
        checkPn(0x4000, 4, "00004000");
        checkPn(0xffff_ffffL, 4, "ffffffff");
    }

    /** quinn {@code packet::tests::pn_encode}. */
    @Test
    void pnEncode() {
        assertEquals(1, PacketNumber.encodedLength(0x10, 0));
        assertEquals(2, PacketNumber.encodedLength(0x100, 0));
        assertEquals(3, PacketNumber.encodedLength(0x10000, 0));
        checkPn(0x10, 1, "10");
        checkPn(0x100, 2, "0100");
        checkPn(0x10000, 3, "010000");
    }

    /** quinn {@code packet::tests::pn_expand_roundtrip}, from the largest acknowledged. */
    @Test
    void pnExpandRoundtrip() {
        for (long largest = 0; largest < 1024; largest++) {
            for (long actual = largest + 1; actual < 1024; actual++) {
                int len = PacketNumber.encodedLength(actual, largest);
                long truncated = PacketNumber.truncate(actual, len);
                assertEquals(actual, PacketNumber.decode(largest, truncated, len));
            }
        }
    }

    @Test
    void noneAcknowledged() {
        assertEquals(1, PacketNumber.encodedLength(0, -1));
        assertEquals(1, PacketNumber.encodedLength(126, -1));
        assertEquals(2, PacketNumber.encodedLength(127, -1));
        assertEquals(0, PacketNumber.decode(-1, 0, 1));
        assertEquals(5, PacketNumber.decode(-1, 5, 4));
    }

    @Test
    void windowEdges() {
        // Near 2^62 the candidate must not be pushed past the largest packet number.
        long max = PacketNumber.MAX;
        assertEquals(max, PacketNumber.decode(max - 1, PacketNumber.truncate(max, 1), 1));
        // A truncated value below the window wraps up; one above wraps down.
        assertEquals(0x1_00L, PacketNumber.decode(0xff, 0x00, 1));
        assertEquals(0xffL, PacketNumber.decode(0x100, 0xff, 1));
        assertThrows(IllegalArgumentException.class, () -> PacketNumber.encodedLength(1L << 40, 0));
        assertThrows(IllegalArgumentException.class, () -> PacketNumber.encodedLength(5, 5));
        assertThrows(IllegalArgumentException.class, () -> PacketNumber.truncate(1, 5));
    }
}
