package io.github.mahmoudimus.quic;

import static io.github.mahmoudimus.quic.TestVectors.hex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Random;
import org.junit.jupiter.api.Test;

class VarIntTest {

    private static long decode(String hex) {
        ByteBuffer in = ByteBuffer.wrap(hex(hex));
        long v = VarInt.read(in);
        assertFalse(in.hasRemaining());
        return v;
    }

    /** RFC 9000 appendix A.1. */
    @Test
    void rfc9000Examples() {
        assertEquals(151_288_809_941_952_652L, decode("c2197c5eff14e88c"));
        assertEquals(494_878_333L, decode("9d7f3e7d"));
        assertEquals(15_293L, decode("7bbd"));
        assertEquals(37L, decode("25"));
        assertEquals(37L, decode("4025"));
        assertArrayEquals(hex("c2197c5eff14e88c"), VarInt.encode(151_288_809_941_952_652L));
        assertArrayEquals(hex("9d7f3e7d"), VarInt.encode(494_878_333L));
        assertArrayEquals(hex("7bbd"), VarInt.encode(15_293L));
        assertArrayEquals(hex("25"), VarInt.encode(37));
    }

    @Test
    void sizesAtBoundaries() {
        long[] values = {0, 63, 64, 16383, 16384, (1L << 30) - 1, 1L << 30, VarInt.MAX};
        int[] sizes = {1, 1, 2, 2, 4, 4, 8, 8};
        for (int i = 0; i < values.length; i++) {
            assertEquals(sizes[i], VarInt.size(values[i]), "size of " + values[i]);
            byte[] enc = VarInt.encode(values[i]);
            assertEquals(sizes[i], enc.length);
            assertEquals(sizes[i], VarInt.sizeOf(enc[0]));
            assertEquals(values[i], VarInt.read(ByteBuffer.wrap(enc)));
        }
        assertThrows(IllegalArgumentException.class, () -> VarInt.size(-1));
        assertThrows(IllegalArgumentException.class, () -> VarInt.size(VarInt.MAX + 1));
        assertThrows(IllegalArgumentException.class, () -> VarInt.encode(1L << 62));
    }

    @Test
    void fixedWidthEncoding() {
        ByteBuffer out = ByteBuffer.allocate(8);
        VarInt.writeWithSize(out, 5, 2);
        VarInt.writeWithSize(out, 5, 4);
        out.flip();
        assertEquals(6, out.remaining());
        assertEquals(5, VarInt.read(out));
        assertEquals(5, VarInt.read(out));
        assertThrows(IllegalArgumentException.class, () -> VarInt.writeWithSize(ByteBuffer.allocate(8), 64, 1));
        assertThrows(IllegalArgumentException.class, () -> VarInt.writeWithSize(ByteBuffer.allocate(8), 1, 3));
    }

    @Test
    void truncatedInputLeavesPosition() {
        ByteBuffer in = ByteBuffer.wrap(hex("c2197c5eff14e8"));
        assertThrows(BufferUnderflowException.class, () -> VarInt.read(in));
        assertEquals(0, in.position());
        assertThrows(BufferUnderflowException.class, () -> VarInt.read(ByteBuffer.allocate(0)));
        assertThrows(BufferOverflowException.class, () -> VarInt.write(ByteBuffer.allocate(1), 64));
    }

    @Test
    void randomRoundTrips() {
        Random r = new Random(42);
        byte[] arr = new byte[8];
        for (int i = 0; i < 10_000; i++) {
            long v = (r.nextLong() >>> 2) >>> r.nextInt(62);
            int end = VarInt.write(arr, 0, v);
            assertEquals(VarInt.size(v), end);
            assertEquals(v, VarInt.read(ByteBuffer.wrap(arr, 0, end)));
        }
    }

    @Test
    void connectionIdValueSemantics() {
        ConnectionId a = ConnectionId.of(hex("0102030405"));
        ConnectionId b = ConnectionId.of(hex("000102030405"), 1, 5);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertEquals("0102030405", a.toString());
        assertEquals(5, a.length());
        assertEquals(0, a.compareTo(b));
        assertTrue(ConnectionId.EMPTY.compareTo(a) < 0);
        byte[] copy = a.toByteArray();
        copy[0] = 9;
        assertEquals(1, a.get(0));
        assertTrue(ConnectionId.of().isEmpty());
        assertEquals(ConnectionId.EMPTY, ConnectionId.read(ByteBuffer.allocate(0), 0));
        assertEquals(20, ConnectionId.of(new byte[20]).length());
        assertThrows(IllegalArgumentException.class, () -> ConnectionId.of(new byte[21]));
        assertThrows(IllegalArgumentException.class, () -> ConnectionId.random(new Random(1), 21));
        assertThrows(BufferUnderflowException.class, () -> ConnectionId.read(ByteBuffer.allocate(3), 4));
        ConnectionId r1 = ConnectionId.random(new Random(7), 8);
        assertEquals(r1, ConnectionId.random(new Random(7), 8));
        assertNotEquals(r1, ConnectionId.random(new Random(8), 8));
        ByteBuffer out = ByteBuffer.allocate(8);
        r1.writeTo(out);
        assertEquals(r1, ConnectionId.of(out.array()));
    }

    @Test
    void versions() {
        assertEquals(QuicVersion.V1, QuicVersion.forWireValue(1));
        assertEquals(QuicVersion.V2, QuicVersion.forWireValue(0x6b3343cf));
        assertNull(QuicVersion.forWireValue(0xff00001d));
        assertTrue(QuicVersion.isReserved(0x0a1a2a3a));
        assertTrue(QuicVersion.isReserved(0xfafafafa));
        assertFalse(QuicVersion.isReserved(1));
        assertEquals("quic ku", QuicVersion.V1.keyUpdateLabel());
        assertEquals("quicv2 hp", QuicVersion.V2.headerProtectionLabel());
        assertEquals("0dede3def700a6db819381be6e269dcbf9bd2ed9", TestVectors.hex(QuicVersion.V2.initialSalt()));
        // RFC 9369 section 3.3.3: the Retry key and nonce derive from the published secret.
        byte[] secret = hex("c4dd2484d681aefa4ff4d69c2c20299984a765a5d3c31982f38fc74162155e9f");
        assertArrayEquals(Hkdf.SHA256.expandLabel(secret, "quicv2 key", new byte[0], 16), QuicVersion.V2.retryIntegrityKey());
        assertArrayEquals(Hkdf.SHA256.expandLabel(secret, "quicv2 iv", new byte[0], 12), QuicVersion.V2.retryIntegrityNonce());
    }

    @Test
    void statelessResetToken() {
        byte[] t = hex("00112233445566778899aabbccddeeff");
        StatelessResetToken token = StatelessResetToken.of(t);
        assertEquals(token, StatelessResetToken.read(ByteBuffer.wrap(t)));
        assertNotEquals(token, StatelessResetToken.of(hex("00112233445566778899aabbccddeefe")));
        assertThrows(IllegalArgumentException.class, () -> StatelessResetToken.of(new byte[15]));

        byte[] datagram = new byte[40];
        datagram[0] = 0x41;
        System.arraycopy(t, 0, datagram, 24, 16);
        assertTrue(token.matches(ByteBuffer.wrap(datagram)));
        assertFalse(token.matches(ByteBuffer.wrap(datagram, 0, 39)));
        // Too short to be a Stateless Reset, even though it ends in the token.
        byte[] tiny = new byte[20];
        System.arraycopy(t, 0, tiny, 4, 16);
        assertFalse(token.matches(ByteBuffer.wrap(tiny)));

        byte[] key = new byte[32];
        ConnectionId cid = ConnectionId.of(hex("0102030405060708"));
        assertEquals(StatelessResetToken.derive(key, cid), StatelessResetToken.derive(key, cid));
        assertNotEquals(StatelessResetToken.derive(key, cid), StatelessResetToken.derive(key, ConnectionId.of(hex("01"))));
    }
}
