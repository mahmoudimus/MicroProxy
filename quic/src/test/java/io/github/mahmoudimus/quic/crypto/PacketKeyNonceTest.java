package io.github.mahmoudimus.quic.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.CipherSuite;
import java.nio.ByteBuffer;
import java.util.Arrays;
import javax.crypto.Cipher;
import org.junit.jupiter.api.Test;

/**
 * The public {@link PacketKey} nonce and constructor behavior after the generated-Dafny bridge.
 *
 * <p>The reference below is a frozen copy of the pre-adoption clone/XOR algorithm. It is test-only
 * and is deliberately independent of the generated class. These tests check the API boundary and
 * compatibility; the Dafny proof and generated-class differential suite live under formal/nonce.
 */
class PacketKeyNonceTest {

    private static final int NONCE_LENGTH = 12;
    private static final int HEADER_LENGTH = 20;

    /** Frozen pre-adoption packet nonce algorithm, kept only as an independent test oracle. */
    private static byte[] referenceNonce(byte[] iv, long packetNumber) {
        byte[] nonce = iv.clone();
        for (int i = 0; i < 8; i++) {
            nonce[NONCE_LENGTH - 1 - i] ^= (byte) (packetNumber >>> (8 * i));
        }
        return nonce;
    }

    private static byte[] ranged(int start) {
        byte[] value = new byte[NONCE_LENGTH];
        for (int i = 0; i < value.length; i++) {
            value[i] = (byte) (start + i);
        }
        return value;
    }

    private static byte[] filled(byte value) {
        byte[] result = new byte[NONCE_LENGTH];
        Arrays.fill(result, value);
        return result;
    }

    private static byte[][] variedIvs() {
        return new byte[][] {
            new byte[NONCE_LENGTH],
            filled((byte) 0xff),
            ranged(0x00),
            ranged(0x40),
            ranged(0x80),
            ranged(0xc0)
        };
    }

    private static byte[] keyBytes(CipherSuite suite, int seed) {
        byte[] key = new byte[suite.keyLength()];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (seed + 7 * i);
        }
        return key;
    }

    private static PacketKey key(CipherSuite suite, byte[] iv, int seed) {
        return PacketKey.of(suite, keyBytes(suite, seed), iv);
    }

    @Test
    void nonceMatchesFrozenReferenceForAll64SingleBitPacketNumbersAndVariedIvs() {
        for (CipherSuite suite : CipherSuite.values()) {
            for (byte[] iv : variedIvs()) {
                PacketKey packetKey = key(suite, iv, 0x30);
                for (int bit = 0; bit < 64; bit++) {
                    long pn = 1L << bit;
                    byte[] actual = packetKey.nonce(pn);
                    assertArrayEquals(referenceNonce(iv, pn), actual,
                            suite + " single-bit " + bit + " iv " + Arrays.toString(iv));
                    assertEquals(NONCE_LENGTH, actual.length);
                    assertNotSame(iv, actual, "nonce must be a fresh array");
                }
            }
        }
    }

    @Test
    void nonceHandlesNegativeHighBitAndEndianPatterns() {
        long[] patterns = {
            0L, 1L, -1L, -2L, Long.MIN_VALUE, Long.MIN_VALUE + 1,
            Long.MAX_VALUE, 0x8000000000000000L, 0x4000000000000000L,
            0x0100000000000000L, 0x0000000100000000L, 0x00000000ffffffffL,
            0xffff000000000000L, 0x0000ffffffffffffL
        };
        for (CipherSuite suite : CipherSuite.values()) {
            for (byte[] iv : variedIvs()) {
                PacketKey packetKey = key(suite, iv, 0x50);
                for (long pn : patterns) {
                    byte[] actual = packetKey.nonce(pn);
                    assertArrayEquals(referenceNonce(iv, pn), actual, suite + " pn " + pn);
                    assertArrayEquals(Arrays.copyOf(iv, 4), Arrays.copyOf(actual, 4),
                            suite + " prefix changed for pn " + pn);
                    assertEquals((byte) (iv[4] ^ (pn >>> 56)), actual[4],
                            suite + " most-significant packet-number byte");
                    assertEquals((byte) (iv[11] ^ pn), actual[11],
                            suite + " least-significant packet-number byte");
                }
            }
        }
    }

    @Test
    void nonceDoesNotMaskTheSixtySecondBitOrAbove() {
        byte[] iv = ranged(0x10);
        PacketKey packetKey = key(CipherSuite.TLS_AES_128_GCM_SHA256, iv, 0x70);
        byte[] zero = packetKey.nonce(0L);
        byte[] bit62 = packetKey.nonce(1L << 62);
        byte[] signBit = packetKey.nonce(Long.MIN_VALUE);
        assertArrayEquals(referenceNonce(iv, 1L << 62), bit62);
        assertArrayEquals(referenceNonce(iv, Long.MIN_VALUE), signBit);
        assertFalse(Arrays.equals(zero, bit62), "bit 62 must not be masked");
        assertFalse(Arrays.equals(zero, signBit), "sign bit must not be masked");
        assertEquals((byte) (iv[4] ^ 0x40), bit62[4]);
        assertEquals((byte) (iv[4] ^ 0x80), signBit[4]);
    }

    @Test
    void constructorRejectsInvalidIvLengthsWithTheHistoricalMessage() {
        for (CipherSuite suite : CipherSuite.values()) {
            for (int length : new int[] {0, 1, 11, 13, 16}) {
                int invalidLength = length;
                IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                        () -> PacketKey.of(suite, new byte[suite.keyLength()], new byte[invalidLength]),
                        suite + " IV length " + invalidLength);
                assertEquals("IV length " + invalidLength, error.getMessage());
            }
            assertTrue(PacketKey.of(suite, new byte[suite.keyLength()], new byte[NONCE_LENGTH]) != null,
                    suite + " exact 12-byte IV must be accepted");
        }
    }

    @Test
    void constructorRejectsInvalidKeyLengthsWithTheHistoricalMessage() {
        for (CipherSuite suite : CipherSuite.values()) {
            for (int length : new int[] {0, suite.keyLength() - 1, suite.keyLength() + 1}) {
                int invalidLength = length;
                IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                        () -> PacketKey.of(suite, new byte[invalidLength], new byte[NONCE_LENGTH]),
                        suite + " key length " + invalidLength);
                assertEquals("key length " + invalidLength + " for " + suite, error.getMessage());
            }
        }
    }

    @Test
    void constructorClonesTheIvAndNonceOutputsAreFresh() {
        for (CipherSuite suite : CipherSuite.values()) {
            for (byte[] original : variedIvs()) {
                long pn = 0x0123456789abcdefL;
                byte[] expected = referenceNonce(original, pn);
                PacketKey packetKey = key(suite, original, 0x90);
                original[0] ^= (byte) 0xff; // after construction; the private clone must not change
                assertArrayEquals(expected, packetKey.nonce(pn),
                        suite + " constructor did not clone the IV");

                byte[] first = packetKey.nonce(pn);
                byte[] second = packetKey.nonce(pn);
                assertNotSame(first, second, suite + " nonce array reused");
                assertArrayEquals(expected, first);
                assertArrayEquals(expected, second);
                first[0] ^= (byte) 0xff;
                assertArrayEquals(second, packetKey.nonce(pn),
                        suite + " later nonce changed after mutating an earlier result");
                assertArrayEquals(expected, packetKey.nonce(pn));
            }
        }
    }

    @Test
    void nonceCallsDoNotShareMutableOutput() {
        for (CipherSuite suite : CipherSuite.values()) {
            byte[] iv = ranged(0xa0);
            PacketKey packetKey = key(suite, iv, 0xb0);
            long pn = -0x0102030405060708L;
            byte[] expected = referenceNonce(iv, pn);
            byte[] first = packetKey.nonce(pn);
            byte[] second = packetKey.nonce(pn);
            byte[] firstCopy = first.clone();
            first[0] ^= (byte) 0xff;
            first[3] ^= (byte) 0x55;
            assertArrayEquals(firstCopy, second, suite + " outputs share storage");
            assertArrayEquals(expected, packetKey.nonce(pn));
        }
    }

    @Test
    void nonceDrivesPacketProtectionRoundTripsForEveryAvailableSuiteAndSize() {
        int covered = 0;
        for (CipherSuite suite : CipherSuite.values()) {
            if (!available(suite)) {
                continue;
            }
            for (int size : new int[] {64, 1200}) {
                byte[] plaintext = new byte[size];
                for (int i = 0; i < plaintext.length; i++) {
                    plaintext[i] = (byte) (0xa5 ^ i);
                }
                byte[] header = new byte[HEADER_LENGTH];
                for (int i = 0; i < header.length; i++) {
                    header[i] = (byte) (0x90 + i);
                }
                for (long pn : new long[] {0L, 1L, -1L, Long.MIN_VALUE, 0x0102030405060708L}) {
                    byte[] packet = new byte[HEADER_LENGTH + size + PacketKey.TAG_LENGTH];
                    System.arraycopy(header, 0, packet, 0, HEADER_LENGTH);
                    System.arraycopy(plaintext, 0, packet, HEADER_LENGTH, size);
                    ByteBuffer buffer = ByteBuffer.wrap(packet);
                    PacketKey packetKey = key(suite, ranged(0xd0), 0xe0);
                    int end = packetKey.seal(pn, buffer, 0, HEADER_LENGTH, HEADER_LENGTH + size);
                    assertEquals(HEADER_LENGTH + size + PacketKey.TAG_LENGTH, end);
                    assertFalse(Arrays.equals(plaintext,
                            Arrays.copyOfRange(packet, HEADER_LENGTH, HEADER_LENGTH + size)),
                            suite + " size " + size + " seal did not replace plaintext");
                    int opened = packetKey.open(pn, buffer, 0, HEADER_LENGTH, end);
                    assertEquals(HEADER_LENGTH + size, opened);
                    assertArrayEquals(plaintext,
                            Arrays.copyOfRange(packet, HEADER_LENGTH, HEADER_LENGTH + size),
                            suite + " size " + size + " pn " + pn + " round-trip");
                    covered++;
                }
            }
        }
        assertTrue(covered > 0, "no AEAD suite was available");
    }

    private static boolean available(CipherSuite suite) {
        try {
            Cipher.getInstance(suite.aead());
            return true;
        } catch (java.security.GeneralSecurityException unavailable) {
            return false;
        }
    }
}
