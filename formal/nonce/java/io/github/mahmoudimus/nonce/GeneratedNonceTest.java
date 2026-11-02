// Standalone differential and compatibility tests for the Dafny-generated
// QUIC nonce primitive. TEST EVIDENCE ONLY: this source is compiled by
// formal/nonce/run.py and is never part of the production quic artifact.
//
// The oracle is the frozen pre-adoption clone/XOR implementation in
// ReferenceNonce, plus independently computed known vectors. This checks
// translation/boundary behavior; it is not a cryptographic or timing proof.

package io.github.mahmoudimus.nonce;

import io.github.mahmoudimus.quic.crypto.internal.verifiednonce.VerifiedNonce.__default;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

public final class GeneratedNonceTest {

    private static final int NONCE_LENGTH = 12;
    private static final HexFormat HEX = HexFormat.of();
    private static final List<String> FAILURES = new ArrayList<>();
    private static int cases;
    private static int assertions;

    private GeneratedNonceTest() {}

    public static void main(String[] args) {
        run("known_vectors", GeneratedNonceTest::knownVectors);
        run("all_64_single_bit_packet_numbers", GeneratedNonceTest::allSingleBitPacketNumbers);
        run("all_256_values_in_each_packet_number_lane", GeneratedNonceTest::allPacketNumberByteValues);
        run("all_256_values_in_each_iv_position", GeneratedNonceTest::allIvByteValues);
        run("random_10000_iv_and_packet_number_pairs", GeneratedNonceTest::randomPairs);
        run("negative_packet_number_patterns", GeneratedNonceTest::negativePatterns);
        run("distinct_packet_numbers_have_distinct_contents", GeneratedNonceTest::distinctContents);
        run("zero_and_ff_ivs", GeneratedNonceTest::boundaryIvs);
        run("fresh_output_and_independent_copy", GeneratedNonceTest::freshAndIndependent);
        run("packet_number_byte_is_big_endian", GeneratedNonceTest::bigEndianByteOrder);

        if (!FAILURES.isEmpty()) {
            System.err.println("FAILED " + FAILURES.size() + " nonce checks:");
            for (String failure : FAILURES) {
                System.err.println("  " + failure);
            }
            System.exit(1);
        }
        System.out.println("NONCE-TEST-OK cases=" + cases + " assertions=" + assertions);
    }

    private static void run(String name, Runnable test) {
        cases++;
        try {
            test.run();
        } catch (Throwable error) {
            FAILURES.add(name + ": unexpected " + error);
        }
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) {
            FAILURES.add(message);
        }
    }

    private static void same(byte[] expected, byte[] actual, String message) {
        check(Arrays.equals(expected, actual),
              message + ": expected " + HEX.formatHex(expected) + " actual " + HEX.formatHex(actual));
    }

    private static byte[] generated(byte[] iv, long packetNumber) {
        return __default.Nonce(iv, packetNumber);
    }

    private static byte[] frozen(byte[] iv, long packetNumber) {
        return ReferenceNonce.nonce(iv, packetNumber);
    }

    private static byte[] ranged(int start) {
        byte[] value = new byte[NONCE_LENGTH];
        for (int i = 0; i < value.length; i++) {
            value[i] = (byte) (start + i);
        }
        return value;
    }

    private static void checkCommon(byte[] iv, byte[] before, byte[] actual, String label) {
        check(actual.length == NONCE_LENGTH, label + ": length " + actual.length);
        check(actual != iv, label + ": output aliases the IV");
        check(Arrays.equals(iv, before), label + ": IV changed to " + HEX.formatHex(iv));
        check(actual[0] == before[0] && actual[1] == before[1]
              && actual[2] == before[2] && actual[3] == before[3],
              label + ": prefix changed");
    }

    private static void knownVectors() {
        byte[] iv = ranged(0);
        String[] packetNumbers = {
            "0000000000000000", "0000000000000001", "0102030405060708",
            "ffffffffffffffff", "fffffffffffffffe", "8000000000000000",
            "7fffffffffffffff", "00000000000000ff", "0000000000000100",
            "0100000000000000"
        };
        String[] expected = {
            "000102030405060708090a0b", "000102030405060708090a0a",
            "00010203050705030d0f0d03", "00010203fbfaf9f8f7f6f5f4",
            "00010203fbfaf9f8f7f6f5f5", "000102038405060708090a0b",
            "000102037bfaf9f8f7f6f5f4", "000102030405060708090af4",
            "000102030405060708090b0b", "000102030505060708090a0b"
        };
        for (int i = 0; i < packetNumbers.length; i++) {
            long pn = Long.parseUnsignedLong(packetNumbers[i], 16);
            byte[] before = iv.clone();
            byte[] actual = generated(iv, pn);
            String label = "known pn=0x" + packetNumbers[i];
            same(HEX.parseHex(expected[i]), actual, label + " independent vector");
            same(frozen(iv, pn), actual, label + " frozen reference");
            checkCommon(iv, before, actual, label);
        }
    }

    private static void allSingleBitPacketNumbers() {
        byte[] iv = ranged(0x20);
        Set<String> outputs = new LinkedHashSet<>();
        for (int bit = 0; bit < 64; bit++) {
            long pn = 1L << bit;
            byte[] before = iv.clone();
            byte[] actual = generated(iv, pn);
            String label = "single bit " + bit;
            same(frozen(iv, pn), actual, label + " frozen reference");
            checkCommon(iv, before, actual, label);
            int position = 11 - (bit / 8);
            check(actual[position] == (byte) (before[position] ^ (1 << (bit % 8))),
                  label + ": wrong XOR byte at " + position);
            for (int i = 0; i < 4; i++) {
                check(actual[i] == before[i], label + ": prefix byte " + i + " changed");
            }
            outputs.add(HEX.formatHex(actual));
        }
        check(outputs.size() == 64, "single-bit outputs are not all distinct: " + outputs.size());
    }

    private static void allPacketNumberByteValues() {
        byte[] iv = ranged(0x40);
        for (int lane = 0; lane < 8; lane++) {
            for (int value = 0; value < 256; value++) {
                long pn = ((long) value) << (8 * lane);
                byte[] before = iv.clone();
                byte[] actual = generated(iv, pn);
                String label = "pn lane " + lane + " value " + value;
                same(frozen(iv, pn), actual, label + " frozen reference");
                checkCommon(iv, before, actual, label);
                int position = 11 - lane;
                check(actual[position] == (byte) (before[position] ^ value),
                      label + ": wrong XOR byte at " + position);
            }
        }
    }

    private static void allIvByteValues() {
        long pn = 0x0102030405060708L;
        for (int position = 0; position < NONCE_LENGTH; position++) {
            for (int value = 0; value < 256; value++) {
                byte[] iv = ranged(0x60);
                iv[position] = (byte) value;
                byte[] before = iv.clone();
                byte[] actual = generated(iv, pn);
                String label = "iv position " + position + " value " + value;
                same(frozen(iv, pn), actual, label + " frozen reference");
                checkCommon(iv, before, actual, label);
                if (position < 4) {
                    check(actual[position] == (byte) value, label + ": prefix copy");
                } else {
                    int shift = 8 * (11 - position);
                    int packetByte = (int) ((pn >>> shift) & 0xffL);
                    check(actual[position] == (byte) (value ^ packetByte),
                          label + ": tail XOR");
                }
            }
        }
    }

    private static void randomPairs() {
        Random random = new Random(0x4e4f4e4345L);
        for (int i = 0; i < 10_000; i++) {
            byte[] iv = new byte[NONCE_LENGTH];
            random.nextBytes(iv);
            long pn = random.nextLong();
            byte[] before = iv.clone();
            byte[] actual = generated(iv, pn);
            byte[] expected = frozen(iv, pn);
            String label = "random case " + i + " pn=0x" + Long.toHexString(pn);
            same(expected, actual, label + " frozen reference");
            checkCommon(iv, before, actual, label);
            for (int k = 4; k < NONCE_LENGTH; k++) {
                check(actual[k] == expected[k], label + ": tail byte " + k);
            }
        }
    }

    private static void negativePatterns() {
        long[] patterns = {
            Long.MIN_VALUE, Long.MIN_VALUE + 1, Long.MIN_VALUE + 2, -2L, -1L,
            -0x0000000100000000L, -0x00000000ffffffffL, 0x8000000000000001L,
            0x80000000ffffffffL, 0xffff000000000000L, 0x0000ffffffffffffL,
            0x7fffffffffffffffL, 0x4000000000000000L, 0x2000000000000000L,
            0x0000000080000000L, 0x0000000000000080L
        };
        byte[] iv = ranged(0x80);
        for (long pn : patterns) {
            byte[] before = iv.clone();
            byte[] actual = generated(iv, pn);
            String label = "negative pattern pn=0x" + Long.toHexString(pn);
            same(frozen(iv, pn), actual, label + " frozen reference");
            checkCommon(iv, before, actual, label);
            int top = (int) ((pn >>> 56) & 0xffL);
            check(actual[4] == (byte) (before[4] ^ top), label + ": top byte");
            check(actual[0] == before[0] && actual[1] == before[1]
                  && actual[2] == before[2] && actual[3] == before[3],
                  label + ": prefix");
        }
    }

    private static void distinctContents() {
        byte[] iv = ranged(0xa0);
        Set<String> outputs = new LinkedHashSet<>();
        for (long pn = 0; pn < 1024; pn++) {
            byte[] actual = generated(iv, pn);
            same(frozen(iv, pn), actual, "adjacent pn " + pn);
            outputs.add(HEX.formatHex(actual));
        }
        long[] high = {
            Long.MIN_VALUE, Long.MIN_VALUE + 1, -1L,
            0x4000000000000000L, 0x0000000100000000L, 0x00000000ffffffffL,
            0xffffffff00000000L
        };
        for (long pn : high) {
            byte[] actual = generated(iv, pn);
            same(frozen(iv, pn), actual, "high pattern " + Long.toHexString(pn));
            outputs.add(HEX.formatHex(actual));
        }
        check(outputs.size() == 1024 + high.length,
              "distinct packet numbers produced duplicate contents: " + outputs.size());
    }

    private static void boundaryIvs() {
        byte[][] ivs = {new byte[NONCE_LENGTH], filled((byte) 0xff)};
        long[] packetNumbers = {0L, 1L, -1L, Long.MIN_VALUE, 0x0102030405060708L};
        for (byte[] iv : ivs) {
            for (long pn : packetNumbers) {
                byte[] before = iv.clone();
                byte[] actual = generated(iv, pn);
                String label = "boundary iv pn=0x" + Long.toHexString(pn);
                same(frozen(iv, pn), actual, label + " frozen reference");
                checkCommon(iv, before, actual, label);
                for (int k = 4; k < NONCE_LENGTH; k++) {
                    int shift = 8 * (11 - k);
                    check(actual[k] == (byte) (before[k] ^ (int) ((pn >>> shift) & 0xffL)),
                          label + ": tail byte " + k);
                }
            }
        }
    }

    private static byte[] filled(byte value) {
        byte[] result = new byte[NONCE_LENGTH];
        Arrays.fill(result, value);
        return result;
    }

    private static void freshAndIndependent() {
        byte[] iv = ranged(0xc0);
        byte[] before = iv.clone();
        byte[] first = generated(iv, 0x0123456789abcdefL);
        byte[] second = generated(iv, 0x0123456789abcdefL);
        check(first != iv, "first output aliases IV");
        check(second != iv, "second output aliases IV");
        check(first != second, "two calls returned the same array object");
        check(Arrays.equals(first, second), "two calls returned different contents");
        check(Arrays.equals(iv, before), "IV changed after two calls");
        byte[] secondBefore = second.clone();
        first[0] ^= (byte) 0xff;
        check(Arrays.equals(second, secondBefore), "mutating one output changed another");
        check(Arrays.equals(iv, before), "mutating an output changed the IV");
    }

    private static void bigEndianByteOrder() {
        byte[] iv = ranged(0xe0);
        for (int lane = 0; lane < 8; lane++) {
            long pn = ((long) (0x80 + lane)) << (8 * lane);
            byte[] actual = generated(iv, pn);
            String label = "big-endian lane " + lane;
            same(frozen(iv, pn), actual, label + " frozen reference");
            int position = 11 - lane;
            check(actual[position] == (byte) (iv[position] ^ (0x80 + lane)),
                  label + ": wrong output position");
            for (int other = 4; other < NONCE_LENGTH; other++) {
                if (other != position) {
                    check(actual[other] == iv[other],
                          label + ": unexpected change at " + other);
                }
            }
        }
    }
}
