// Isolated baseline-vs-candidate PacketKey packet-protection benchmark.
// TEST/EVIDENCE ONLY. Compile and run through formal/nonce/packet_bench.py;
// never part of the production artifact.
//
// "baseline" is the frozen main-30d7c3c PacketKey class tree. "candidate" is a
// private overlay containing only the reviewed PacketKey.java and the frozen
// generated VerifiedNonce class. Both modes use the public PacketKey API with
// synthetic key/IV/packet-number/payload data.
//
// This is performance evidence on one shared host. It is not a constant-time,
// side-channel, security, throughput or capacity claim.

package io.github.mahmoudimus.nonce.packetbench;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.crypto.PacketKey;
import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;

public final class PacketKeyBenchmark {

    private static final int NONCE_LENGTH = 12;
    private static final int HEADER_LENGTH = 20;
    private static volatile long sink;
    private static volatile ByteBuffer escaped;

    private PacketKeyBenchmark() {}

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("validate")) {
            validate();
            return;
        }
        if (args.length == 6 && args[0].equals("time")) {
            time(args);
            return;
        }
        throw new IllegalArgumentException(
                "usage: PacketKeyBenchmark validate | time <suite> <size> <iterations> <rounds> <fork>");
    }

    private static void validate() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        List<String> suites = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        int cases = 0;
        for (CipherSuite suite : CipherSuite.values()) {
            if (!available(suite)) {
                skipped.add(suite.name());
                continue;
            }
            suites.add(suite.name());
            for (int size : new int[] {64, 1200}) {
                byte[] header = header();
                for (byte[] iv : new byte[][] {
                    ranged(0x00), ranged(0x20), ranged(0x40), filled(NONCE_LENGTH, (byte) 0xff)
                }) {
                    for (long pn : new long[] {
                        0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE,
                        0x0102030405060708L, 0x8000000000000000L,
                        0xffff000000000000L, 0x0000ffffffffffffL
                    }) {
                        for (int pattern : new int[] {0x00, 0x5a, 0xa5, 0xff}) {
                            byte[] plaintext = filled(size, (byte) pattern);
                            byte[] packet = new byte[HEADER_LENGTH + size + PacketKey.TAG_LENGTH];
                            System.arraycopy(header, 0, packet, 0, HEADER_LENGTH);
                            System.arraycopy(plaintext, 0, packet, HEADER_LENGTH, size);
                            ByteBuffer buffer = ByteBuffer.wrap(packet);
                            PacketKey key = PacketKey.of(suite, keyBytes(suite, 0x30), iv.clone());
                            byte[] expectedNonce = referenceNonce(iv, pn);
                            byte[] actualNonce = key.nonce(pn);
                            if (!Arrays.equals(expectedNonce, actualNonce)) {
                                throw new AssertionError(suite + " nonce differs from frozen reference");
                            }
                            int end = key.seal(pn, buffer, 0, HEADER_LENGTH, HEADER_LENGTH + size);
                            if (end != HEADER_LENGTH + size + PacketKey.TAG_LENGTH) {
                                throw new AssertionError("unexpected seal end " + end);
                            }
                            byte[] ciphertext =
                                    Arrays.copyOfRange(packet, HEADER_LENGTH, HEADER_LENGTH + size + PacketKey.TAG_LENGTH);
                            if (Arrays.equals(plaintext, Arrays.copyOf(ciphertext, size))) {
                                throw new AssertionError("seal did not replace plaintext");
                            }
                            int opened = key.open(pn, buffer, 0, HEADER_LENGTH, end);
                            if (opened != HEADER_LENGTH + size) {
                                throw new AssertionError("unexpected open end " + opened);
                            }
                            byte[] recovered = Arrays.copyOfRange(packet, HEADER_LENGTH, HEADER_LENGTH + size);
                            if (!Arrays.equals(plaintext, recovered)) {
                                throw new AssertionError("open did not recover plaintext");
                            }
                            updateString(digest, suite.name());
                            updateInt(digest, size);
                            updateBytes(digest, iv);
                            updateLong(digest, pn);
                            updateInt(digest, pattern);
                            updateBytes(digest, expectedNonce);
                            updateBytes(digest, ciphertext);
                            updateBytes(digest, recovered);
                            cases++;
                        }
                    }
                }
            }
        }
        if (cases == 0) {
            throw new AssertionError("no AEAD suite was available");
        }
        System.out.println("{\"mode\":\"validate\",\"cases\":" + cases
                + ",\"digest\":\"" + hex(digest.digest())
                + "\",\"suites\":" + jsonStrings(suites)
                + ",\"skipped\":" + jsonStrings(skipped) + "}");
    }

    private static void time(String[] args) throws Exception {
        String suiteName = args[1];
        int size = Integer.parseInt(args[2]);
        int iterations = Integer.parseInt(args[3]);
        int rounds = Integer.parseInt(args[4]);
        int fork = Integer.parseInt(args[5]);
        if (size < 1 || iterations < 1 || rounds < 3 || fork < 0) {
            throw new IllegalArgumentException("invalid benchmark parameters");
        }
        CipherSuite suite = CipherSuite.valueOf(suiteName);
        if (!available(suite)) {
            System.out.println("{\"mode\":\"time\",\"suite\":\"" + suiteName
                    + "\",\"size\":" + size + ",\"fork\":" + fork
                    + ",\"available\":false,\"jdk\":\"" + System.getProperty("java.version")
                    + "\",\"vm\":\"" + System.getProperty("java.vm.name") + "\"}");
            return;
        }
        byte[] header = header();
        byte[] plaintext = filled(size, (byte) 0x5a);
        byte[] packet = new byte[HEADER_LENGTH + size + PacketKey.TAG_LENGTH];
        System.arraycopy(header, 0, packet, 0, HEADER_LENGTH);
        System.arraycopy(plaintext, 0, packet, HEADER_LENGTH, size);
        ByteBuffer buffer = ByteBuffer.wrap(packet);
        PacketKey key = PacketKey.of(suite, keyBytes(suite, 0x40), ranged(0x80));

        // Two full warmup rounds; never part of the reported samples.
        for (int warmup = 0; warmup < 2; warmup++) {
            consume(key, buffer, packet, size, iterations);
        }

        com.sun.management.ThreadMXBean threads = null;
        try {
            threads = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
            if (!threads.isThreadCpuTimeSupported()) {
                threads = null;
            } else if (!threads.isThreadCpuTimeEnabled()) {
                threads.setThreadCpuTimeEnabled(true);
            }
        } catch (Throwable ignored) {
            // CPU-time and allocation counters are optional; wall time remains.
        }

        long[] samples = new long[rounds];
        long[] cpuSamples = new long[rounds];
        for (int round = 0; round < rounds; round++) {
            long cpuStart = threads == null ? 0 : threads.getCurrentThreadCpuTime();
            long start = System.nanoTime();
            consume(key, buffer, packet, size, iterations);
            samples[round] = System.nanoTime() - start;
            cpuSamples[round] = threads == null ? -1 : threads.getCurrentThreadCpuTime() - cpuStart;
        }

        long allocated = -1;
        if (threads != null) {
            try {
                long before = threads.getCurrentThreadAllocatedBytes();
                consume(key, buffer, packet, size, iterations);
                allocated = (threads.getCurrentThreadAllocatedBytes() - before) / iterations;
            } catch (Throwable ignored) {
                // The allocation counter is optional.
            }
        }

        long[] sorted = samples.clone();
        Arrays.sort(sorted);
        long[] sortedCpu = cpuSamples.clone();
        Arrays.sort(sortedCpu);
        long median = sorted[rounds / 2];
        long cpuMedian = sortedCpu[rounds / 2];
        StringBuilder json = new StringBuilder();
        json.append("{\"mode\":\"time\",\"suite\":\"").append(suiteName)
            .append("\",\"size\":").append(size)
            .append(",\"fork\":").append(fork)
            .append(",\"iterations\":").append(iterations)
            .append(",\"rounds\":").append(rounds)
            .append(",\"available\":true")
            .append(",\"ns_per_iteration\":").append((double) median / iterations)
            .append(",\"cpu_ns_per_iteration\":")
            .append(threads == null ? -1 : (double) cpuMedian / iterations)
            .append(",\"allocated_bytes_per_iteration\":").append(allocated)
            .append(",\"samples_ns\":[");
        appendLongs(json, samples);
        json.append("],\"samples_cpu_ns\":[");
        appendLongs(json, cpuSamples);
        json.append("],\"jdk\":\"").append(System.getProperty("java.version"))
            .append("\",\"vm\":\"").append(System.getProperty("java.vm.name"))
            .append("\",\"sink\":").append(sink)
            .append(",\"escaped_size\":").append(escaped == null ? -1 : escaped.capacity())
            .append('}');
        System.out.println(json);
    }

    private static void consume(PacketKey key, ByteBuffer buffer, byte[] packet,
                                int size, int iterations) {
        long base = 0x0102030405060708L;
        for (int i = 0; i < iterations; i++) {
            long pn = base + i;
            int end = key.seal(pn, buffer, 0, HEADER_LENGTH, HEADER_LENGTH + size);
            if (end != HEADER_LENGTH + size + PacketKey.TAG_LENGTH) {
                throw new AssertionError("unexpected seal end " + end);
            }
            sink ^= packet[HEADER_LENGTH] ^ packet[end - 1];
            int opened = key.open(pn, buffer, 0, HEADER_LENGTH, end);
            if (opened != HEADER_LENGTH + size) {
                throw new AssertionError("unexpected open end " + opened);
            }
            sink ^= packet[HEADER_LENGTH] ^ opened;
            if ((i & 63) == 0) {
                // Force the packet buffer/ciphertext path to remain observable.
                escaped = buffer;
            }
        }
    }

    private static boolean available(CipherSuite suite) {
        try {
            Cipher.getInstance(suite.aead());
            return true;
        } catch (GeneralSecurityException unavailable) {
            return false;
        }
    }

    private static byte[] referenceNonce(byte[] iv, long packetNumber) {
        byte[] nonce = iv.clone();
        for (int i = 0; i < 8; i++) {
            nonce[NONCE_LENGTH - 1 - i] ^= (byte) (packetNumber >>> (8 * i));
        }
        return nonce;
    }

    private static byte[] header() {
        byte[] header = new byte[HEADER_LENGTH];
        for (int i = 0; i < header.length; i++) {
            header[i] = (byte) (0x90 + i);
        }
        return header;
    }

    private static byte[] keyBytes(CipherSuite suite, int seed) {
        byte[] key = new byte[suite.keyLength()];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (seed + 7 * i);
        }
        return key;
    }

    private static byte[] ranged(int start) {
        byte[] value = new byte[NONCE_LENGTH];
        for (int i = 0; i < value.length; i++) {
            value[i] = (byte) (start + i);
        }
        return value;
    }

    private static byte[] filled(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }

    private static void updateString(MessageDigest digest, String value) {
        updateBytes(digest, value.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    private static void updateInt(MessageDigest digest, int value) {
        digest.update(new byte[] {
            (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
        });
    }

    private static void updateLong(MessageDigest digest, long value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            digest.update((byte) (value >>> shift));
        }
    }

    private static void updateBytes(MessageDigest digest, byte[] value) {
        updateInt(digest, value.length);
        digest.update(value);
    }

    private static String hex(byte[] value) {
        StringBuilder text = new StringBuilder(value.length * 2);
        for (byte b : value) {
            text.append(Character.forDigit((b >>> 4) & 0xf, 16));
            text.append(Character.forDigit(b & 0xf, 16));
        }
        return text.toString();
    }

    private static String jsonStrings(List<String> values) {
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(values.get(i)).append('"');
        }
        return json.append(']').toString();
    }

    private static void appendLongs(StringBuilder json, long[] values) {
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append(values[i]);
        }
    }
}
