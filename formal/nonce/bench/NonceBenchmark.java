// Isolated old-vs-new nonce benchmark. TEST/EVIDENCE ONLY.
// Compile and run through formal/nonce/bench_nonce.py; never part of the
// production artifact.
//
// This measures one operation on one JVM thread, with warmup, forced array
// escape, thread CPU time, wall clock and thread allocation. It is performance
// evidence on one host, not a constant-time, side-channel, throughput or
// capacity claim.

package io.github.mahmoudimus.nonce.bench;

import io.github.mahmoudimus.nonce.ReferenceNonce;
import io.github.mahmoudimus.quic.crypto.internal.verifiednonce.VerifiedNonce.__default;
import java.lang.management.ManagementFactory;
import java.util.Arrays;

public final class NonceBenchmark {

    private static volatile long sink;
    private static volatile byte[] escaped;

    private interface Operation {
        byte[] apply(byte[] iv, long packetNumber);
    }

    private NonceBenchmark() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException("usage: NonceBenchmark old|new iterations rounds fork");
        }
        String mode = args[0];
        int iterations = Integer.parseInt(args[1]);
        int rounds = Integer.parseInt(args[2]);
        int fork = Integer.parseInt(args[3]);
        if (iterations < 1 || rounds < 3 || fork < 0) {
            throw new IllegalArgumentException("invalid benchmark parameters");
        }
        Operation operation = mode.equals("old") ? ReferenceNonce::nonce : __default::Nonce;
        byte[] iv = new byte[12];
        for (int i = 0; i < iv.length; i++) {
            iv[i] = (byte) (0x30 + i);
        }
        validate(mode, operation, iv, Math.min(iterations, 4096));

        // The first two rounds load classes and compile the exact paths; they
        // are never part of the reported samples.
        for (int warmup = 0; warmup < 2; warmup++) {
            consume(operation, iv, iterations);
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
            consume(operation, iv, iterations);
            samples[round] = System.nanoTime() - start;
            cpuSamples[round] = threads == null ? -1 : threads.getCurrentThreadCpuTime() - cpuStart;
        }

        long allocated = -1;
        if (threads != null) {
            try {
                long before = threads.getCurrentThreadAllocatedBytes();
                consume(operation, iv, iterations);
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
        json.append("{\"mode\":\"").append(mode)
            .append("\",\"fork\":").append(fork)
            .append(",\"iterations\":").append(iterations)
            .append(",\"rounds\":").append(rounds)
            .append(",\"ns_per_iteration\":").append((double) median / iterations)
            .append(",\"cpu_ns_per_iteration\":")
            .append(threads == null ? -1 : (double) cpuMedian / iterations)
            .append(",\"allocated_bytes_per_iteration\":").append(allocated)
            .append(",\"samples_ns\":[");
        for (int i = 0; i < samples.length; i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append(samples[i]);
        }
        json.append("],\"samples_cpu_ns\":[");
        for (int i = 0; i < cpuSamples.length; i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append(cpuSamples[i]);
        }
        json.append("],\"jdk\":\"").append(System.getProperty("java.version"))
            .append("\",\"vm\":\"").append(System.getProperty("java.vm.name"))
            .append("\",\"sink\":").append(sink)
            .append(",\"escaped_length\":").append(escaped == null ? -1 : escaped.length)
            .append('}');
        System.out.println(json);
    }

    private static void consume(Operation operation, byte[] iv, int iterations) {
        for (int i = 0; i < iterations; i++) {
            long packetNumber = 0x0102030405060708L + i;
            byte[] nonce = operation.apply(iv, packetNumber);
            sink ^= nonce[0] ^ nonce[11];
            if ((i & 63) == 0) {
                // Volatile store forces the fresh array to escape; without it
                // HotSpot may scalar-replace the allocation.
                escaped = nonce;
            }
        }
    }

    private static void validate(String mode, Operation operation, byte[] iv, int count) {
        for (int i = 0; i < count; i++) {
            long packetNumber = 0x0102030405060708L + i;
            byte[] before = iv.clone();
            byte[] actual = operation.apply(iv, packetNumber);
            if (actual.length != 12 || actual == iv || !Arrays.equals(iv, before)) {
                throw new AssertionError("nonce shape/freshness/preservation failed in " + mode);
            }
            if (mode.equals("new") && !Arrays.equals(ReferenceNonce.nonce(iv, packetNumber), actual)) {
                throw new AssertionError("generated nonce differs from frozen reference");
            }
        }
        escaped = operation.apply(iv, 0L);
    }
}
