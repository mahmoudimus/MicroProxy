// Isolated old-vs-new HKDF key-schedule benchmark. TEST/EVIDENCE ONLY.
// Compile and run through formal/dafny/bench_hkdf.py; never part of the production artifact.
//
// The workload is a TLS 1.3-shaped key schedule (RFC 8446 section 7.1) plus QUIC key/iv/hp
// expansion. It measures wall-clock cost on one JVM thread and one allocation counter. It is
// performance evidence only: not a constant-time, side-channel, throughput or capacity claim.

import io.github.mahmoudimus.quic.Hkdf;
import io.github.mahmoudimus.verifiedcrypto.ReferenceHkdf;
import java.lang.management.ManagementFactory;
import java.util.Arrays;

public final class HkdfBenchmark {
    private static volatile long sink;

    private HkdfBenchmark() {}

    private interface Schedule {
        int hashLength();
        byte[] extract(byte[] salt, byte[] ikm);
        byte[] expandLabel(byte[] secret, String label, byte[] context, int length);
    }

    private static final class OldSchedule implements Schedule {
        private final ReferenceHkdf hkdf;
        OldSchedule(ReferenceHkdf hkdf) { this.hkdf = hkdf; }
        public int hashLength() { return hkdf.hashLength(); }
        public byte[] extract(byte[] salt, byte[] ikm) { return hkdf.extract(salt, ikm); }
        public byte[] expandLabel(byte[] secret, String label, byte[] context, int length) {
            return hkdf.expandLabel(secret, label, context, length);
        }
    }

    private static final class NewSchedule implements Schedule {
        private final Hkdf hkdf;
        NewSchedule(Hkdf hkdf) { this.hkdf = hkdf; }
        public int hashLength() { return hkdf.hashLength(); }
        public byte[] extract(byte[] salt, byte[] ikm) { return hkdf.extract(salt, ikm); }
        public byte[] expandLabel(byte[] secret, String label, byte[] context, int length) {
            return hkdf.expandLabel(secret, label, context, length);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            throw new IllegalArgumentException("usage: HkdfBenchmark old|new sha256|sha384 iterations rounds fork");
        }
        String mode = args[0];
        String hash = args[1];
        int iterations = Integer.parseInt(args[2]);
        int rounds = Integer.parseInt(args[3]);
        int fork = Integer.parseInt(args[4]);
        Schedule schedule = mode.equals("old")
                ? new OldSchedule(hash.equals("sha256") ? ReferenceHkdf.SHA256 : ReferenceHkdf.SHA384)
                : new NewSchedule(hash.equals("sha256") ? Hkdf.SHA256 : Hkdf.SHA384);
        int hashLength = schedule.hashLength();
        byte[] ikm = range(0, 64);
        byte[] shared = range(0x40, 32);
        byte[] transcript = range(0x80, hashLength);
        byte[] context = range(0xc0, 17);
        byte[] emptyHash = range(0xe0, hashLength);

        // Warm up the exact code paths before timing. The first two rounds include class
        // loading and JIT compilation; they are never part of the reported samples.
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < iterations; j++) {
                sink ^= keySchedule(schedule, ikm, shared, transcript, context, emptyHash)[0];
            }
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
            // CPU-time and allocation counters are optional; wall-clock samples remain valid.
        }

        long[] samples = new long[rounds];
        long[] cpuSamples = new long[rounds];
        for (int round = 0; round < rounds; round++) {
            long cpuStart = threads == null ? 0 : threads.getCurrentThreadCpuTime();
            long start = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                sink ^= keySchedule(schedule, ikm, shared, transcript, context, emptyHash)[0];
            }
            samples[round] = System.nanoTime() - start;
            cpuSamples[round] = threads == null ? -1 : threads.getCurrentThreadCpuTime() - cpuStart;
        }

        long allocated = -1;
        if (threads != null) {
            try {
                long before = threads.getCurrentThreadAllocatedBytes();
                for (int i = 0; i < iterations; i++) {
                    sink ^= keySchedule(schedule, ikm, shared, transcript, context, emptyHash)[0];
                }
                allocated = (threads.getCurrentThreadAllocatedBytes() - before) / iterations;
            } catch (Throwable ignored) {
                // The allocation counter is optional; CPU/wall samples remain valid.
            }
        }

        Arrays.sort(samples);
        Arrays.sort(cpuSamples);
        long median = samples[rounds / 2];
        long cpuMedian = cpuSamples[rounds / 2];
        StringBuilder json = new StringBuilder();
        json.append("{\"mode\":\"").append(mode)
            .append("\",\"hash\":\"").append(hash)
            .append("\",\"fork\":").append(fork)
            .append(",\"iterations\":").append(iterations)
            .append(",\"ns_per_iteration\":").append((double) median / iterations)
            .append(",\"cpu_ns_per_iteration\":").append(threads == null ? -1 : (double) cpuMedian / iterations)
            .append(",\"allocated_bytes_per_iteration\":").append(allocated)
            .append(",\"samples_ns\":[");
        for (int i = 0; i < samples.length; i++) {
            if (i > 0) json.append(',');
            json.append(samples[i]);
        }
        json.append("],\"samples_cpu_ns\":[");
        for (int i = 0; i < cpuSamples.length; i++) {
            if (i > 0) json.append(',');
            json.append(cpuSamples[i]);
        }
        json.append("],\"jdk\":\"").append(System.getProperty("java.version"))
            .append("\",\"vm\":\"").append(System.getProperty("java.vm.name"))
            .append("\"}");
        System.out.println(json);
        System.out.println("sink=" + sink);
    }

    /**
     * RFC 8446 section 7.1-shaped schedule: Extract/Expand-Label for early, handshake and master
     * secrets, both traffic directions, exporter/resumption, and QUIC key/iv/hp expansion.
     */
    private static byte[] keySchedule(Schedule hkdf, byte[] ikm, byte[] shared,
            byte[] transcript, byte[] context, byte[] emptyHash) {
        int h = hkdf.hashLength();
        byte[] zeros = new byte[h];
        byte[] early = hkdf.extract(zeros, ikm);
        byte[] derived = hkdf.expandLabel(early, "derived", emptyHash, h);
        byte[] handshake = hkdf.extract(derived, shared);
        byte[] clientHandshake = hkdf.expandLabel(handshake, "c hs traffic", transcript, h);
        byte[] serverHandshake = hkdf.expandLabel(handshake, "s hs traffic", transcript, h);
        byte[] derivedHandshake = hkdf.expandLabel(handshake, "derived", emptyHash, h);
        byte[] master = hkdf.extract(derivedHandshake, zeros);
        byte[] clientApplication = hkdf.expandLabel(master, "c ap traffic", transcript, h);
        byte[] serverApplication = hkdf.expandLabel(master, "s ap traffic", transcript, h);
        byte[] exporter = hkdf.expandLabel(master, "exp master", transcript, h);
        byte[] resumption = hkdf.expandLabel(master, "res master", transcript, h);
        byte[] output = new byte[16];
        mix(output, hkdf.expandLabel(clientHandshake, "quic key", context, 16));
        mix(output, hkdf.expandLabel(clientHandshake, "quic iv", context, 12));
        mix(output, hkdf.expandLabel(clientHandshake, "quic hp", context, 16));
        mix(output, hkdf.expandLabel(serverHandshake, "quic key", context, 16));
        mix(output, hkdf.expandLabel(serverHandshake, "quic iv", context, 12));
        mix(output, hkdf.expandLabel(serverHandshake, "quic hp", context, 16));
        mix(output, hkdf.expandLabel(clientApplication, "quic key", context, 16));
        mix(output, hkdf.expandLabel(clientApplication, "quic iv", context, 12));
        mix(output, hkdf.expandLabel(clientApplication, "quic hp", context, 16));
        mix(output, hkdf.expandLabel(serverApplication, "quic key", context, 16));
        mix(output, hkdf.expandLabel(serverApplication, "quic iv", context, 12));
        mix(output, hkdf.expandLabel(serverApplication, "quic hp", context, 16));
        mix(output, hkdf.expandLabel(master, "quic ku", context, h));
        mix(output, exporter);
        mix(output, resumption);
        return output;
    }

    private static void mix(byte[] output, byte[] value) {
        for (int i = 0; i < value.length; i++) {
            output[i % output.length] ^= value[i];
        }
    }

    private static byte[] range(int start, int length) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = (byte) (start + i);
        }
        return result;
    }
}
